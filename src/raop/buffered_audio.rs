//! AirPlay 2 buffered audio processor (stream type 103).
//!
//! Receives encrypted AAC packets over TCP, decrypts them with ChaCha20-Poly1305 and keeps them
//! compressed in a timed playout buffer; frames are decoded (AAC backend: `codec::aac`), mixed down or
//! resampled if the output asks for it, and delivered in the session's sample format as they fall due.
//! Senders stream far ahead (up to the advertised `audioBufferSize`), so holding compressed audio
//! instead of decoded PCM keeps the buffer ~5x (s16) to ~11x (f32) smaller, and decoding is spread
//! evenly over playback instead of in bursts as packets arrive.
//!
//! Three concurrent tasks:
//! - **Receiver** (tokio): accepts TCP, decrypts, buffers compressed frames by RTP timestamp
//! - **Command handler** (tokio): processes SetRate/Flush/Stop from RTSP thread
//! - **Delivery** (std::thread): timed playout using anchor-based scheduling; decodes and delivers

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::codec::aac::{AacBackend, AudioSsrc};
use crate::error::{CodecError, NetworkError, ShairplayError};
use crate::raop::audio_pipeline::{NONCE_TRAIL_LEN, RTP_HEADER_LEN, decrypt_rtp_chacha};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};
use crate::util::now_ns;

#[derive(Clone)]
/// Output configuration passed from the server builder.
pub(crate) struct OutputConfig {
    /// Target sample rate, or None for source native rate.
    pub(crate) sample_rate: Option<u32>,
    /// Maximum output channels, or None to pass through.
    pub(crate) max_channels: Option<u8>,
    /// Sample format of the PCM handed to the session.
    pub(crate) format: crate::raop::SampleFormat,
    /// The application's AAC decoder, tried first.
    pub(crate) aac_decoder: Option<crate::raop::offload::AacDecoderFactory>,
}

impl std::fmt::Debug for OutputConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputConfig")
            .field("sample_rate", &self.sample_rate)
            .field("max_channels", &self.max_channels)
            .field("format", &self.format)
            .field("aac_decoder", &self.aac_decoder.is_some())
            .finish()
    }
}

#[derive(Debug)]
/// Commands sent from the RTSP handler thread to the playout engine.
pub enum PlayoutCommand {
    /// Set playback rate and anchor point. rate=0 means pause.
    SetRate {
        /// RTP timestamp at the anchor point.
        anchor_rtp: u32,
        /// Network time at the anchor point (ns).
        anchor_time_ns: u64,
        /// The PTP clock that network time is on (`networkTimeTimelineID`; 0: the master heard last).
        timeline: u64,
        /// Playback rate (1 = playing, 0 = paused).
        rate: u32,
    },
    /// Flush buffered frames in the given RTP timestamp range.
    Flush {
        /// First timestamp to flush.
        from_seq: u32,
        /// Last timestamp to flush.
        until_seq: u32,
    },
    /// Stop playback and tear down.
    Stop,
}

struct PlayoutState {
    buffer: BTreeMap<u32, (AudioSsrc, Vec<u8>)>, // rtp_timestamp → decrypted (compressed) AAC frame
    anchor_rtp: u32,
    anchor_local_ns: u64,
    /// On the network timeline: the followed clock, the anchor's network time and RTP time (the sender's); frames
    /// then go out [`TIMED_LEAD_NS`] ahead with the local time they should play (`audio_process_timed_s16`), once
    /// the clock is followed (`timed_anchored`: the delivery schedule moved onto the timeline).
    timed: Option<(u64, u64, u32)>,
    timed_anchored: bool,
    rate: u32,
    /// The RTP clock: the stream's sample rate (timestamps count source frames).
    sample_rate: u32,
    stopped: bool,
    /// Counts flushes and re-anchors; `flushed` holds the timestamp ranges flushed since the delivery thread
    /// last looked, so it can drop the same frames from what it decoded ahead.
    epoch: u64,
    flushed: Vec<(u32, u32)>,
}

/// TCP listener for buffered audio. Binds a port and spawns the processing pipeline.
pub(crate) struct BufferedAudioProcessor {
    /// TCP listener waiting for the iPhone to connect.
    pub(crate) listener: TcpListener,
}

impl BufferedAudioProcessor {
    /// Start the processing pipeline. Returns a command sender for playback control.
    pub(crate) fn start(
        self,
        shk: [u8; 32],
        output_config: OutputConfig,
        handler: Arc<dyn AudioHandler>,
    ) -> tokio::sync::mpsc::UnboundedSender<PlayoutCommand> {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let state = Arc::new((
            Mutex::new(PlayoutState {
                buffer: BTreeMap::new(),
                anchor_rtp: 0,
                anchor_local_ns: 0,
                timed: None,
                timed_anchored: false,
                rate: 0,
                sample_rate: 44100,
                stopped: false,
                epoch: 0,
                flushed: Vec::new(),
            }),
            Condvar::new(),
        ));

        // Delivery thread
        let state2 = state.clone();
        let handler2 = handler.clone();
        let output_config2 = output_config.clone();
        std::thread::spawn(move || {
            delivery_loop(state2, handler2, output_config2);
        });

        // Command handler
        let state3 = state.clone();
        let mut cmd_rx = cmd_rx;
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let (lock, cvar) = &*state3;
                let mut s = lock.lock().unwrap();
                match cmd {
                    PlayoutCommand::SetRate {
                        anchor_rtp,
                        anchor_time_ns,
                        timeline,
                        rate,
                    } => {
                        s.anchor_rtp = anchor_rtp;
                        s.epoch += 1;
                        let was_paused = s.rate == 0;
                        s.rate = rate;
                        let ptp = crate::net::ptp::follower();
                        let clock = if timeline != 0 {
                            Some(timeline)
                        } else {
                            ptp.latest()
                        };
                        let anchor_local = clock.filter(|_| anchor_time_ns != 0).and_then(|c| {
                            ptp.to_local(c, anchor_time_ns + buffered_latency_ns())
                                .map(|t| (c, t))
                        });
                        // on the network timeline if the sender gave one: play times once the clock is followed
                        s.timed = clock
                            .filter(|_| anchor_time_ns != 0 && rate != 0)
                            .map(|c| (c, anchor_time_ns, anchor_rtp));
                        s.timed_anchored = anchor_local.is_some();
                        if rate == 0 {
                            info!("Playout paused");
                        } else if let Some((clock, local)) = anchor_local {
                            // On the network timeline: frames due TIMED_LEAD_NS before they should play
                            s.anchor_local_ns = local.saturating_sub(TIMED_LEAD_NS);
                            let anchor = s.anchor_rtp;
                            let stale: Vec<u32> = s
                                .buffer
                                .keys()
                                .filter(|&&ts| (anchor.wrapping_sub(ts) as i32) > 0)
                                .copied()
                                .collect();
                            for k in stale {
                                s.buffer.remove(&k);
                            }
                            info!(
                                clock = format!("{clock:016x}"),
                                in_ms = (local as i64 - now_ns() as i64) / 1_000_000,
                                anchor_rtp,
                                "Playout on the network timeline"
                            );
                        } else {
                            // Set anchor so the earliest buffered frame is deliverable
                            // with a small lead time for smooth playback
                            if let Some(&first_ts) = s.buffer.keys().next() {
                                let lead_frames = s.sample_rate / 10; // 100ms lead
                                s.anchor_rtp = first_ts.wrapping_sub(lead_frames);
                            }
                            s.anchor_local_ns = now_ns();
                            let stale: Vec<u32> = s
                                .buffer
                                .keys()
                                .filter(|&&ts| (s.anchor_rtp.wrapping_sub(ts) as i32) > 0)
                                .copied()
                                .collect();
                            if !stale.is_empty() {
                                debug!(discarded = stale.len(), "Discarded stale frames");
                            }
                            for k in stale {
                                s.buffer.remove(&k);
                            }
                            if was_paused {
                                info!(
                                    anchor_rtp,
                                    clock_pending = s.timed.is_some(),
                                    "Playout started"
                                );
                            }
                        }
                        cvar.notify_all();
                    }
                    PlayoutCommand::Flush {
                        from_seq,
                        until_seq,
                    } => {
                        let keys: Vec<u32> = s
                            .buffer
                            .keys()
                            .filter(|&&ts| ts >= from_seq && ts <= until_seq)
                            .copied()
                            .collect();
                        for k in &keys {
                            s.buffer.remove(k);
                        }
                        s.epoch += 1;
                        s.flushed.push((from_seq, until_seq));
                        debug!(flushed = keys.len(), "Flushed");
                    }
                    PlayoutCommand::Stop => {
                        s.stopped = true;
                        s.buffer.clear();
                        cvar.notify_all();
                        break;
                    }
                }
            }
        });

        // Receiver task
        let state4 = state.clone();

        tokio::spawn(async move {
            let (stream, addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Buffered audio accept failed: {e}");
                    handler.on_error(&ShairplayError::Network(NetworkError::Io(e)));
                    return;
                }
            };
            info!(%addr, "Buffered audio client connected");
            receive_loop(stream, &shk, output_config, state4, &handler).await;
        });

        cmd_tx
    }
}

/// TCP receive loop: reads length-prefixed packets, decrypts, buffers the compressed frames.
async fn receive_loop(
    mut stream: TcpStream,
    shk: &[u8; 32],
    _output_config: OutputConfig,
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    _handler: &Arc<dyn AudioHandler>,
) {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

    let cipher = ChaCha20Poly1305::new(shk.into());
    let mut len_buf = [0u8; 2];
    let mut current_ssrc = AudioSsrc::None;

    loop {
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let total_len = u16::from_be_bytes(len_buf) as usize;
        if total_len < 2 {
            break;
        }

        let mut packet = vec![0u8; total_len - 2];
        if stream.read_exact(&mut packet).await.is_err() {
            break;
        }
        if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN {
            continue;
        }

        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ssrc_val = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let ssrc = AudioSsrc::from_u32(ssrc_val);
        if ssrc == AudioSsrc::None {
            continue;
        }

        // The RTP clock follows the stream's rate; the delivery thread sets up the decoder.
        if ssrc != current_ssrc {
            current_ssrc = ssrc;
            info!(ssrc = ?ssrc, src_sr = ssrc.sample_rate(), src_ch = ssrc.channels(), "Audio format detected");
            let (lock, _) = &*state;
            lock.lock().unwrap().sample_rate = ssrc.sample_rate();
        }

        // Decrypt the ChaCha20-Poly1305 RTP frame.
        let Some(plaintext) = decrypt_rtp_chacha(&cipher, &packet) else {
            debug!("Audio decrypt failed");
            continue;
        };

        let (lock, cvar) = &*state;
        let mut s = lock.lock().unwrap();
        s.buffer.insert(timestamp, (ssrc, plaintext));
        cvar.notify_all();
    }
    debug!("Buffered audio receive loop ended");
    let (lock, cvar) = &*state;
    if let Ok(mut s) = lock.lock() {
        s.stopped = true;
        s.buffer.clear();
        cvar.notify_all();
    }
}

/// The decoder and output shaping for the current stream format.
struct Stream {
    ssrc: AudioSsrc,
    decoder: Option<Box<dyn AacBackend>>,
    #[cfg(feature = "resample")]
    resampler: Option<crate::codec::resample::StreamResampler>,
    src_channels: u8,
    out_channels: u8,
}

impl Stream {
    fn new(
        ssrc: AudioSsrc,
        output_config: &OutputConfig,
        handler: &Arc<dyn AudioHandler>,
    ) -> (Self, AudioFormat) {
        let src_sr = ssrc.sample_rate();
        let src_ch = ssrc.channels();
        let external = output_config
            .aac_decoder
            .as_ref()
            .and_then(|f| f(src_sr, src_ch));
        let decoder = match external {
            Some(d) => Ok(Box::new(crate::codec::aac::External(d)) as Box<dyn AacBackend>),
            None => crate::codec::aac::new_decoder(src_sr, src_ch),
        };
        let decoder = match decoder {
            Ok(d) => Some(d),
            Err(e) => {
                warn!("Failed to create AAC decoder for {:?}: {e}", ssrc);
                handler.on_error(&ShairplayError::Codec(CodecError::UnsupportedFormat(format!(
                    "AAC decoder init failed (ssrc={ssrc:?}, sample_rate={src_sr}, channels={src_ch}): {e}"
                ))));
                None
            }
        };
        let target_sr = output_config.sample_rate.unwrap_or(src_sr);
        let target_ch = output_config
            .max_channels
            .map(|max| src_ch.min(max))
            .unwrap_or(src_ch);
        #[cfg(feature = "resample")]
        let resampler =
            crate::codec::resample::StreamResampler::new(src_sr, target_sr, target_ch as usize);
        #[cfg(not(feature = "resample"))]
        let target_sr = {
            if target_sr != src_sr {
                warn!(
                    from = src_sr,
                    to = target_sr,
                    "Resampling needs the resample feature; playing at the stream's rate"
                );
            }
            src_sr
        };
        let format = AudioFormat {
            codec: AudioCodec::Pcm,
            bits: output_config.format.bits(),
            channels: target_ch,
            sample_rate: target_sr,
        };
        let stream = Self {
            ssrc,
            decoder,
            #[cfg(feature = "resample")]
            resampler,
            src_channels: src_ch,
            out_channels: target_ch,
        };
        (stream, format)
    }

    fn decode(&mut self, aac: &[u8]) -> Option<crate::codec::Pcm> {
        let pcm = self.decoder.as_mut()?.decode(aac)?;
        Some(self.shape(pcm))
    }

    fn shape(&mut self, pcm: crate::codec::Pcm) -> crate::codec::Pcm {
        crate::codec::shape(
            pcm,
            self.src_channels,
            self.out_channels,
            #[cfg(feature = "resample")]
            &mut self.resampler,
        )
    }

    /// Queue a frame with an asynchronous decoder; `false` if it has none or it can't take the frame now.
    fn submit(&mut self, tag: u32, aac: &[u8]) -> bool {
        self.decoder
            .as_mut()
            .and_then(|d| d.external())
            .is_some_and(|d| d.submit(tag, aac))
    }

    /// Finished frames into their `ahead` entries.
    fn collect(&mut self, ahead: &mut VecDeque<Ahead>) {
        let mut done: Vec<(u32, Option<Vec<i16>>)> = Vec::new();
        if let Some(d) = self.decoder.as_mut().and_then(|d| d.external()) {
            d.collect(&mut |tag, pcm| done.push((tag, pcm.map(<[i16]>::to_vec))));
        }
        for (tag, pcm) in done {
            let pcm = pcm.map(|v| self.shape(crate::codec::Pcm::S16(v)));
            if let Some(e) = ahead
                .iter_mut()
                .find(|e| e.tag == tag && matches!(e.pcm, Decoding::Pending))
            {
                e.pcm = Decoding::Done(pcm);
            }
        }
    }
}

/// A frame given to an asynchronous decoder ahead of its time.
struct Ahead {
    ts: u32,
    tag: u32,
    pcm: Decoding,
}

/// Where an `Ahead` frame is.
enum Decoding {
    /// The decoder has it.
    Pending,
    /// Decoded, or dropped by the decoder (`None`).
    Done(Option<crate::codec::Pcm>),
}

/// On the network timeline, frames go to the session this long before they should play (the session schedules
/// them: queue, device buffer).
const TIMED_LEAD_NS: u64 = 500_000_000;

/// A buffered stream's frame plays this long after the network time its anchor gives it: the anchor arrives
/// stamped "now", and Apple's own receivers play behind it. Measured against macOS Music's "This Computer" in a
/// group with this receiver: 699.5 ms. SHAIRPLAY_BUFFERED_LATENCY_MS overrides.
fn buffered_latency_ns() -> u64 {
    static L: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *L.get_or_init(|| {
        std::env::var("SHAIRPLAY_BUFFERED_LATENCY_MS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .map_or(699_500_000, |ms| (ms * 1e6) as u64)
    })
}

/// How far ahead of its time a frame goes to an asynchronous decoder, and how many at most.
const LOOKAHEAD_NS: u64 = 80_000_000;
const AHEAD_MAX: usize = 6;

/// Timed playout delivery thread. Wakes on condvar, decodes due frames and delivers them to the
/// AudioSession, which is (re)created when the stream format changes. With an asynchronous decoder
/// (a coprocessor), frames go to it up to [`LOOKAHEAD_NS`] before they are due and come back in order.
fn delivery_loop(
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    handler: Arc<dyn AudioHandler>,
    output_config: OutputConfig,
) {
    let (lock, cvar) = &*state;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;
    let mut stream: Option<Stream> = None;
    let (mut decoded, mut decode_ns) = (0u64, 0u64);
    let mut ahead: VecDeque<Ahead> = VecDeque::new();
    let (mut next_tag, mut epoch, mut asynchronous) = (0u32, 0u64, true);
    let mut paused = false;

    loop {
        let mut s = lock.lock().unwrap();

        // Paused: what the session still holds stops too (it holds up to TIMED_LEAD_NS ahead, or its prebuffer)
        if s.rate == 0 && !paused && session.is_some() {
            paused = true;
            drop(s);
            if let Some(sess) = session.as_mut() {
                sess.audio_flush();
            }
            continue;
        }
        while !s.stopped && (s.rate == 0 || (s.buffer.is_empty() && ahead.is_empty())) {
            s = cvar.wait(s).unwrap();
        }
        paused = s.rate == 0;
        if s.stopped {
            break;
        }
        // the clock followed after playout started: move the delivery schedule onto the network timeline
        if let Some((clock, net, rtp)) = s.timed
            && !s.timed_anchored
            && let Some(local) =
                crate::net::ptp::follower().to_local(clock, net + buffered_latency_ns())
        {
            s.anchor_rtp = rtp;
            s.anchor_local_ns = local.saturating_sub(TIMED_LEAD_NS);
            s.timed_anchored = true;
            info!(
                clock = format!("{clock:016x}"),
                "Playout moved onto the network timeline"
            );
        }
        if s.epoch != epoch {
            // flushed or re-anchored: drop the same frames from what went ahead (late results are ignored)
            epoch = s.epoch;
            let flushed = std::mem::take(&mut s.flushed);
            if !flushed.is_empty()
                && let Some(sess) = session.as_mut()
            {
                // a flush (seek, skip): the session's queue goes too
                sess.audio_flush();
            }
            let anchor = s.anchor_rtp;
            let rate = s.rate;
            ahead.retain(|e| {
                let in_flush = flushed.iter().any(|&(a, b)| e.ts >= a && e.ts <= b);
                let behind_anchor = rate != 0 && (anchor.wrapping_sub(e.ts) as i32) > 0;
                !(in_flush || behind_anchor)
            });
        }

        // A new stream format starts with the oldest frame, once everything before it is out.
        if ahead.is_empty()
            && let Some((_, (ssrc, _))) = s.buffer.iter().next()
            && stream.as_ref().is_none_or(|st| st.ssrc != *ssrc)
        {
            let ssrc = *ssrc;
            drop(s);
            let (st, format) = Stream::new(ssrc, &output_config, &handler);
            info!(?format, "Audio session initialized");
            session = Some(handler.audio_init(format));
            stream = Some(st);
            asynchronous = true;
            continue;
        }

        let now = now_ns();
        let elapsed_ns = now.saturating_sub(s.anchor_local_ns);
        let elapsed_frames = (elapsed_ns as u128 * s.sample_rate as u128 / 1_000_000_000) as u32;
        let target_rtp = s.anchor_rtp.wrapping_add(elapsed_frames);
        let is_due = |ts: u32| (target_rtp.wrapping_sub(ts) as i32) >= 0;
        let lookahead = (LOOKAHEAD_NS as u128 * s.sample_rate as u128 / 1_000_000_000) as i32;

        // Frames for the asynchronous decoder: oldest first, within the lookahead, this stream's.
        let mut to_submit: Vec<(u32, Vec<u8>)> = Vec::new();
        if asynchronous && let Some(st) = stream.as_ref() {
            while ahead.len() + to_submit.len() < AHEAD_MAX {
                let Some((&ts, (ssrc, _))) = s.buffer.iter().next() else {
                    break;
                };
                if *ssrc != st.ssrc || (ts.wrapping_sub(target_rtp) as i32) > lookahead {
                    break;
                }
                let (_, aac) = s.buffer.remove(&ts).unwrap();
                to_submit.push((ts, aac));
            }
        }

        // Due frames, oldest first: the map is ordered, so stop at the first one not due yet. Around the RTP
        // timestamp wrap (every ~27 h at 44.1 kHz) the oldest frames sort last: then scan everything. Only
        // when nothing decoded ahead is older.
        let mut ready: Vec<(u32, AudioSsrc, Vec<u8>)> = Vec::new();
        if ahead.is_empty() && to_submit.is_empty() {
            let mut due: Vec<u32> = s
                .buffer
                .keys()
                .copied()
                .take_while(|&ts| is_due(ts))
                .collect();
            if due.is_empty() && s.buffer.keys().next_back().is_some_and(|&ts| is_due(ts)) {
                due = s.buffer.keys().copied().filter(|&ts| is_due(ts)).collect();
            }
            ready = due
                .iter()
                .filter_map(|&ts| s.buffer.remove(&ts).map(|(ssrc, aac)| (ts, ssrc, aac)))
                .collect();
        }
        let next_ts = s.buffer.keys().next().copied();
        let sample_rate = i64::from(s.sample_rate.max(1));
        // where each frame belongs on the network timeline, in local time (None: untimed)
        let (timed, sr_now) = (s.timed.filter(|_| s.timed_anchored), s.sample_rate.max(1));
        let play_at = move |ts: u32| -> Option<u64> {
            let (clock, anchor_net, anchor_rtp) = timed?;
            let frames = ts.wrapping_sub(anchor_rtp) as i32 as i64;
            let net = anchor_net as i64
                + buffered_latency_ns() as i64
                + frames * 1_000_000_000 / sr_now as i64;
            crate::net::ptp::follower().to_local(clock, net.max(0) as u64)
        };
        drop(s);

        let mut progress = !to_submit.is_empty() || !ready.is_empty();
        if let Some(st) = stream.as_mut() {
            for (ts, aac) in to_submit {
                let tag = next_tag;
                next_tag = next_tag.wrapping_add(1);
                if st.submit(tag, &aac) {
                    ahead.push_back(Ahead {
                        ts,
                        tag,
                        pcm: Decoding::Pending,
                    });
                } else {
                    if ahead.is_empty() {
                        asynchronous = false; // the decoder never took one: decode when due from now on
                    }
                    let t = now_ns();
                    let pcm = st.decode(&aac);
                    decode_ns += now_ns().saturating_sub(t);
                    ahead.push_back(Ahead {
                        ts,
                        tag,
                        pcm: Decoding::Done(pcm),
                    });
                }
            }
            let before = ahead
                .iter()
                .filter(|e| matches!(e.pcm, Decoding::Done(_)))
                .count();
            st.collect(&mut ahead);
            progress |= ahead
                .iter()
                .filter(|e| matches!(e.pcm, Decoding::Done(_)))
                .count()
                != before;
        }
        while ahead
            .front()
            .is_some_and(|e| is_due(e.ts) && matches!(e.pcm, Decoding::Done(_)))
        {
            let e = ahead.pop_front().unwrap();
            decoded += 1;
            if let (Decoding::Done(Some(pcm)), Some(sess)) = (e.pcm, session.as_mut()) {
                pcm.deliver_timed(sess.as_mut(), output_config.format, play_at(e.ts));
            }
            progress = true;
        }

        for (ts, ssrc, aac) in ready {
            if stream.as_ref().is_none_or(|st| st.ssrc != ssrc) {
                let (st, format) = Stream::new(ssrc, &output_config, &handler);
                info!(?format, "Audio session initialized");
                session = Some(handler.audio_init(format));
                stream = Some(st);
            }
            let t = now_ns();
            let pcm = stream.as_mut().and_then(|st| st.decode(&aac));
            decode_ns += now_ns().saturating_sub(t);
            decoded += 1;
            if let (Some(pcm), Some(sess)) = (pcm, session.as_mut()) {
                pcm.deliver_timed(sess.as_mut(), output_config.format, play_at(ts));
            }
        }

        if !progress {
            // Nothing to do: sleep until the next frame is due (or due to go ahead), or a decoder result may be
            // in: at most 20 ms; new data or a command wakes us.
            let until = |ts: u32, early: i64| {
                let frames = ts.wrapping_sub(target_rtp) as i32 as i64 - early;
                (frames.max(0) * 1_000_000_000 / sample_rate) as u64
            };
            let mut wait_ns = 20_000_000u64;
            if let Some(e) = ahead.front() {
                wait_ns = wait_ns.min(if matches!(e.pcm, Decoding::Pending) {
                    2_000_000
                } else {
                    until(e.ts, 0)
                });
            }
            if let Some(ts) = next_ts {
                wait_ns = wait_ns.min(until(
                    ts,
                    if asynchronous {
                        i64::from(lookahead)
                    } else {
                        0
                    },
                ));
            }
            let s = lock.lock().unwrap();
            if s.epoch == epoch && !s.stopped {
                drop(
                    cvar.wait_timeout(s, std::time::Duration::from_nanos(wait_ns.max(1_000_000)))
                        .unwrap(),
                );
            }
        }
    }
    info!(
        frames = decoded,
        decode_ms = decode_ns / 1_000_000,
        "Delivery loop ended"
    );
}

#[cfg(test)]
mod decode_ahead_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    /// Decodes a frame [k] to 1024 stereo samples of value k, `delay` after it was submitted (or at once when
    /// `asynchronous` is off).
    struct Mock {
        asynchronous: bool,
        delay: Duration,
        queue: VecDeque<(u32, i16, Instant)>,
    }

    impl crate::raop::offload::AacDecoder for Mock {
        fn decode(&mut self, au: &[u8]) -> Option<Vec<i16>> {
            Some(vec![au[0] as i16; 2048])
        }
        fn submit(&mut self, tag: u32, au: &[u8]) -> bool {
            if self.asynchronous {
                self.queue
                    .push_back((tag, au[0] as i16, Instant::now() + self.delay));
            }
            self.asynchronous
        }
        fn collect(&mut self, done: &mut dyn FnMut(u32, Option<&[i16]>)) {
            while let Some(&(tag, v, at)) = self.queue.front() {
                if Instant::now() < at {
                    return;
                }
                self.queue.pop_front();
                done(tag, Some(&vec![v; 2048]));
            }
        }
        fn in_flight(&self) -> usize {
            self.queue.len()
        }
    }

    struct Sink(Arc<StdMutex<Vec<i16>>>);
    impl crate::raop::AudioSession for Sink {
        fn audio_process(&mut self, _: &[f32]) {}
        fn audio_process_s16(&mut self, s: &[i16]) {
            self.0.lock().unwrap().push(s[0]);
        }
    }
    struct Handler(Arc<StdMutex<Vec<i16>>>);
    impl AudioHandler for Handler {
        fn audio_init(&self, _: AudioFormat) -> Box<dyn crate::raop::AudioSession> {
            Box::new(Sink(self.0.clone()))
        }
    }

    /// Frames 0..n (one every 1024 samples, playing from now), the delivery loop with `mock`: what came out.
    fn play(n: u8, asynchronous: bool, flush_at: Option<u8>) -> Vec<i16> {
        let mut buffer = BTreeMap::new();
        for k in 0..n {
            buffer.insert(u32::from(k) * 1024, (AudioSsrc::Aac44100F24Stereo, vec![k]));
        }
        let state = Arc::new((
            Mutex::new(PlayoutState {
                buffer,
                anchor_rtp: 0u32.wrapping_sub(441),
                anchor_local_ns: now_ns(),
                timed: None,
                timed_anchored: false,
                rate: 1,
                sample_rate: 44100,
                stopped: false,
                epoch: 0,
                flushed: Vec::new(),
            }),
            Condvar::new(),
        ));
        let out = Arc::new(StdMutex::new(Vec::new()));
        let handler: Arc<dyn AudioHandler> = Arc::new(Handler(out.clone()));
        let factory: crate::raop::offload::AacDecoderFactory = Arc::new(move |_, _| {
            Some(Box::new(Mock {
                asynchronous,
                delay: Duration::from_millis(12),
                queue: VecDeque::new(),
            }) as Box<dyn crate::raop::offload::AacDecoder>)
        });
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::S16,
            aac_decoder: Some(factory),
        };
        let st = state.clone();
        let t = std::thread::spawn(move || delivery_loop(st, handler, config));
        if let Some(k) = flush_at {
            std::thread::sleep(Duration::from_millis(u64::from(k) * 1024 * 1000 / 44100));
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            let keys: Vec<u32> = s
                .buffer
                .keys()
                .copied()
                .filter(|&ts| ts >= (u32::from(k) + 4) * 1024)
                .collect();
            for key in keys.iter().take(3) {
                s.buffer.remove(key);
            }
            let range = (keys[0], keys[2]);
            s.flushed.push(range);
            s.epoch += 1;
            cvar.notify_all();
        }
        std::thread::sleep(Duration::from_millis(
            u64::from(n) * 1024 * 1000 / 44100 + 300,
        ));
        {
            let (lock, cvar) = &*state;
            lock.lock().unwrap().stopped = true;
            cvar.notify_all();
        }
        t.join().unwrap();
        out.lock().unwrap().clone()
    }

    #[test]
    fn asynchronous_decoder_frames_come_out_in_order() {
        assert_eq!(play(24, true, None), (0..24).collect::<Vec<i16>>());
    }

    #[test]
    fn synchronous_decoder_frames_come_out_in_order() {
        assert_eq!(play(16, false, None), (0..16).collect::<Vec<i16>>());
    }

    #[test]
    fn a_flush_drops_frames_and_nothing_comes_out_twice_or_out_of_order() {
        let got = play(24, true, Some(6));
        assert!(got.windows(2).all(|w| w[0] < w[1]), "order: {got:?}");
        let want: Vec<i16> = (0..24).filter(|&k| !(10..13).contains(&k)).collect();
        assert_eq!(got, want, "exactly the flushed frames are missing");
    }
}
