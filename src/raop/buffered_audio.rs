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

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::codec::aac::{AacBackend, AudioSsrc};
use crate::error::{CodecError, NetworkError, ShairplayError};
use crate::raop::audio_pipeline::{NONCE_TRAIL_LEN, POLY1305_TAG_LEN, RTP_HEADER_LEN, decrypt_rtp_chacha};
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
    /// The application's ALAC offload, tried first.
    pub(crate) alac_offload: Option<crate::raop::offload::AlacOffloadFactory>,
}

impl std::fmt::Debug for OutputConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputConfig")
            .field("sample_rate", &self.sample_rate)
            .field("max_channels", &self.max_channels)
            .field("format", &self.format)
            .field("aac_decoder", &self.aac_decoder.is_some())
            .field("alac_offload", &self.alac_offload.is_some())
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
    /// FLUSHBUFFERED: drop frames by sequence number (23 bits). Without `from_seq` an immediate flush: everything
    /// before `until_seq`, and playing stops until the next anchor; with it a deferred one: the frames from
    /// `from_seq` up to (not including) `until_seq`, wherever playout is (a skip while the sender is ahead).
    Flush {
        /// First sequence number to drop (deferred flush), or none (immediate).
        from_seq: Option<u32>,
        /// The first sequence number that stays (none: everything queued goes).
        until_seq: Option<u32>,
    },
    /// Stop playback and tear down.
    Stop,
}

/// Buffered packets' sequence numbers: 23 bits (the RTP header's marker bit is always set; with the 7 bits after it
/// and the next two bytes they count the packets).
const SEQ_MASK: u32 = 0x7F_FFFF;

/// `a - b` modulo 2^23, as a signed distance.
fn seq_diff(a: u32, b: u32) -> i32 {
    let d = a.wrapping_sub(b) & SEQ_MASK;
    if d & 0x40_0000 != 0 {
        d as i32 - (SEQ_MASK as i32 + 1)
    } else {
        d as i32
    }
}

/// One compressed frame, in the order the sender sent it.
struct Frame {
    seq: u32,
    ts: u32,
    ssrc: AudioSsrc,
    data: Vec<u8>,
}

/// A flush still to apply to frames that have not arrived yet.
#[derive(Clone, Copy, Debug)]
struct PendingFlush {
    from: Option<u32>,
    until: u32,
}

impl PendingFlush {
    fn drops(&self, seq: u32) -> bool {
        seq_diff(seq, self.until) < 0 && self.from.is_none_or(|f| seq_diff(seq, f) >= 0)
    }
}

/// Where frames go on the local clock.
#[derive(Clone, Copy, Debug)]
enum Timing {
    /// On the network timeline: frame `rtp` plays at network time `net_ns` of PTP clock `clock`.
    Network { clock: u64, net_ns: u64, rtp: u32 },
    /// No followed clock (yet): frame `rtp` plays at local time `local_ns`.
    Local { local_ns: u64, rtp: u32 },
}

struct PlayoutState {
    /// Compressed frames in arrival order (the sender's sequence order: one TCP stream).
    queue: VecDeque<Frame>,
    queued_bytes: usize,
    flushes: Vec<PendingFlush>,
    /// Flushes since the delivery thread last looked: it drops the same frames from what it decoded ahead.
    recent_flushes: Vec<PendingFlush>,
    /// Playing (rate 1) and the anchor's network time and clock: what SETRATEANCHORTIME said.
    playing: bool,
    anchor: Option<(u64, u64, u32)>, // (clock, network ns, rtp)
    /// How the delivery thread times frames now (set from `anchor` once the clock is followed).
    timing: Option<Timing>,
    /// The RTP clock: the stream's sample rate (timestamps count source frames).
    sample_rate: u32,
    stopped: bool,
    /// Counts flushes, pauses and re-anchors: the delivery thread then drops what it decoded ahead and may not
    /// play any more.
    epoch: u64,
    /// The session's queue must go (a pause, an immediate flush): its frames would play late or not at all.
    flush_session: bool,
    /// The last frame given to the session (its sequence number): a deferred flush from before it covers frames the
    /// session already holds.
    delivered: Option<u32>,
}

impl PlayoutState {
    fn new() -> Self {
        PlayoutState {
            queue: VecDeque::new(),
            queued_bytes: 0,
            flushes: Vec::new(),
            recent_flushes: Vec::new(),
            playing: false,
            anchor: None,
            timing: None,
            sample_rate: 44100,
            stopped: false,
            epoch: 0,
            flush_session: false,
            delivered: None,
        }
    }

    /// Drop the queued frames a flush covers.
    fn apply_flush(&mut self, f: PendingFlush) -> usize {
        let before = self.queue.len();
        self.queue.retain(|fr| !f.drops(fr.seq));
        self.queued_bytes = self.queue.iter().map(|fr| fr.data.len()).sum();
        before - self.queue.len()
    }

    /// A frame from the sender: queued unless a pending flush covers it. A flush is done once a frame at or after its
    /// end has arrived (TCP keeps the order).
    fn arrive(&mut self, frame: Frame) {
        let seq = frame.seq;
        let dropped = self.flushes.iter().any(|f| f.drops(seq));
        self.flushes.retain(|f| seq_diff(seq, f.until) < 0);
        if dropped {
            return;
        }
        self.queued_bytes += frame.data.len();
        self.queue.push_back(frame);
        // a sender that sends further ahead than it was told it may: the oldest go (bounded memory)
        while self.queued_bytes > MAX_QUEUED_BYTES {
            let Some(old) = self.queue.pop_front() else {
                break;
            };
            self.queued_bytes -= old.data.len();
        }
    }

    /// The anchor onto the local clock, if its PTP clock is followed.
    fn time_anchor(&mut self) -> bool {
        let Some((clock, net_ns, rtp)) = self.anchor else {
            return false;
        };
        if !crate::net::ptp::follower().locked(clock) {
            return false;
        }
        self.timing = Some(Timing::Network { clock, net_ns, rtp });
        true
    }
}

/// Local time (`now_ns`'s clock) at which frame `ts` should play, by `timing`.
fn play_time(timing: Timing, ts: u32, sample_rate: u32) -> Option<u64> {
    let rate = i128::from(sample_rate.max(1));
    match timing {
        Timing::Network { clock, net_ns, rtp } => {
            let frames = i128::from(ts.wrapping_sub(rtp) as i32);
            let net = i128::from(net_ns)
                + i128::from(buffered_offset_ns())
                + frames * 1_000_000_000 / rate;
            crate::net::ptp::follower().to_local(clock, net.max(0) as u64)
        }
        Timing::Local { local_ns, rtp } => {
            let frames = i128::from(ts.wrapping_sub(rtp) as i32);
            Some((i128::from(local_ns) + frames * 1_000_000_000 / rate).max(0) as u64)
        }
    }
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
        let state = Arc::new((Mutex::new(PlayoutState::new()), Condvar::new()));

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
                        s.epoch += 1;
                        let front = s.queue.front().map(|f| (f.seq, f.ts));
                        if rate & 1 == 0 {
                            s.playing = false;
                            s.flush_session = true;
                            info!(queued = s.queue.len(), "Playout paused");
                        } else {
                            s.playing = true;
                            let ptp = crate::net::ptp::follower();
                            let clock = if timeline != 0 {
                                Some(timeline)
                            } else {
                                ptp.latest()
                            };
                            s.anchor = clock
                                .filter(|_| anchor_time_ns != 0)
                                .map(|c| (c, anchor_time_ns, anchor_rtp));
                            if s.time_anchor() {
                                let in_ms = s
                                    .timing
                                    .and_then(|t| play_time(t, anchor_rtp, s.sample_rate))
                                    .map_or(0, |t| (t as i64 - now_ns() as i64) / 1_000_000);
                                info!(
                                    clock = format!("{:016x}", clock.unwrap_or(0)),
                                    anchor_in_ms = in_ms,
                                    anchor_rtp,
                                    ?front,
                                    "Playout on the network timeline"
                                );
                            } else {
                                // no followed clock (yet): from the first queued frame, a little ahead
                                let rtp = front.map_or(anchor_rtp, |f| f.1);
                                s.timing = Some(Timing::Local {
                                    local_ns: now_ns() + UNTIMED_START_NS,
                                    rtp,
                                });
                                info!(
                                    anchor_rtp,
                                    clock_pending = s.anchor.is_some(),
                                    ?front,
                                    "Playout started on the local clock"
                                );
                            }
                        }
                        cvar.notify_all();
                    }
                    PlayoutCommand::Flush {
                        from_seq,
                        until_seq,
                    } => {
                        // without an end: up to the frame after the last one queued, and nothing on the way
                        let until = until_seq
                            .or_else(|| s.queue.back().map(|f| f.seq.wrapping_add(1)))
                            .unwrap_or(0);
                        let f = PendingFlush {
                            from: from_seq.map(|v| v & SEQ_MASK),
                            until: until & SEQ_MASK,
                        };
                        let dropped = s.apply_flush(f);
                        if until_seq.is_some() {
                            // frames still on the way may be covered too
                            s.flushes.push(f);
                        }
                        s.recent_flushes.push(f);
                        s.epoch += 1;
                        if f.from.is_none() {
                            // immediate: stop until the next anchor (a seek, a new track)
                            s.playing = false;
                            s.anchor = None;
                            s.timing = None;
                            s.flush_session = true;
                        } else if let (Some(from), Some(d)) = (f.from, s.delivered)
                            && seq_diff(d, from) >= 0
                        {
                            // deferred, from a frame the session already has (it holds the last TIMED_LEAD_NS): what
                            // it holds goes too, else the old position's last half second played before the new one
                            // (a seek by Music) [HW 2026-10-28]
                            s.flush_session = true;
                        }
                        info!(from = ?f.from, until = f.until, dropped, queued = s.queue.len(), "Flushed");
                        cvar.notify_all();
                    }
                    PlayoutCommand::Stop => {
                        s.stopped = true;
                        s.queue.clear();
                        s.queued_bytes = 0;
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
            crate::net::keepalive(&stream);
            receive_loop(stream, &shk, output_config, state4, &handler).await;
        });

        cmd_tx
    }
}

/// TCP receive loop: reads length-prefixed packets, decrypts, queues the compressed frames.
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
    let mut failed = 0u32;
    // frames read; empty ones (an Apple TV sends a few per stream: SSRC 0, no payload); of an unknown format
    let (mut packets, mut empty, mut unknown) = (0u64, 0u32, 0u32);

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
        packets += 1;
        if packet.len() <= RTP_HEADER_LEN + POLY1305_TAG_LEN + NONCE_TRAIL_LEN {
            empty += 1;
            continue;
        }

        let seq = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) & SEQ_MASK;
        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ssrc_val = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let ssrc = AudioSsrc::from_u32(ssrc_val);
        if ssrc == AudioSsrc::None {
            unknown += 1;
            if unknown.is_power_of_two() {
                warn!(unknown, ssrc = format_args!("{ssrc_val:#010x}"), seq, "Buffered audio: frames of an unknown format");
            }
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
            failed += 1;
            if failed.is_power_of_two() {
                warn!(failed, seq, "Buffered audio: frames that don't decrypt");
            }
            continue;
        };

        let (lock, cvar) = &*state;
        let mut s = lock.lock().unwrap();
        if s.queue.is_empty() {
            debug!(seq, timestamp, "first frame into an empty queue");
        }
        s.arrive(Frame {
            seq,
            ts: timestamp,
            ssrc,
            data: plaintext,
        });
        cvar.notify_all();
    }
    info!(packets, empty, unknown, failed, "Buffered audio receive loop ended");
    let (lock, cvar) = &*state;
    if let Ok(mut s) = lock.lock() {
        s.stopped = true;
        s.queue.clear();
        s.queued_bytes = 0;
        cvar.notify_all();
    }
}

/// The decoder and output shaping for the current stream format.
struct Stream {
    ssrc: AudioSsrc,
    decoder: Option<Box<dyn AacBackend>>,
    /// The application's ALAC offload: frames it takes are decoded there, the rest by `decoder`.
    alac_offload: Option<Box<dyn crate::raop::offload::AlacOffload>>,
    #[cfg(feature = "resample")]
    resampler: Option<crate::codec::resample::StreamResampler>,
    src_channels: u8,
    out_channels: u8,
    /// The session's sample format, resolved for this stream's depth.
    format: crate::raop::SampleFormat,
    /// The frame the decoder should see next (sequence number), to tell a discontinuity.
    next_seq: Option<u32>,
}

impl Stream {
    /// Whether frame `seq`, about to go to the decoder, decodes only to prime it. AAC is a lapped transform: each
    /// frame's output is completed by the previous one's, so the first frame after a discontinuity (a stream's start,
    /// a flush, frames skipped as late) comes out as the new audio over the old position's tail with its aliasing
    /// uncancelled: 23 ms of garbage at each seek, many of them while scrubbing [HW 2026-10-28]. It is decoded, to
    /// fill the overlap, and its output dropped (pre-roll, as decoders do after a seek). ALAC frames stand alone.
    fn preroll(&mut self, seq: u32) -> bool {
        let gap = self.next_seq != Some(seq);
        self.next_seq = Some(seq.wrapping_add(1) & SEQ_MASK);
        gap && !self.ssrc.is_alac()
    }

    fn new(
        ssrc: AudioSsrc,
        output_config: &OutputConfig,
        handler: &Arc<dyn AudioHandler>,
    ) -> (Self, AudioFormat) {
        let src_sr = ssrc.sample_rate();
        let src_ch = ssrc.channels();
        let mut alac_offload = None;
        let decoder = if ssrc.is_alac() {
            let bit_depth = ssrc.bit_depth().unwrap_or(16);
            let params = crate::codec::alac::buffered_params(bit_depth, src_ch);
            alac_offload = output_config
                .alac_offload
                .as_ref()
                .and_then(|f| f(&params, src_sr));
            Ok(Box::new(crate::codec::alac::buffered_decoder(
                src_sr, bit_depth, src_ch,
            )) as Box<dyn AacBackend>)
        } else {
            let external = output_config
                .aac_decoder
                .as_ref()
                .and_then(|f| f(src_sr, src_ch));
            match external {
                Some(d) => Ok(Box::new(crate::codec::aac::External(d)) as Box<dyn AacBackend>),
                None => crate::codec::aac::new_decoder(src_sr, src_ch),
            }
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
        let sample_format = output_config.format.resolve(ssrc.bit_depth().unwrap_or(16));
        let format = AudioFormat {
            codec: AudioCodec::Pcm,
            bits: sample_format.bits(),
            channels: target_ch,
            sample_rate: target_sr,
        };
        let stream = Self {
            ssrc,
            decoder,
            alac_offload,
            #[cfg(feature = "resample")]
            resampler,
            src_channels: src_ch,
            out_channels: target_ch,
            format: sample_format,
            next_seq: None,
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
    fn submit(&mut self, tag: u32, frame: &[u8]) -> bool {
        if let Some(o) = self.alac_offload.as_mut() {
            return o.submit(tag, frame);
        }
        self.decoder
            .as_mut()
            .and_then(|d| d.external())
            .is_some_and(|d| d.submit(tag, frame))
    }

    /// Finished frames into their `ahead` entries.
    fn collect(&mut self, ahead: &mut VecDeque<Ahead>) {
        use crate::codec::Pcm;
        use crate::raop::offload::FramePcm;
        let mut done: Vec<(u32, Option<Pcm>)> = Vec::new();
        if let Some(o) = self.alac_offload.as_mut() {
            o.collect(&mut |tag, pcm| {
                done.push((
                    tag,
                    pcm.map(|p| match p {
                        FramePcm::S16(v) => Pcm::S16(v.to_vec()),
                        FramePcm::S24(v) => Pcm::S24(v.to_vec()),
                    }),
                ))
            });
        } else if let Some(d) = self.decoder.as_mut().and_then(|d| d.external()) {
            d.collect(&mut |tag, pcm| done.push((tag, pcm.map(|v| Pcm::S16(v.to_vec())))));
        }
        for (tag, pcm) in done {
            let pcm = pcm.map(|p| self.shape(p));
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
    seq: u32,
    ts: u32,
    tag: u32,
    pcm: Decoding,
    /// Decoded only to prime the decoder ([`Stream::preroll`]): not delivered.
    preroll: bool,
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

/// Without a followed clock, playout starts this long after the anchor arrived.
const UNTIMED_START_NS: u64 = 100_000_000;

/// A frame whose time has passed by more than this goes unplayed (a frame of AAC is 23 ms).
const LATE_NS: u64 = 25_000_000;

/// At most this much compressed audio is held (the sender is told `audioBufferSize`; this bounds one that sends
/// more).
const MAX_QUEUED_BYTES: usize = 4 << 20;

/// A fixed offset added to every frame's network time (SHAIRPLAY_BUFFERED_LATENCY_MS, may be negative; default
/// none): a frame plays at the network time its anchor gives it, as Apple's receivers do.
fn buffered_offset_ns() -> i64 {
    static L: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *L.get_or_init(|| {
        std::env::var("SHAIRPLAY_BUFFERED_LATENCY_MS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .map_or(0, |ms| (ms * 1e6) as i64)
    })
}

/// How far ahead of its time a frame goes to an asynchronous decoder, and how many at most.
const LOOKAHEAD_NS: u64 = 80_000_000;
const AHEAD_MAX: usize = 6;

/// Timed playout delivery thread. Takes frames off the queue in the sender's order as they fall due (on the network
/// timeline: [`TIMED_LEAD_NS`] before they play, with their play time), decodes and delivers them to the
/// AudioSession, which is (re)created when the stream format changes. With an asynchronous decoder (a coprocessor),
/// frames go to it up to [`LOOKAHEAD_NS`] earlier and come back in order. Frames already past their time are
/// dropped undecoded.
fn delivery_loop(
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    handler: Arc<dyn AudioHandler>,
    output_config: OutputConfig,
) {
    let (lock, cvar) = &*state;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;
    let mut stream: Option<Stream> = None;
    let (mut decoded, mut decode_ns, mut late) = (0u64, 0u64, 0u64);
    let mut ahead: VecDeque<Ahead> = VecDeque::new();
    let (mut next_tag, mut epoch, mut asynchronous) = (0u32, 0u64, true);
    let mut late_logged = 0u64;

    loop {
        let mut s = lock.lock().unwrap();

        // A pause or an immediate flush: what the session still holds goes (up to TIMED_LEAD_NS, or its prebuffer)
        if std::mem::take(&mut s.flush_session) {
            drop(s);
            if let Some(sess) = session.as_mut() {
                sess.audio_flush();
            }
            continue;
        }
        while !s.stopped
            && !s.flush_session
            && (!s.playing || s.timing.is_none() || (s.queue.is_empty() && ahead.is_empty()))
        {
            s = cvar.wait(s).unwrap();
        }
        if s.stopped {
            break;
        }
        if s.flush_session {
            continue;
        }
        // the clock followed after playout started: move onto the network timeline
        if matches!(s.timing, Some(Timing::Local { .. })) && s.time_anchor() {
            info!("Playout moved onto the network timeline");
        }
        if s.epoch != epoch {
            // flushed: drop the same frames from what went ahead (results that come back late are ignored)
            epoch = s.epoch;
            let recent = std::mem::take(&mut s.recent_flushes);
            ahead.retain(|e| !recent.iter().any(|f| f.drops(e.seq)));
        }

        // A new stream format starts with the oldest frame, once everything before it is out.
        if ahead.is_empty()
            && let Some(f) = s.queue.front()
            && stream.as_ref().is_none_or(|st| st.ssrc != f.ssrc)
        {
            let ssrc = f.ssrc;
            drop(s);
            // the previous stream's decoder goes first: it may hold a coprocessor the new one wants
            drop(stream.take());
            let (st, format) = Stream::new(ssrc, &output_config, &handler);
            info!(?format, "Audio session initialized");
            session = Some(handler.audio_init(format));
            stream = Some(st);
            asynchronous = true;
            continue;
        }

        let Some(timing) = s.timing else { continue };
        let sr = s.sample_rate;
        let now = now_ns();
        // on the network timeline the session gets frames ahead, with their time; else as they fall due
        let lead = if matches!(timing, Timing::Network { .. }) {
            TIMED_LEAD_NS
        } else {
            0
        };
        let due_in = |ts: u32| play_time(timing, ts, sr).map(|t| t as i64 - now as i64);
        let ssrc = stream.as_ref().map(|st| st.ssrc);

        // frames whose time has passed (a late start, a resume): dropped undecoded
        if ahead.is_empty() {
            while let Some(f) = s.queue.front()
                && due_in(f.ts).is_some_and(|d| d < -(LATE_NS as i64))
            {
                let f = s.queue.pop_front().unwrap();
                s.queued_bytes -= f.data.len();
                late += 1;
            }
        }

        // Frames for the asynchronous decoder: in order, within the lookahead, this stream's.
        let mut to_submit: Vec<Frame> = Vec::new();
        if asynchronous && ssrc.is_some() {
            while ahead.len() + to_submit.len() < AHEAD_MAX
                && let Some(f) = s.queue.front()
                && Some(f.ssrc) == ssrc
                && due_in(f.ts).is_some_and(|d| d <= (lead + LOOKAHEAD_NS) as i64)
            {
                let f = s.queue.pop_front().unwrap();
                s.queued_bytes -= f.data.len();
                to_submit.push(f);
            }
        }

        // Due frames, in order. Only when nothing decoded ahead is older.
        let mut ready: Vec<Frame> = Vec::new();
        if ahead.is_empty() && to_submit.is_empty() {
            while let Some(f) = s.queue.front()
                && Some(f.ssrc) == ssrc
                && due_in(f.ts).is_some_and(|d| d <= lead as i64)
            {
                let f = s.queue.pop_front().unwrap();
                s.queued_bytes -= f.data.len();
                ready.push(f);
            }
        }
        let next_in = s.queue.front().and_then(|f| due_in(f.ts));
        drop(s);
        if late > late_logged {
            debug!(late, "Frames past their time dropped");
            late_logged = late;
        }

        let format = stream.as_ref().map_or(output_config.format, |st| st.format);
        let deliver =
            |pcm: crate::codec::Pcm, ts: u32, sess: &mut Box<dyn crate::raop::AudioSession>| {
                let at = match timing {
                    Timing::Network { .. } => play_time(timing, ts, sr),
                    Timing::Local { .. } => None,
                };
                pcm.deliver_timed(sess.as_mut(), format, at);
            };

        let mut progress = !to_submit.is_empty() || !ready.is_empty();
        let mut delivered = None;
        if let Some(st) = stream.as_mut() {
            for f in to_submit {
                let tag = next_tag;
                next_tag = next_tag.wrapping_add(1);
                let preroll = st.preroll(f.seq);
                if st.submit(tag, &f.data) {
                    ahead.push_back(Ahead {
                        seq: f.seq,
                        ts: f.ts,
                        tag,
                        pcm: Decoding::Pending,
                        preroll,
                    });
                } else {
                    if ahead.is_empty() {
                        asynchronous = false; // the decoder never took one: decode when due from now on
                    }
                    let t = now_ns();
                    let pcm = st.decode(&f.data);
                    decode_ns += now_ns().saturating_sub(t);
                    ahead.push_back(Ahead {
                        seq: f.seq,
                        ts: f.ts,
                        tag,
                        pcm: Decoding::Done(pcm),
                        preroll,
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
        let now = now_ns();
        let due_in = |ts: u32| play_time(timing, ts, sr).map(|t| t as i64 - now as i64);
        while let Some(e) = ahead.front()
            && matches!(e.pcm, Decoding::Done(_))
            && due_in(e.ts).is_some_and(|d| d <= lead as i64)
        {
            let e = ahead.pop_front().unwrap();
            if due_in(e.ts).is_some_and(|d| d < -(LATE_NS as i64)) {
                late += 1;
                continue;
            }
            decoded += 1;
            delivered = Some(e.seq);
            if let (Decoding::Done(Some(pcm)), Some(sess), false) = (e.pcm, session.as_mut(), e.preroll) {
                deliver(pcm, e.ts, sess);
            }
            progress = true;
        }

        for f in ready {
            let t = now_ns();
            let preroll = stream.as_mut().is_some_and(|st| st.preroll(f.seq));
            let pcm = stream.as_mut().and_then(|st| st.decode(&f.data)).filter(|_| !preroll);
            decode_ns += now_ns().saturating_sub(t);
            decoded += 1;
            delivered = Some(f.seq);
            if let (Some(pcm), Some(sess)) = (pcm, session.as_mut()) {
                deliver(pcm, f.ts, sess);
            }
        }
        if delivered.is_some() {
            lock.lock().unwrap().delivered = delivered;
        }

        if !progress {
            // Nothing to do: sleep until the next frame is due (or due to go ahead), or a decoder result may be
            // in: at most 20 ms; new data or a command wakes us.
            let mut wait_ns = 20_000_000i64;
            if let Some(e) = ahead.front() {
                wait_ns = wait_ns.min(match e.pcm {
                    Decoding::Pending => 2_000_000,
                    Decoding::Done(_) => due_in(e.ts).map_or(wait_ns, |d| d - lead as i64),
                });
            }
            if let Some(d) = next_in {
                let early = if asynchronous {
                    lead + LOOKAHEAD_NS
                } else {
                    lead
                };
                wait_ns = wait_ns.min(d - early as i64);
            }
            let s = lock.lock().unwrap();
            if s.epoch == epoch && !s.stopped && !s.flush_session {
                drop(
                    cvar.wait_timeout(
                        s,
                        std::time::Duration::from_nanos(wait_ns.max(1_000_000) as u64),
                    )
                    .unwrap(),
                );
            }
        }
    }
    info!(
        frames = decoded,
        late,
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

    /// Frames 0..n but `skip` (one every 1024 samples, playing from now), the delivery loop with `mock`: what came
    /// out. `flush_at`: k frames in, a deferred flush of frames k+4 .. k+7.
    fn play_skipping(n: u8, skip: std::ops::Range<u8>, asynchronous: bool, flush_at: Option<u8>) -> Vec<i16> {
        let mut st = PlayoutState::new();
        for k in (0..n).filter(|k| !skip.contains(k)) {
            st.arrive(Frame {
                seq: u32::from(k),
                ts: u32::from(k) * 1024,
                ssrc: AudioSsrc::Aac44100F24Stereo,
                data: vec![k],
            });
        }
        st.playing = true;
        st.timing = Some(Timing::Local {
            local_ns: now_ns() + 10_000_000,
            rtp: 0,
        });
        let state = Arc::new((Mutex::new(st), Condvar::new()));
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
            alac_offload: None,
        };
        let st = state.clone();
        let t = std::thread::spawn(move || delivery_loop(st, handler, config));
        if let Some(k) = flush_at {
            std::thread::sleep(Duration::from_millis(u64::from(k) * 1024 * 1000 / 44100));
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            let f = PendingFlush {
                from: Some(u32::from(k) + 4),
                until: u32::from(k) + 7,
            };
            s.apply_flush(f);
            s.flushes.push(f);
            s.recent_flushes.push(f);
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

    fn play(n: u8, asynchronous: bool, flush_at: Option<u8>) -> Vec<i16> {
        play_skipping(n, 0..0, asynchronous, flush_at)
    }

    #[test]
    fn asynchronous_decoder_frames_come_out_in_order() {
        // (the first only primes the decoder: pre-roll)
        assert_eq!(play(24, true, None), (1..24).collect::<Vec<i16>>());
    }

    /// An offload that decodes frame [k] to 352 stereo 24-bit samples of value k << 4, 12 ms after it was
    /// submitted, and declines frames with k in `decline`.
    struct AlacMock {
        decline: std::ops::Range<u8>,
        queue: VecDeque<(u32, i32, Instant)>,
    }

    impl crate::raop::offload::AlacOffload for AlacMock {
        fn submit(&mut self, tag: u32, frame: &[u8]) -> bool {
            if self.decline.contains(&frame[0]) {
                return false;
            }
            let at = Instant::now() + Duration::from_millis(12);
            self.queue.push_back((tag, i32::from(frame[0]) << 4, at));
            true
        }
        fn collect(
            &mut self,
            done: &mut dyn FnMut(u32, Option<crate::raop::offload::FramePcm<'_>>),
        ) {
            while let Some(&(tag, v, at)) = self.queue.front() {
                if Instant::now() < at {
                    return;
                }
                self.queue.pop_front();
                done(
                    tag,
                    Some(crate::raop::offload::FramePcm::S24(&vec![v; 704])),
                );
            }
        }
        fn in_flight(&self) -> usize {
            self.queue.len()
        }
    }

    struct Sink32(Arc<StdMutex<(Vec<u8>, Vec<i32>)>>);
    impl crate::raop::AudioSession for Sink32 {
        fn audio_process(&mut self, _: &[f32]) {}
        fn audio_process_s16(&mut self, _: &[i16]) {
            panic!("16-bit delivery of a 24-bit stream");
        }
        fn audio_process_s32(&mut self, s: &[i32]) {
            self.0.lock().unwrap().1.push(s[0]);
        }
    }
    struct Handler32(Arc<StdMutex<(Vec<u8>, Vec<i32>)>>);
    impl AudioHandler for Handler32 {
        fn audio_init(&self, f: AudioFormat) -> Box<dyn crate::raop::AudioSession> {
            self.0.lock().unwrap().0.push(f.bits);
            Box::new(Sink32(self.0.clone()))
        }
    }

    /// ALAC/48000/S24 frames 0..n through the offload (declining `decline`) to an `Integer` session: the formats
    /// the session was set up with and the first sample of each delivery.
    fn play_alac24(n: u8, decline: std::ops::Range<u8>) -> (Vec<u8>, Vec<i32>) {
        let mut st = PlayoutState::new();
        for k in 0..n {
            st.arrive(Frame {
                seq: u32::from(k),
                ts: u32::from(k) * 352,
                ssrc: AudioSsrc::Alac48000S24Stereo,
                data: vec![k],
            });
        }
        st.playing = true;
        st.timing = Some(Timing::Local {
            local_ns: now_ns() + 10_000_000,
            rtp: 0,
        });
        let state = Arc::new((Mutex::new(st), Condvar::new()));
        let out = Arc::new(StdMutex::new((Vec::new(), Vec::new())));
        let handler: Arc<dyn AudioHandler> = Arc::new(Handler32(out.clone()));
        let factory: crate::raop::offload::AlacOffloadFactory = Arc::new(move |p, rate| {
            assert_eq!(
                (p.frame_length, p.bit_depth, p.channels, rate),
                (352, 24, 2, 48000)
            );
            Some(Box::new(AlacMock {
                decline: decline.clone(),
                queue: VecDeque::new(),
            }) as Box<dyn crate::raop::offload::AlacOffload>)
        });
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::Integer,
            aac_decoder: None,
            alac_offload: Some(factory),
        };
        let st = state.clone();
        let t = std::thread::spawn(move || delivery_loop(st, handler, config));
        std::thread::sleep(Duration::from_millis(
            u64::from(n) * 352 * 1000 / 48000 + 300,
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
    fn alac_offload_24_bit_frames_come_out_in_order_as_s32() {
        // ALAC frames stand alone: no pre-roll
        let (formats, got) = play_alac24(24, 0..0);
        assert_eq!(formats, [32]);
        assert_eq!(got, (0..24).map(|k| k << 12).collect::<Vec<i32>>());
    }

    #[test]
    fn alac_offload_declined_frames_go_to_the_software_decoder() {
        // frames 10 and 11 aren't ALAC: the library's decoder drops them; the offload goes on after them
        let (_, got) = play_alac24(24, 10..12);
        let want: Vec<i32> = (0..24)
            .filter(|k| !(10..12).contains(k))
            .map(|k| k << 12)
            .collect();
        assert_eq!(got, want);
    }

    /// An AAC decoder (synchronous) that counts the live ones.
    struct Live(Arc<std::sync::atomic::AtomicUsize>);
    impl crate::raop::offload::AacDecoder for Live {
        fn decode(&mut self, au: &[u8]) -> Option<Vec<i16>> {
            Some(vec![au[0] as i16; 2048])
        }
    }
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn a_new_formats_decoder_is_made_after_the_previous_one_is_gone() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        // AAC frames 0..8, then ALAC frames 8..16 (an Apple TV between a lossy and a lossless item)
        let mut st = PlayoutState::new();
        for k in 0..16u8 {
            st.arrive(Frame {
                seq: u32::from(k),
                ts: u32::from(k) * 352,
                ssrc: if k < 8 {
                    AudioSsrc::Aac44100F24Stereo
                } else {
                    AudioSsrc::Alac48000S24Stereo
                },
                data: vec![k],
            });
        }
        st.playing = true;
        st.timing = Some(Timing::Local {
            local_ns: now_ns() + 10_000_000,
            rtp: 0,
        });
        let state = Arc::new((Mutex::new(st), Condvar::new()));
        let out = Arc::new(StdMutex::new(Vec::new()));
        let handler: Arc<dyn AudioHandler> = Arc::new(Handler(out.clone()));
        let live = Arc::new(AtomicUsize::new(0));
        let alive_at_alac = Arc::new(AtomicUsize::new(usize::MAX));
        let (l1, l2, a2) = (live.clone(), live.clone(), alive_at_alac.clone());
        let aac: crate::raop::offload::AacDecoderFactory = Arc::new(move |_, _| {
            l1.fetch_add(1, SeqCst);
            Some(Box::new(Live(l1.clone())) as Box<dyn crate::raop::offload::AacDecoder>)
        });
        let alac: crate::raop::offload::AlacOffloadFactory = Arc::new(move |_, _| {
            a2.store(l2.load(SeqCst), SeqCst);
            Some(Box::new(AlacMock {
                decline: 0..0,
                queue: VecDeque::new(),
            }) as Box<dyn crate::raop::offload::AlacOffload>)
        });
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::S16,
            aac_decoder: Some(aac),
            alac_offload: Some(alac),
        };
        let st = state.clone();
        let t = std::thread::spawn(move || delivery_loop(st, handler, config));
        std::thread::sleep(Duration::from_millis(16 * 352 * 1000 / 44100 + 300));
        {
            let (lock, cvar) = &*state;
            lock.lock().unwrap().stopped = true;
            cvar.notify_all();
        }
        t.join().unwrap();
        assert_eq!(
            alive_at_alac.load(SeqCst),
            0,
            "the AAC decoder was still there"
        );
        // AAC from frame 1 (frame 0 primes it), ALAC frames (k << 4, 24-bit) rounded to 16 bits
        let want: Vec<i16> = (1..8)
            .chain((8..16).map(|k| ((k << 4) + 128) >> 8))
            .collect();
        assert_eq!(*out.lock().unwrap(), want);
    }

    #[test]
    fn synchronous_decoder_frames_come_out_in_order() {
        assert_eq!(play(16, false, None), (1..16).collect::<Vec<i16>>());
    }

    #[test]
    fn a_flush_drops_frames_and_nothing_comes_out_twice_or_out_of_order() {
        let got = play(24, true, Some(6));
        assert!(got.windows(2).all(|w| w[0] < w[1]), "order: {got:?}");
        // and the frame after them, if the decoder hadn't had them yet (pre-roll after the gap)
        let want: Vec<i16> = (1..24).filter(|&k| !(10..13).contains(&k)).collect();
        let want_preroll: Vec<i16> = (1..24).filter(|&k| !(10..14).contains(&k)).collect();
        assert!(got == want || got == want_preroll, "exactly the flushed frames are missing: {got:?}");
    }

    #[test]
    fn the_first_frame_after_a_gap_only_primes_the_decoder() {
        for asynchronous in [true, false] {
            let want: Vec<i16> = (1..16).filter(|&k| !(5..9).contains(&k)).collect();
            assert_eq!(play_skipping(16, 5..8, asynchronous, None), want, "asynchronous: {asynchronous}");
        }
    }

    #[test]
    fn sequence_numbers_compare_across_the_wrap() {
        assert_eq!(seq_diff(5, 3), 2);
        assert_eq!(seq_diff(3, 5), -2);
        assert_eq!(seq_diff(1, SEQ_MASK), 2);
        assert_eq!(seq_diff(SEQ_MASK, 1), -2);
    }

    #[test]
    fn an_immediate_flush_drops_what_came_before_and_what_is_still_on_the_way() {
        let mut st = PlayoutState::new();
        let frame = |seq: u32| Frame {
            seq,
            ts: seq * 1024,
            ssrc: AudioSsrc::Aac44100F24Stereo,
            data: vec![0; 10],
        };
        for k in 100..110 {
            st.arrive(frame(k));
        }
        let f = PendingFlush {
            from: None,
            until: 120,
        };
        assert_eq!(st.apply_flush(f), 10);
        st.flushes.push(f);
        // the rest of the old track, then the new one from 120
        for k in 110..125 {
            st.arrive(frame(k));
        }
        assert_eq!(
            st.queue.iter().map(|f| f.seq).collect::<Vec<_>>(),
            (120..125).collect::<Vec<_>>()
        );
        assert!(
            st.flushes.is_empty(),
            "done once the first frame after it arrived"
        );
        assert_eq!(st.queued_bytes, 50);
    }

    #[test]
    fn a_deferred_flush_keeps_both_sides() {
        let mut st = PlayoutState::new();
        for k in (SEQ_MASK - 3)..=SEQ_MASK {
            st.arrive(Frame {
                seq: k,
                ts: 0,
                ssrc: AudioSsrc::Aac44100F24Stereo,
                data: vec![],
            });
        }
        for k in 0..6 {
            st.arrive(Frame {
                seq: k,
                ts: 0,
                ssrc: AudioSsrc::Aac44100F24Stereo,
                data: vec![],
            });
        }
        // across the sequence wrap: SEQ_MASK-1 .. 2 go
        st.apply_flush(PendingFlush {
            from: Some(SEQ_MASK - 1),
            until: 3,
        });
        assert_eq!(
            st.queue.iter().map(|f| f.seq).collect::<Vec<_>>(),
            vec![SEQ_MASK - 3, SEQ_MASK - 2, 3, 4, 5]
        );
    }
}
