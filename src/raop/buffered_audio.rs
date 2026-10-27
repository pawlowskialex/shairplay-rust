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

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::codec::aac::{AacBackend, AudioSsrc};
use crate::error::{CodecError, NetworkError, ShairplayError};
use crate::raop::audio_pipeline::{NONCE_TRAIL_LEN, RTP_HEADER_LEN, decrypt_rtp_chacha};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};
use crate::util::now_ns;

#[derive(Debug, Clone)]
/// Output configuration passed from the server builder.
pub(crate) struct OutputConfig {
    /// Target sample rate, or None for source native rate.
    pub(crate) sample_rate: Option<u32>,
    /// Maximum output channels, or None to pass through.
    pub(crate) max_channels: Option<u8>,
    /// Sample format of the PCM handed to the session.
    pub(crate) format: crate::raop::SampleFormat,
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
    rate: u32,
    /// The RTP clock: the stream's sample rate (timestamps count source frames).
    sample_rate: u32,
    stopped: bool,
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
                rate: 0,
                sample_rate: 44100,
                stopped: false,
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
                        anchor_time_ns: _,
                        rate,
                    } => {
                        s.anchor_rtp = anchor_rtp;
                        let was_paused = s.rate == 0;
                        s.rate = rate;
                        if rate == 0 {
                            info!("Playout paused");
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
                                info!(anchor_rtp, "Playout started");
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
        let decoder = match crate::codec::aac::new_decoder(src_sr, src_ch) {
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
        Some(crate::codec::shape(
            pcm,
            self.src_channels,
            self.out_channels,
            #[cfg(feature = "resample")]
            &mut self.resampler,
        ))
    }
}

/// Timed playout delivery thread. Wakes on condvar, decodes due frames and delivers them to the
/// AudioSession, which is (re)created when the stream format changes.
fn delivery_loop(
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    handler: Arc<dyn AudioHandler>,
    output_config: OutputConfig,
) {
    let (lock, cvar) = &*state;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;
    let mut stream: Option<Stream> = None;
    let (mut decoded, mut decode_ns) = (0u64, 0u64);

    loop {
        let mut s = lock.lock().unwrap();

        while !s.stopped && (s.rate == 0 || s.buffer.is_empty()) {
            s = cvar.wait(s).unwrap();
        }
        if s.stopped {
            break;
        }

        let now = now_ns();
        let elapsed_ns = now.saturating_sub(s.anchor_local_ns);
        let elapsed_frames = (elapsed_ns as u128 * s.sample_rate as u128 / 1_000_000_000) as u32;
        let target_rtp = s.anchor_rtp.wrapping_add(elapsed_frames);

        // Due frames, oldest first: the map is ordered, so stop at the first one not due yet. Around the RTP
        // timestamp wrap (every ~27 h at 44.1 kHz) the oldest frames sort last: then scan everything.
        let is_due = |ts: u32| (target_rtp.wrapping_sub(ts) as i32) >= 0;
        let mut due: Vec<u32> = s
            .buffer
            .keys()
            .copied()
            .take_while(|&ts| is_due(ts))
            .collect();
        if due.is_empty() && s.buffer.keys().next_back().is_some_and(|&ts| is_due(ts)) {
            due = s.buffer.keys().copied().filter(|&ts| is_due(ts)).collect();
        }
        let ready: Vec<(AudioSsrc, Vec<u8>)> =
            due.iter().filter_map(|ts| s.buffer.remove(ts)).collect();
        if ready.is_empty() {
            // nothing due: sleep until the next frame is (at most 20 ms; new data or a command wakes us)
            let wait_ns = s.buffer.keys().next().map_or(20_000_000, |&ts| {
                let frames = ts.wrapping_sub(target_rtp) as i32 as i64;
                (frames.max(0) * 1_000_000_000 / i64::from(s.sample_rate.max(1))).min(20_000_000)
                    as u64
            });
            drop(
                cvar.wait_timeout(s, std::time::Duration::from_nanos(wait_ns.max(1_000_000)))
                    .unwrap(),
            );
            continue;
        }
        drop(s);

        for (ssrc, aac) in ready {
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
                pcm.deliver(sess.as_mut(), output_config.format);
            }
        }
    }
    info!(
        frames = decoded,
        decode_ms = decode_ns / 1_000_000,
        "Delivery loop ended"
    );
}
