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

use crate::codec::aac::AudioSsrc;
use crate::error::{CodecError, ShairplayError};
use crate::raop::AudioHandler;
use crate::raop::pipeline::{
    Decoder, Library, NONCE_TRAIL_LEN, NoDecoder, Output, POLY1305_TAG_LEN, RTP_HEADER_LEN, Source,
    Timeline, decrypt_rtp_chacha,
};
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
    /// The application's offload (its AAC decoder, its ALAC offload), tried first.
    pub(crate) offload: Option<crate::raop::offload::OffloadFactory>,
    /// Added to every frame's network time (may be negative; the builder's buffered_offset_ms)
    pub(crate) offset_ns: i64,
}

impl std::fmt::Debug for OutputConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputConfig")
            .field("sample_rate", &self.sample_rate)
            .field("max_channels", &self.max_channels)
            .field("format", &self.format)
            .field("offload", &self.offload.is_some())
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
    timing: Option<Timeline>,
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
        self.timing = Some(Timeline::Network { clock, net_ns, rtp });
        true
    }
}

/// Local time (`now_ns`'s clock) at which frame `ts` should play, by `timing`.
fn play_time(timing: Timeline, ts: u32, sample_rate: u32) -> Option<u64> {
    timing.play_at(ts, sample_rate, 0)
}

/// TCP listener for buffered audio. Binds a port and spawns the processing pipeline.
pub(crate) struct BufferedAudioProcessor {
    /// TCP listener waiting for the iPhone to connect.
    pub(crate) listener: TcpListener,
    /// The sender: the one host whose connection it takes.
    pub(crate) peer: std::net::IpAddr,
}

/// A running buffered stream: what the connection tells it (SETRATEANCHORTIME, FLUSHBUFFERED). When it goes, the
/// stream stops: the receiver ends, the delivery thread with the command task.
pub(crate) struct BufferedStream {
    commands: tokio::sync::mpsc::UnboundedSender<PlayoutCommand>,
    receiver: Option<tokio::task::JoinHandle<()>>,
}

impl BufferedStream {
    pub(crate) fn command(&self, command: PlayoutCommand) {
        let _ = self.commands.send(command);
    }

    /// A stream with no tasks, and what it was told: for tests.
    #[cfg(test)]
    pub(crate) fn probe() -> (Self, Probe) {
        let (commands, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            BufferedStream {
                commands,
                receiver: None,
            },
            Probe(rx),
        )
    }
}

impl Drop for BufferedStream {
    fn drop(&mut self) {
        let _ = self.commands.send(PlayoutCommand::Stop);
        if let Some(r) = self.receiver.take() {
            r.abort();
        }
    }
}

/// What a [`BufferedStream::probe`] was told.
#[cfg(test)]
pub(crate) struct Probe(tokio::sync::mpsc::UnboundedReceiver<PlayoutCommand>);

#[cfg(test)]
impl Probe {
    /// Whether the stream was stopped.
    pub(crate) fn stopped(&mut self) -> bool {
        while let Ok(c) = self.0.try_recv() {
            if matches!(c, PlayoutCommand::Stop) {
                return true;
            }
        }
        false
    }
}

impl BufferedAudioProcessor {
    /// Start the processing pipeline.
    pub(crate) fn start(
        self,
        shk: [u8; 32],
        output_config: OutputConfig,
        handler: Arc<dyn AudioHandler>,
    ) -> BufferedStream {
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
        let offset_ns = output_config.offset_ns;
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
                            s.anchor = clock.filter(|_| anchor_time_ns != 0).map(|c| {
                                (
                                    c,
                                    anchor_time_ns.saturating_add_signed(offset_ns),
                                    anchor_rtp,
                                )
                            });
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
                                s.timing = Some(Timeline::Local {
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

        let receiver = tokio::spawn(async move {
            let Some((stream, addr)) = crate::net::accept_from(&self.listener, self.peer).await
            else {
                return;
            };
            info!(%addr, "Buffered audio client connected");
            crate::net::keepalive(&stream);
            receive_loop(stream, &shk, output_config, state4, &handler).await;
        });

        BufferedStream {
            commands: cmd_tx,
            receiver: Some(receiver),
        }
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
                warn!(
                    unknown,
                    ssrc = format_args!("{ssrc_val:#010x}"),
                    seq,
                    "Buffered audio: frames of an unknown format"
                );
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
    info!(
        packets,
        empty, unknown, failed, "Buffered audio receive loop ended"
    );
    let (lock, cvar) = &*state;
    if let Ok(mut s) = lock.lock() {
        s.stopped = true;
        s.queue.clear();
        s.queued_bytes = 0;
        cvar.notify_all();
    }
}

/// The decoder and the session for a stream format (an SSRC: AAC or ALAC, its rate, depth and channels). The
/// application's offload decodes what it takes (an AAC one decodes the rest too); the library's decoder the rest:
/// ALAC's always, AAC's without the application's. AAC is a lapped transform: the first frame after a discontinuity
/// (a stream's start, a flush, frames skipped as late) only primes the decoder (its output is the new audio over the
/// old position's tail with its aliasing uncancelled: 23 ms of garbage at each seek [HW 2026-10-28]).
fn open_stream(
    ssrc: AudioSsrc,
    output_config: &OutputConfig,
    handler: &Arc<dyn AudioHandler>,
) -> (Decoder, Output) {
    use crate::raop::offload::OffloadJob;
    let source = Source {
        sample_rate: ssrc.sample_rate(),
        channels: ssrc.channels(),
        bits: ssrc.bit_depth().unwrap_or(16),
    };
    let factory = output_config.offload.as_ref();
    let decoder = if ssrc.is_alac() {
        match crate::codec::alac::AlacConfig::buffered(
            source.sample_rate,
            source.bits,
            source.channels,
        ) {
            Some(alac) => {
                let offload = factory.and_then(|f| {
                    f(&OffloadJob::AlacFrames {
                        alac: &alac.offload(),
                        sample_rate: source.sample_rate,
                    })
                });
                Decoder::new(offload, Library::Frames(Box::new(alac.decoder())))
            }
            None => Decoder::new(None, Library::Frames(Box::new(NoDecoder))),
        }
    } else {
        let offload = factory.and_then(|f| {
            f(&OffloadJob::AacFrames {
                sample_rate: source.sample_rate,
                channels: source.channels,
            })
        });
        // the application's decoder replaces the library's
        let library = match offload {
            Some(_) => Library::Offload,
            None => match crate::codec::aac::new_decoder(source.sample_rate, source.channels) {
                Ok(d) => Library::Frames(d),
                Err(e) => {
                    warn!("Failed to create AAC decoder for {:?}: {e}", ssrc);
                    handler.on_error(&ShairplayError::Codec(CodecError::UnsupportedFormat(format!(
                        "AAC decoder init failed (ssrc={ssrc:?}, sample_rate={}, channels={}): {e}",
                        source.sample_rate, source.channels
                    ))));
                    Library::Frames(Box::new(NoDecoder))
                }
            },
        };
        Decoder::new(offload, library).lapped(SEQ_MASK)
    };
    let output = Output::new(handler.as_ref(), source, &output_config.output());
    (decoder, output)
}

impl OutputConfig {
    fn output(&self) -> crate::raop::pipeline::OutputConfig {
        crate::raop::pipeline::OutputConfig {
            sample_rate: self.sample_rate,
            max_channels: self.max_channels,
            format: self.format,
        }
    }
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
    // the current format's decoder and session
    let mut stream: Option<(AudioSsrc, Decoder, Output)> = None;
    let (mut decoded, mut decode_ns, mut late) = (0u64, 0u64, 0u64);
    let (mut epoch, mut asynchronous) = (0u64, true);
    let mut late_logged = 0u64;
    // an offload that tells when a frame is done wakes the thread (else it looks every 2 ms while frames are out)
    let waker = condvar_waker(state.clone());
    let in_decoder =
        |st: &Option<(AudioSsrc, Decoder, Output)>| st.as_ref().map_or(0, |s| s.1.len());

    loop {
        let mut s = lock.lock().unwrap();

        // A pause or an immediate flush: what the session still holds goes (up to TIMED_LEAD_NS, or its prebuffer)
        if std::mem::take(&mut s.flush_session) {
            drop(s);
            if let Some((_, _, out)) = stream.as_mut() {
                out.flush();
            }
            continue;
        }
        while !s.stopped
            && !s.flush_session
            && (!s.playing
                || s.timing.is_none()
                || (s.queue.is_empty() && in_decoder(&stream) == 0))
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
        if matches!(s.timing, Some(Timeline::Local { .. })) && s.time_anchor() {
            info!("Playout moved onto the network timeline");
        }
        if s.epoch != epoch {
            // flushed: drop the same frames from what went ahead (results that come back late are ignored)
            epoch = s.epoch;
            let recent = std::mem::take(&mut s.recent_flushes);
            if let Some((_, d, _)) = stream.as_mut() {
                d.flush(|seq, _| recent.iter().any(|f| f.drops(seq)));
            }
        }

        // A new stream format starts with the oldest frame, once everything before it is out.
        if in_decoder(&stream) == 0
            && let Some(f) = s.queue.front()
            && stream.as_ref().is_none_or(|st| st.0 != f.ssrc)
        {
            let ssrc = f.ssrc;
            drop(s);
            // the previous stream's decoder goes first: it may hold a coprocessor the new one wants; its session
            // goes unflushed, what it holds still plays
            if let Some((_, d, out)) = stream.take() {
                drop(d);
                out.finish();
            }
            let (d, out) = open_stream(ssrc, &output_config, &handler);
            stream = Some((ssrc, d, out));
            asynchronous = true;
            continue;
        }

        let Some(timing) = s.timing else { continue };
        let sr = s.sample_rate;
        let now = now_ns();
        // on the network timeline the session gets frames ahead, with their time; else as they fall due
        let lead = if matches!(timing, Timeline::Network { .. }) {
            TIMED_LEAD_NS
        } else {
            0
        };
        let due_in = |ts: u32| play_time(timing, ts, sr).map(|t| t as i64 - now as i64);
        let ssrc = stream.as_ref().map(|st| st.0);

        // frames whose time has passed (a late start, a resume): dropped undecoded
        if in_decoder(&stream) == 0 {
            while let Some(f) = s.queue.front()
                && due_in(f.ts).is_some_and(|d| d < -(LATE_NS as i64))
            {
                let f = s.queue.pop_front().unwrap();
                s.queued_bytes -= f.data.len();
                late += 1;
            }
        }

        // Frames into the decoder, in order, this stream's: an asynchronous one gets them up to LOOKAHEAD_NS
        // early (at most AHEAD_MAX out), the others when they are due.
        let window = if asynchronous {
            lead + LOOKAHEAD_NS
        } else {
            lead
        };
        let mut to_decode: Vec<Frame> = Vec::new();
        while (!asynchronous || in_decoder(&stream) + to_decode.len() < AHEAD_MAX)
            && let Some(f) = s.queue.front()
            && Some(f.ssrc) == ssrc
            && due_in(f.ts).is_some_and(|d| d <= window as i64)
        {
            let f = s.queue.pop_front().unwrap();
            s.queued_bytes -= f.data.len();
            to_decode.push(f);
        }
        let next_in = s.queue.front().and_then(|f| due_in(f.ts));
        drop(s);
        if late > late_logged {
            debug!(late, "Frames past their time dropped");
            late_logged = late;
        }

        let mut progress = !to_decode.is_empty();
        let mut delivered = None;
        let mut wakes = false;
        if let Some((_, decoder, out)) = stream.as_mut() {
            for f in to_decode {
                let was_empty = decoder.len() == 0;
                let t = now_ns();
                if !decoder.push(f.seq, f.ts, 0, &f.data) {
                    decode_ns += now_ns().saturating_sub(t);
                    if was_empty {
                        asynchronous = false; // the decoder never took one: decode when due from now on
                    }
                }
            }
            decoder.collect();
            let now = now_ns();
            let due_in = |ts: u32| play_time(timing, ts, sr).map(|t| t as i64 - now as i64);
            while let Some((ts, true)) = decoder.peek()
                && due_in(ts).is_some_and(|d| d <= lead as i64)
            {
                let Some(unit) = decoder.pop() else { break };
                progress = true;
                if due_in(unit.ts).is_some_and(|d| d < -(LATE_NS as i64)) {
                    late += 1;
                    continue;
                }
                decoded += 1;
                delivered = Some(unit.seq);
                if let (Some(pcm), false) = (unit.pcm, unit.preroll) {
                    let at = match timing {
                        Timeline::Network { .. } => play_time(timing, unit.ts, sr),
                        Timeline::Local { .. } => None,
                    };
                    out.play(pcm, at);
                }
            }
            wakes = decoder.waiting() && decoder.wake_on_done(&waker);
        }
        if delivered.is_some() {
            lock.lock().unwrap().delivered = delivered;
        }

        if !progress {
            // Nothing to do: sleep until the next frame is due (or due to go ahead), or a decoder result may be
            // in: at most 20 ms; new data, a command or the offload's wake wakes us.
            let now = now_ns();
            let due_in = |ts: u32| play_time(timing, ts, sr).map(|t| t as i64 - now as i64);
            let mut wait_ns = 20_000_000i64;
            if let Some((ts, done)) = stream.as_ref().and_then(|st| st.1.peek()) {
                wait_ns = wait_ns.min(match done {
                    false if wakes => wait_ns,
                    false => 2_000_000,
                    true => due_in(ts).map_or(wait_ns, |d| d - lead as i64),
                });
            }
            if let Some(d) = next_in {
                wait_ns = wait_ns.min(d - window as i64);
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

/// A waker for the delivery thread: an offload's "a frame is done" wakes its wait.
fn condvar_waker(state: Arc<(Mutex<PlayoutState>, Condvar)>) -> std::task::Waker {
    struct W(Arc<(Mutex<PlayoutState>, Condvar)>);
    impl std::task::Wake for W {
        fn wake(self: Arc<Self>) {
            // under the lock: the thread is either waiting (and wakes) or hasn't checked yet
            let (lock, cvar) = &*self.0;
            let _held = lock.lock();
            cvar.notify_all();
        }
    }
    std::task::Waker::from(Arc::new(W(state)))
}

#[cfg(test)]
mod decode_ahead_tests {
    use super::*;
    use crate::raop::AudioFormat;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    /// Decodes a frame [k] to 1024 stereo samples of value k, `delay` after it was submitted (or at once when
    /// `asynchronous` is off).
    struct Mock {
        asynchronous: bool,
        delay: Duration,
        queue: VecDeque<(u32, i16, Instant)>,
    }

    impl crate::raop::offload::Offload for Mock {
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
        fn collect(&mut self, done: &mut dyn FnMut(u32, crate::raop::offload::Decoded<'_>)) {
            while let Some(&(tag, v, at)) = self.queue.front() {
                if Instant::now() < at {
                    return;
                }
                self.queue.pop_front();
                done(tag, crate::raop::offload::Decoded::S16(&vec![v; 2048]));
            }
        }
        fn in_flight(&self) -> usize {
            self.queue.len()
        }
    }

    struct Sink(Arc<StdMutex<Vec<i16>>>);
    impl crate::raop::AudioSession for Sink {
        fn audio(&mut self, samples: crate::raop::Samples<'_>, _: Option<u64>) {
            if let crate::raop::Samples::S16(s) = samples {
                self.0.lock().unwrap().push(s[0]);
            }
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
    fn play_skipping(
        n: u8,
        skip: std::ops::Range<u8>,
        asynchronous: bool,
        flush_at: Option<u8>,
    ) -> Vec<i16> {
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
        st.timing = Some(Timeline::Local {
            local_ns: now_ns() + 10_000_000,
            rtp: 0,
        });
        let state = Arc::new((Mutex::new(st), Condvar::new()));
        let out = Arc::new(StdMutex::new(Vec::new()));
        let handler: Arc<dyn AudioHandler> = Arc::new(Handler(out.clone()));
        let factory: crate::raop::offload::OffloadFactory = Arc::new(move |_| {
            Some(Box::new(Mock {
                asynchronous,
                delay: Duration::from_millis(12),
                queue: VecDeque::new(),
            }) as Box<dyn crate::raop::offload::Offload>)
        });
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::S16,
            offload: Some(factory),
            offset_ns: 0,
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

    impl crate::raop::offload::Offload for AlacMock {
        fn submit(&mut self, tag: u32, frame: &[u8]) -> bool {
            if self.decline.contains(&frame[0]) {
                return false;
            }
            let at = Instant::now() + Duration::from_millis(12);
            self.queue.push_back((tag, i32::from(frame[0]) << 4, at));
            true
        }
        fn collect(&mut self, done: &mut dyn FnMut(u32, crate::raop::offload::Decoded<'_>)) {
            while let Some(&(tag, v, at)) = self.queue.front() {
                if Instant::now() < at {
                    return;
                }
                self.queue.pop_front();
                done(tag, crate::raop::offload::Decoded::S24(&vec![v; 704]));
            }
        }
        fn in_flight(&self) -> usize {
            self.queue.len()
        }
    }

    struct Sink32(Arc<StdMutex<(Vec<crate::raop::SampleFormat>, Vec<i32>)>>);
    impl crate::raop::AudioSession for Sink32 {
        fn audio(&mut self, samples: crate::raop::Samples<'_>, _: Option<u64>) {
            match samples {
                crate::raop::Samples::S32(s) => self.0.lock().unwrap().1.push(s[0]),
                _ => panic!("not 32-bit delivery of a 24-bit stream"),
            }
        }
    }
    struct Handler32(Arc<StdMutex<(Vec<crate::raop::SampleFormat>, Vec<i32>)>>);
    impl AudioHandler for Handler32 {
        fn audio_init(&self, f: AudioFormat) -> Box<dyn crate::raop::AudioSession> {
            self.0.lock().unwrap().0.push(f.format);
            Box::new(Sink32(self.0.clone()))
        }
    }

    /// ALAC/48000/S24 frames 0..n through the offload (declining `decline`) to an `Integer` session: the formats
    /// the session was set up with and the first sample of each delivery.
    fn play_alac24(
        n: u8,
        decline: std::ops::Range<u8>,
    ) -> (Vec<crate::raop::SampleFormat>, Vec<i32>) {
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
        st.timing = Some(Timeline::Local {
            local_ns: now_ns() + 10_000_000,
            rtp: 0,
        });
        let state = Arc::new((Mutex::new(st), Condvar::new()));
        let out = Arc::new(StdMutex::new((Vec::new(), Vec::new())));
        let handler: Arc<dyn AudioHandler> = Arc::new(Handler32(out.clone()));
        let factory: crate::raop::offload::OffloadFactory = Arc::new(move |job| {
            let crate::raop::offload::OffloadJob::AlacFrames {
                alac: p,
                sample_rate: rate,
            } = job
            else {
                panic!("an ALAC stream asked for another job");
            };
            assert_eq!(
                (p.frame_length, p.bit_depth, p.channels, *rate),
                (352, 24, 2, 48000)
            );
            Some(Box::new(AlacMock {
                decline: decline.clone(),
                queue: VecDeque::new(),
            }) as Box<dyn crate::raop::offload::Offload>)
        });
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::Integer,
            offload: Some(factory),
            offset_ns: 0,
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
        assert_eq!(formats, [crate::raop::SampleFormat::S32]);
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
    impl crate::raop::offload::Offload for Live {
        fn submit(&mut self, _: u32, _: &[u8]) -> bool {
            false
        }
        fn collect(&mut self, _: &mut dyn FnMut(u32, crate::raop::offload::Decoded<'_>)) {}
        fn in_flight(&self) -> usize {
            0
        }
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
        st.timing = Some(Timeline::Local {
            local_ns: now_ns() + 10_000_000,
            rtp: 0,
        });
        let state = Arc::new((Mutex::new(st), Condvar::new()));
        let out = Arc::new(StdMutex::new(Vec::new()));
        let handler: Arc<dyn AudioHandler> = Arc::new(Handler(out.clone()));
        let live = Arc::new(AtomicUsize::new(0));
        let alive_at_alac = Arc::new(AtomicUsize::new(usize::MAX));
        let (l1, l2, a2) = (live.clone(), live.clone(), alive_at_alac.clone());
        let factory: crate::raop::offload::OffloadFactory = Arc::new(move |job| {
            if let crate::raop::offload::OffloadJob::AacFrames { .. } = job {
                l1.fetch_add(1, SeqCst);
                return Some(Box::new(Live(l1.clone())) as Box<dyn crate::raop::offload::Offload>);
            }
            a2.store(l2.load(SeqCst), SeqCst);
            Some(Box::new(AlacMock {
                decline: 0..0,
                queue: VecDeque::new(),
            }) as Box<dyn crate::raop::offload::Offload>)
        });
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::S16,
            offload: Some(factory),
            offset_ns: 0,
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
        assert!(
            got == want || got == want_preroll,
            "exactly the flushed frames are missing: {got:?}"
        );
    }

    #[test]
    fn the_first_frame_after_a_gap_only_primes_the_decoder() {
        for asynchronous in [true, false] {
            let want: Vec<i16> = (1..16).filter(|&k| !(5..9).contains(&k)).collect();
            assert_eq!(
                play_skipping(16, 5..8, asynchronous, None),
                want,
                "asynchronous: {asynchronous}"
            );
        }
    }

    /// A stream that stops (another took over, TEARDOWN) ends its receiver: the sender's connection closes, it
    /// doesn't stay open until the sender lets go.
    #[tokio::test]
    async fn a_stopped_streams_receiver_ends() {
        use tokio::io::AsyncReadExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proc = BufferedAudioProcessor {
            listener,
            peer: addr.ip(),
        };
        let config = OutputConfig {
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::S16,
            offload: None,
            offset_ns: 0,
        };
        let out = Arc::new(StdMutex::new(Vec::new()));
        let stream = proc.start([0; 32], config, Arc::new(Handler(out)));
        let mut sender = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(stream);
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), sender.read(&mut b))
            .await
            .expect("the receiver still holds the connection")
            .unwrap();
        assert_eq!(n, 0);
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
