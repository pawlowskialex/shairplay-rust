//! Realtime ALAC audio receiver (stream type 96).
//!
//! Receives UDP packets with RTP headers, puts them in sequence order (asking the sender to resend lost ones),
//! decrypts with ChaCha20-Poly1305, decodes ALAC, resamples/mixes down if asked, and delivers PCM in the session's
//! sample format.

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use crate::error::{NetworkError, ShairplayError};
use crate::raop::audio_pipeline::{NONCE_TRAIL_LEN, RTP_HEADER_LEN, decrypt_rtp_chacha};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};

#[cfg(feature = "resample")]
use crate::codec::resample::StreamResampler;

/// Output configuration for resampling/mixdown.
pub(crate) struct OutputConfig {
    /// Source sample rate from the stream SETUP.
    pub(crate) source_sample_rate: u32,
    /// Source samples per ALAC frame from the stream SETUP.
    pub(crate) samples_per_frame: u32,
    /// Source channel count.
    pub(crate) channels: u8,
    /// Source bit depth.
    pub(crate) bit_depth: u8,
    /// Target sample rate, or None for source native rate.
    pub(crate) sample_rate: Option<u32>,
    /// Maximum output channels, or None to pass through.
    pub(crate) max_channels: Option<u8>,
    /// Sample format of the PCM handed to the session.
    pub(crate) format: crate::raop::SampleFormat,
    /// Coprocessor decrypt + decode.
    pub(crate) offload: Option<crate::raop::offload::OffloadFactory>,
    /// The receiver latency the sender asks for (SETUP `latencyMin`, frames), if it does.
    pub(crate) latency_min: Option<u32>,
}

fn alac_decoder_info(config: &OutputConfig) -> [u8; 48] {
    let mut info = [0u8; 48];
    info[24..28].copy_from_slice(&config.samples_per_frame.to_be_bytes());
    info[29] = config.bit_depth;
    info[30] = 40; // pb
    info[31] = 10; // mb
    info[32] = 14; // kb
    info[33] = config.channels;
    info[34..36].copy_from_slice(&255u16.to_be_bytes());
    info[44..48].copy_from_slice(&config.source_sample_rate.to_be_bytes());
    info
}

/// What the connection tells a running realtime stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RealtimeCommand {
    /// FLUSH: `before` is RTP-Info's rtptime, the first frame that stays (what came before goes, the timing stays);
    /// without one everything goes until the sender's next sync packet anchors the stream again.
    Flush { before: Option<u32> },
}

/// Run the realtime audio receiver loop.
pub(crate) async fn run(
    socket: UdpSocket,
    ctrl: Option<Retransmit>,
    shk: [u8; 32],
    handler: Arc<dyn AudioHandler>,
    output_config: OutputConfig,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<RealtimeCommand>,
) {
    let cipher = ChaCha20Poly1305::new((&shk).into());
    let mut buf = vec![0u8; 4096];
    let mut decoder: Option<crate::codec::alac::AlacDecoder> = None;
    #[cfg(feature = "resample")]
    let mut resampler: Option<StreamResampler> = None;
    // flushed when the stream ends, however it ends (TEARDOWN aborts this task): what it queued for later doesn't play
    let mut session = Ending(None);
    #[allow(unused_assignments)]
    let mut src_sr: u32 = 44100;
    let mut src_ch: u8 = 2;
    let mut out_ch: u8 = 2;

    let mut offload = output_config.offload.as_ref().and_then(|f| {
        f(&crate::raop::offload::OffloadStream {
            cipher: crate::raop::offload::OffloadCipher::ChaCha20Poly1305 { key: shk },
            alac: Some(crate::raop::offload::OffloadAlac {
                frame_length: output_config.samples_per_frame,
                bit_depth: output_config.bit_depth,
                pb: 40,
                mb: 10,
                kb: 14,
                channels: output_config.channels,
            }),
        })
    });

    let offset_ns = realtime_offset_ns(output_config.latency_min, output_config.source_sample_rate);
    info!(
        offload = offload.is_some(),
        retransmit = ctrl.is_some(),
        latency_min = ?output_config.latency_min,
        offset_ms = offset_ns / 1_000_000,
        "Realtime ALAC receiver started"
    );

    // Packets go through `Reorder` in sequence order. Behind a gap the later ones are held while the missing ones are
    // asked for again on the sender's control port (resent packets arrive on ours); a gap the sender doesn't fill in
    // time, or a packet that fails to decrypt or decode, is played as silence of the same length: the sender paces the
    // stream in real time, so audio that never arrives would otherwise shorten the output's queue for good until it
    // runs dry (on Wi-Fi, ~1 % loss emptied a 250 ms prebuffer within a minute). Counts every 10 s.
    let mut reorder = Reorder::new(ctrl.is_some());
    // The network timeline, from the sender's sync packets (0xd7 on the control port): an RTP time and the network
    // time (its PTP clock) it plays at. Packets go out with their play time once the clock is followed; until then,
    // as they arrive.
    let mut anchor: Option<Anchor> = None;
    let mut timed_logged = false;
    // FLUSH: packets before `floor` aren't played; `await_anchor`: none until a sync packet; the last RTP time played
    let mut floor: Option<u32> = None;
    let mut await_anchor = false;
    let mut last_played: Option<u32> = None;
    let flushed = |ts: u32, floor: Option<u32>, await_anchor: bool| {
        await_anchor || floor.is_some_and(|f| (ts.wrapping_sub(f) as i32) < 0)
    };
    // RTP times of the packets out on the offload, in order
    let mut offload_ts: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
    let mut report = std::time::Instant::now();
    let mut cbuf = vec![0u8; 4096];
    let mut ctrl_logged = 0u32;
    // `packets` packets of silence, in the stream's layout, to the session
    macro_rules! silence {
        ($packets:expr) => {
            let packets = $packets as usize;
            if packets > 0 {
                if let Some(ref mut sess) = *session {
                    let n = packets * output_config.samples_per_frame as usize * src_ch as usize;
                    let pcm = crate::codec::shape(
                        crate::codec::Pcm::S16(vec![0; n]),
                        src_ch,
                        out_ch,
                        #[cfg(feature = "resample")]
                        &mut resampler,
                    );
                    pcm.deliver(sess.as_mut(), output_config.format);
                }
            }
        };
    }

    // Finished offload packets, in order: decode a plaintext one here if need be, then shape and deliver.
    macro_rules! drain_offload {
        () => {
            if let Some(off) = offload.as_mut() {
                off.collect(&mut |fill, out| {
                    silence!(fill);
                    let pcm = match out {
                        crate::raop::offload::OffloadOutput::Pcm(s) => {
                            crate::codec::Pcm::S16(s.to_vec())
                        }
                        crate::raop::offload::OffloadOutput::Plain(p) => {
                            match decoder.as_mut().and_then(|d| d.decode_frame_pcm(p)) {
                                Some(pcm) => pcm,
                                None => {
                                    silence!(1);
                                    return;
                                }
                            }
                        }
                        crate::raop::offload::OffloadOutput::Failed => {
                            silence!(1);
                            return;
                        }
                    };
                    let pcm = crate::codec::shape(
                        pcm,
                        src_ch,
                        out_ch,
                        #[cfg(feature = "resample")]
                        &mut resampler,
                    );
                    let ts = offload_ts.pop_front();
                    if ts.is_some_and(|t| flushed(t, floor, await_anchor)) {
                        return;
                    }
                    let at =
                        ts.and_then(|ts| anchor.and_then(|a| a.play_at(ts, src_sr, offset_ns)));
                    if ts.is_some() {
                        last_played = ts;
                    }
                    if let Some(ref mut sess) = *session {
                        pcm.deliver_timed(sess.as_mut(), output_config.format, at);
                    }
                });
            }
        };
    }

    // One packet in order, after `fill` packets' worth of silence for the ones before it that never came.
    macro_rules! play {
        ($fill:expr, $packet:expr) => {
            'play: {
                let (fill, packet): (u32, &[u8]) = ($fill, $packet);
                let ts = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
                if flushed(ts, floor, await_anchor) {
                    break 'play;
                }
                floor = None;
                if !timed_logged && let Some(at) = anchor.and_then(|a| a.play_at(ts, src_sr, offset_ns)) {
                    timed_logged = true;
                    let lead_ms = (at as i64 - crate::util::now_ns() as i64) / 1_000_000;
                    info!(ts, lead_ms, "Realtime playout on the network timeline");
                }
                if let Some(off) = offload.as_mut() {
                    if off.submit(fill, packet) {
                        offload_ts.push_back(ts);
                        drain_offload!();
                        break 'play;
                    }
                    // Processed here instead: let the packets before it out first, so the order holds.
                    while offload.as_ref().is_some_and(|o| o.in_flight() > 0) {
                        drain_offload!();
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                }
                silence!(fill);
                // Decrypt the ChaCha20-Poly1305 RTP frame.
                let Some(alac_data) = decrypt_rtp_chacha(&cipher, packet) else {
                    debug!("Realtime audio decrypt failed");
                    silence!(1);
                    break 'play;
                };
                // Decode ALAC → PCM (16-bit streams stay integer)
                let Some(pcm) = decoder.as_mut().and_then(|d| d.decode_frame_pcm(&alac_data)) else {
                    silence!(1);
                    break 'play;
                };
                // Mix down + resample, only if the output needs it.
                let pcm = crate::codec::shape(
                    pcm,
                    src_ch,
                    out_ch,
                    #[cfg(feature = "resample")]
                    &mut resampler,
                );
                let at = anchor.and_then(|a| a.play_at(ts, src_sr, offset_ns));
                last_played = Some(ts);
                if let Some(ref mut sess) = *session {
                    pcm.deliver_timed(sess.as_mut(), output_config.format, at);
                }
            }
        };
    }

    loop {
        // Look again shortly while packets are out on the offload or held behind a gap, even if nothing arrives.
        let waiting = offload.as_ref().is_some_and(|o| o.in_flight() > 0) || reorder.holding();
        let received = tokio::select! {
            r = socket.recv(&mut buf) => Some(r.map(|n| (n, false))),
            r = async {
                match &ctrl {
                    Some(c) => c.socket.recv(&mut cbuf).await,
                    None => std::future::pending().await,
                }
            } => Some(r.map(|n| (n, true))),
            _ = tokio::time::sleep(std::time::Duration::from_millis(5)), if waiting => None,
            c = commands.recv() => {
                let Some(RealtimeCommand::Flush { before }) = c else { continue };
                // queued audio goes if it is all before the flush point (it can't be cut in part), and without a
                // point all of it
                let older = before.is_none_or(|n| last_played.is_none_or(|l| (l.wrapping_sub(n) as i32) < 0));
                if older && let Some(ref mut sess) = *session {
                    sess.audio_flush();
                }
                floor = before;
                await_anchor = before.is_none();
                info!(?before, ?last_played, dropped_queued = older, "Realtime FLUSH");
                continue;
            }
        };
        let now = std::time::Instant::now();
        let mut out = Vec::new();
        match received {
            None => {}
            Some(Err(e)) => {
                warn!("Realtime audio recv error: {e}");
                handler.on_error(&ShairplayError::Network(NetworkError::Io(e)));
                break;
            }
            Some(Ok((0, false))) => break,
            Some(Ok((n, resent))) => {
                // A resend answer is the original packet behind 4 bytes (0x80 0xd6 seq); anything else on the
                // control port (sync packets) isn't audio.
                let packet = if resent {
                    if let Some(a) = Anchor::parse(&cbuf[..n]) {
                        if anchor.is_none_or(|o| o.clock != a.clock) {
                            info!(
                                clock = format!("{:016x}", a.clock),
                                rtp = a.rtp,
                                latency = a.latency,
                                "Realtime sync: the sender's timeline"
                            );
                        }
                        anchor = Some(a);
                        await_anchor = false;
                        continue;
                    }
                    if n < RESENT_HEADER_LEN || cbuf[1] & 0x7f != RESENT_PAYLOAD_TYPE {
                        // not a resent packet: sync packets (0xd7: RTP time <-> the sender's network time) and the
                        // like; the first few go to the log until the realtime path uses them
                        if ctrl_logged < 8 {
                            ctrl_logged += 1;
                            info!(
                                len = n,
                                bytes = hex::encode(&cbuf[..n.min(48)]),
                                "realtime control packet"
                            );
                        }
                        continue;
                    }
                    &cbuf[RESENT_HEADER_LEN..n]
                } else {
                    &buf[..n]
                };
                if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN {
                    continue;
                }
                // Lazy init decoder + session on first packet
                if session.is_none() {
                    src_sr = output_config.source_sample_rate;
                    src_ch = output_config.channels;
                    let target_sr = output_config.sample_rate.unwrap_or(src_sr);
                    out_ch = output_config
                        .max_channels
                        .map(|m| src_ch.min(m))
                        .unwrap_or(src_ch);

                    let mut alac = crate::codec::alac::AlacDecoder::new(
                        output_config.bit_depth as i32,
                        src_ch as i32,
                    );
                    let decoder_info = alac_decoder_info(&output_config);
                    alac.set_info(&decoder_info);
                    decoder = Some(alac);
                    #[cfg(feature = "resample")]
                    if target_sr != src_sr {
                        resampler = StreamResampler::new(src_sr, target_sr, out_ch as usize);
                    }
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
                        channels: out_ch,
                        sample_rate: target_sr,
                    };
                    info!(?format, "Realtime audio session initialized");
                    *session = Some(handler.audio_init(format));
                }
                let seq = u16::from_be_bytes([packet[2], packet[3]]);
                reorder.push(seq, packet, now, &mut out);
            }
        }
        reorder.tick(now, &mut out);
        for (first, count) in reorder.take_requests() {
            if let Some(c) = &ctrl {
                let _ = c
                    .socket
                    .send_to(&resend_request(first, count), c.sender)
                    .await;
            }
        }
        for (fill, packet) in &out {
            play!(*fill, packet);
        }
        if out.is_empty() {
            drain_offload!();
        }
        if report.elapsed() >= std::time::Duration::from_secs(10) {
            let s = std::mem::take(&mut reorder.stats);
            info!(
                packets = s.packets,
                missing = s.missing,
                asked = s.asked,
                recovered = s.recovered,
                wait_avg_ms = s.wait_us / 1000 / s.recovered.max(1) as u64,
                wait_max_ms = s.wait_max_us / 1000,
                gap_max_ms = s.gap_max_us / 1000,
                filled = s.filled,
                late = s.late,
                "realtime 10 s"
            );
            report = std::time::Instant::now();
        }
    }

    debug!("Realtime ALAC receiver ended");
}

/// The stream's session, flushed when it is dropped: a realtime stream ends at its TEARDOWN (a pause: iOS and macOS
/// tear the stream down and set up a new one to resume), and on the network timeline its last ~2 s are still
/// queued, waiting for their time.
struct Ending(Option<Box<dyn crate::raop::AudioSession>>);

impl Drop for Ending {
    fn drop(&mut self) {
        if let Some(s) = self.0.as_mut() {
            s.audio_flush();
        }
    }
}

impl std::ops::Deref for Ending {
    type Target = Option<Box<dyn crate::raop::AudioSession>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Ending {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A sync packet's anchor (0xd7, 28 bytes: 0x80|0x90, 0xd7, 2 bytes, then the RTP time that plays at the network
/// time (the sender's "now" less the stream's latency), the network time in ns on its PTP clock, the RTP time of the
/// sender's now, the clock's ID; shairport-sync's rtp.c).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Anchor {
    clock: u64,
    net_ns: u64,
    rtp: u32,
    latency: u32, // frames between the sender's now and what plays now (77175 from Apple's senders: 1.75 s)
}

impl Anchor {
    fn parse(p: &[u8]) -> Option<Self> {
        if p.len() < 28 || p[1] != 0xd7 {
            return None;
        }
        let u32_at = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        let rtp = u32_at(4);
        Some(Anchor {
            rtp,
            net_ns: u64::from_be_bytes(p[8..16].try_into().ok()?),
            latency: u32_at(16).wrapping_sub(rtp),
            clock: u64::from_be_bytes(p[20..28].try_into().ok()?),
        })
    }

    /// Local time (`util::now_ns`'s clock) at which RTP time `ts` leaves the speaker, once the clock is followed.
    fn play_at(self, ts: u32, rate: u32, offset_ns: i64) -> Option<u64> {
        let frames = i128::from(ts.wrapping_sub(self.rtp) as i32);
        let net = i128::from(self.net_ns)
            + i128::from(offset_ns)
            + frames * 1_000_000_000 / i128::from(rate.max(1));
        crate::net::ptp::follower().to_local(self.clock, net.max(0) as u64)
    }
}

/// Added to every realtime packet's network time: the receiver latency the sender asked for (SETUP `latencyMin`, when
/// it is sane), else 11025 frames; SHAIRPLAY_REALTIME_LATENCY_MS overrides (ms, may be negative).
fn realtime_offset_ns(latency_min: Option<u32>, rate: u32) -> i64 {
    if let Some(ms) = std::env::var("SHAIRPLAY_REALTIME_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
    {
        return (ms * 1e6) as i64;
    }
    let frames = latency_min
        .filter(|&f| f > 0 && f <= MAX_LATENCY_FRAMES)
        .unwrap_or(DEFAULT_LATENCY_FRAMES);
    i64::from(frames) * 1_000_000_000 / i64::from(rate.max(1))
}

/// The receiver's own latency when the sender names none: 11025 frames (250 ms at 44.1 kHz). A Mac's AirPlay output
/// device reports a stream latency of 88200 frames, the sync packets' 77175 plus these (AirPlay 1 receivers announce
/// theirs as Audio-Latency: 11025; shairport-sync adds the same "to bring everything into sync", and the
/// esp32-airplay2 receivers' multi-room tests found it so).
const DEFAULT_LATENCY_FRAMES: u32 = 11025;
/// A `latencyMin` beyond this (2 s at 44.1 kHz) is taken for a mistake.
const MAX_LATENCY_FRAMES: u32 = 88200;

/// RTP payload type of a retransmit request (AirPlay's, from the receiver to the sender's control port) and of its
/// answer (the resent packet, on our control port behind a 4-byte header).
const RESEND_PAYLOAD_TYPE: u8 = 0x55;
const RESENT_PAYLOAD_TYPE: u8 = 0x56;
const RESENT_HEADER_LEN: usize = 4;

/// Ask for `count` packets from sequence number `first`: 0x80, 0xd5 (marker | 0x55), our own sequence number (1),
/// then first and count, big-endian.
fn resend_request(first: u16, count: u16) -> [u8; 8] {
    let mut r = [0x80, 0x80 | RESEND_PAYLOAD_TYPE, 0, 1, 0, 0, 0, 0];
    r[4..6].copy_from_slice(&first.to_be_bytes());
    r[6..8].copy_from_slice(&count.to_be_bytes());
    r
}

/// Where retransmit requests go and their answers come from: our control socket (its port went to the sender as
/// `controlPort`) and the sender's control port (its `controlPort` in the stream SETUP).
pub(crate) struct Retransmit {
    pub(crate) socket: UdpSocket,
    pub(crate) sender: std::net::SocketAddr,
}

#[derive(Default, Debug, PartialEq)]
struct ReorderStats {
    packets: u32,   // arrived, resent ones included
    missing: u32,   // sequence numbers found missing
    asked: u32,     // retransmit requests (packets asked for, repeats included)
    recovered: u32, // missing ones that arrived in time
    wait_us: u64,   // their total wait from the first ask (the average tells the round trip)
    wait_max_us: u64,
    gap_max_us: u64, // the longest time without any packet arriving (network stalls)
    filled: u32,     // given up on: played as silence
    late: u32,       // arrived after their place was played (or twice)
}

/// Realtime packets in sequence order. A packet behind a gap is held while the gap is asked for again (`ASK_AGAIN`
/// later once more); after `GIVE_UP`, or with `MAX_HELD` packets waiting, the gap is played as silence (the output
/// queue has to cover the wait, a few hundred ms). A jump of more than `MAX_GAP` is a new start (a flush), not a
/// loss. Without retransmits (`hold` false) gaps are given up at once.
struct Reorder {
    hold: bool,
    next: Option<u64>, // extended sequence number of the next packet to play
    held: std::collections::BTreeMap<u64, Vec<u8>>, // arrived beyond a gap
    asked: std::collections::BTreeMap<u64, (std::time::Instant, std::time::Instant, u8)>, // missing: first, last ask, asks
    requests: Vec<(u16, u16)>,
    last_arrival: Option<std::time::Instant>,
    stats: ReorderStats,
}

const ASK_AGAIN: std::time::Duration = std::time::Duration::from_millis(50);
const GIVE_UP: std::time::Duration = std::time::Duration::from_millis(120);
const MAX_HELD: usize = 48;
const MAX_GAP: u64 = 64;

impl Reorder {
    fn new(hold: bool) -> Self {
        Reorder {
            hold,
            next: None,
            held: std::collections::BTreeMap::default(),
            asked: std::collections::BTreeMap::default(),
            requests: Vec::new(),
            last_arrival: None,
            stats: ReorderStats::default(),
        }
    }

    fn holding(&self) -> bool {
        !self.held.is_empty()
    }

    fn take_requests(&mut self) -> Vec<(u16, u16)> {
        std::mem::take(&mut self.requests)
    }

    /// An arriving packet; whatever can be played now (with the silence before it) goes to `out`.
    fn push(
        &mut self,
        seq: u16,
        packet: &[u8],
        now: std::time::Instant,
        out: &mut Vec<(u32, Vec<u8>)>,
    ) {
        self.stats.packets += 1;
        if let Some(t) = self.last_arrival.replace(now) {
            self.stats.gap_max_us = self
                .stats
                .gap_max_us
                .max(now.duration_since(t).as_micros() as u64);
        }
        let next = *self.next.get_or_insert(seq as u64 + 0x10000);
        // the extended number nearest to `next`
        let ext = (next as i64 + (seq.wrapping_sub(next as u16) as i16) as i64) as u64;
        if ext < next || self.held.contains_key(&ext) {
            self.stats.late += 1;
            return;
        }
        if ext - next > MAX_GAP {
            // a new start: play what is held (gaps in it as silence), then go on from here
            self.give_up_all(out);
            self.asked.clear();
            self.next = Some(ext);
        }
        if let Some((t0, _, _)) = self.asked.remove(&ext) {
            let w = now.duration_since(t0).as_micros() as u64;
            self.stats.recovered += 1;
            self.stats.wait_us += w;
            self.stats.wait_max_us = self.stats.wait_max_us.max(w);
        }
        self.held.insert(ext, packet.to_vec());
        self.release(out);
        // newly missing: everything below the newest held packet that is neither held nor asked for
        if let Some(&top) = self.held.keys().next_back() {
            let mut run: Option<(u64, u64)> = None;
            for m in self.next.unwrap()..top {
                if self.held.contains_key(&m) || self.asked.contains_key(&m) {
                    continue;
                }
                self.stats.missing += 1;
                self.asked.insert(m, (now, now, 1));
                run = match run {
                    Some((a, b)) if b == m => Some((a, m + 1)),
                    Some((a, b)) => {
                        self.ask(a, b);
                        Some((m, m + 1))
                    }
                    None => Some((m, m + 1)),
                };
            }
            if let Some((a, b)) = run {
                self.ask(a, b);
            }
        }
        if !self.hold {
            self.give_up_all(out);
        }
    }

    /// Time passing: ask again, or give up on gaps that waited long enough.
    fn tick(&mut self, now: std::time::Instant, out: &mut Vec<(u32, Vec<u8>)>) {
        let again: Vec<u64> = self
            .asked
            .iter()
            .filter(|(_, (_, last, n))| *n < 2 && now.duration_since(*last) >= ASK_AGAIN)
            .map(|(&m, _)| m)
            .collect();
        for m in again {
            if let Some(e) = self.asked.get_mut(&m) {
                e.1 = now;
                e.2 += 1;
            }
            self.ask(m, m + 1);
        }
        while let Some(next) = self.next {
            let Some((&first, _)) = self.held.iter().next() else {
                break;
            };
            let waited = self
                .asked
                .get(&next)
                .map_or(GIVE_UP, |(t, _, _)| now.duration_since(*t));
            if waited < GIVE_UP && self.held.len() <= MAX_HELD {
                break;
            }
            self.skip_to(first, out);
        }
    }

    fn ask(&mut self, from: u64, to: u64) {
        if self.hold {
            self.stats.asked += (to - from) as u32;
            self.requests.push((from as u16, (to - from) as u16));
        }
    }

    /// Play the held packets that are next in line.
    fn release(&mut self, out: &mut Vec<(u32, Vec<u8>)>) {
        while let Some(next) = self.next {
            let Some(p) = self.held.remove(&next) else {
                break;
            };
            out.push((0, p));
            self.next = Some(next + 1);
        }
    }

    /// Give up on everything before `first` (held): silence for it, then play on.
    fn skip_to(&mut self, first: u64, out: &mut Vec<(u32, Vec<u8>)>) {
        let next = self.next.unwrap();
        let fill = (first - next) as u32;
        self.stats.filled += fill;
        for m in next..first {
            self.asked.remove(&m);
        }
        let p = self.held.remove(&first).unwrap();
        out.push((fill, p));
        self.next = Some(first + 1);
        self.release(out);
    }

    fn give_up_all(&mut self, out: &mut Vec<(u32, Vec<u8>)>) {
        while let Some((&first, _)) = self.held.iter().next() {
            self.skip_to(first, out);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_latency_is_the_senders_latency_min_when_sane() {
        assert_eq!(realtime_offset_ns(Some(11025), 44100), 250_000_000);
        assert_eq!(realtime_offset_ns(Some(22050), 44100), 500_000_000);
        assert_eq!(realtime_offset_ns(None, 44100), 250_000_000);
        assert_eq!(realtime_offset_ns(Some(0), 44100), 250_000_000);
        assert_eq!(realtime_offset_ns(Some(500_000), 44100), 250_000_000);
    }

    #[test]
    fn a_macs_sync_packet_is_an_anchor() {
        // from a Mac's system audio (macOS 26), realtime ALAC 44.1 kHz
        let p = hex::decode("80d700068173ef930000ca6df003b64481751d0a9a7c6e4c200d0008").unwrap();
        let a = Anchor::parse(&p).unwrap();
        assert_eq!(
            a,
            Anchor {
                clock: 0x9a7c_6e4c_200d_0008,
                net_ns: 0x0000_ca6d_f003_b644,
                rtp: 0x8173_ef93,
                latency: 77175,
            }
        );
        assert_eq!(Anchor::parse(&p[..27]), None);
        let mut resend = p.clone();
        resend[1] = 0xd6;
        assert_eq!(Anchor::parse(&resend), None);
    }

    use super::*;

    use std::time::{Duration, Instant};

    fn seqs(out: &[(u32, Vec<u8>)]) -> Vec<(u32, u8)> {
        out.iter().map(|(f, p)| (*f, p[0])).collect()
    }

    #[test]
    fn resend_request_bytes() {
        assert_eq!(
            resend_request(0x1234, 3),
            [0x80, 0xd5, 0, 1, 0x12, 0x34, 0, 3]
        );
    }

    #[test]
    fn in_order_packets_pass_straight_through() {
        let (mut r, t, mut out) = (Reorder::new(true), Instant::now(), Vec::new());
        for s in 10..15u16 {
            r.push(s, &[s as u8], t, &mut out);
        }
        assert_eq!(
            seqs(&out),
            vec![(0, 10), (0, 11), (0, 12), (0, 13), (0, 14)]
        );
        assert!(!r.holding() && r.take_requests().is_empty());
    }

    #[test]
    fn a_gap_is_asked_for_and_filled_by_the_resent_packet() {
        let (mut r, t, mut out) = (Reorder::new(true), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(4, &[4], t, &mut out); // 2 and 3 missing
        r.push(5, &[5], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1)]);
        assert_eq!(r.take_requests(), vec![(2, 2)]);
        r.push(2, &[2], t + Duration::from_millis(10), &mut out);
        r.push(3, &[3], t + Duration::from_millis(11), &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (0, 2), (0, 3), (0, 4), (0, 5)]);
        assert_eq!(
            (r.stats.missing, r.stats.recovered, r.stats.filled),
            (2, 2, 0)
        );
        assert!(!r.holding());
    }

    #[test]
    fn asks_once_more_then_gives_up_with_silence() {
        let (mut r, t, mut out) = (Reorder::new(true), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(3, &[3], t, &mut out);
        assert_eq!(r.take_requests(), vec![(2, 1)]);
        r.tick(t + ASK_AGAIN, &mut out);
        assert_eq!(r.take_requests(), vec![(2, 1)]);
        r.tick(t + ASK_AGAIN * 2, &mut out); // asked twice already: not again
        assert!(r.take_requests().is_empty());
        assert_eq!(seqs(&out), vec![(0, 1)]);
        r.tick(t + GIVE_UP, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (1, 3)]);
        r.push(2, &[2], t + GIVE_UP, &mut out); // too late now
        assert_eq!((r.stats.filled, r.stats.late, r.stats.asked), (1, 1, 2));
    }

    #[test]
    fn without_retransmits_gaps_are_silence_at_once() {
        let (mut r, t, mut out) = (Reorder::new(false), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(4, &[4], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (2, 4)]);
        assert!(r.take_requests().is_empty() && !r.holding());
    }

    #[test]
    fn sequence_numbers_wrap() {
        let (mut r, t, mut out) = (Reorder::new(true), Instant::now(), Vec::new());
        r.push(65534, &[0xfe], t, &mut out);
        r.push(0, &[0], t, &mut out); // 65535 missing
        assert_eq!(r.take_requests(), vec![(65535, 1)]);
        r.push(65535, &[0xff], t, &mut out);
        r.push(1, &[1], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 0xfe), (0, 0xff), (0, 0), (0, 1)]);
    }

    #[test]
    fn a_big_jump_is_a_new_start_not_a_loss() {
        let (mut r, t, mut out) = (Reorder::new(true), Instant::now(), Vec::new());
        r.push(100, &[1], t, &mut out);
        r.push(5000, &[2], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (0, 2)]);
        assert!(r.take_requests().is_empty());
        assert_eq!((r.stats.missing, r.stats.filled), (0, 0));
    }

    #[test]
    fn too_many_held_gives_up_early() {
        let (mut r, t, mut out) = (Reorder::new(true), Instant::now(), Vec::new());
        r.push(0, &[0], t, &mut out);
        for s in 2..=(MAX_HELD as u16 + 2) {
            r.push(s, &[s as u8], t, &mut out);
        }
        r.tick(t, &mut out); // well before GIVE_UP
        assert_eq!(out.len(), MAX_HELD + 2);
        assert_eq!(out[1].0, 1); // packet 1 as silence
        assert!(!r.holding());
    }

    #[test]
    fn alac_decoder_info_uses_realtime_setup_values() {
        let info = alac_decoder_info(&OutputConfig {
            source_sample_rate: 48_000,
            samples_per_frame: 352,
            channels: 2,
            bit_depth: 16,
            sample_rate: None,
            max_channels: None,
            format: crate::raop::SampleFormat::F32,
            offload: None,
            latency_min: None,
        });

        assert_eq!(u32::from_be_bytes(info[24..28].try_into().unwrap()), 352);
        assert_eq!(info[29], 16);
        assert_eq!(info[30], 40);
        assert_eq!(info[31], 10);
        assert_eq!(info[32], 14);
        assert_eq!(info[33], 2);
        assert_eq!(u16::from_be_bytes(info[34..36].try_into().unwrap()), 255);
        assert_eq!(u32::from_be_bytes(info[44..48].try_into().unwrap()), 48_000);
    }
}
