//! Realtime ALAC audio receiver (stream type 96): the UDP source in front of the shared pipeline.
//!
//! Packets are authenticated as they arrive (their ChaCha20-Poly1305 tag; another host's, or a forged one, never
//! reaches the reorder stage), put in sequence order (lost ones asked for again), decrypted and decoded (the
//! stream's decoder: the application's, or the library's), and delivered with their play time on the sender's network timeline.

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::codec::alac::AlacConfig;
use crate::decoder::{Cipher, Codec, Framing, StreamInfo};
use crate::error::{NetworkError, ShairplayError};
use crate::raop::AudioHandler;
use crate::raop::pipeline::{
    Decoding, NONCE_TRAIL_LEN, Output, RTP_HEADER_LEN, Source, Timeline, notify_waker,
};
use crate::raop::reorder::{Reorder, Retransmit, resent_packet};

/// A realtime stream's parameters (its SETUP) and the output's.
pub(crate) struct OutputConfig {
    /// The stream's ALAC parameters (SETUP `spf`, `audioFormat` or `sr`; Apple's defaults for the rest).
    pub(crate) alac: AlacConfig,
    /// What the samples go out as.
    pub(crate) output: crate::raop::pipeline::OutputConfig,
    /// The application's decoders.
    pub(crate) decoders: Option<crate::decoder::DecoderFactory>,
    /// The receiver latency the sender asks for (SETUP `latencyMin`, frames), if it does.
    pub(crate) latency_min: Option<u32>,
    /// The sender: datagrams from other hosts are dropped (sync packets aren't authenticated). None: any (tests).
    pub(crate) peer: Option<std::net::IpAddr>,
    /// The latency instead of the sender's (the builder's realtime_latency_ms)
    pub(crate) latency_ns: Option<i64>,
}

/// What the connection tells a running realtime stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RealtimeCommand {
    /// FLUSH: `before` is RTP-Info's rtptime, the first frame that stays (what came before goes, the timing stays);
    /// without one everything goes until the sender's next sync packet anchors the stream again.
    Flush { before: Option<u32> },
}

/// A running realtime stream: its receiver ends when this goes (TEARDOWN, another stream, the connection's end).
pub(crate) struct RealtimeStream {
    commands: tokio::sync::mpsc::UnboundedSender<RealtimeCommand>,
    task: tokio::task::JoinHandle<()>,
}

impl RealtimeStream {
    /// Receive on `socket` (and `ctrl`: resends, sync packets) into the handler's sessions.
    pub(crate) fn start(
        socket: UdpSocket,
        ctrl: Option<Retransmit>,
        shk: [u8; 32],
        handler: Arc<dyn AudioHandler>,
        output_config: OutputConfig,
    ) -> Self {
        let (commands, rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run(socket, ctrl, shk, handler, output_config, rx));
        RealtimeStream { commands, task }
    }

    /// FLUSH: see [`RealtimeCommand::Flush`].
    pub(crate) fn flush(&self, before: Option<u32>) {
        let _ = self.commands.send(RealtimeCommand::Flush { before });
    }
}

impl Drop for RealtimeStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What came in on the sockets, or that the loop should look again.
enum Event {
    Look,
    Data(usize),
    Control(usize),
    Failed(std::io::Error),
    Command(Option<RealtimeCommand>),
}

/// Run the realtime audio receiver loop.
async fn run(
    socket: UdpSocket,
    ctrl: Option<Retransmit>,
    shk: [u8; 32],
    handler: Arc<dyn AudioHandler>,
    config: OutputConfig,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<RealtimeCommand>,
) {
    let cipher = Cipher::ChaCha20Poly1305 { key: shk };
    let alac = &config.alac;
    let rate = alac.sample_rate;
    let source = Source {
        sample_rate: rate,
        channels: alac.num_channels,
        bits: alac.bit_depth,
    };
    let info = StreamInfo {
        codec: Codec::Alac(alac.params()),
        sample_rate: rate,
        channels: alac.num_channels,
        bit_depth: alac.bit_depth,
        framing: Framing::Rtp(cipher.clone()),
    };
    let mut decoder = Decoding::new(
        crate::decoder::for_stream(&info, config.decoders.as_ref()).unwrap_or_else(|| {
            warn!(?info, "No decoder for this stream: it plays nothing");
            crate::decoder::nothing()
        }),
    );
    let frames = alac.frame_length as usize;
    // made at the first packet; flushed when the stream ends, however it ends (TEARDOWN aborts this task): what it
    // queued for later doesn't play
    let mut output: Option<Output> = None;

    let offset_ns = config
        .latency_ns
        .unwrap_or_else(|| realtime_offset_ns(config.latency_min, rate));
    info!(
        retransmit = ctrl.is_some(),
        latency_min = ?config.latency_min,
        offset_ms = offset_ns / 1_000_000,
        "Realtime ALAC receiver started"
    );

    // Packets go through `Reorder` in sequence order. Behind a gap the later ones are held while the missing ones are
    // asked for again on the sender's control port (resent packets arrive on ours); a gap the sender doesn't fill in
    // time, or a packet that fails to decrypt or decode, is played as silence of the same length: the sender paces the
    // stream in real time, so audio that never arrives would otherwise shorten the output's queue for good until it
    // runs dry (on Wi-Fi, ~1 % loss emptied a 250 ms prebuffer within a minute). Counts every 10 s.
    let mut reorder = Reorder::new(ctrl.is_some(), MAX_HELD);
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
    let mut report = std::time::Instant::now();
    let mut buf = vec![0u8; 4096];
    let mut cbuf = vec![0u8; 4096];
    let (mut ctrl_logged, mut forged) = (0u32, 0u32);
    let ready = Arc::new(tokio::sync::Notify::new());
    let waker = notify_waker(&ready);

    loop {
        // Look again when the decoder says (or shortly) while packets are out on it, or shortly while packets are
        // held behind a gap, even if nothing arrives.
        let wakes = decoder.waiting() && decoder.wake_on_done(&waker);
        let poll = (decoder.waiting() && !wakes) || reorder.holding();
        // another host's datagram counts as empty: ignored
        let from_peer = |(n, from): (usize, std::net::SocketAddr)| {
            if config.peer.is_none_or(|p| p == from.ip()) {
                n
            } else {
                0
            }
        };
        let event = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(r) => Event::Data(from_peer(r)),
                Err(e) => Event::Failed(e),
            },
            r = async {
                match &ctrl {
                    Some(c) => c.socket.recv_from(&mut cbuf).await,
                    None => std::future::pending().await,
                }
            } => match r {
                Ok(r) => Event::Control(from_peer(r)),
                Err(e) => Event::Failed(e),
            },
            _ = tokio::time::sleep(std::time::Duration::from_millis(5)), if poll => Event::Look,
            _ = ready.notified(), if wakes => Event::Look,
            c = commands.recv() => Event::Command(c),
        };
        let now = std::time::Instant::now();
        let mut out = Vec::new();
        let packet: Option<&[u8]> = match event {
            Event::Look => None,
            // the connection is gone (its end of the channel with it): so is the stream
            Event::Command(None) => break,
            Event::Command(Some(RealtimeCommand::Flush { before })) => {
                // queued audio goes if it is all before the flush point (it can't be cut in part), and without a
                // point all of it
                let older = before
                    .is_none_or(|n| last_played.is_none_or(|l| (l.wrapping_sub(n) as i32) < 0));
                if older && let Some(o) = output.as_mut() {
                    o.flush();
                }
                floor = before;
                await_anchor = before.is_none();
                info!(
                    ?before,
                    ?last_played,
                    dropped_queued = older,
                    "Realtime FLUSH"
                );
                continue;
            }
            Event::Failed(e) => {
                warn!("Realtime audio recv error: {e}");
                handler.on_error(&ShairplayError::Network(NetworkError::Io(e)));
                break;
            }
            // an empty datagram is no packet (UDP has no end of stream)
            Event::Data(0) | Event::Control(0) => None,
            Event::Data(n) => Some(&buf[..n]),
            // A resend answer is the original packet behind 4 bytes (0x80 0xd6 seq); sync packets (0xd7) anchor the
            // stream on the sender's timeline; anything else on the control port isn't audio.
            Event::Control(n) => {
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
                match resent_packet(&cbuf[..n]) {
                    Some(p) => Some(p),
                    None => {
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
                }
            }
        };
        if let Some(packet) = packet.filter(|p| p.len() > RTP_HEADER_LEN + NONCE_TRAIL_LEN) {
            if cipher.authentic(packet) {
                output.get_or_insert_with(|| Output::new(handler.as_ref(), source, &config.output));
                let seq = u16::from_be_bytes([packet[2], packet[3]]);
                reorder.push(seq, packet, now, &mut out);
            } else {
                forged += 1;
                if forged.is_power_of_two() {
                    debug!(forged, "Realtime packets whose tag doesn't check");
                }
            }
        }
        reorder.tick(now, &mut out);
        if let Some(c) = &ctrl {
            c.ask(&mut reorder).await;
        }
        for (fill, packet) in &out {
            let ts = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
            if flushed(ts, floor, await_anchor) {
                continue;
            }
            floor = None;
            if !timed_logged
                && let Some(at) = anchor.and_then(|a| a.timeline().play_at(ts, rate, offset_ns))
            {
                timed_logged = true;
                let lead_ms = (at as i64 - crate::util::now_ns() as i64) / 1_000_000;
                info!(ts, lead_ms, "Realtime playout on the network timeline");
            }
            let seq = u16::from_be_bytes([packet[2], packet[3]]);
            decoder.push(u32::from(seq), ts, *fill, packet);
        }
        // Finished packets, in order: the silence owed before each, then it (a failed one as silence too)
        while let Some(unit) = decoder.pop() {
            let Some(o) = output.as_mut() else { break };
            o.silence(unit.fill as usize * frames, None);
            if flushed(unit.ts, floor, await_anchor) {
                continue;
            }
            match unit.pcm {
                Some(pcm) => {
                    let at = anchor.and_then(|a| a.timeline().play_at(unit.ts, rate, offset_ns));
                    last_played = Some(unit.ts);
                    o.play(pcm, at);
                }
                None => o.silence(frames, None),
            }
        }
        if report.elapsed() >= std::time::Duration::from_secs(10) {
            reorder.report("realtime");
            report = std::time::Instant::now();
        }
    }

    debug!("Realtime ALAC receiver ended");
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

    /// The sender's network timeline: this anchor's RTP time plays at its network time.
    fn timeline(self) -> Timeline {
        Timeline::Network {
            clock: self.clock,
            net_ns: self.net_ns,
            rtp: self.rtp,
        }
    }
}

/// Added to every realtime packet's network time: the receiver latency the sender asked for (SETUP `latencyMin`, when
/// it is sane), else 11025 frames.
fn realtime_offset_ns(latency_min: Option<u32>, rate: u32) -> i64 {
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
/// Packets held behind a gap at most.
const MAX_HELD: usize = 48;

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

    struct Silent;
    impl crate::raop::AudioSession for Silent {
        fn audio(&mut self, _: crate::raop::Samples<'_>, _: Option<u64>) {}
    }
    struct NoAudio;
    impl AudioHandler for NoAudio {
        fn audio_init(&self, _: crate::raop::AudioFormat) -> Box<dyn crate::raop::AudioSession> {
            Box::new(Silent)
        }
    }

    /// The stream ends with its connection (the command channel's other end): it spun on the closed channel at
    /// 100 % of a CPU before. An empty datagram doesn't end it.
    #[tokio::test]
    async fn the_stream_ends_with_its_connection_not_with_an_empty_datagram() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let config = OutputConfig {
            alac: AlacConfig::defaults(352, 16, 2, 44100).unwrap(),
            output: crate::raop::pipeline::OutputConfig {
                sample_rate: None,
                max_channels: None,
                format: crate::raop::SampleFormat::S16,
            },
            decoders: None,
            latency_min: None,
            peer: None,
            latency_ns: None,
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run(socket, None, [0; 32], Arc::new(NoAudio), config, rx));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(&[], ("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "an empty datagram ended the stream");
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("the stream outlived its connection")
            .unwrap();
    }
}
