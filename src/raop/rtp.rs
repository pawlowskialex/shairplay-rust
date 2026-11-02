//! AirPlay 1 RTP audio: the UDP and TCP sources in front of the shared pipeline.
//!
//! ```text
//! sender -> RTP/UDP -> Reorder (lost packets asked for again) -> Decoder -> Output -> AudioSession
//!        -> RTP/TCP ($-framed, in order) ----------------------->
//! ```
//!
//! - **UDP** (default): data, control and timing on separate sockets. Packets go through
//!   [`Reorder`](super::reorder::Reorder): lost ones are asked for on the sender's control port and come back on
//!   ours (payload type 0x56); one given up on is played as silence.
//! - **TCP**: one connection with `$`-prefixed interleaved framing, reliable: no retransmits.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tracing::info;

use crate::codec::alac::AlacConfig;
use crate::error::{NetworkError, ShairplayError};
use crate::raop::AudioHandler;
use crate::raop::pipeline::{
    Decoder, Library, Output, OutputConfig, RtpCipher, RtpDecode, Source, Unit, notify_waker,
};
use crate::raop::reorder::{Reorder, Retransmit, resent_packet};

/// Packets held behind a gap at most.
const MAX_HELD: usize = 24;

/// Maximum RTP packet size (including 12-byte header).
const RAOP_PACKET_LEN: usize = 32768;

/// Frames a missing packet of a PCM stream is taken to have before the first one came (the classic AirPlay frame);
/// after that, as many as the last one had.
const PCM_DEFAULT_FRAMES: usize = 352;

/// Determine the bind address for RTP sockets.
/// Uses the specific local IP for routable addresses (respects BindConfig).
/// Falls back to unspecified for link-local IPv6 — the iPhone may send RTP
/// packets from a different address than the RTSP connection used.
fn rtp_bind_addr(local: IpAddr) -> IpAddr {
    match local {
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
        other => other,
    }
}

fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, ShairplayError> {
    let socket = std::net::UdpSocket::bind(addr).map_err(NetworkError::Io)?;
    socket.set_nonblocking(true).map_err(NetworkError::Io)?;
    UdpSocket::from_std(socket)
        .map_err(NetworkError::Io)
        .map_err(Into::into)
}

fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, ShairplayError> {
    let listener = std::net::TcpListener::bind(addr).map_err(NetworkError::Io)?;
    listener.set_nonblocking(true).map_err(NetworkError::Io)?;
    TcpListener::from_std(listener)
        .map_err(NetworkError::Io)
        .map_err(Into::into)
}

/// An AirPlay 1 stream's audio format, from the SDP: ALAC (`AppleLossless`, also PipeWire's
/// `raop.audio.codec=PCM`, which is uncompressed ALAC on the wire) or raw linear PCM (`L16/<rate>[/<channels>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ap1Format {
    Alac(AlacConfig),
    L16 { channels: u8, sample_rate: u32 },
}

impl Ap1Format {
    /// The format an SDP `rtpmap` (`"<payload-type> <encoding>"`) and `fmtp` describe; `None` if they are malformed
    /// or name a codec or shape the receiver doesn't take.
    pub(crate) fn parse(rtpmap: &str, fmtp: &str) -> Option<Self> {
        let mut fields = rtpmap.split_whitespace();
        fields.next()?.parse::<u8>().ok()?;
        let encoding = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        let mut parts = encoding.split('/');
        let name = parts.next()?;
        if name.eq_ignore_ascii_case("AppleLossless") {
            return AlacConfig::from_fmtp(fmtp).map(Ap1Format::Alac);
        }
        if !name.eq_ignore_ascii_case("L16") {
            return None;
        }
        // RFC 3551: one channel when the count is left out
        let sample_rate: u32 = parts.next()?.parse().ok()?;
        let channels: u8 = match parts.next() {
            Some(ch) => ch.parse().ok()?,
            None => 1,
        };
        (parts.next().is_none() && sample_rate > 0 && channels > 0).then_some(Ap1Format::L16 {
            channels,
            sample_rate,
        })
    }

    pub(crate) fn source(&self) -> Source {
        match self {
            Ap1Format::Alac(c) => Source {
                sample_rate: c.sample_rate,
                channels: c.num_channels,
                bits: c.bit_depth,
            },
            Ap1Format::L16 {
                channels,
                sample_rate,
            } => Source {
                sample_rate: *sample_rate,
                channels: *channels,
                bits: 16,
            },
        }
    }

    /// The library's decoder for a packet's payload.
    pub(crate) fn codec(&self) -> Box<dyn crate::codec::Decode> {
        match self {
            Ap1Format::Alac(c) => Box::new(c.decoder()),
            Ap1Format::L16 { channels, .. } => Box::new(crate::codec::L16 {
                channels: *channels,
            }),
        }
    }

    /// Frames in a packet (a missing one's silence), before any came.
    fn frames(&self) -> usize {
        match self {
            Ap1Format::Alac(c) => c.frame_length as usize,
            Ap1Format::L16 { .. } => PCM_DEFAULT_FRAMES,
        }
    }
}

/// Configuration for creating an AP1 RTP session, parsed from SDP.
pub(crate) struct RtpConfig {
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    pub(crate) remote: String,
    /// Local IP address to bind sockets to.
    pub(crate) local_addr: IpAddr,
    /// SDP `a=rtpmap` attribute.
    pub(crate) rtpmap: String,
    /// Optional SDP `a=fmtp` attribute. Required for ALAC and unused for L16.
    pub(crate) fmtp: Option<String>,
    /// AES-CBC parameters when encryption was negotiated; `None` for plaintext RTP.
    pub(crate) encryption: Option<RtpEncryption>,
    /// What the samples go out as.
    pub(crate) output: OutputConfig,
    /// Full socket address of the remote peer (preserves scope_id for link-local IPv6).
    pub(crate) remote_socket: std::net::SocketAddr,
    /// Coprocessor decrypt + decode (UDP streams only).
    pub(crate) offload: Option<crate::raop::offload::OffloadFactory>,
}

/// Validated AES-CBC parameters for an encrypted RTP session.
pub(crate) struct RtpEncryption {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 16],
}

/// AP1 RTP streaming session.
///
/// Created when the sender's ANNOUNCE describes the stream; SETUP binds its ports and starts the receive task.
/// Dropped when it stops (TEARDOWN, another stream, the connection's end): the [`watch`] channel's sender goes, and
/// with it the receive task and the NTP responder.
pub(crate) struct RaopRtp {
    handler: Arc<dyn AudioHandler>,
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    remote: String,
    /// Local IP address to bind sockets to (matches the RTSP connection's interface).
    local_addr: IpAddr,
    format: Ap1Format,
    cipher: RtpCipher,
    output: OutputConfig,
    /// Send `true` to shut down the receive task.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// FLUSH: the sequence number the stream goes on from, or `None` for all of it
    flush_tx: mpsc::UnboundedSender<Option<u16>>,
    flush_rx: Option<mpsc::UnboundedReceiver<Option<u16>>>,
    /// Full socket address of the remote peer.
    remote_socket: std::net::SocketAddr,
    offload: Option<crate::raop::offload::OffloadFactory>,
}

/// One stream's playing end: the decoder in front of the session, and the silence a missing packet is owed.
struct Playout {
    decoder: Decoder,
    output: Output,
    /// Frames in a packet: the format's, or (PCM) the last packet's
    frames: usize,
    pcm_channels: Option<usize>,
}

impl Playout {
    /// Every unit the decoder has done, in order, into the session.
    fn drain(&mut self) {
        while let Some(Unit { fill, pcm, .. }) = self.decoder.pop() {
            self.output.silence(fill as usize * self.frames, None);
            match pcm {
                Some(pcm) => {
                    if let Some(ch) = self.pcm_channels {
                        self.frames = pcm.len() / ch.max(1);
                    }
                    self.output.play(pcm, None);
                }
                // didn't decrypt or decode: as long a silence
                None => self.output.silence(self.frames, None),
            }
        }
    }

    /// FLUSH: what is in the decoder from `next` on stays (a sender streams right after RECORD, so its first packets
    /// can come before the flush RECORD asks for); without one, all of it goes. What the session holds goes.
    fn flush(&mut self, next: Option<u16>) {
        self.decoder
            .flush(|seq, _| next.is_none_or(|n| ((seq as u16).wrapping_sub(n) as i16) < 0));
        self.output.flush();
    }
}

fn rtp_seq(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[2], packet[3]])
}

fn rtp_ts(packet: &[u8]) -> u32 {
    u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]])
}

impl RaopRtp {
    /// Create a new RTP session from SDP parameters and AES session keys.
    /// Does not bind sockets or start receiving — call [`start`](Self::start) for that.
    ///
    /// Returns `None` if the peer-supplied codec configuration is unsupported or malformed.
    pub(crate) fn new(callbacks: Arc<dyn AudioHandler>, config: RtpConfig) -> Option<Self> {
        let format = Ap1Format::parse(&config.rtpmap, config.fmtp.as_deref().unwrap_or_default())?;
        let cipher = match config.encryption {
            Some(e) => RtpCipher::Aes128Cbc {
                key: e.key,
                iv: e.iv,
            },
            None => RtpCipher::None,
        };
        let (flush_tx, flush_rx) = mpsc::unbounded_channel();
        Some(Self {
            handler: callbacks,
            remote: config.remote,
            local_addr: config.local_addr,
            format,
            cipher,
            output: config.output,
            remote_socket: config.remote_socket,
            offload: config.offload,
            shutdown_tx: None,
            flush_tx,
            flush_rx: Some(flush_rx),
        })
    }

    /// The stream's decoder and session. The offload (UDP, ALAC) decrypts and decodes what it takes.
    fn playout(&self, offload: bool) -> Playout {
        let offload = match (&self.format, self.offload.as_ref().filter(|_| offload)) {
            (Ap1Format::Alac(alac), Some(factory)) => {
                factory(&crate::raop::offload::OffloadJob::Packets {
                    cipher: &self.cipher.offload(),
                    alac: Some(&alac.offload()),
                })
            }
            _ => None,
        };
        let library = Library::Packets(RtpDecode {
            cipher: self.cipher.clone(),
            codec: self.format.codec(),
        });
        Playout {
            decoder: Decoder::new(offload, library).replaceable(),
            output: Output::new(self.handler.as_ref(), self.format.source(), &self.output),
            frames: self.format.frames(),
            pcm_channels: matches!(self.format, Ap1Format::L16 { .. })
                .then(|| self.format.source().channels as usize),
        }
    }

    /// Bind UDP/TCP sockets and spawn the async receive task.
    ///
    /// Returns `(control_port, timing_port, data_port)` — the local ports
    /// that the iPhone should send RTP packets to.
    ///
    /// # Transport modes
    ///
    /// - `use_udp = true`: binds 3 UDP sockets (data, control, timing).
    ///   Control channel receives retransmit responses (RTP payload type 0x56).
    /// - `use_udp = false`: binds 1 TCP listener. iPhone connects and sends
    ///   `$`-prefixed interleaved RTP frames.
    pub(crate) fn start(
        &mut self,
        use_udp: bool,
        control_rport: u16,
        timing_rport: u16,
    ) -> Result<(u16, u16, u16), ShairplayError> {
        info!(use_udp, control_rport, timing_rport, remote = %self.remote, "AP1 RTP starting");
        let Some(flushes) = self.flush_rx.take() else {
            return Err(crate::error::ServerError::InvalidConfiguration("started twice").into());
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        let bind_addr = SocketAddr::new(rtp_bind_addr(self.local_addr), 0);

        if use_udp {
            let csock = bind_udp(bind_addr)?;
            let tsock = bind_udp(bind_addr)?;
            let dsock = bind_udp(bind_addr)?;
            let control_lport = csock.local_addr().map_err(NetworkError::Io)?.port();
            let timing_lport = tsock.local_addr().map_err(NetworkError::Io)?.port();
            let data_lport = dsock.local_addr().map_err(NetworkError::Io)?.port();

            // Spawn NTP timing responder for this connection.
            let mut timing_addr = self.remote_socket;
            timing_addr.set_port(timing_rport);
            super::ntp::spawn_ntp_responder(tsock, timing_addr, Some(shutdown_rx.clone()));

            // A control port of 0: the sender takes no retransmit requests (our control port stays open, unread).
            let (ctrl, unread) = if control_rport != 0 {
                let mut sender = self.remote_socket;
                sender.set_port(control_rport);
                (
                    Some(Retransmit {
                        socket: csock,
                        sender,
                    }),
                    None,
                )
            } else {
                (None, Some(csock))
            };
            let playout = self.playout(true);
            let peer = self.remote_socket.ip();
            tokio::spawn(async move {
                let _unread = unread;
                receive_udp(dsock, ctrl, peer, playout, flushes, shutdown_rx).await;
            });
            Ok((control_lport, timing_lport, data_lport))
        } else {
            let listener = bind_tcp(bind_addr)?;
            let data_lport = listener.local_addr().map_err(NetworkError::Io)?.port();
            let playout = self.playout(false);
            tokio::spawn(receive_tcp(listener, playout, flushes, shutdown_rx));
            Ok((0, 0, data_lport))
        }
    }

    /// Flush to sequence number `next_seq` (out of 0..=0xFFFF: everything).
    pub(crate) fn flush(&self, next_seq: i32) {
        let _ = self.flush_tx.send(u16::try_from(next_seq).ok());
    }
}

/// The UDP source: packets in sequence order, gaps asked for again, then decoded and played.
async fn receive_udp(
    dsock: UdpSocket,
    ctrl: Option<Retransmit>,
    peer: IpAddr,
    mut playout: Playout,
    mut flushes: mpsc::UnboundedReceiver<Option<u16>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut data_packet = vec![0u8; RAOP_PACKET_LEN];
    let mut ctrl_packet = vec![0u8; RAOP_PACKET_LEN];
    // In sequence order before the decoder, gaps asked for again; one given up on reaches the decoder as silence
    // owed before the packet after it.
    let mut reorder = Reorder::new(ctrl.is_some(), MAX_HELD);
    let mut report = std::time::Instant::now();
    let ready = Arc::new(tokio::sync::Notify::new());
    let waker = notify_waker(&ready);
    loop {
        // Packets with the offload, or held behind a gap: look again when the offload says (or shortly) even if
        // nothing arrives.
        let wakes = playout.decoder.waiting() && playout.decoder.wake_on_done(&waker);
        let poll = (playout.decoder.waiting() && !wakes) || reorder.holding();
        let received = tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(5)), if poll => None,
            _ = ready.notified(), if wakes => None,
            // only the sender's: anyone's packets went into the reorder stage
            result = dsock.recv_from(&mut data_packet) => match result {
                Ok((len, from)) if len >= 12 && from.ip() == peer => Some(&data_packet[..len]),
                _ => None,
            },
            // Control channel: resent packets; sync packets aren't used.
            result = async {
                match &ctrl {
                    Some(c) => c.socket.recv_from(&mut ctrl_packet).await,
                    None => std::future::pending().await,
                }
            } => match result {
                Ok((len, from)) if from.ip() == peer => {
                    resent_packet(&ctrl_packet[..len]).filter(|p| p.len() >= 12)
                }
                _ => None,
            },
            next = flushes.recv() => {
                let Some(next) = next else { break };
                playout.flush(next);
                reorder.flush(next);
                continue;
            }
            _ = shutdown_rx.changed() => break,
        };
        let now = std::time::Instant::now();
        let mut out = Vec::new();
        // A packet under a sequence number that went out already is the decoder's to judge: a sender's placeholder
        // and the frame come under one number.
        if let Some(p) = received
            && !reorder.push(rtp_seq(p), p, now, &mut out)
        {
            playout.decoder.replace(u32::from(rtp_seq(p)), p);
        }
        reorder.tick(now, &mut out);
        if let Some(c) = &ctrl {
            c.ask(&mut reorder).await;
        }
        for (fill, packet) in &out {
            playout
                .decoder
                .push(u32::from(rtp_seq(packet)), rtp_ts(packet), *fill, packet);
        }
        playout.drain();
        if report.elapsed() >= std::time::Duration::from_secs(10) {
            reorder.report("AP1");
            report = std::time::Instant::now();
        }
    }
}

/// The TCP source: `$ <channel> <len_hi> <len_lo> <rtp...>` frames, in order.
async fn receive_tcp(
    listener: TcpListener,
    mut playout: Playout,
    mut flushes: mpsc::UnboundedReceiver<Option<u16>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    use tokio::io::AsyncReadExt;
    let stream = tokio::select! {
        result = listener.accept() => match result {
            Ok((s, _)) => s,
            Err(_) => return,
        },
        _ = shutdown_rx.changed() => return,
    };
    let mut reader = tokio::io::BufReader::new(stream);
    let mut packet_buf = Vec::with_capacity(RAOP_PACKET_LEN + 4);
    let mut read_buf = [0u8; 4096];
    loop {
        tokio::select! {
            result = reader.read(&mut read_buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => packet_buf.extend_from_slice(&read_buf[..n]),
                }
                if packet_buf.len() > RAOP_PACKET_LEN * 4 {
                    tracing::warn!("TCP RTP buffer exceeded safety limit");
                    break;
                }
            }
            next = flushes.recv() => {
                let Some(next) = next else { break };
                playout.flush(next);
                continue;
            }
            _ = shutdown_rx.changed() => break,
        }
        while packet_buf.len() >= 4 {
            if packet_buf[0] != b'$' || packet_buf[1] != 0 {
                packet_buf.drain(..1);
                continue;
            }
            let rtp_len = usize::from(u16::from_be_bytes([packet_buf[2], packet_buf[3]]));
            if rtp_len > RAOP_PACKET_LEN {
                tracing::warn!(rtp_len, "TCP RTP frame exceeded maximum size, closing");
                return;
            }
            if packet_buf.len() < 4 + rtp_len {
                break;
            }
            let packet = &packet_buf[4..4 + rtp_len];
            if packet.len() >= 12 {
                playout
                    .decoder
                    .push(u32::from(rtp_seq(packet)), rtp_ts(packet), 0, packet);
            }
            packet_buf.drain(..4 + rtp_len);
            playout.drain();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raop::offload::{Decoded, Offload, OffloadCipher, OffloadJob};
    use crate::raop::{AudioFormat, AudioSession, SampleFormat, Samples};
    use std::sync::Mutex;

    #[test]
    fn fmtp_takes_only_streams_the_decoder_takes() {
        let ok = |s: &str| Ap1Format::parse("96 AppleLossless", s).is_some();
        assert!(ok("96 352 0 16 40 10 14 2 255 0 0 44100"));
        assert!(ok("96 4096 0 24 40 10 14 1 255 0 0 48000"));
        // the decoder was sized from these: 128 MB for a million samples a frame
        assert!(!ok("96 1000000 0 16 40 10 14 2 255 0 0 44100"));
        assert!(!ok("96 4294967295 0 16 40 10 14 2 255 0 0 44100"));
        assert!(
            !ok("96 352 0 272 40 10 14 2 255 0 0 44100"),
            "272 isn't 16 bits"
        );
        assert!(!ok("96 352 0 20 40 10 14 2 255 0 0 44100"));
        assert!(!ok("96 352 0 16 40 10 14 6 255 0 0 44100"));
        assert!(!ok("96 352 0 16 40 10 14 2 255 0 0 0"));
        assert!(!ok("96 352 0 16 40 10 14 2"));
        assert_eq!(
            Ap1Format::parse("96 L16/44100/2", ""),
            Some(Ap1Format::L16 {
                channels: 2,
                sample_rate: 44100
            })
        );
        assert!(Ap1Format::parse("96 L16/0/2", "").is_none());
        assert!(Ap1Format::parse("96 mpeg4-generic/44100/2", "").is_none());
    }

    /// What a session got: the first sample of each delivery (0 for silence).
    #[derive(Clone, Default)]
    struct Got(Arc<Mutex<Vec<i16>>>);
    impl AudioSession for Got {
        fn audio(&mut self, samples: Samples<'_>, _: Option<u64>) {
            if let Samples::S16(s) = samples {
                self.0.lock().unwrap().push(s[0]);
            }
        }
    }
    impl AudioHandler for Got {
        fn audio_init(&self, _: AudioFormat) -> Box<dyn AudioSession> {
            Box::new(self.clone())
        }
    }

    type Jobs = Arc<Mutex<Vec<(u32, i16, bool)>>>;

    /// Finishes packets only when told; "decodes" one to 4 samples of its RTP sequence number (a placeholder, a
    /// packet shorter than 40 bytes, to -100).
    struct Mock(Jobs);
    impl Offload for Mock {
        fn submit(&mut self, tag: u32, packet: &[u8]) -> bool {
            let v = if packet.len() < 40 {
                -100
            } else {
                rtp_seq(packet) as i16
            };
            self.0.lock().unwrap().push((tag, v, false));
            true
        }
        fn collect(&mut self, done: &mut dyn FnMut(u32, Decoded<'_>)) {
            let mut q = self.0.lock().unwrap();
            while let Some(&(tag, v, true)) = q.first() {
                done(tag, Decoded::S16(&[v; 4]));
                q.remove(0);
            }
        }
        fn in_flight(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    fn packet(seq: u16, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p
    }

    /// An ALAC stream with the mock offload, playing into `got`.
    fn playout(got: &Got) -> (Playout, Jobs) {
        let q = Jobs::default();
        let q2 = q.clone();
        let factory: crate::raop::offload::OffloadFactory =
            Arc::new(move |job: &OffloadJob<'_>| {
                let OffloadJob::Packets { cipher, alac } = job else {
                    panic!("an AP1 stream asked for another job");
                };
                assert!(matches!(cipher, OffloadCipher::None));
                assert_eq!(alac.unwrap().frame_length, 352);
                Some(Box::new(Mock(q2.clone())) as Box<dyn Offload>)
            });
        let rtp = RaopRtp::new(
            Arc::new(got.clone()),
            RtpConfig {
                remote: "127.0.0.1".into(),
                local_addr: "127.0.0.1".parse().unwrap(),
                rtpmap: "96 AppleLossless".into(),
                fmtp: Some("96 352 0 16 40 10 14 2 255 0 0 44100".into()),
                encryption: None,
                output: OutputConfig {
                    sample_rate: None,
                    max_channels: None,
                    format: SampleFormat::S16,
                },
                remote_socket: "127.0.0.1:5000".parse().unwrap(),
                offload: Some(factory),
            },
        )
        .unwrap();
        (rtp.playout(true), q)
    }

    fn finish(q: &Jobs) {
        for e in q.lock().unwrap().iter_mut() {
            e.2 = true;
        }
    }

    /// Packets through the reorder stage and the decoder as the UDP source passes them: in order across the
    /// 65535 -> 0 wrap, a gap given up on played as a packet's worth of silence.
    #[test]
    fn packets_play_in_order_across_the_wrap_with_silence_for_a_lost_one() {
        let got = Got::default();
        let (mut p, q) = playout(&got);
        let mut reorder = Reorder::new(false, MAX_HELD);
        let t = std::time::Instant::now();
        let mut out = Vec::new();
        for seq in [65534u16, 65535, 0, 2] {
            reorder.push(seq, &packet(seq, 40), t, &mut out);
        }
        for (fill, pk) in &out {
            p.decoder.push(u32::from(rtp_seq(pk)), 0, *fill, pk);
        }
        p.drain();
        assert!(got.0.lock().unwrap().is_empty(), "nothing back yet");
        finish(&q);
        p.drain();
        // 65534 as -2, 65535 as -1, 0, silence for 1, 2
        assert_eq!(*got.0.lock().unwrap(), [-2, -1, 0, 0, 2]);
    }

    /// A sender that opens with placeholders under the first sequence numbers, then sends the frames under the
    /// same numbers: the frames play, not the placeholders.
    #[test]
    fn placeholders_are_replaced_by_the_frames_under_their_numbers() {
        let got = Got::default();
        let (mut p, q) = playout(&got);
        let mut reorder = Reorder::new(true, MAX_HELD);
        let t = std::time::Instant::now();
        let mut out = Vec::new();
        for (seq, len) in [(7u16, 20), (8, 20), (7, 40), (8, 40), (9, 40)] {
            let pk = packet(seq, len);
            if !reorder.push(seq, &pk, t, &mut out) {
                assert!(p.decoder.replace(u32::from(seq), &pk));
            }
            for (fill, pk) in out.drain(..) {
                p.decoder.push(u32::from(rtp_seq(&pk)), 0, fill, &pk);
            }
        }
        // the placeholders' results come back first: not taken for the frames
        finish(&q);
        p.drain();
        assert_eq!(*got.0.lock().unwrap(), [7, 8, 9]);
    }

    /// FLUSH keeps what is in the decoder from its sequence number on.
    #[test]
    fn a_flush_keeps_what_is_here_from_its_sequence_number_on() {
        let got = Got::default();
        let (mut p, q) = playout(&got);
        for seq in 30..33u16 {
            p.decoder.push(u32::from(seq), 0, 0, &packet(seq, 40));
        }
        p.flush(Some(31));
        finish(&q);
        p.drain();
        assert_eq!(*got.0.lock().unwrap(), [31, 32]);
    }
}
