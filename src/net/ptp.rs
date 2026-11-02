//! PTP for AirPlay 2 (Apple's aPTP profile): the sink on UDP ports 319 (event) and 320 (general) that takes the
//! senders' Sync / Follow_Up / Announce messages and sends Delay_Reqs, and the [`Follower`] of their clocks that
//! the playout uses (the network timeline). Ports 319/320 need root or CAP_NET_BIND_SERVICE.

use std::sync::Arc;

use crate::util::now_ns;

/// PTP message types (IEEE 1588).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PtpMessageType {
    /// Sync message.
    Sync = 0,
    /// Follow-up message (carries precise timestamp).
    FollowUp = 8,
    /// Announce message (master clock election).
    Announce = 11,
    /// Unrecognized message type.
    Other = 0xFF,
}

impl From<u8> for PtpMessageType {
    fn from(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::Sync,
            8 => Self::FollowUp,
            11 => Self::Announce,
            _ => Self::Other,
        }
    }
}

/// Parse a PTP Follow_Up message and extract the preciseOriginTimestamp.
/// Returns (clock_id, precise_origin_timestamp_ns, correction_field_ns).
pub fn parse_follow_up(buf: &[u8]) -> Option<(u64, u64, i64)> {
    if buf.len() < 54 {
        return None;
    }
    let msg_type = PtpMessageType::from(buf[0]);
    if msg_type != PtpMessageType::FollowUp {
        return None;
    }

    // Clock identity: bytes 20..28
    let clock_id = u64::from_be_bytes(buf[20..28].try_into().ok()?);

    // Correction field: bytes 8..16 (signed, in units of 2^-16 ns)
    let correction_raw = i64::from_be_bytes(buf[8..16].try_into().ok()?);
    let correction_ns = correction_raw / 65536;

    // preciseOriginTimestamp: bytes 34..44 (6-byte seconds + 4-byte nanoseconds)
    let seconds_hi = u16::from_be_bytes([buf[34], buf[35]]) as u64;
    let seconds_lo = u32::from_be_bytes(buf[36..40].try_into().ok()?) as u64;
    let nanoseconds = u32::from_be_bytes(buf[40..44].try_into().ok()?) as u64;
    let seconds = (seconds_hi << 32) | seconds_lo;
    let timestamp_ns = seconds * 1_000_000_000 + nanoseconds;

    Some((
        clock_id,
        timestamp_ns.wrapping_add(correction_ns as u64),
        correction_ns,
    ))
}

/// Parse a PTP Announce message and extract the clock identity.
pub fn parse_announce(buf: &[u8]) -> Option<u64> {
    if buf.len() < 64 {
        return None;
    }
    let msg_type = PtpMessageType::from(buf[0]);
    if msg_type != PtpMessageType::Announce {
        return None;
    }
    let clock_id = u64::from_be_bytes(buf[20..28].try_into().ok()?);
    Some(clock_id)
}

/// AirPlay 2 PTP sink: bind the PTP event (319) and general (320) ports and
/// drain the sender's clock stream. We do not discipline a clock — draining is
/// enough. With nothing bound, every PTP packet the sender emits bounces an
/// ICMPv6 port-unreachable, which the sender reads as "no PTP peer here" and
/// stalls the buffered-audio start by several seconds; accepting the packets
/// removes that stall (measured ~2.6s → ~0.5s before the type-103 SETUP).
///
/// Received messages are decoded at `debug`; the first is noted once at `info`.
/// Binds gracefully — ports <1024 may need root / `CAP_NET_BIND_SERVICE`; on bind
/// failure it logs one line and returns, leaving normal operation untouched.
/// IPv6-unspecified bind (AirPlay timing traffic is IPv6), IPv4 on hosts without IPv6. Set `SHAIRPLAY_NO_PTP`
/// to skip the bind (for A/B measuring the effect).
pub(crate) async fn spawn_ptp_sink() {
    if std::env::var("SHAIRPLAY_NO_PTP").is_ok() {
        tracing::info!("PTP sink disabled via SHAIRPLAY_NO_PTP — expect slow AP2 connect");
        return;
    }
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let samples = Arc::new(SyncSamples::new(std::env::var("SHAIRPLAY_PTP_LOG").ok()));
    let mut bound = 0u8;
    for port in [319u16, 320u16] {
        let bind = match tokio::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)).await
        {
            Err(e) if e.kind() != std::io::ErrorKind::PermissionDenied => {
                tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await
            }
            r => r,
        };
        match bind {
            Ok(sock) => {
                bound += 1;
                let sock = Arc::new(sock);
                let seen = seen.clone();
                let samples = samples.clone();
                #[cfg(all(target_os = "linux", feature = "ptp-timestamps"))]
                if let Err(e) = nix::sys::socket::setsockopt(
                    &sock,
                    nix::sys::socket::sockopt::ReceiveTimestampns,
                    &true,
                ) {
                    tracing::warn!(port, "PTP: no kernel receive timestamps: {e}");
                }
                if port == 319 {
                    tokio::spawn(request_delays(sock.clone(), samples.clone()));
                }
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match recv_stamped(&sock, &mut buf).await {
                            Ok((n, from, kernel_ns)) => {
                                let user_ns = now_ns();
                                log_ptp_packet(port, from, &buf[..n], &seen);
                                samples.packet(
                                    &buf[..n],
                                    from,
                                    kernel_ns.unwrap_or(user_ns),
                                    user_ns,
                                );
                            }
                            Err(e) => {
                                tracing::warn!(port, "PTP sink recv error: {e}");
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => tracing::warn!(
                port,
                error = %e,
                "PTP sink: cannot bind (ports <1024 may need sudo / setcap CAP_NET_BIND_SERVICE)"
            ),
        }
    }
    if bound > 0 {
        tracing::info!(
            ports = bound,
            "PTP sink active on 319/320 — accepting sender clock (keeps AP2 connect fast)"
        );
    }
}

/// One datagram, with the kernel's receive time where the build has it: SO_TIMESTAMPNS is on the wall clock, moved
/// onto `now_ns`'s by the clocks' difference just after the read.
async fn recv_stamped(
    sock: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Option<u64>)> {
    #[cfg(all(target_os = "linux", feature = "ptp-timestamps"))]
    {
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
        use std::os::fd::AsRawFd;
        loop {
            sock.readable().await?;
            let r = sock.try_io(tokio::io::Interest::READABLE, || {
                let mut iov = [std::io::IoSliceMut::new(buf)];
                // room for two: musl (time64) appends its own 64-bit copy after the kernel's record
                let mut cmsg = Vec::with_capacity(128);
                let m = recvmsg::<SockaddrStorage>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::empty(),
                )
                .map_err(std::io::Error::from)?;
                let mut stamp = None;
                if let Ok(cmsgs) = m.cmsgs() {
                    for c in cmsgs {
                        if let ControlMessageOwned::ScmTimestampns(t) = c {
                            stamp = Some(t.tv_sec() as u64 * 1_000_000_000 + t.tv_nsec() as u64);
                        }
                    }
                }
                let from = m
                    .address
                    .and_then(|a: SockaddrStorage| {
                        a.as_sockaddr_in()
                            .map(|v| std::net::SocketAddr::from(std::net::SocketAddrV4::from(*v)))
                            .or_else(|| {
                                a.as_sockaddr_in6().map(|v| {
                                    std::net::SocketAddr::from(std::net::SocketAddrV6::from(*v))
                                })
                            })
                    })
                    .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
                // a timestamp not within a second of now is a misread (time_t width), or the wall clock stepped
                // between the arrival and the read: ignore it
                let (wall, user) = (crate::util::wall_ns(), now_ns());
                let stamp = stamp
                    .filter(|&t| t.abs_diff(wall) < 1_000_000_000)
                    .map(|t| (user as i64 + (t as i64 - wall as i64)) as u64);
                Ok((m.bytes, from, stamp))
            });
            match r {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                r => return r,
            }
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "ptp-timestamps")))]
    {
        let (n, from) = sock.recv_from(buf).await?;
        Ok((n, from, None))
    }
}

/// Clock samples: each Sync's receive time paired with its Follow_Up's preciseOriginTimestamp (the master's send
/// time), by clock identity and sequence number, for the [`follower`]. With SHAIRPLAY_PTP_LOG set, also appended
/// there as CSV (clock_id, seq, master_ns, local_ns: kernel receive time or our own, user_ns: when the task saw it).
struct SyncSamples {
    // (clock id, sequence) -> the Sync's (local, user) receive times or the Follow_Up's master time, whichever came
    // first: the two arrive on different sockets, handled by different tasks
    syncs: std::sync::Mutex<std::collections::VecDeque<(u64, u16, u64, u64)>>,
    /// (clock, sequence number, master time, when it came)
    follow_ups: std::sync::Mutex<std::collections::VecDeque<(u64, u16, u64, u64)>>,
    log: Option<std::sync::Mutex<std::fs::File>>,
    /// The master heard last: its clock, where its Syncs come from, when (local ns), their first byte (the
    /// profile's transportSpecific nibble, mirrored in our Delay_Req).
    master: std::sync::Mutex<Option<(u64, std::net::SocketAddr, u64, u8)>>,
    /// Delay_Reqs sent: (sequence, local send time, the master's clock)
    requests: std::sync::Mutex<std::collections::VecDeque<(u16, u64, u64)>>,
    /// Our port identity in Delay_Reqs (random per start)
    identity: [u8; 8],
}

impl SyncSamples {
    fn new(path: Option<String>) -> Self {
        let log = path.and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .map_err(|e| {
                    tracing::warn!(path = p, "PTP sample log: {e}");
                })
                .ok()
        });
        if log.is_some() {
            tracing::info!("PTP: logging Sync / Follow_Up samples");
        }
        let seed = now_ns() ^ (u64::from(std::process::id()) << 32);
        SyncSamples {
            syncs: std::sync::Mutex::default(),
            follow_ups: std::sync::Mutex::default(),
            log: log.map(std::sync::Mutex::new),
            master: std::sync::Mutex::default(),
            requests: std::sync::Mutex::default(),
            identity: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes(),
        }
    }

    fn packet(&self, buf: &[u8], from: std::net::SocketAddr, local_ns: u64, user_ns: u64) {
        if buf.len() < 34 {
            return;
        }
        let clock_id = u64::from_be_bytes(buf[20..28].try_into().unwrap());
        let seq = u16::from_be_bytes([buf[30], buf[31]]);
        let sample = match buf[0] & 0x0f {
            9 => {
                self.delay_resp(buf, local_ns, user_ns);
                None
            }
            0 => {
                *self.master.lock().unwrap() = Some((clock_id, from, user_ns, buf[0] & 0xf0));
                let fu = {
                    let mut f = self.follow_ups.lock().unwrap();
                    f.retain(|e| user_ns.saturating_sub(e.3) < PAIR_NS);
                    f.iter()
                        .position(|e| e.0 == clock_id && e.1 == seq)
                        .map(|i| f.remove(i).unwrap())
                };
                match fu {
                    Some((_, _, master, _)) => Some((master, local_ns, user_ns)),
                    None => {
                        let mut p = self.syncs.lock().unwrap();
                        p.retain(|e| user_ns.saturating_sub(e.3) < PAIR_NS);
                        p.push_back((clock_id, seq, local_ns, user_ns));
                        while p.len() > 16 {
                            p.pop_front();
                        }
                        None
                    }
                }
            }
            8 => {
                let Some((id, master_ns, _)) = parse_follow_up(buf) else {
                    return;
                };
                let sync = {
                    let mut p = self.syncs.lock().unwrap();
                    p.retain(|e| user_ns.saturating_sub(e.3) < PAIR_NS);
                    p.iter()
                        .position(|e| e.0 == id && e.1 == seq)
                        .map(|i| p.remove(i).unwrap())
                };
                match sync {
                    Some((_, _, local, user)) => Some((master_ns, local, user)),
                    None => {
                        let mut f = self.follow_ups.lock().unwrap();
                        f.retain(|e| user_ns.saturating_sub(e.3) < PAIR_NS);
                        f.push_back((id, seq, master_ns, user_ns));
                        while f.len() > 16 {
                            f.pop_front();
                        }
                        None
                    }
                }
            }
            _ => None,
        };
        if let Some((master, local, user)) = sample {
            follower().sample(clock_id, master, local);
            if let Some(log) = &self.log {
                use std::io::Write;
                let _ = writeln!(
                    log.lock().unwrap(),
                    "{clock_id:016x},{seq},{master},{local},{user}"
                );
            }
        }
    }
}

impl SyncSamples {
    /// A Delay_Req for the master heard in the last 2 s, if any: (the datagram, where to), recorded as sent now.
    fn delay_req(&self) -> Option<(Vec<u8>, std::net::SocketAddr)> {
        let (clock, from, seen, ts) = (*self.master.lock().unwrap())?;
        let now = now_ns();
        if now.saturating_sub(seen) > 2_000_000_000 {
            return None;
        }
        let mut req = self.requests.lock().unwrap();
        let seq = req.back().map_or(1, |r| r.0.wrapping_add(1));
        let mut m = vec![0u8; 44];
        m[0] = ts | 1; // Delay_Req, the master's transportSpecific (Apple's profile: 1)
        m[1] = 2; // PTP version 2
        m[2..4].copy_from_slice(&44u16.to_be_bytes());
        m[20..28].copy_from_slice(&self.identity);
        m[28..30].copy_from_slice(&1u16.to_be_bytes());
        m[30..32].copy_from_slice(&seq.to_be_bytes());
        m[32] = 1; // controlField: Delay_Req
        m[33] = 0x7f;
        req.push_back((seq, now, clock));
        while req.len() > 8 {
            req.pop_front();
        }
        Some((m, std::net::SocketAddr::new(from.ip(), 319)))
    }

    /// A Delay_Resp to one of our Delay_Reqs: the round trip on our clock (send to the kernel's receive time). The
    /// master's own receiveTimestamp isn't used: a Mac's isn't on its Sync timescale (it saws by ~20 ms a second).
    fn delay_resp(&self, buf: &[u8], local_ns: u64, user_ns: u64) {
        if buf.len() < 54 || buf[44..52] != self.identity {
            return;
        }
        let seq = u16::from_be_bytes([buf[30], buf[31]]);
        let Some((_, sent, clock)) = self
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.0 == seq)
            .copied()
        else {
            return;
        };
        follower().round_trip(clock, local_ns.saturating_sub(sent));
        if let Some(log) = &self.log {
            use std::io::Write;
            let _ = writeln!(
                log.lock().unwrap(),
                "{clock:016x},D{seq},0,{sent},{local_ns},{user_ns}"
            );
        }
    }
}

/// Delay_Reqs to the master once a second while one is heard: the path delay, which the Sync samples alone can't
/// tell from the clocks' offset (over Wi-Fi ~2 ms, all of it showing up as playing late).
async fn request_delays(sock: Arc<tokio::net::UdpSocket>, samples: Arc<SyncSamples>) {
    if std::env::var_os("SHAIRPLAY_NO_DELAY_REQ").is_some() {
        return;
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Some((m, to)) = samples.delay_req()
            && let Err(e) = sock.send_to(&m, to).await
        {
            tracing::debug!(%to, "PTP Delay_Req: {e}");
        }
    }
}

/// Decode one inbound PTP datagram at `debug` (message type from the low nibble
/// of byte 0, domain, source, length, plus Follow_Up/Announce detail). The first
/// packet seen is noted once at `info` to confirm the sender engaged PTP.
fn log_ptp_packet(
    port: u16,
    from: std::net::SocketAddr,
    buf: &[u8],
    seen: &std::sync::atomic::AtomicBool,
) {
    if !seen.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::info!(%from, "PTP: receiving sender clock — AP2 timing path healthy");
    }
    let raw_type = buf.first().map(|b| b & 0x0F).unwrap_or(0xFF);
    let domain = buf.get(4).copied().unwrap_or(0);
    let name = match raw_type {
        0 => "Sync",
        1 => "Delay_Req",
        8 => "Follow_Up",
        9 => "Delay_Resp",
        11 => "Announce",
        12 => "Signaling",
        13 => "Management",
        _ => "?",
    };
    tracing::debug!(port, %from, len = buf.len(), msg = name, raw_type, domain, "PTP in");
    if let Some((clock_id, origin_ns, corr_ns)) = parse_follow_up(buf) {
        tracing::debug!(
            clock_id = format!("{clock_id:016x}"),
            origin_ns,
            corr_ns,
            "  ↳ Follow_Up"
        );
    } else if let Some(clock_id) = parse_announce(buf) {
        tracing::debug!(
            clock_id = format!("{clock_id:016x}"),
            "  ↳ Announce (grandmaster)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sync_pairs_only_with_a_recent_follow_up() {
        let path =
            std::env::temp_dir().join(format!("shairplay-ptp-pair-{}.csv", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let s = SyncSamples::new(Some(path.to_string_lossy().into_owned()));
        let from = "127.0.0.1:320".parse().unwrap();
        let id = 0x1122_33ff_fe44_5566u64;
        let msg = |kind: u8, seq: u16, secs: u32| {
            let mut b = vec![0u8; 54];
            b[0] = kind;
            b[20..28].copy_from_slice(&id.to_be_bytes());
            b[30..32].copy_from_slice(&seq.to_be_bytes());
            b[36..40].copy_from_slice(&secs.to_be_bytes());
            b
        };
        // a Follow_Up whose Sync was lost; 40 s later a restarted master's Sync with the same number, then its own
        s.packet(&msg(8, 7, 100), from, 1_000_000_000, 1_000_000_000);
        s.packet(&msg(0, 7, 0), from, 41_000_000_000, 41_000_000_000);
        s.packet(&msg(8, 7, 140), from, 41_001_000_000, 41_001_000_000);
        let log = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let rows: Vec<&str> = log.lines().collect();
        assert_eq!(rows.len(), 1, "{log}");
        assert!(rows[0].contains(",140000000000,41000000000,"), "{log}");
    }

    #[test]
    fn parse_follow_up_valid() {
        // Construct a minimal Follow_Up message (54 bytes)
        let mut buf = vec![0u8; 54];
        buf[0] = 0x08; // Follow_Up type
        // Clock identity at bytes 20..28
        buf[20..28].copy_from_slice(&0xAABBCCDD11223344u64.to_be_bytes());
        // Correction field at bytes 8..16 (0 for simplicity)
        // preciseOriginTimestamp at bytes 34..44
        // seconds_hi = 0, seconds_lo = 1000, nanoseconds = 500000000
        buf[36..40].copy_from_slice(&1000u32.to_be_bytes());
        buf[40..44].copy_from_slice(&500_000_000u32.to_be_bytes());

        let (clock_id, ts, corr) = parse_follow_up(&buf).unwrap();
        assert_eq!(clock_id, 0xAABBCCDD11223344);
        assert_eq!(ts, 1000 * 1_000_000_000 + 500_000_000);
        assert_eq!(corr, 0);
    }

    #[test]
    fn parse_announce_valid() {
        let mut buf = vec![0u8; 64];
        buf[0] = 0x0B; // Announce type
        buf[20..28].copy_from_slice(&0x1234567890ABCDEFu64.to_be_bytes());
        let clock_id = parse_announce(&buf).unwrap();
        assert_eq!(clock_id, 0x1234567890ABCDEF);
    }
}

/// Follows PTP masters' clocks from Sync / Follow_Up samples: per clock, the fastest sample of every
/// [`FOLLOW_WINDOW_NS`] (the least delayed: queueing on the way only ever adds), a least-squares line through the
/// last [`FOLLOW_WINDOWS`] of them (the clocks' drift), refitted without minima that sit more than 1 ms above it.
/// Over Wi-Fi this holds a master to ~0.3 ms rms. The path's minimum delay is
/// not measured: a constant bias (~2.6 ms over Wi-Fi), which output calibration absorbs.
pub struct Follower {
    clocks: std::sync::Mutex<std::collections::HashMap<u64, ClockTrack>>,
}

pub const FOLLOW_WINDOW_NS: u64 = 2_000_000_000;
/// A Sync and its Follow_Up come milliseconds apart; a half that waited longer is from a lost packet's pair or from
/// a master that restarted (its sequence numbers from 0 again, under the same identity): never paired, dropped. Paired
/// with the new master's same-numbered half, it made a sample tens of seconds off, and the follower started over
/// every few seconds [HW 2026-10-30: back-to-back ap2send sessions].
const PAIR_NS: u64 = 1_000_000_000;
pub const FOLLOW_WINDOWS: usize = 32;
pub const LOCK_SAMPLES: u32 = 8;

#[derive(Default)]
struct ClockTrack {
    minima: std::collections::VecDeque<(u64, i64)>, // (local ns, local - master ns) per window
    window: u64,
    fit: Option<(f64, f64, u64)>, // d = a + b * (local - t0) ns, t0
    samples: u32,                 // since the track (re)started
    /// Round trips of Delay_Req / Delay_Resp: (local time, ns); half the least of the recent ones is the path
    /// delay the fit includes (both ways taken as equal)
    trips: std::collections::VecDeque<(u64, f64)>,
    /// The last sample's local time (which track goes when there are too many)
    last: u64,
}

/// Clocks followed at once: any host on the network can send Sync messages, each identity a track.
const MAX_CLOCKS: usize = 8;

/// Round trips kept for the path delay (a Delay_Req a second), and the longest delay believed.
const DELAY_TRIPS: usize = 32;
const MIN_TRIPS: usize = 5;
const MAX_DELAY_NS: f64 = 50e6;

impl ClockTrack {
    fn sample(&mut self, master: u64, local: u64) {
        self.last = local;
        let d = local as i64 - master as i64;
        // a master that stepped (or restarted on another timescale under the same identity): start over. Below the
        // line by more than jitter can explain, or seconds above it (stalls stay well under)
        if self
            .d_at(local)
            .is_some_and(|p| (d as f64) < p - 20e6 || d as f64 > p + 5e9)
        {
            self.minima.clear();
            self.fit = None;
            self.samples = 0;
            self.trips.clear();
        }
        self.samples = self.samples.saturating_add(1);
        // windows older than the span (a master heard again after a pause)
        while self
            .minima
            .front()
            .is_some_and(|m| m.0 + FOLLOW_WINDOW_NS * FOLLOW_WINDOWS as u64 <= local)
        {
            self.minima.pop_front();
        }
        let w = local / FOLLOW_WINDOW_NS;
        match self.minima.back_mut() {
            Some(last) if self.window == w => {
                if d < last.1 {
                    *last = (local, d);
                }
            }
            _ => {
                self.window = w;
                self.minima.push_back((local, d));
                while self.minima.len() > FOLLOW_WINDOWS {
                    self.minima.pop_front();
                }
            }
        }
        self.refit();
    }

    fn refit(&mut self) {
        if self.minima.is_empty() {
            self.fit = None;
            return;
        }
        let pts: Vec<(f64, f64)> = {
            let t0 = self.minima.front().map_or(0, |m| m.0);
            let base = self.minima.front().map_or(0, |m| m.1);
            self.minima
                .iter()
                .map(|&(t, d)| ((t - t0) as f64, (d - base) as f64))
                .collect()
        };
        let (t0, base) = (
            self.minima.front().unwrap().0,
            self.minima.front().unwrap().1,
        );
        let line = |pts: &[(f64, f64)]| -> (f64, f64) {
            let n = pts.len() as f64;
            if pts.len() < 4 {
                // too few for a slope: the lowest
                let lo = pts.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
                return (lo, 0.0);
            }
            let (mx, my) = (
                pts.iter().map(|p| p.0).sum::<f64>() / n,
                pts.iter().map(|p| p.1).sum::<f64>() / n,
            );
            let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
            let b = if sxx > 0.0 {
                pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum::<f64>() / sxx
            } else {
                0.0
            };
            (my - b * mx, b)
        };
        let (a, b) = line(&pts);
        let kept: Vec<(f64, f64)> = pts
            .iter()
            .copied()
            .filter(|p| p.1 - (a + b * p.0) < 1e6)
            .collect();
        let (a, b) = if kept.len() >= 4 && kept.len() < pts.len() {
            line(&kept)
        } else {
            (a, b)
        };
        // a drift only from a span long enough to mean one, and within what crystals do
        let span = pts.last().map_or(0.0, |p| p.0);
        let (a, b) = if span < 8e9 {
            (pts.iter().map(|p| p.1).fold(f64::INFINITY, f64::min), 0.0)
        } else {
            (a, b.clamp(-200e-6, 200e-6))
        };
        self.fit = Some((a + base as f64, b, t0));
    }

    /// local - master at local time `local`
    fn d_at(&self, local: u64) -> Option<f64> {
        let (a, b, t0) = self.fit?;
        Some(a + b * (local as f64 - t0 as f64))
    }

    /// A Delay_Req's round trip to the master and back (ns, our clock).
    fn trip(&mut self, local: u64, rt: u64) {
        let rt = rt as f64;
        if !(0.0..2.0 * MAX_DELAY_NS).contains(&rt) {
            return;
        }
        self.trips.push_back((local, rt));
        while self.trips.len() > DELAY_TRIPS {
            self.trips.pop_front();
        }
    }

    /// The path delay: half the least recent round trip (both ways equal, queueing only adds); 0 until there are
    /// [`MIN_TRIPS`] (the first ones of a session are the slowest).
    fn delay(&self) -> f64 {
        if self.trips.len() < MIN_TRIPS {
            return 0.0;
        }
        self.trips
            .iter()
            .map(|t| t.1)
            .fold(f64::INFINITY, f64::min)
            .clamp(0.0, 2.0 * MAX_DELAY_NS)
            / 2.0
    }
}

impl Follower {
    fn new() -> Self {
        Follower {
            clocks: std::sync::Mutex::default(),
        }
    }

    /// A Sync's receive time (local clock, ns) and its Follow_Up's send time (the master's clock).
    pub fn sample(&self, clock_id: u64, master_ns: u64, local_ns: u64) {
        let mut clocks = self.clocks.lock().unwrap();
        if !clocks.contains_key(&clock_id) && clocks.len() >= MAX_CLOCKS {
            // a new identity when the table is full: the one heard from longest ago makes room
            let oldest = clocks.iter().min_by_key(|(_, c)| c.last).map(|(&id, _)| id);
            if let Some(oldest) = oldest {
                clocks.remove(&oldest);
            }
        }
        clocks
            .entry(clock_id)
            .or_default()
            .sample(master_ns, local_ns);
    }

    /// The round trip of a Delay_Req to `clock_id`'s master and back (our clock, ns).
    pub fn round_trip(&self, clock_id: u64, rt_ns: u64) {
        let mut clocks = self.clocks.lock().unwrap();
        if let Some(c) = clocks.get_mut(&clock_id) {
            let before = c.delay();
            c.trip(now_ns(), rt_ns);
            let after = c.delay();
            if (after - before).abs() > 100e3 {
                tracing::info!(
                    clock = format!("{clock_id:016x}"),
                    delay_us = (after / 1e3) as i64,
                    "PTP path delay"
                );
            }
        }
    }

    /// Whether `clock_id` has been followed long enough to use: [`LOCK_SAMPLES`] (a second at Apple's 8 Hz; the
    /// lowest so far until there are windows enough for a drift fit).
    pub fn locked(&self, clock_id: u64) -> bool {
        self.clocks
            .lock()
            .unwrap()
            .get(&clock_id)
            .is_some_and(|c| c.samples >= LOCK_SAMPLES)
    }

    /// The clock most recently heard from, if any (for senders that don't name their timeline).
    pub fn latest(&self) -> Option<u64> {
        self.clocks
            .lock()
            .unwrap()
            .iter()
            .max_by_key(|(_, c)| c.minima.back().map(|m| m.0))
            .map(|(&id, _)| id)
    }

    /// Local wall-clock time (ns, `now_ns`'s clock) at which `clock_id` reads `master_ns`.
    pub fn to_local(&self, clock_id: u64, master_ns: u64) -> Option<u64> {
        let clocks = self.clocks.lock().unwrap();
        let c = clocks.get(&clock_id)?;
        if c.samples < LOCK_SAMPLES {
            return None;
        }
        // local = master + d(local), d = a + b (local - t0): solved for local. (Evaluating d at the master's time
        // instead would multiply the slope by the clocks' distance: days, between a Mac's uptime and ours.)
        let (a, b, t0) = c.fit?;
        // the fit is offset + the path's least delay: without the delay, the master's time as it is
        let a = a - c.delay();
        let local = (master_ns as f64 + a - b * t0 as f64) / (1.0 - b);
        Some(local.max(0.0) as u64)
    }
}

/// The process's clock follower (fed by the PTP sink).
pub fn follower() -> &'static Follower {
    static F: std::sync::OnceLock<Follower> = std::sync::OnceLock::new();
    F.get_or_init(Follower::new)
}

#[cfg(test)]
mod follower_tests {
    use super::*;

    #[test]
    fn follows_offset_and_drift_through_jitter() {
        let mut c = ClockTrack::default();
        // local = master * (1 - 22e-6) + 5 s offset; delay 1 ms + jitter, every 125 ms over 60 s
        let mut x: u64 = 12345;
        for i in 0..480u64 {
            let master = 1_000_000_000_000 + i * 125_000_000;
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let jitter = (x >> 40) % 20_000_000; // 0..20 ms
            let jitter = if i % 7 == 0 { 0 } else { jitter }; // some fast packets
            let local = (master as f64 * (1.0 - 22e-6)) as u64 + 5_000_000_000 + 1_000_000 + jitter;
            c.sample(master, local);
        }
        let f = Follower::new();
        f.clocks.lock().unwrap().insert(7, c);
        let m = 1_000_000_000_000 + 60_000_000_000;
        let expect = (m as f64 * (1.0 - 22e-6)) as u64 + 5_000_000_000 + 1_000_000;
        let got = f.to_local(7, m).unwrap();
        assert!(got.abs_diff(expect) < 200_000, "{} vs {}", got, expect);
    }

    #[test]
    fn a_flood_of_clock_identities_keeps_the_table_bounded() {
        let f = Follower::new();
        f.sample(1, 1_000, 2_000_000);
        for id in 100..10_100u64 {
            f.sample(id, 1_000, 1_000_000 + id);
            // the clock that keeps sending stays
            f.sample(1, 1_000 + id, 2_000_000 + id);
        }
        let clocks = f.clocks.lock().unwrap();
        assert_eq!(clocks.len(), MAX_CLOCKS);
        assert!(clocks.contains_key(&1));
    }

    #[test]
    fn converts_between_clocks_days_apart() {
        // a Mac's uptime (23 days) against ours (4 h), 22 ppm apart, 64 s of samples
        let mut c = ClockTrack::default();
        let (m0, l0) = (2_048_000_000_000_000u64, 15_000_000_000_000u64);
        for i in 0..512u64 {
            let m = m0 + i * 125_000_000;
            let l = l0
                + ((i * 125_000_000) as f64 * (1.0 - 22e-6)) as u64
                + 1_000_000
                + (i % 5) * 300_000;
            c.sample(m, l);
        }
        let f = Follower::new();
        f.clocks.lock().unwrap().insert(9, c);
        let m = m0 + 65_000_000_000;
        let expect = l0 + (65_000_000_000f64 * (1.0 - 22e-6)) as u64 + 1_000_000;
        let got = f.to_local(9, m).unwrap();
        assert!(got.abs_diff(expect) < 100_000, "{} vs {}", got, expect);
    }

    #[test]
    fn a_master_on_another_timescale_starts_over() {
        let mut c = ClockTrack::default();
        for i in 0..80u64 {
            c.sample(
                1_000_000_000_000 + i * 125_000_000,
                5_000_000_000 + i * 125_000_000,
            );
        }
        // the same identity, now a clock 8 days behind
        let back = 700 * 1_000_000_000u64;
        for i in 80..120u64 {
            c.sample(
                1_000_000_000_000 - back + i * 125_000_000,
                5_000_000_000 + i * 125_000_000,
            );
        }
        // local - master: 5 s - (1000 s - 700 s)
        let d = c.d_at(5_000_000_000 + 119 * 125_000_000).unwrap();
        assert!((d - (5e9 - 1e12 + back as f64)).abs() < 1e6, "{d}");
    }

    #[test]
    fn not_locked_without_enough_samples() {
        let f = Follower::new();
        f.sample(1, 1_000, 2_000);
        assert!(!f.locked(1));
        assert!(f.to_local(1, 5_000).is_none());
    }

    #[test]
    fn the_path_delay_comes_off() {
        // local = master + 5 s, 2 ms each way (more now and then): the fit alone says 5.002 s
        let mut c = ClockTrack::default();
        for i in 0..80u64 {
            let master = 1_000_000_000_000 + i * 125_000_000;
            let extra = if i % 3 == 0 { 0 } else { 700_000 };
            c.sample(master, master + 5_000_000_000 + 2_000_000 + extra);
        }
        for i in 0..10u64 {
            // 4 ms there and back, more with queueing
            c.trip(i, 4_000_000 + if i % 2 == 0 { 0 } else { 3_000_000 });
        }
        assert!((c.delay() - 2e6).abs() < 50e3, "{}", c.delay());
        let f = Follower::new();
        f.clocks.lock().unwrap().insert(3, c);
        let m = 1_000_000_000_000 + 9_000_000_000;
        let got = f.to_local(3, m).unwrap();
        assert!(
            got.abs_diff(m + 5_000_000_000) < 100_000,
            "{}",
            got as i64 - (m + 5_000_000_000) as i64
        );
    }
}
