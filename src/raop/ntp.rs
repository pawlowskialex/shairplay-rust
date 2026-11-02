//! NTP timing responder for AirPlay legacy connections.
//!
//! Sends timing requests to the iPhone and responds to incoming
//! timing requests. Required for legacy (non-PTP) AirPlay connections.

/// How long the responder runs without a timing request (senders send one every ~3 s).
const IDLE_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Seconds between the NTP epoch (1900-01-01) and the UNIX epoch (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 0x83AA_7E80; // 2_208_988_800

/// timing requests and sends periodic keepalives. Required for legacy AirPlay
/// connections where the iPhone expects NTP sync before streaming audio.
///
/// It ends with the stream (`shutdown` changes or its sender goes), or after [`IDLE_LIMIT`] without a timing
/// request from the sender (one that vanished, or a stream with no shutdown signal).
pub(crate) fn spawn_ntp_responder(
    tsock: tokio::net::UdpSocket,
    remote_timing: std::net::SocketAddr,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutdown = shutdown;
        let mut last_request = tokio::time::Instant::now();
        let mut buf = [0u8; 128];

        let ntp_now = || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = (now.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS) as u32;
            let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
            (secs, frac as u32)
        };

        let put_ntp = |buf: &mut [u8], off: usize, secs: u32, frac: u32| {
            buf[off..off + 4].copy_from_slice(&secs.to_be_bytes());
            buf[off + 4..off + 8].copy_from_slice(&frac.to_be_bytes());
        };

        // Send initial timing requests to iPhone
        if remote_timing.port() > 0 {
            tracing::debug!(%remote_timing, "NTP: sending initial timing requests");
            for _ in 0..3 {
                let mut req = [0u8; 32];
                req[0] = 0x80;
                req[1] = 0xd2;
                req[2] = 0x00;
                req[3] = 0x07;
                let (s, f) = ntp_now();
                put_ntp(&mut req, 24, s, f);
                let _ = tsock.send_to(&req, remote_timing).await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        loop {
            if last_request.elapsed() > IDLE_LIMIT {
                tracing::debug!(%remote_timing, "NTP: no timing request for a minute, ending");
                break;
            }
            let timeout = tokio::time::sleep(std::time::Duration::from_secs(3));
            tokio::select! {
                _ = async {
                    match shutdown.as_mut() {
                        Some(rx) => {
                            let _ = rx.changed().await;
                        }
                        None => std::future::pending().await,
                    }
                } => break,
                result = tsock.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) if len >= 32 && buf[1] & 0x7f == 0x52 => {
                            last_request = tokio::time::Instant::now();
                            // Timing request — send response
                            let mut resp = [0u8; 32];
                            resp[..32].copy_from_slice(&buf[..32]);
                            resp[1] = 0xd3;
                            resp[8..16].copy_from_slice(&buf[24..32]);
                            let (s, f) = ntp_now();
                            put_ntp(&mut resp, 16, s, f);
                            put_ntp(&mut resp, 24, s, f);
                            let _ = tsock.send_to(&resp, addr).await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                _ = timeout => {
                    if remote_timing.port() > 0 {
                        let mut req = [0u8; 32];
                        req[0] = 0x80;
                        req[1] = 0xd2;
                        req[2] = 0x00;
                        req[3] = 0x07;
                        let (s, f) = ntp_now();
                        put_ntp(&mut req, 24, s, f);
                        let _ = tsock.send_to(&req, remote_timing).await;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::spawn_ntp_responder;
    use std::time::Duration;

    async fn socket() -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    /// The responder ended with nothing: each AP1 session left one running, with its socket.
    #[tokio::test]
    async fn the_responder_ends_with_its_stream() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = spawn_ntp_responder(socket().await, "127.0.0.1:9".parse().unwrap(), Some(rx));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!task.is_finished());
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_responder_ends_when_the_sender_falls_silent() {
        let task = spawn_ntp_responder(socket().await, "127.0.0.1:9".parse().unwrap(), None);
        tokio::time::sleep(Duration::from_secs(70)).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
