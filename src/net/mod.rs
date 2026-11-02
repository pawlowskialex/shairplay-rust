//! Networking layer — TCP server, mDNS discovery, PTP timing, feature flags.

#[cfg(feature = "ap2-core")]
pub mod features;
pub mod mdns;
#[cfg(feature = "diagnostic-headers")]
pub(crate) mod protocol_diagnostics;
#[cfg(feature = "ap2-core")]
pub(crate) mod ptp;
pub(crate) mod server;

/// How long a port a SETUP opened for the sender waits for it to connect.
#[cfg(feature = "ap2-core")]
pub(crate) const ACCEPT_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The sender's connection to a port its SETUP asked for: the first one from `peer` within [`ACCEPT_LIMIT`].
/// Connections from other hosts are closed (anyone could take the slot otherwise), and a sender that never connects
/// doesn't leave the listener and its task waiting for good.
#[cfg(feature = "ap2-core")]
pub(crate) async fn accept_from(
    listener: &tokio::net::TcpListener,
    peer: std::net::IpAddr,
) -> Option<(tokio::net::TcpStream, std::net::SocketAddr)> {
    let deadline = tokio::time::Instant::now() + ACCEPT_LIMIT;
    loop {
        match tokio::time::timeout_at(deadline, listener.accept()).await {
            Ok(Ok((stream, addr))) if addr.ip() == peer => return Some((stream, addr)),
            Ok(Ok((_, addr))) => {
                tracing::warn!(%addr, %peer, "connection from another host than the sender: closed")
            }
            Ok(Err(e)) => {
                tracing::warn!("accept failed: {e}");
                return None;
            }
            Err(_) => {
                tracing::info!(%peer, "the sender didn't connect");
                return None;
            }
        }
    }
}

/// TCP keepalive on a sender's connection: a sender that disappears without closing (a Mac put to sleep, a phone
/// out of range) is noticed after ~30 s of silence instead of never, so its connection, its session and its slot
/// (`max_clients`) go. Senders that are only idle answer the probes and stay.
pub(crate) fn keepalive(stream: &tokio::net::TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(5));
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let ka = ka.with_retries(3);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&ka) {
        tracing::debug!("TCP keepalive not set: {e}");
    }
}

#[cfg(all(test, feature = "ap2-core"))]
mod accept_tests {
    use super::accept_from;

    #[tokio::test]
    async fn only_the_sender_connects_and_only_for_a_while() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let here: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let connect =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        assert!(accept_from(&listener, here).await.is_some());
        connect.await.unwrap();

        // another host's connection is closed, and with no sender the wait ends
        tokio::time::pause();
        let other: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let connect =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        assert!(accept_from(&listener, other).await.is_none());
        connect.await.unwrap();
    }
}
