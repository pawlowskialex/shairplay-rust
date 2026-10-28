//! Networking layer — TCP server, mDNS discovery, PTP timing, feature flags.

#[cfg(feature = "ap2-core")]
pub mod features;
pub mod mdns;
#[cfg(feature = "diagnostic-headers")]
pub(crate) mod protocol_diagnostics;
#[cfg(feature = "ap2-core")]
pub(crate) mod ptp;
pub(crate) mod server;

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
