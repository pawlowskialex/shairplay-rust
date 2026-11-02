//! Per-connection state and RTSP request handling.

use super::MAX_NONCE_LEN;
use super::handlers_ap1 as handlers;
use super::rtsp;
use super::types::*;
use crate::crypto::fairplay::FairPlay;
use crate::crypto::pairing::Pairing;
use crate::crypto::rsa::RsaKey;
use crate::net::server::{ConnectionHandler, HttpdCallbacks, Reply};
use crate::proto::digest;
use crate::proto::http::HttpRequest;
use std::net::SocketAddr;
use std::sync::Arc;

/// Shared state passed to each connection.
pub(crate) struct RaopShared {
    pub(crate) rsakey: Arc<RsaKey>,
    pub(crate) identity: crate::raop::DeviceIdentity,
    pub(crate) pairing: Arc<Pairing>,
    pub(crate) hwaddr: Vec<u8>,
    pub(crate) password: String,
    #[cfg(feature = "pipewire-auth-setup-compat")]
    pub(crate) pipewire_auth_setup_compat: bool,
    pub(crate) handler: Arc<dyn AudioHandler>,
    #[cfg(feature = "ap2-core")]
    pub(crate) pairing_store: Arc<dyn PairingStore>,
    /// Accessory's long-term Ed25519 identity seed (random, persisted via the store).
    #[cfg(feature = "ap2-core")]
    pub(crate) identity_seed: [u8; 32],
    pub(crate) output_sample_rate: Option<u32>,
    pub(crate) output_max_channels: Option<u8>,
    /// Buffered audio plays this much after its network time (builder's buffered_offset_ms)
    #[cfg(feature = "ap2-core")]
    pub(crate) buffered_offset_ns: i64,
    /// Realtime audio's latency instead of the sender's (builder's realtime_latency_ms)
    #[cfg(feature = "ap2-core")]
    pub(crate) realtime_latency_ns: Option<i64>,
    /// Sample format of the PCM handed to the sessions.
    pub(crate) output_format: crate::raop::SampleFormat,
    /// AP2 buffered audio: the buffer size advertised to the sender (how far ahead it may send).
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
    pub(crate) audio_buffer_size: u32,
    /// The application's offload, if it supplied one.
    pub(crate) offload: Option<crate::raop::offload::OffloadFactory>,
    #[cfg(feature = "ap2-core")]
    pub(crate) pin: Option<String>,
    /// The next pair-setup's SRP state, made ahead of time.
    #[cfg(feature = "ap2-core")]
    pub(crate) srp_spare: std::sync::Arc<crate::crypto::pairing_homekit::SrpSpare>,
    /// Failed pair-setup proofs since the start: after [`MAX_PAIR_FAILURES`] pair-setup is refused (HAP's 100)
    #[cfg(feature = "ap2-core")]
    pub(crate) pair_failures: std::sync::atomic::AtomicU32,
    #[cfg(feature = "video")]
    pub(crate) video_handler: Option<Arc<dyn crate::raop::video::VideoHandler>>,
    /// Shared video encryption keys — set by audio SETUP, read by video SETUP.
    #[cfg(feature = "video")]
    pub(crate) video_ekey: Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    #[cfg(feature = "video")]
    pub(crate) video_eiv: Arc<std::sync::RwLock<Option<[u8; 16]>>>,
    #[cfg(feature = "ap2-core")]
    pub(crate) pairing_id: String,
    /// Accessory device id (`hwaddr_airplay(hwaddr)`), computed once at build.
    #[cfg(feature = "ap2-core")]
    pub(crate) device_id: String,
    #[cfg(feature = "ap2-core")]
    pub(crate) airplay_name: String,
    #[cfg(feature = "hls")]
    pub(crate) hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
    /// Every connection and the stream it plays
    pub(crate) sessions: crate::raop::sessions::Sessions,
}

impl RaopShared {
    /// What streams' samples go out as (the builder's output options).
    pub(crate) fn output(&self) -> crate::raop::pipeline::OutputConfig {
        crate::raop::pipeline::OutputConfig {
            sample_rate: self.output_sample_rate,
            max_channels: self.output_max_channels,
            format: self.output_format,
        }
    }
}

/// Failed pair-setup attempts after which the server refuses pair-setup until it restarts: each costs an online
/// guess of the PIN (HAP's limit).
#[cfg(feature = "ap2-core")]
pub(crate) const MAX_PAIR_FAILURES: u32 = 100;

fn socket_ip_bytes(address: SocketAddr) -> Vec<u8> {
    match address.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn new_raop_connection(
    shared: Arc<RaopShared>,
    local: SocketAddr,
    remote: SocketAddr,
) -> handlers::RaopConnection {
    let id = {
        // (no 64-bit atomics on 32-bit ARMv5)
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64
    };
    let close = Arc::new(tokio::sync::Notify::new());
    shared
        .sessions
        .open(id, remote.ip().to_string(), close.clone());
    handlers::RaopConnection {
        announced: None,
        fairplay: FairPlay::new(),
        pairing: shared.pairing.create_session(),
        local_addr: socket_ip_bytes(local),
        remote_socket: remote,
        session: false,
        id,
        close,
        nonce: digest::generate_nonce(MAX_NONCE_LEN),
        challenges: 0,
        #[cfg(feature = "ap2-core")]
        peer: handlers::Peer::Plain,
        #[cfg(feature = "ap2-core")]
        pairing_step: handlers::PairingStep::None,
        #[cfg(feature = "ap2-core")]
        secret: None,
        #[cfg(feature = "video")]
        ecdh: None,
        #[cfg(feature = "ap2-core")]
        mr_supported: Arc::default(),
        #[cfg(feature = "ap2-core")]
        tasks: Vec::new(),
        #[cfg(feature = "video")]
        ekey: None,
        #[cfg(feature = "video")]
        eiv: None,
        #[cfg(feature = "hls")]
        hls_state: crate::raop::hls::HlsState::new(),
        shared,
    }
}

impl HttpdCallbacks for RaopShared {
    fn conn_init(
        self: Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<Box<dyn ConnectionHandler>> {
        let remote_str = remote.ip().to_string();
        self.handler.on_client_connected(&remote_str);
        Some(Box::new(RaopConnectionHandler {
            conn: new_raop_connection(self, local, remote),
            remote_addr: remote_str,
            connected_at: std::time::Instant::now(),
            #[cfg(feature = "ap2-core")]
            encrypted: false,
        }))
    }
}

struct RaopConnectionHandler {
    conn: handlers::RaopConnection,
    remote_addr: String,
    /// Connection-start instant, used to log per-request elapsed time for
    /// connect-latency diagnostics (AP2 PTP-sync wait vs AP1 fast path).
    connected_at: std::time::Instant,
    /// The connection is encrypted (a pairing gave it its secret)
    #[cfg(feature = "ap2-core")]
    encrypted: bool,
}

impl Drop for RaopConnectionHandler {
    fn drop(&mut self) {
        self.conn.shared.sessions.close(self.conn.id);
        if self.conn.session {
            self.conn.shared.handler.on_session_end(&self.remote_addr);
        }
        self.conn
            .shared
            .handler
            .on_client_disconnected(&self.remote_addr);
        // a sender has left and its audio stopped: the CPU is free to make the next pair-setup's SRP state
        #[cfg(feature = "ap2-core")]
        self.conn
            .shared
            .srp_spare
            .refill(std::time::Duration::from_secs(1));
    }
}

impl ConnectionHandler for RaopConnectionHandler {
    /// Set up a session (ANNOUNCE, SETUP), or paired (transient pairing included: iOS keeps such a connection
    /// open, idle, for remote control).
    fn has_session(&self) -> bool {
        self.conn.paired()
            || self.conn.session
            || self.conn.announced.is_some()
            || self.conn.shared.sessions.plays(self.conn.id)
    }

    fn request_body_policy(
        &self,
        request: &HttpRequest,
    ) -> Result<crate::net::server::RequestBodyPolicy, crate::error::ProtocolError> {
        rtsp::request_body_policy(&self.conn, request)
    }

    fn request(&mut self, request: &HttpRequest) -> Reply {
        // Connect-latency timeline: one line per RTSP request, elapsed since the
        // connection opened. `/feedback` is a ~2s keep-alive heartbeat, so it drops
        // to `debug` to keep the connect sequence readable; everything else at info.
        let elapsed_ms = self.connected_at.elapsed().as_millis() as u64;
        let method = request.method().unwrap_or("");
        let url = request.url().unwrap_or("");
        if url == "/feedback" {
            tracing::debug!(elapsed_ms, method, url, "RTSP request");
        } else {
            tracing::info!(elapsed_ms, method, url, "RTSP request");
        }
        #[allow(unused_mut)]
        let mut reply = Reply::from(rtsp::dispatch(&mut self.conn, request));

        // The pairing that gave the connection its secret finished with this response: encrypted after it
        #[cfg(feature = "ap2-core")]
        if !self.encrypted
            && let Some(secret) = &self.conn.secret
        {
            self.encrypted = true;
            match crate::crypto::chacha_transport::EncryptedChannel::control(secret) {
                Ok(channel) => reply.encrypt = Some(channel),
                Err(e) => {
                    tracing::warn!("Failed to create cipher: {e}");
                    reply.response.set_disconnect(true);
                }
            }
        }
        reply
    }

    fn close_signal(&self) -> Option<Arc<tokio::sync::Notify>> {
        Some(self.conn.close.clone())
    }
}

// On drop, RTP session is cleaned up automatically (RaopRtp dropped → shutdown sent)
