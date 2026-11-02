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
    /// Only consulted by the AP2 mixdown path; dead in AP1-only builds.
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
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
    /// Stop-handle for the currently-active audio session. iOS opens parallel
    /// connections (Happy Eyeballs) and switches between them; registering each
    /// new session here — and stopping the previous — keeps only the newest
    /// playout feeding the output (avoids overlapping / post-disconnect audio).
    #[cfg(feature = "ap2-core")]
    /// (the connection that started it, its stop)
    #[allow(clippy::type_complexity)]
    pub(crate) active_audio: std::sync::Mutex<Option<(u64, Box<dyn FnOnce() + Send>)>>,
    #[cfg(feature = "hls")]
    pub(crate) hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
    /// The connection whose sender has the audio now: (connection id, sender, its close signal).
    pub(crate) stream_owner: std::sync::Mutex<Option<(u64, String, Arc<tokio::sync::Notify>)>>,
    /// Connections verified as a paired controller: (connection id, controller, its close signal), so removing a
    /// pairing can close that controller's sessions
    pub(crate) verified: std::sync::Mutex<Vec<(u64, String, Arc<tokio::sync::Notify>)>>,
}

/// Failed pair-setup attempts after which the server refuses pair-setup until it restarts: each costs an online
/// guess of the PIN (HAP's limit).
#[cfg(feature = "ap2-core")]
pub(crate) const MAX_PAIR_FAILURES: u32 = 100;

impl RaopShared {
    /// Connection `id` (sender `sender`) sets up an audio stream: if another sender's connection had the audio,
    /// that connection is closed. The newest sender takes the speaker, as with Apple's receivers; the one before
    /// sees the speaker go instead of believing it still plays. The same sender's other connections (iOS keeps
    /// several) stay.
    pub(crate) fn claim_stream(&self, id: u64, sender: &str, close: &Arc<tokio::sync::Notify>) {
        let Ok(mut owner) = self.stream_owner.lock() else {
            return;
        };
        if let Some((prev_id, prev_sender, prev_close)) = owner.as_ref()
            && *prev_id != id
            && prev_sender != sender
        {
            tracing::info!(from = %prev_sender, to = %sender, "Another sender takes over: closing its connection");
            prev_close.notify_one();
        }
        *owner = Some((id, sender.to_string(), close.clone()));
    }

    /// Connection `id` was verified as `controller`.
    #[cfg(feature = "ap2-core")]
    pub(crate) fn verified_as(&self, id: u64, controller: &str, close: &Arc<tokio::sync::Notify>) {
        if let Ok(mut v) = self.verified.lock() {
            v.retain(|e| e.0 != id);
            v.push((id, controller.to_string(), close.clone()));
        }
    }

    /// Close every connection verified as `controller` (its pairing was removed).
    #[cfg(feature = "ap2-core")]
    pub(crate) fn close_controller(&self, controller: &str) {
        if let Ok(v) = self.verified.lock() {
            for (_, _, close) in v.iter().filter(|e| e.1 == controller) {
                close.notify_one();
            }
        }
    }

    /// Connection `id` ends: it no longer has the audio.
    pub(crate) fn release_stream(&self, id: u64) {
        if let Ok(mut owner) = self.stream_owner.lock()
            && owner.as_ref().is_some_and(|o| o.0 == id)
        {
            *owner = None;
        }
        if let Ok(mut v) = self.verified.lock() {
            v.retain(|e| e.0 != id);
        }
    }
}

#[cfg(feature = "ap2-core")]
impl RaopShared {
    /// Register a newly-started audio session of connection `id`, stopping the previous one so only
    /// the latest connection's playout feeds the audio output.
    pub(crate) fn set_active_audio(&self, id: u64, stop: Box<dyn FnOnce() + Send>) {
        let prev = self
            .active_audio
            .lock()
            .ok()
            .and_then(|mut g| g.replace((id, stop)));
        if let Some((_, prev)) = prev {
            prev();
        }
    }

    /// Stop the active audio session if connection `id` started it (a streams-only TEARDOWN).
    pub(crate) fn stop_audio_of(&self, id: u64) {
        let stop = self
            .active_audio
            .lock()
            .ok()
            .and_then(|mut g| g.take_if(|(owner, _)| *owner == id));
        if let Some((_, stop)) = stop {
            stop();
        }
    }
}

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
    handlers::RaopConnection {
        raop_rtp: None,
        fairplay: FairPlay::new(),
        pairing: shared.pairing.create_session(),
        local_addr: socket_ip_bytes(local),
        remote_socket: remote,
        session: false,
        id: {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64
        },
        close: Arc::new(tokio::sync::Notify::new()),
        sender_id: remote.ip().to_string(),
        #[cfg(feature = "ap2-core")]
        controller: None,
        nonce: digest::generate_nonce(MAX_NONCE_LEN),
        challenges: 0,
        #[cfg(feature = "ap2-core")]
        srp_server: None,
        #[cfg(feature = "ap2-core")]
        pair_verify: None,
        #[cfg(feature = "ap2-core")]
        ap2_shared_secret: None,
        #[cfg(feature = "ap2-core")]
        pair_verify_secret: None,
        #[cfg(feature = "ap2-core")]
        is_ap2: false,
        #[cfg(feature = "ap2-core")]
        playout_cmd: None,
        #[cfg(feature = "ap2-core")]
        event_sender: None,
        #[cfg(feature = "ap2-core")]
        mr_supported: Arc::default(),
        #[cfg(feature = "ap2-core")]
        realtime_cmd: None,
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
        self.conn.shared.release_stream(self.conn.id);
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
        #[cfg(feature = "ap2-core")]
        if self.conn.is_ap2 {
            return true;
        }
        self.conn.session || self.conn.raop_rtp.is_some()
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
            && let Some(secret) = &self.conn.ap2_shared_secret
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
