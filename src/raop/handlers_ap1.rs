//! RTSP request handlers for AP1 and AP2 AirPlay sessions.

use std::sync::Arc;

use crate::crypto::fairplay::FairPlay;
use crate::crypto::pairing::PairingSession;
use crate::error::{CodecError, ShairplayError};
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::proto::sdp::Sdp;
use crate::raop::rtp::{RaopRtp, RtpEncryption};
use crate::raop::rtsp::{Handled, RtspError, bad};

#[cfg(feature = "ap2-core")]
use crate::crypto::pairing_homekit::{PairVerifyServer, SrpServer};

/// Per-connection state for RTSP handler dispatch. Equivalent to raop_conn_t.
pub(crate) struct RaopConnection {
    pub(crate) raop_rtp: Option<RaopRtp>,
    pub(crate) fairplay: FairPlay,
    pub(crate) pairing: PairingSession,
    pub(crate) local_addr: Vec<u8>,
    pub(crate) remote_socket: std::net::SocketAddr,
    /// This connection started a session (`AudioHandler::on_session_setup`): its end is the session's end.
    pub(crate) session: bool,
    /// This connection's number, its close signal, and who the sender is (AP2: the SETUP's `deviceID`, else its
    /// address): a stream from another sender closes the connection that has the current one
    /// (`RaopShared::claim_stream`).
    pub(crate) id: u64,
    pub(crate) close: std::sync::Arc<tokio::sync::Notify>,
    pub(crate) sender_id: String,
    /// The paired controller pair-verify verified on this connection (none: transient or unverified)
    #[cfg(feature = "ap2-core")]
    pub(crate) controller: Option<String>,
    pub(crate) nonce: String,
    /// Apple-Challenges signed on this connection (each an RSA-2048 private-key operation)
    pub(crate) challenges: u8,
    /// Cheap shared handle to server-wide config (identity, keys, handler, settings).
    /// Replaces the ~17 fields that were previously deep-copied into every connection.
    pub(crate) shared: Arc<crate::raop::connection::RaopShared>,
    // AirPlay 2 state
    #[cfg(feature = "ap2-core")]
    pub(crate) srp_server: Option<SrpServer>,
    #[cfg(feature = "ap2-core")]
    pub(crate) pair_verify: Option<PairVerifyServer>,
    #[cfg(feature = "ap2-core")]
    pub(crate) ap2_shared_secret: Option<Vec<u8>>,
    /// X25519 shared secret from pair-verify (32 bytes). Used for video key derivation.
    #[cfg(feature = "ap2-core")]
    pub(crate) pair_verify_secret: Option<[u8; 32]>,
    #[cfg(feature = "ap2-core")]
    pub(crate) is_ap2: bool,
    #[cfg(feature = "ap2-core")]
    pub(crate) playout_cmd:
        Option<tokio::sync::mpsc::UnboundedSender<crate::raop::buffered_audio::PlayoutCommand>>,
    #[cfg(feature = "ap2-core")]
    pub(crate) event_sender: Option<crate::raop::event_channel::EventSender>,
    /// What the sender says it takes (`updateMRSupportedCommands`), shared with the session's remote control.
    #[cfg(feature = "ap2-core")]
    pub(crate) mr_supported: std::sync::Arc<crate::raop::SupportedCommands>,
    #[cfg(feature = "ap2-core")]
    pub(crate) realtime_cmd:
        Option<tokio::sync::mpsc::UnboundedSender<crate::raop::realtime_audio::RealtimeCommand>>,
    #[cfg(feature = "video")]
    pub(crate) ekey: Option<[u8; 16]>,
    #[cfg(feature = "video")]
    pub(crate) eiv: Option<[u8; 16]>,
    #[cfg(feature = "hls")]
    pub(crate) hls_state: std::sync::Arc<std::sync::Mutex<crate::raop::hls::HlsState>>,
}

/// Returns the connection's local IP address.
pub(crate) fn local_ip_from(conn: &RaopConnection) -> std::net::IpAddr {
    ip_from_bytes(&conn.local_addr)
}

pub(crate) fn ip_from_bytes(bytes: &[u8]) -> std::net::IpAddr {
    if bytes.len() == 16 {
        let ip: [u8; 16] = bytes[..16].try_into().unwrap_or([0; 16]);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip))
    } else {
        let ip: [u8; 4] = bytes[..4].try_into().unwrap_or([0; 4]);
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip))
    }
}

/// Returns a bind address for sub-listeners (buffered audio, event channel, etc.).
/// Uses the specific local IP for routable addresses (respects BindConfig).
/// Falls back to unspecified for link-local IPv6.
#[cfg(feature = "ap2-core")]
pub(crate) fn bind_addr_for(conn: &RaopConnection) -> std::net::SocketAddr {
    let ip = local_ip_from(conn);
    let bind_ip = match ip {
        std::net::IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
        other => other,
    };
    std::net::SocketAddr::new(bind_ip, 0)
}
/// AP1 pair-setup: return Ed25519 public key.
pub(crate) fn handle_pair_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    let data = request.data().ok_or(bad("no body"))?;
    if data.len() != 32 {
        return Err(bad("an AP1 pair-setup body is a 32-byte key"));
    }
    let public_key = conn.shared.pairing.public_key();
    response.add_header("Content-Type", "application/octet-stream");
    Ok(Some(public_key.to_vec()))
}

/// AP1 pair-verify: Ed25519/Curve25519 handshake (M1/M2).
pub(crate) fn handle_pair_verify(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    let data = request.data().ok_or(bad("no body"))?;
    match data.first() {
        Some(1) if data.len() == 4 + 32 + 32 => {
            let ecdh_key: &[u8; 32] = data[4..36].try_into().map_err(|_| bad("key"))?;
            let ed_key: &[u8; 32] = data[36..68].try_into().map_err(|_| bad("key"))?;
            let verified = conn.pairing.handshake(ecdh_key, ed_key).and_then(|()| {
                Ok((
                    conn.pairing.get_public_key()?,
                    conn.pairing.get_signature()?,
                ))
            });
            let (public_key, signature) = verified.map_err(|e| {
                RtspError::unauthorized("AP1 pair-verify M1").report(ShairplayError::Crypto(e))
            })?;
            response.add_header("Content-Type", "application/octet-stream");
            let mut resp = Vec::with_capacity(96);
            resp.extend_from_slice(&public_key);
            resp.extend_from_slice(&signature);
            Ok(Some(resp))
        }
        Some(0) if data.len() == 4 + 64 => {
            let sig: &[u8; 64] = data[4..68].try_into().map_err(|_| bad("signature"))?;
            conn.pairing.finish(sig).map_err(|e| {
                RtspError::unauthorized("AP1 pair-verify finish")
                    .closing()
                    .report(ShairplayError::Crypto(e))
            })?;
            Ok(None)
        }
        _ => Err(bad("not an AP1 pair-verify message")),
    }
}

/// FairPlay DRM handshake (fp-setup M1/M2).
pub(crate) fn handle_fp_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    let data = request.data().ok_or(bad("no body"))?;
    tracing::debug!(data_len = data.len(), "fp-setup");
    let failed = |e| RtspError::bad_request("fp-setup").report(ShairplayError::Crypto(e));
    match data.len() {
        16 => {
            let req: &[u8; 16] = data.try_into().map_err(|_| bad("fp-setup M1"))?;
            Ok(Some(conn.fairplay.setup(req).map_err(failed)?.to_vec()))
        }
        164 => {
            let req: &[u8; 164] = data.try_into().map_err(|_| bad("fp-setup M2"))?;
            Ok(Some(conn.fairplay.handshake(req).map_err(failed)?.to_vec()))
        }
        _ => Err(bad("an fp-setup body is 16 or 164 bytes")),
    }
}

/// RTSP OPTIONS: return supported methods.
pub(crate) fn handle_options(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    #[cfg(feature = "ap2-core")]
    response.add_header(
        "Public",
        "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, PUT",
    );
    #[cfg(not(feature = "ap2-core"))]
    response.add_header(
        "Public",
        "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER",
    );
    Ok(None)
}

/// RTSP ANNOUNCE: parse SDP, extract AES keys, create RTP session. Every failure closes the connection: the
/// sender's stream can't play here.
pub(crate) fn handle_announce(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    let refuse = |detail: &'static str| RtspError::bad_request(detail).closing();
    let data = request.data().ok_or(refuse("ANNOUNCE without SDP"))?;
    let sdp_str = std::str::from_utf8(data).map_err(|_| refuse("the SDP isn't text"))?;
    if !conn.session {
        conn.session = true;
        conn.shared
            .handler
            .on_session_setup(&conn.remote_socket.ip().to_string());
    }
    let sdp = Sdp::parse(sdp_str);

    let remote = sdp.connection().ok_or(refuse("the SDP has no c= line"))?;
    let rtpmap = sdp.rtpmap().ok_or(refuse("the SDP has no rtpmap"))?;
    let fmtp = sdp.fmtp();
    // aesiv/rsaaeskey are absent when the sender negotiated no encryption
    // (e.g. PipeWire's et=0 mode).
    let rsa_key = sdp.rsaaeskey();
    let fairplay_key = sdp.fpaeskey();
    let aesiv_str = sdp.aesiv();

    if rsa_key.is_some() && fairplay_key.is_some() {
        return Err(refuse("ANNOUNCE: two audio encryption keys"));
    }

    let encryption_expected = rsa_key.is_some() || fairplay_key.is_some();
    if !encryption_expected && aesiv_str.is_some() {
        return Err(refuse("ANNOUNCE: aesiv without an audio encryption key"));
    }

    let crypto = |detail: &'static str, e| refuse(detail).report(ShairplayError::Crypto(e));
    // Decrypt AES key from RSA or FairPlay
    let key_bytes = if let Some(rsa_key_str) = rsa_key {
        Some(
            conn.shared
                .rsakey
                .decrypt(rsa_key_str)
                .map_err(|e| crypto("ANNOUNCE: rsaaeskey doesn't decrypt", e))?,
        )
    } else if let Some(fp_key_str) = fairplay_key {
        let fp_data = conn
            .shared
            .rsakey
            .decode(fp_key_str)
            .map_err(|e| crypto("ANNOUNCE: fpaeskey doesn't decode", e))?;
        let input: &[u8; 72] = fp_data
            .as_slice()
            .try_into()
            .map_err(|_| refuse("ANNOUNCE: fpaeskey isn't 72 bytes"))?;
        Some(
            conn.fairplay
                .decrypt(input)
                .map_err(|e| crypto("ANNOUNCE: fpaeskey doesn't decrypt", e))?
                .to_vec(),
        )
    } else {
        None
    };

    // A sender that advertised a key (`a=rsaaeskey`/`a=fpaeskey`) without a usable key and iv is refused, not played
    // unencrypted: still-encrypted bytes fed to the decoder as PCM play loud static. Only a sender that advertised
    // no key at all is unencrypted.
    let encryption = match key_bytes {
        Some(key_bytes) => {
            let key = key_bytes
                .get(..16)
                .and_then(|k| <[u8; 16]>::try_from(k).ok())
                .ok_or(refuse("ANNOUNCE: the AES key is short"))?;
            let iv = aesiv_str
                .and_then(|iv_str| conn.shared.rsakey.decode(iv_str).ok())
                .and_then(|iv| iv.get(..16).and_then(|v| <[u8; 16]>::try_from(v).ok()))
                .ok_or(refuse("ANNOUNCE: aesiv missing or malformed"))?;
            Some(RtpEncryption { key, iv })
        }
        None => None,
    };

    // Destroy existing RTP session if any
    conn.raop_rtp = None;

    conn.raop_rtp = RaopRtp::new(
        conn.shared.handler.clone(),
        crate::raop::rtp::RtpConfig {
            remote: remote.to_string(),
            local_addr: local_ip_from(conn),
            rtpmap: rtpmap.to_string(),
            fmtp: fmtp.map(str::to_owned),
            encryption,
            output_sample_rate: conn.shared.output_sample_rate,
            output_format: conn.shared.output_format,
            remote_socket: conn.remote_socket,
            offload: conn.shared.offload.clone(),
        },
    );

    if conn.raop_rtp.is_none() {
        let fmtp = fmtp.unwrap_or("<missing>");
        return Err(
            RtspError::unsupported(format!("ANNOUNCE: rtpmap {rtpmap} fmtp {fmtp}"))
                .closing()
                .report(CodecError::UnsupportedFormat(format!(
                    "ANNOUNCE rtpmap={rtpmap} fmtp={fmtp}"
                ))),
        );
    }
    Ok(None)
}

/// AP1 RTSP SETUP: bind RTP ports and start audio receiver.
pub(crate) fn handle_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    let transport = request
        .header("Transport")
        .ok_or(bad("SETUP without Transport"))?;
    tracing::debug!(transport, "AP1 SETUP");

    // Check for DACP remote control headers
    if let (Some(dacp_id), Some(active_remote)) =
        (request.header("DACP-ID"), request.header("Active-Remote"))
    {
        let remote = std::sync::Arc::new(crate::raop::DacpRemoteControl::new(
            dacp_id,
            active_remote,
            conn.remote_socket.ip(),
        ));
        conn.shared.handler.on_remote_control(remote);
    }

    let use_udp = !transport.starts_with("RTP/AVP/TCP");
    let mut remote_cport = 0u16;
    let mut remote_tport = 0u16;

    if use_udp {
        for part in transport.split(';') {
            if let Some(val) = part.strip_prefix("control_port=") {
                remote_cport = val.parse().unwrap_or(0);
            } else if let Some(val) = part.strip_prefix("timing_port=") {
                remote_tport = val.parse().unwrap_or(0);
            }
        }
    }

    let Some(rtp) = &mut conn.raop_rtp else {
        return Err(RtspError::not_now("AP1 SETUP before ANNOUNCE").closing());
    };
    conn.shared
        .claim_stream(conn.id, &conn.sender_id, &conn.close);
    let (cport, tport, dport) = rtp
        .start(use_udp, remote_cport, remote_tport)
        .map_err(|e| RtspError::internal("AP1 SETUP: the RTP ports").report(e))?;

    let transport_resp = if use_udp {
        format!(
            "RTP/AVP/UDP;unicast;mode=record;timing_port={tport};events;control_port={cport};server_port={dport}"
        )
    } else {
        format!("RTP/AVP/TCP;unicast;interleaved=0-1;mode=record;server_port={dport}")
    };
    response.add_header("Transport", &transport_resp);
    response.add_header("Session", "DEADBEEF");
    Ok(None)
}

/// AP1 RTSP RECORD: acknowledge the start of RTP streaming.
pub(crate) fn handle_record(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    // Mirror the AP2 RECORD response: classic RAOP clients expect an
    // Audio-Latency header. The value is a placeholder — actual playback
    // timing is handled by the RTP layer, not advertised here.
    response.add_header("Audio-Latency", "0");
    Ok(None)
}

/// RTSP GET_PARAMETER: return volume or other parameters. Without a body (a keepalive) or a parameter it knows:
/// an empty answer.
pub(crate) fn handle_get_parameter(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    if request.header("Content-Type") != Some("text/parameters") {
        return Ok(None);
    }
    let text = std::str::from_utf8(request.data().unwrap_or_default())
        .map_err(|_| bad("the parameters aren't text"))?;
    if text.contains("volume") {
        response.add_header("Content-Type", "text/parameters");
        let volume = conn.shared.handler.volume().unwrap_or(0.0);
        return Ok(Some(format!("volume: {volume:.6}\r\n").into_bytes()));
    }
    Ok(None)
}

/// RTSP SET_PARAMETER: handle volume, metadata, artwork, progress. What it doesn't know is ignored.
pub(crate) fn handle_set_parameter(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    let (Some(content_type), Some(data)) = (request.header("Content-Type"), request.data()) else {
        return Ok(None);
    };
    tracing::debug!(content_type, len = data.len(), "SET_PARAMETER");

    // Volume, progress, cover art, and DMAP metadata are delivered straight to the
    // AudioHandler (never blocking the audio pipeline). This dispatch is identical
    // for AP1 and AP2 — only audio-pipeline commands (rate/flush) differ, and those
    // arrive on their own RTSP methods, not here.
    match content_type {
        "text/parameters" => {
            let text = std::str::from_utf8(data).map_err(|_| bad("the parameters aren't text"))?;
            if let Some(rest) = text.strip_prefix("volume: ") {
                // dB, -144 (mute) to 0; "nan" and "inf" parse as f32 too
                let vol = rest
                    .trim()
                    .parse::<f32>()
                    .ok()
                    .filter(|v| v.is_finite())
                    .ok_or(bad("volume isn't a number"))?;
                conn.shared.handler.on_volume(vol.clamp(-144.0, 0.0));
            } else if let Some(rest) = text.strip_prefix("progress: ") {
                let parts: Vec<&str> = rest.trim().split('/').collect();
                if parts.len() == 3 {
                    conn.shared.handler.on_progress(
                        parts[0].parse().unwrap_or(0),
                        parts[1].parse().unwrap_or(0),
                        parts[2].parse().unwrap_or(0),
                    );
                }
            }
        }
        "image/jpeg" | "image/png" => conn.shared.handler.on_coverart(data),
        "application/x-dmap-tagged" => {
            let meta = crate::proto::dmap::TrackMetadata::from_dmap(data);
            conn.shared.handler.on_metadata(&meta);
        }
        _ => {}
    }
    Ok(None)
}

// --- AirPlay 2 handlers ---

// Verifies that handler-facing error notification (`AudioHandler::on_error`) is
// actually wired to a representative failure path. Gated to AP1-only builds so the
// `RaopShared`/`RaopConnection` literals below need only the base (non-AP2) fields.
#[cfg(all(test, not(feature = "ap2-core")))]
mod tests {
    use super::*;
    use crate::crypto::pairing::Pairing;
    use crate::crypto::rsa::RsaKey;
    use crate::raop::connection::RaopShared;
    use crate::raop::{AudioFormat, AudioHandler, AudioSession};
    use std::sync::{Arc, Mutex};

    /// An `AudioHandler` that records every error passed to `on_error`.
    #[derive(Default)]
    struct RecordingHandler {
        errors: Mutex<Vec<String>>,
    }

    impl AudioHandler for RecordingHandler {
        fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
            unreachable!("audio_init is not exercised by the fp-setup error path")
        }
        fn on_error(&self, error: &ShairplayError) {
            self.errors.lock().unwrap().push(error.to_string());
        }
    }

    fn test_connection(handler: Arc<RecordingHandler>) -> RaopConnection {
        let shared = Arc::new(RaopShared {
            rsakey: Arc::new(RsaKey::from_pem(include_str!("../../airport.key")).unwrap()),
            pairing: Arc::new(Pairing::generate().unwrap()),
            hwaddr: vec![0u8; 6],
            password: String::new(),
            #[cfg(feature = "pipewire-auth-setup-compat")]
            pipewire_auth_setup_compat: false,
            handler,
            output_sample_rate: None,
            output_max_channels: None,
            output_format: crate::raop::SampleFormat::F32,
            audio_buffer_size: 0x10_0000,
            offload: None,
            identity: crate::raop::DeviceIdentity::default(),
            stream_owner: Mutex::new(None),
            verified: Mutex::new(Vec::new()),
        });
        let pairing = shared.pairing.create_session();
        RaopConnection {
            raop_rtp: None,
            fairplay: FairPlay::new(),
            pairing,
            local_addr: vec![127, 0, 0, 1],
            remote_socket: "127.0.0.1:5000".parse().unwrap(),
            session: false,
            nonce: String::new(),
            challenges: 0,
            shared,
            id: 0,
            close: Arc::new(tokio::sync::Notify::new()),
            sender_id: String::new(),
        }
    }

    fn fp_setup_request(body: &[u8]) -> HttpRequest {
        let mut msg = format!(
            "POST /fp-setup RTSP/1.0\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        msg.extend_from_slice(body);
        let mut req = HttpRequest::new();
        req.add_data(&msg).unwrap();
        assert_eq!(
            req.data().map(|d| d.len()),
            Some(body.len()),
            "body should parse"
        );
        req
    }

    /// A malformed fp-setup M1 (version byte != 0x03) must surface the FairPlay
    /// `CryptoError` to the application via `on_error`, exactly once.
    #[test]
    fn fp_setup_failure_notifies_handler() {
        let handler = Arc::new(RecordingHandler::default());
        let mut conn = test_connection(handler.clone());

        // 16-byte M1 with byte[4] = 0x00 (!= 0x03) → FairPlay::setup returns Err.
        let req = fp_setup_request(&[0u8; 16]);

        let resp = crate::raop::rtsp::dispatch(&mut conn, &req);

        assert_eq!(
            resp.status_code(),
            400,
            "malformed fp-setup should be refused"
        );
        let errors = handler.errors.lock().unwrap();
        assert_eq!(
            errors.len(),
            1,
            "on_error should fire exactly once: {errors:?}"
        );
        assert!(
            errors[0].contains("unsupported version"),
            "on_error should carry the FairPlay error, got: {:?}",
            errors[0]
        );
    }

    /// A well-formed fp-setup M1 must NOT trigger `on_error`.
    #[test]
    fn fp_setup_success_does_not_notify() {
        let handler = Arc::new(RecordingHandler::default());
        let mut conn = test_connection(handler.clone());

        // Valid M1: byte[4] = 0x03 (version), byte[14] = 0 (mode).
        let mut body = [0u8; 16];
        body[4] = 0x03;
        let req = fp_setup_request(&body);
        let mut resp = HttpResponse::new("RTSP/1.0", 200, "OK");

        let out = handle_fp_setup(&mut conn, &req, &mut resp);

        assert!(
            out.unwrap().is_some(),
            "valid fp-setup M1 should produce a reply"
        );
        assert!(
            handler.errors.lock().unwrap().is_empty(),
            "no error expected on success"
        );
    }
}
