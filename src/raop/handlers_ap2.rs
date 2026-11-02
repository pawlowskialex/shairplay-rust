//! AP2 RTSP request handlers — pairing, encrypted SETUP, buffered audio, video.

use crate::codec::alac::AlacFormat;
use crate::crypto::pairing_homekit::{self, PairVerifyServer};
#[cfg(feature = "video")]
use crate::error::CryptoError;
use crate::error::{ProtocolError, ShairplayError};
use crate::proto::http::{HttpRequest, HttpResponse};
#[cfg(feature = "ap2-core")]
use crate::raop::connection::MAX_PAIR_FAILURES;
#[cfg(feature = "video")]
use crate::raop::rtp::RaopRtp;
#[cfg(feature = "ap2-core")]
use std::sync::atomic::Ordering;

use super::handlers_ap1::{PairingStep, Peer, RaopConnection, bind_addr_for, local_ip_from};
use super::rtsp::{Handled, RtspError, bad, plist_body};
use super::sessions::Stream;

#[cfg(feature = "ap2-core")]
fn bind_tcp(addr: std::net::SocketAddr) -> Result<(tokio::net::TcpListener, u16), RtspError> {
    let bound = std::net::TcpListener::bind(addr).and_then(|l| {
        l.set_nonblocking(true)?;
        let l = tokio::net::TcpListener::from_std(l)?;
        let port = l.local_addr()?.port();
        Ok((l, port))
    });
    bound.map_err(|e| RtspError::internal(format!("a TCP port on {addr}: {e}")))
}

#[cfg(feature = "ap2-core")]
fn bind_udp(addr: std::net::SocketAddr) -> Result<(tokio::net::UdpSocket, u16), RtspError> {
    let bound = std::net::UdpSocket::bind(addr).and_then(|s| {
        s.set_nonblocking(true)?;
        let s = tokio::net::UdpSocket::from_std(s)?;
        let port = s.local_addr()?.port();
        Ok((s, port))
    });
    bound.map_err(|e| RtspError::internal(format!("a UDP port on {addr}: {e}")))
}

#[cfg(feature = "ap2-core")]
impl RaopConnection {
    /// The event channel: the sender connects to `event_listener`, then what goes into `rx` goes to it. It ends with
    /// the connection (`sender`, the channel's own end, kept until then: what the application holds may go first).
    pub(crate) fn spawn_event_channel(
        &mut self,
        event_listener: tokio::net::TcpListener,
        event_channel_cipher: crate::crypto::chacha_transport::EncryptedChannel,
        rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        sender: crate::raop::event_channel::EventSender,
    ) {
        let peer = self.remote_socket.ip();
        self.tasks.push(crate::util::OwnedTask::spawn(async move {
            let _sender = sender;
            if let Some((stream, addr)) = crate::net::accept_from(&event_listener, peer).await {
                tracing::info!(%addr, "Event channel client connected");
                crate::net::keepalive(&stream);
                crate::raop::event_channel::EventChannel::handle_stream(
                    stream,
                    event_channel_cipher,
                    rx,
                )
                .await;
            }
        }));
    }

    /// The pair-setup state M3 or M5 continues from (taken: one proof per M1).
    fn take_setup(&mut self) -> Option<Box<crate::crypto::pairing_homekit::SrpServer>> {
        match std::mem::replace(&mut self.pairing_step, PairingStep::None) {
            PairingStep::Setup(srp) => Some(srp),
            other => {
                self.pairing_step = other;
                None
            }
        }
    }
}

#[cfg(feature = "ap2-core")]
/// AP2 pair-setup: SRP-6a + HomeKit pairing (M1→M5).
pub(crate) fn handle_pair_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    let data = request.data().ok_or(bad("no body"))?;
    response.add_header("Content-Type", "application/octet-stream");

    // Try AP2 TLV-based pairing first; fall back to AP1 if not valid TLV
    let tlv = match crate::crypto::tlv::TlvValues::decode(data) {
        Ok(t) if t.get(6).is_some() => t, // Must have State field
        _ => return super::handlers_ap1::handle_pair_setup(conn, request, response),
    };
    let state = *tlv
        .get(6)
        .and_then(|s| s.first())
        .ok_or(bad("an empty State"))?;
    let failed = |what: &'static str| {
        move |e: crate::error::CryptoError| {
            RtspError::internal(what).report(ShairplayError::Crypto(e))
        }
    };

    match state {
        1 => {
            tracing::info!("AP2 pair-setup M1 received");
            if conn.shared.pair_failures.load(Ordering::Relaxed) >= MAX_PAIR_FAILURES {
                tracing::warn!("pair-setup refused: too many failed attempts since the start");
                return Ok(Some(pairing_homekit::pairing_error(
                    2,
                    pairing_homekit::TLV_ERROR_MAX_TRIES,
                )));
            }
            let mut srp = conn
                .shared
                .srp_spare
                .take()
                .map_err(failed("pair-setup M1: the SRP state"))?;
            if let Err(e) = srp.process_m1(data) {
                tracing::warn!("pair-setup M1 failed: {e}");
                conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                return Ok(Some(pairing_homekit::pairing_error_response(2)));
            }
            let m2 = srp.build_m2();
            conn.pairing_step = PairingStep::Setup(Box::new(srp));
            Ok(Some(m2))
        }
        3 => {
            // one proof per M1: the SRP state (b, B) goes with it, so a wrong PIN can't be tried again against it
            let Some(mut srp) = conn.take_setup() else {
                return Ok(Some(pairing_homekit::pairing_error_response(4)));
            };
            if !srp.process_m3(data).unwrap_or(false) {
                conn.shared.pair_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("pair-setup M3: the proof didn't check");
                return Ok(Some(pairing_homekit::pairing_error_response(4)));
            }
            let m4 = srp.build_m4().map_err(failed("pair-setup M4"))?;
            if srp.is_transient() {
                conn.secret = srp
                    .shared_secret()
                    .map(|s| zeroize::Zeroizing::new(s.to_vec()));
                conn.peer = Peer::Transient;
                tracing::info!("AP2 transient pair-setup complete");
            } else {
                // M5 follows
                conn.pairing_step = PairingStep::Setup(srp);
            }
            Ok(Some(m4))
        }
        5 => {
            let Some(mut srp) = conn.take_setup() else {
                return Ok(Some(pairing_homekit::pairing_error_response(6)));
            };
            match srp.process_m5(data) {
                // a pairing doesn't replace another controller's key under the same identifier (HAP: as AddPairing);
                // forget that pairing first
                Ok((client_id, client_pk))
                    if conn
                        .shared
                        .pairing_store
                        .get(&client_id)
                        .is_some_and(|known| known != client_pk) =>
                {
                    tracing::warn!(
                        client_id,
                        "pair-setup M5: identifier already paired with another key"
                    );
                    Ok(Some(pairing_homekit::pairing_error_response(6)))
                }
                Ok((client_id, client_pk)) => {
                    let m6 = srp
                        .build_m6(&conn.shared.device_id, &conn.shared.identity_seed)
                        .map_err(failed("pair-setup M6"))?;
                    if !conn.shared.pairing_store.put(&client_id, client_pk, true) {
                        tracing::warn!(client_id, "pair-setup M5: the pairing store is full");
                        return Ok(Some(pairing_homekit::pairing_error(
                            6,
                            pairing_homekit::TLV_ERROR_MAX_PEERS,
                        )));
                    }
                    tracing::info!(
                        client_id,
                        "AP2 normal pair-setup complete, client key stored"
                    );
                    Ok(Some(m6))
                }
                Err(e) => {
                    tracing::warn!("pair-setup M5 failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    Ok(Some(pairing_homekit::pairing_error_response(6)))
                }
            }
        }
        _ => Err(bad("pair-setup: not M1, M3 or M5")),
    }
}

#[cfg(feature = "ap2-core")]
/// AP2 pair-verify: Ed25519 verify + HKDF shared secret derivation.
pub(crate) fn handle_pair_verify(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    let data = request.data().ok_or(bad("no body"))?;
    response.add_header("Content-Type", "application/octet-stream");

    let tlv = match crate::crypto::tlv::TlvValues::decode(data) {
        Ok(t) if t.get(6).is_some() => t,
        _ => {
            tracing::debug!(
                data_len = data.len(),
                "pair-verify: no TLV state, falling back to legacy"
            );
            return super::handlers_ap1::handle_pair_verify(conn, request, response);
        }
    };
    let state = *tlv
        .get(6)
        .and_then(|s| s.first())
        .ok_or(bad("an empty State"))?;
    tracing::debug!(state, data_len = data.len(), "pair-verify TLV state");

    match state {
        1 => {
            tracing::info!("AP2 pair-verify M1 received");
            let mut pv = PairVerifyServer::new(&conn.shared.device_id, &conn.shared.identity_seed);
            match pv.process_m1_build_m2(data) {
                Ok(m2) => {
                    tracing::debug!(m2_len = m2.len(), "pair-verify M2 built");
                    // Store ECDH shared secret immediately (needed for video even if M3 never arrives)
                    #[cfg(feature = "video")]
                    {
                        conn.ecdh = Some(zeroize::Zeroizing::new(*pv.ecdh_shared_secret()));
                    }
                    conn.pairing_step = PairingStep::Verify(Box::new(pv));
                    Ok(Some(m2))
                }
                Err(e) => {
                    tracing::warn!("pair-verify M1 failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    Ok(Some(pairing_homekit::pairing_error_response(2)))
                }
            }
        }
        3 => {
            // its state goes with this message, whatever comes of it
            let PairingStep::Verify(mut pv) =
                std::mem::replace(&mut conn.pairing_step, PairingStep::None)
            else {
                tracing::warn!("pair-verify M3 without M1");
                return Ok(Some(pairing_homekit::pairing_error_response(4)));
            };
            let store = conn.shared.pairing_store.clone();
            match pv.process_m3_build_m4(data, Some(&|id| store.get(id))) {
                Ok(m4) => {
                    #[cfg(feature = "video")]
                    {
                        conn.ecdh = pv.shared_secret().map(|s| zeroize::Zeroizing::new(*s));
                    }
                    conn.secret = pv
                        .shared_secret()
                        .map(|s| zeroize::Zeroizing::new(s.to_vec()));
                    conn.peer = match pv.controller() {
                        Some(c) => {
                            conn.shared.sessions.verified(conn.id, c);
                            Peer::Controller(c.to_string())
                        }
                        None => Peer::Transient,
                    };
                    tracing::info!("AP2 pair-verify complete, encrypted RTSP active");
                    Ok(Some(m4))
                }
                Err(e) => {
                    tracing::warn!("pair-verify M3 failed: {e}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                    Ok(Some(pairing_homekit::pairing_error_response(4)))
                }
            }
        }
        _ => Err(bad("pair-verify: not M1 or M3")),
    }
}

#[cfg(feature = "ap2-core")]
/// HAP pairing management, POST /pairings: [`pairings`] on this session's verified controller; the controllers whose
/// pairing went have their connections closed (this one's after its response).
pub(crate) fn handle_pairings(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    response.add_header("Content-Type", "application/pairing+tlv8");
    let (body, removed) = pairings(
        conn.shared.pairing_store.as_ref(),
        conn.controller(),
        request.data().unwrap_or(&[]),
    );
    for id in removed {
        conn.shared.sessions.close_controller(&id);
    }
    Ok(Some(body))
}

#[cfg(feature = "ap2-core")]
/// HAP pairing management (State 1; Method 3 AddPairing, 4 RemovePairing, 5 ListPairings) for a session verified as
/// `controller`: only an admin may. Removing the last admin removes every pairing. Returns the response TLV and the
/// controllers removed.
pub(crate) fn pairings(
    store: &dyn crate::raop::PairingStore,
    controller: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, Vec<String>) {
    use crate::crypto::tlv::{TlvType, TlvValues};
    // HAP's kTLVError codes
    const UNKNOWN: u8 = 1;
    const AUTHENTICATION: u8 = 2;
    const MAX_PEERS: u8 = 4;
    let mut resp = TlvValues::new();
    resp.add(TlvType::State as u8, &[2]);
    let error = |mut resp: TlvValues, code: u8| {
        resp.add(TlvType::Error as u8, &[code]);
        (resp.encode(), Vec::new())
    };
    let Ok(tlv) = TlvValues::decode(body) else {
        return error(resp, UNKNOWN);
    };
    if tlv.get_type(TlvType::State) != Some(&[1][..]) {
        return error(resp, UNKNOWN);
    }
    let Some(admin) = controller.filter(|c| store.is_admin(c)) else {
        tracing::warn!(?controller, "/pairings: not an admin controller's session");
        return error(resp, AUTHENTICATION);
    };
    let id = tlv
        .get_type(TlvType::Identifier)
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(str::to_string);
    let mut removed = Vec::new();
    match tlv.get_type(TlvType::Method).and_then(|m| m.first()) {
        Some(3) => {
            let (Some(id), Some(pk)) = (
                id,
                tlv.get_type(TlvType::PublicKey)
                    .and_then(|v| <[u8; 32]>::try_from(v).ok()),
            ) else {
                return error(resp, UNKNOWN);
            };
            let admin_perm = tlv
                .get_type(TlvType::Permissions)
                .and_then(|p| p.first())
                .is_some_and(|p| p & 1 != 0);
            // an identifier already paired with another key is refused (HAP); the same one updates its permission
            if store.get(&id).is_some_and(|k| k != pk) {
                return error(resp, UNKNOWN);
            }
            if !store.put(&id, pk, admin_perm) {
                return error(resp, MAX_PEERS);
            }
            tracing::info!(
                by = admin,
                id,
                admin = admin_perm,
                "/pairings: controller added"
            );
        }
        Some(4) => {
            let Some(id) = id else {
                return error(resp, UNKNOWN);
            };
            store.remove(&id);
            tracing::info!(by = admin, id, "/pairings: controller removed");
            removed.push(id);
            if !store.list().iter().any(|c| c.2) {
                for (other, _, _) in store.list() {
                    store.remove(&other);
                    removed.push(other);
                }
                tracing::info!("/pairings: no admin left: every pairing removed");
            }
        }
        Some(5) => {
            for (k, (id, pk, a)) in store.list().into_iter().enumerate() {
                if k > 0 {
                    resp.add(TlvType::Separator as u8, &[]);
                }
                resp.add(TlvType::Identifier as u8, id.as_bytes());
                resp.add(TlvType::PublicKey as u8, &pk);
                resp.add(TlvType::Permissions as u8, &[u8::from(a)]);
            }
        }
        _ => return error(resp, UNKNOWN),
    }
    (resp.encode(), removed)
}

#[cfg(all(test, feature = "ap2-core"))]
mod pairings_tests {
    use super::pairings;
    use crate::crypto::tlv::{TlvType, TlvValues};
    use crate::raop::{MemoryPairingStore, PairingStore};

    fn req(method: u8, id: Option<&str>, pk: Option<[u8; 32]>, perm: Option<u8>) -> Vec<u8> {
        let mut t = TlvValues::new();
        t.add(TlvType::State as u8, &[1]);
        t.add(TlvType::Method as u8, &[method]);
        if let Some(id) = id {
            t.add(TlvType::Identifier as u8, id.as_bytes());
        }
        if let Some(pk) = pk {
            t.add(TlvType::PublicKey as u8, &pk);
        }
        if let Some(p) = perm {
            t.add(TlvType::Permissions as u8, &[p]);
        }
        t.encode()
    }

    fn err(resp: &[u8]) -> Option<u8> {
        TlvValues::decode(resp)
            .unwrap()
            .get_type(TlvType::Error)
            .map(|e| e[0])
    }

    #[test]
    fn only_an_admin_manages_pairings() {
        let s = MemoryPairingStore::default();
        s.put("admin", [1; 32], true);
        s.put("user", [2; 32], false);
        assert_eq!(
            err(&pairings(&s, None, &req(5, None, None, None)).0),
            Some(2)
        );
        assert_eq!(
            err(&pairings(&s, Some("user"), &req(5, None, None, None)).0),
            Some(2)
        );
        assert_eq!(
            err(&pairings(&s, Some("stranger"), &req(5, None, None, None)).0),
            Some(2)
        );
        assert_eq!(
            err(&pairings(&s, Some("admin"), &req(5, None, None, None)).0),
            None
        );
    }

    #[test]
    fn add_list_and_remove() {
        let s = MemoryPairingStore::default();
        s.put("admin", [1; 32], true);
        let (r, _) = pairings(
            &s,
            Some("admin"),
            &req(3, Some("phone"), Some([3; 32]), Some(0)),
        );
        assert_eq!(err(&r), None);
        assert_eq!(s.get("phone"), Some([3; 32]));
        assert!(!s.is_admin("phone"));
        // the same identifier with another key is refused
        let (r, _) = pairings(
            &s,
            Some("admin"),
            &req(3, Some("phone"), Some([4; 32]), Some(1)),
        );
        assert_eq!(err(&r), Some(1));
        let (r, _) = pairings(&s, Some("admin"), &req(5, None, None, None));
        let listed = TlvValues::decode(&r).unwrap();
        assert_eq!(err(&r), None);
        assert!(
            listed.get_type(TlvType::Separator).is_some(),
            "two controllers, separated"
        );
        let (r, removed) = pairings(&s, Some("admin"), &req(4, Some("phone"), None, None));
        assert_eq!((err(&r), removed), (None, vec!["phone".to_string()]));
        assert_eq!(s.get("phone"), None);
    }

    #[test]
    fn removing_the_last_admin_removes_everyone() {
        let s = MemoryPairingStore::default();
        s.put("admin", [1; 32], true);
        s.put("user", [2; 32], false);
        let (r, mut removed) = pairings(&s, Some("admin"), &req(4, Some("admin"), None, None));
        removed.sort();
        assert_eq!(
            (err(&r), removed),
            (None, vec!["admin".to_string(), "user".to_string()])
        );
        assert!(!s.has_any_pairing());
    }
}

#[cfg(feature = "ap2-core")]
/// AP2 GET /info: return device capabilities as binary plist.
pub(crate) fn handle_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    use crate::raop::config;

    let (_, vk) = crate::crypto::pairing_homekit::identity_keypair(&conn.shared.identity_seed);
    let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();

    let hw = crate::util::hwaddr_airplay(&conn.shared.hwaddr);

    let mut dict = plist::Dictionary::new();
    dict.insert("deviceID".into(), plist::Value::String(hw.clone()));
    dict.insert("macAddress".into(), plist::Value::String(hw));
    dict.insert(
        "pi".into(),
        plist::Value::String(conn.shared.pairing_id.clone()),
    );
    dict.insert(
        "name".into(),
        plist::Value::String(conn.shared.airplay_name.clone()),
    );
    dict.insert(
        "features".into(),
        plist::Value::Integer(
            (crate::net::features::receiver_features_for_pairing(conn.shared.pin.is_some()) as i64)
                .into(),
        ),
    );
    dict.insert(
        "model".into(),
        plist::Value::String(conn.shared.identity.model.clone()),
    );
    if let Some(m) = &conn.shared.identity.manufacturer {
        dict.insert("manufacturer".into(), plist::Value::String(m.clone()));
    }
    if let Some(sn) = &conn.shared.identity.serial_number {
        dict.insert("serialNumber".into(), plist::Value::String(sn.clone()));
    }
    dict.insert(
        "protocolVersion".into(),
        plist::Value::String(config::AP2_PROTOVERS.into()),
    );
    dict.insert(
        "sourceVersion".into(),
        plist::Value::String(config::AP2_SRCVERS.into()),
    );
    dict.insert(
        "statusFlags".into(),
        plist::Value::Integer(
            (config::ap2_status_flags(
                conn.shared.pin.is_some(),
                conn.shared.pairing_store.has_any_pairing(),
            ) as i64)
                .into(),
        ),
    );
    dict.insert("pk".into(), plist::Value::String(pk_hex));
    dict.insert(
        "supportedFormats".into(),
        plist::Value::Dictionary(plist::Dictionary::from_iter([
            (
                "audioStream".to_string(),
                plist::Value::Integer(config::AUDIO_STREAM_FORMATS.into()),
            ),
            (
                "bufferStream".to_string(),
                plist::Value::Integer(config::BUFFER_STREAM_FORMATS.into()),
            ),
        ])),
    );
    if let Some(volume) = conn.shared.handler.volume() {
        dict.insert("initialVolume".into(), plist::Value::Real(volume.into()));
    }

    // Video: advertise a display so the iPhone offers screen mirroring
    #[cfg(feature = "video")]
    if conn.shared.video_handler.is_some() {
        let display = plist::Dictionary::from_iter([
            (
                "widthPixels".to_string(),
                plist::Value::Integer(config::MIRRORING_WIDTH.into()),
            ),
            (
                "heightPixels".to_string(),
                plist::Value::Integer(config::MIRRORING_HEIGHT.into()),
            ),
            (
                "uuid".to_string(),
                plist::Value::String(config::MIRRORING_UUID.into()),
            ),
            (
                "maxFPS".to_string(),
                plist::Value::Integer(config::MIRRORING_FPS.into()),
            ),
            (
                "features".to_string(),
                plist::Value::Integer(config::MIRRORING_FEATURES.into()),
            ),
        ]);
        dict.insert(
            "displays".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(display)]),
        );
    }

    plist_reply(response, &dict)
}

/// A binary plist answer.
#[cfg(feature = "ap2-core")]
fn plist_reply(response: &mut HttpResponse, dict: &plist::Dictionary) -> Handled {
    response
        .set_plist_body(dict)
        .map(Some)
        .ok_or_else(|| RtspError::internal("the answer's plist"))
}

#[cfg(feature = "ap2-core")]
/// AP2 `/pair-pin-start`: acknowledge that the accessory is ready for PIN entry.
///
/// macOS sends this after seeing PIN-required mDNS/status flags and aborts
/// normal pair-setup if the receiver answers 404.
pub(crate) fn handle_pair_pin_start(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    response.add_header("Content-Type", "application/octet-stream");
    Ok(None)
}

#[cfg(feature = "ap2-core")]
/// Build the `updateInfo` `POST /command` message queued on a freshly-opened
/// event channel (status flags, features, model, versions). Identical for the
/// RC-only and normal event channels.
fn build_update_info_message(
    requires_pin_pairing: bool,
    already_paired: bool,
    model: &str,
) -> Option<Vec<u8>> {
    use crate::raop::config;

    let mut update_info = plist::Dictionary::new();
    update_info.insert("type".into(), plist::Value::String("updateInfo".into()));
    let mut value = plist::Dictionary::new();
    value.insert(
        "statusFlags".into(),
        plist::Value::Integer(
            (config::ap2_status_flags(requires_pin_pairing, already_paired) as i64).into(),
        ),
    );
    value.insert(
        "features".into(),
        plist::Value::Integer(
            (crate::net::features::receiver_features_for_pairing(requires_pin_pairing) as i64)
                .into(),
        ),
    );
    value.insert("model".into(), plist::Value::String(model.into()));
    value.insert(
        "sourceVersion".into(),
        plist::Value::String(config::AP2_SRCVERS.into()),
    );
    value.insert(
        "protocolVersion".into(),
        plist::Value::String(config::AP2_PROTOVERS.into()),
    );
    update_info.insert("value".into(), plist::Value::Dictionary(value));
    crate::raop::event_channel::command_message(&update_info, 0)
}

#[cfg(feature = "ap2-core")]
/// AP2 SETUP: configure streams (type 96/103/110/130), event channel, timing.
pub(crate) fn handle_setup(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    let dict = &plist_body(request)?;
    let keys: Vec<_> = dict.keys().collect();
    let has_streams = dict.get("streams").is_some();
    let is_mirror = dict
        .get("isScreenMirroringSession")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);
    let has_ekey = dict.get("ekey").is_some();
    let timing = dict
        .get("timingProtocol")
        .and_then(|v| v.as_string())
        .unwrap_or("");
    tracing::info!(
        ?keys,
        has_streams,
        is_mirror,
        has_ekey,
        timing,
        "SETUP plist"
    );
    tracing::debug!(
        plist = plist_brief(&plist::Value::Dictionary(dict.clone())),
        "SETUP"
    );
    tracing::debug!(
        dacp_id = request.header("DACP-ID"),
        active_remote = request.header("Active-Remote").is_some(),
        "SETUP remote-control headers"
    );

    let resp_dict = if let Some(streams) = dict.get("streams") {
        let streams = streams.as_array().ok_or(bad("streams isn't an array"))?;
        setup_streams(conn, streams)?
    } else {
        setup_initial(conn, dict)?
    };

    plist_reply(response, &resp_dict)
}

#[cfg(feature = "ap2-core")]
/// A plist integer as its 64 bits: Apple's plists carry unsigned 64-bit values (a fraction of a second, a clock
/// identity) as signed integers when the top bit is set.
pub(crate) fn plist_u64(v: &plist::Value) -> Option<u64> {
    v.as_unsigned_integer()
        .or_else(|| v.as_signed_integer().map(|i| i as u64))
}

#[cfg(feature = "ap2-core")]
/// A plist in one line for the debug log: data as its length (keys and secrets never appear), long arrays cut.
pub(crate) fn plist_brief(v: &plist::Value) -> String {
    match v {
        plist::Value::Dictionary(d) => format!(
            "{{{}}}",
            d.iter()
                .map(|(k, v)| format!("{k}: {}", plist_brief(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        plist::Value::Array(a) => {
            let mut items: Vec<String> = a.iter().take(8).map(plist_brief).collect();
            if a.len() > 8 {
                items.push(format!("... {} more", a.len() - 8));
            }
            format!("[{}]", items.join(", "))
        }
        plist::Value::Data(d) => format!("<{} bytes>", d.len()),
        plist::Value::String(s) => format!("{s:?}"),
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(r) => r.to_string(),
        plist::Value::Boolean(b) => b.to_string(),
        other => format!("{other:?}"),
    }
}

#[cfg(feature = "ap2-core")]
/// Stream SETUP (`streams` present): dispatch by stream type, then add the shared control port.
fn setup_streams(
    conn: &mut RaopConnection,
    streams: &[plist::Value],
) -> Result<plist::Dictionary, RtspError> {
    // Stream SETUP — type 96 (realtime) or type 103 (buffered) or type 110 (video)
    let stream0 = streams
        .first()
        .and_then(|s| s.as_dictionary())
        .ok_or(bad("no stream"))?;
    let stream_type = stream0
        .get("type")
        .and_then(|t| t.as_unsigned_integer())
        .ok_or(bad("a stream without its type"))?;
    let stream_keys: Vec<_> = stream0.keys().collect();
    tracing::info!(stream_type, ?stream_keys, "Stream SETUP");

    let mut stream_resp = plist::Dictionary::new();
    stream_resp.insert("type".into(), plist::Value::Integer(stream_type.into()));

    match stream_type {
        96 => setup_stream_realtime(conn, stream0, &mut stream_resp)?,
        103 => setup_stream_buffered(conn, stream0, &mut stream_resp)?,
        130 => setup_stream_rc(conn, stream0, &mut stream_resp)?,
        #[cfg(feature = "video")]
        110 => setup_stream_video(conn, stream0, &mut stream_resp)?,
        _ => {
            // Type 120 = Apple Music video (animated album art / music videos). Not implemented.
            tracing::warn!(stream_type, "Unknown AP2 stream type");
        }
    }

    // Control port: streams that use one (realtime: retransmits) put their own; the others get a port nobody listens
    // on, as the sender expects the key
    if !stream_resp.contains_key("controlPort") {
        let (ctrl_sock, ctrl_port) = bind_udp(bind_addr_for(conn))?;
        drop(ctrl_sock);
        stream_resp.insert(
            "controlPort".into(),
            plist::Value::Integer(ctrl_port.into()),
        );
    }

    let mut resp_dict = plist::Dictionary::new();
    resp_dict.insert(
        "streams".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_resp)]),
    );
    Ok(resp_dict)
}

#[cfg(feature = "ap2-core")]
/// Initial SETUP (no `streams`): capture FairPlay keys (video), establish the event
/// channel and timing, and return the response dictionary.
fn setup_initial(
    conn: &mut RaopConnection,
    dict: &plist::Dictionary,
) -> Result<plist::Dictionary, RtspError> {
    let mut resp_dict = plist::Dictionary::new();
    let timing = dict
        .get("timingProtocol")
        .and_then(|v| v.as_string())
        .unwrap_or("None");

    // Capture FairPlay encryption keys for video.
    // The audio connection provides ekey (72 bytes, FairPlay-encrypted) + eiv (16 bytes).
    // The video connection (separate RTSP session) reads them from shared state.
    #[cfg(feature = "video")]
    {
        if let Some(ekey_data) = dict.get("ekey").and_then(|v| v.as_data())
            && ekey_data.len() == 72
            && let Ok(input) = <[u8; 72]>::try_from(ekey_data)
        {
            match conn.fairplay.decrypt(&input) {
                Ok(fp_key) => {
                    // SHA-512 two-step: hash FairPlay key with ECDH shared secret
                    // Stage 2: hash with ECDH only if AP2 pairing was used.
                    // With UxPlay-style features (bit 27 off), no pairing occurs
                    // and the raw FairPlay key is used directly.
                    let derived = if let Some(secret) = conn.secret.as_deref() {
                        use sha2::{Digest, Sha512};
                        let mut hasher = Sha512::new();
                        hasher.update(fp_key);
                        hasher.update(secret);
                        let hash = hasher.finalize();
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&hash[..16]);
                        key
                    } else {
                        fp_key
                    };
                    conn.ekey = Some(derived);
                    // Store in shared state for the video connection
                    if let Ok(mut shared) = conn.shared.video_ekey.write() {
                        *shared = Some(derived);
                        tracing::debug!("Video ekey stored in shared state");
                    }
                }
                Err(e) => {
                    tracing::warn!("FairPlay decrypt failed: {e:?}");
                    conn.shared.handler.on_error(&ShairplayError::Crypto(e));
                }
            }
        }
        if let Some(eiv_data) = dict.get("eiv").and_then(|v| v.as_data())
            && let Ok(iv) = <[u8; 16]>::try_from(eiv_data)
        {
            conn.eiv = Some(iv);
            if let Ok(mut shared) = conn.shared.video_eiv.write() {
                *shared = Some(iv);
                tracing::debug!("Video eiv stored in shared state");
            }
        }
    }

    if let Some(id) = dict.get("deviceID").and_then(|v| v.as_string()) {
        conn.shared.sessions.set_sender(conn.id, id);
    }

    let is_rc_only = dict
        .get("isRemoteControlOnly")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);
    if !is_rc_only && !conn.session {
        conn.session = true;
        conn.shared
            .handler
            .on_session_setup(&conn.remote_socket.ip().to_string());
    }

    if is_rc_only {
        tracing::info!("Remote Control Only connection - establishing event channel");

        let event_port_resp = if let Some(shared_secret) = conn.secret.clone() {
            let (event_listener, event_port) = bind_tcp(bind_addr_for(conn))?;

            if let Ok(event_channel_cipher) =
                crate::crypto::chacha_transport::EncryptedChannel::events(&shared_secret)
            {
                {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

                    if let Some(msg) = build_update_info_message(
                        conn.shared.pin.is_some(),
                        conn.shared.pairing_store.has_any_pairing(),
                        &conn.shared.identity.model,
                    ) {
                        let _ = tx.send(msg);
                        tracing::debug!("updateInfo queued for RC event channel");
                    }

                    let sender = crate::raop::event_channel::EventSender::from_tx(tx);
                    conn.spawn_event_channel(event_listener, event_channel_cipher, rx, sender);
                }
            }
            event_port as u64
        } else {
            0
        };

        resp_dict.insert(
            "eventPort".into(),
            plist::Value::Integer(event_port_resp.into()),
        );

        return Ok(resp_dict);
    }

    if timing == "PTP" {
        let mut tpi = plist::Dictionary::new();
        let self_ip = local_ip_from(conn).to_string();
        tracing::debug!(self_ip, "timingPeerInfo address");
        let addrs = vec![plist::Value::String(self_ip.clone())];
        tpi.insert("Addresses".into(), plist::Value::Array(addrs));
        tpi.insert("ID".into(), plist::Value::String(self_ip));
        resp_dict.insert("timingPeerInfo".into(), plist::Value::Dictionary(tpi));
    }

    // Bind event port on same address family as the client connection
    let (event_listener, event_port) = bind_tcp(bind_addr_for(conn))?;
    tracing::info!(event_port, "Event channel opened");

    // Derive event channel encryption keys from shared secret (AP2 only).
    // In legacy mode there's no shared secret — skip the encrypted event channel.
    if let Some(shared_secret) = conn.secret.clone()
        && let Ok(event_channel_cipher) =
            crate::crypto::chacha_transport::EncryptedChannel::events(&shared_secret)
    {
        // Spawn bidirectional event channel
        {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

            // Queue updateInfo so it's sent immediately when client connects
            if let Some(msg) = build_update_info_message(
                conn.shared.pin.is_some(),
                conn.shared.pairing_store.has_any_pairing(),
                &conn.shared.identity.model,
            ) {
                let _ = tx.send(msg);
                tracing::debug!("updateInfo queued for event channel");
            }

            let sender = crate::raop::event_channel::EventSender::from_tx(tx);
            // the session's remote control: commands go back on this channel (not on a remote-control-only
            // connection's: senders drop them there)
            let group = dict
                .get("groupUUID")
                .and_then(|v| v.as_string())
                .map(str::to_string);
            tracing::debug!(?group, "AP2 remote control on the event channel");
            conn.shared.handler.on_remote_control(std::sync::Arc::new(
                crate::raop::Ap2RemoteControl::new(
                    sender.clone(),
                    group,
                    conn.mr_supported.clone(),
                ),
            ));
            conn.spawn_event_channel(event_listener, event_channel_cipher, rx, sender);
        }
    }

    // In legacy mode, event channel is not encrypted — return port 0 like UxPlay.
    let event_port_resp = if conn.secret.is_some() {
        event_port as u64
    } else {
        0
    };
    resp_dict.insert(
        "eventPort".into(),
        plist::Value::Integer(event_port_resp.into()),
    );

    // Legacy mode: bind a standalone NTP timing socket and return its port.
    // The iPhone needs NTP sync before it sends the stream SETUP.
    // RaopRtp is created later in the stream SETUP with real ALAC parameters.
    #[cfg(feature = "video")]
    let timing_port = if !conn.paired() && conn.ekey.is_some() {
        let timing_rport = dict
            .get("timingPort")
            .and_then(|v| v.as_unsigned_integer())
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0);
        let (tsock, tport) = bind_udp(bind_addr_for(conn))?;
        let mut remote_timing = conn.remote_socket;
        remote_timing.set_port(timing_rport);
        conn.tasks
            .push(crate::raop::ntp::spawn_ntp_responder(tsock, remote_timing, None).into());
        tracing::debug!(tport, timing_rport, "Legacy video: NTP timing socket bound");
        tport
    } else {
        0
    };
    #[cfg(not(feature = "video"))]
    let timing_port: u16 = 0;

    resp_dict.insert(
        "timingPort".into(),
        plist::Value::Integer(u64::from(timing_port).into()),
    );

    Ok(resp_dict)
}

#[cfg(feature = "ap2-core")]
/// Stream type 96 — realtime ALAC (ChaCha20 per-packet), or legacy AES-CBC ALAC under `video`.
fn setup_stream_realtime(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Result<(), RtspError> {
    let sr = stream0
        .get("sr")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(44100);
    let spf = stream0
        .get("spf")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(352);
    let audio_format = stream0
        .get("audioFormat")
        .and_then(|v| v.as_unsigned_integer())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let alac_format = AlacFormat::from_audio_format(audio_format).unwrap_or_else(|| AlacFormat {
        sample_rate: u32::try_from(sr).unwrap_or(0),
        bit_depth: 16,
        channels: 2,
    });
    let shk = stream0.get("shk").and_then(|v| v.as_data()).unwrap_or(&[]);
    // the decoder's buffers are sized from these: a stream the decoder can't take is refused here
    let spf = u32::try_from(spf).map_err(|_| bad("spf"))?;
    let alac = crate::codec::alac::AlacConfig::defaults(
        spf,
        alac_format.bit_depth,
        alac_format.channels,
        alac_format.sample_rate,
    )
    .ok_or_else(|| {
        RtspError::unsupported(format!(
            "AP2 realtime stream refused, not a shape the decoder takes: spf {spf}, {alac_format:?}"
        ))
    })?;

    if shk.len() == 32 {
        // AP2 realtime ALAC — ChaCha20-Poly1305 per-packet encryption.
        tracing::info!(
            stream_type = 96,
            sample_rate = sr,
            samples_per_frame = spf,
            audio_format,
            alac_format = ?alac_format,
            "AP2 realtime ALAC (ChaCha20)"
        );
        if AlacFormat::from_audio_format(audio_format).is_none() {
            tracing::warn!(
                audio_format,
                sample_rate = sr,
                "Unknown AP2 realtime ALAC audioFormat; falling back to SETUP sr and 16-bit stereo"
            );
        }
        let mut shk_arr = [0u8; 32];
        shk_arr.copy_from_slice(shk);

        let (socket, audio_port) = bind_udp(bind_addr_for(conn))?;
        // Our control port, kept open: the sender answers retransmit requests there. Its own is where they go.
        let (ctrl, ctrl_port) = bind_udp(bind_addr_for(conn))?;
        stream_resp.insert(
            "controlPort".into(),
            plist::Value::Integer(ctrl_port.into()),
        );
        let retransmit = stream0
            .get("controlPort")
            .and_then(|v| v.as_unsigned_integer())
            .filter(|&p| p > 0 && u16::try_from(p).is_ok())
            .map(|p| crate::raop::reorder::Retransmit {
                socket: ctrl,
                sender: std::net::SocketAddr::new(conn.remote_socket.ip(), p as u16),
            });

        let handler = conn.shared.handler.clone();
        let output_config = crate::raop::realtime_audio::OutputConfig {
            alac,
            output: conn.shared.output(),
            offload: conn.shared.offload.clone(),
            latency_min: stream0
                .get("latencyMin")
                .and_then(|v| v.as_unsigned_integer())
                .and_then(|v| u32::try_from(v).ok()),
            peer: Some(conn.remote_socket.ip()),
            latency_ns: conn.shared.realtime_latency_ns,
        };

        let stream = crate::raop::realtime_audio::RealtimeStream::start(
            socket,
            retransmit,
            shk_arr,
            handler,
            output_config,
        );
        conn.shared.sessions.play(conn.id, Stream::Realtime(stream));

        stream_resp.insert("dataPort".into(), plist::Value::Integer(audio_port.into()));
    } else {
        // Legacy ALAC — only available with video feature (UxPlay-style features).
        #[cfg(feature = "video")]
        {
            tracing::info!(
                stream_type = 96,
                sample_rate = sr,
                "Legacy ALAC (AES-CBC via ekey)"
            );

            let aes_key = conn.ekey.unwrap_or([0u8; 16]);
            let aes_iv = conn.eiv.unwrap_or([0u8; 16]);
            let fmtp = format!("96 {spf} 0 16 40 10 14 2 255 0 0 {sr}");
            let rtp = RaopRtp::new(
                conn.shared.handler.clone(),
                crate::raop::rtp::RtpConfig {
                    remote: conn.remote_socket.ip().to_string(),
                    local_addr: local_ip_from(conn),
                    rtpmap: "96 AppleLossless".to_string(),
                    fmtp: Some(fmtp),
                    encryption: Some(crate::raop::rtp::RtpEncryption {
                        key: aes_key,
                        iv: aes_iv,
                    }),
                    output: conn.shared.output(),
                    remote_socket: conn.remote_socket,
                    offload: None,
                },
            );
            if let Some(mut rtp) = rtp {
                let control_port = stream0
                    .get("controlPort")
                    .and_then(|v| v.as_unsigned_integer())
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(0);
                let (cport, _tport, dport) = rtp
                    .start(true, control_port, 0)
                    .map_err(|e| RtspError::internal("legacy ALAC: the RTP ports").report(e))?;
                stream_resp.insert("dataPort".into(), plist::Value::Integer(dport.into()));
                stream_resp.insert("controlPort".into(), plist::Value::Integer(cport.into()));
                conn.shared.sessions.play(conn.id, Stream::Ap1(rtp));
            }
        }
        #[cfg(not(feature = "video"))]
        {
            return Err(
                RtspError::bad_request("a realtime stream without shk").report(
                    ProtocolError::InvalidRtsp(
                        "realtime (type 96) SETUP requires a shared key or the video feature"
                            .into(),
                    ),
                ),
            );
        }
    }
    Ok(())
}

#[cfg(feature = "ap2-core")]
/// Stream type 103 — buffered audio over TCP with a timed playout buffer.
fn setup_stream_buffered(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Result<(), RtspError> {
    let audio_format = stream0
        .get("audioFormat")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);
    let num = |k: &str| stream0.get(k).and_then(|v| v.as_unsigned_integer());
    tracing::info!(
        stream_type = 103,
        audio_format,
        spf = num("spf"),
        ct = num("ct"),
        "AP2 buffered audio stream setup"
    );

    let shk = stream0.get("shk").and_then(|v| v.as_data()).unwrap_or(&[]);
    let shk_arr = <[u8; 32]>::try_from(shk).map_err(|_| {
        RtspError::bad_request("a buffered stream without a 32-byte shk").report(
            ProtocolError::InvalidRtsp(format!(
                "buffered (type 103) SETUP: invalid shk length {}",
                shk.len()
            )),
        )
    })?;

    let (listener, audio_port) = bind_tcp(bind_addr_for(conn))?;
    tracing::info!(audio_port, "Buffered audio TCP port opened");

    let handler = conn.shared.handler.clone();
    let output_config = crate::raop::buffered_audio::OutputConfig {
        sample_rate: conn.shared.output_sample_rate,
        max_channels: conn.shared.output_max_channels,
        format: conn.shared.output_format,
        offload: conn.shared.offload.clone(),
        offset_ns: conn.shared.buffered_offset_ns,
    };

    let proc = crate::raop::buffered_audio::BufferedAudioProcessor {
        listener,
        peer: conn.remote_socket.ip(),
    };
    let stream = proc.start(shk_arr, output_config, handler);
    conn.shared.sessions.play(conn.id, Stream::Buffered(stream));

    stream_resp.insert("dataPort".into(), plist::Value::Integer(audio_port.into()));
    stream_resp.insert(
        "audioBufferSize".into(),
        plist::Value::Integer(i64::from(conn.shared.audio_buffer_size).into()),
    );
    Ok(())
}

#[cfg(feature = "ap2-core")]
/// Stream type 130 — remote-control data channel (acknowledged on PTP, opened on RC).
fn setup_stream_rc(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Result<(), RtspError> {
    tracing::info!("Remote Control stream setup (type 130)");

    // On PTP connections, type 130 is just acknowledged.
    // On RC connections, it sets up an encrypted data channel.
    if let Some(_seed) = stream0.get("seed").and_then(|v| v.as_unsigned_integer()) {
        let (data_listener, data_port) = bind_tcp(bind_addr_for(conn))?;
        tracing::debug!(data_port, "RC data channel opened");

        let peer = conn.remote_socket.ip();
        conn.tasks.push(crate::util::OwnedTask::spawn(async move {
            if let Some((_, addr)) = crate::net::accept_from(&data_listener, peer).await {
                tracing::info!(%addr, "RC data channel client connected");
            }
        }));

        stream_resp.insert("streamID".into(), plist::Value::Integer(1_i64.into()));
        stream_resp.insert("dataPort".into(), plist::Value::Integer(data_port.into()));
    } else {
        stream_resp.insert("streamID".into(), plist::Value::Integer(1_i64.into()));
    }
    Ok(())
}

#[cfg(feature = "video")]
/// Stream type 110 — screen-mirroring video. Derives the per-stream AES key/IV
/// (see [`crate::crypto::video_key`]) and spawns the video receiver.
fn setup_stream_video(
    conn: &mut RaopConnection,
    stream0: &plist::Dictionary,
    stream_resp: &mut plist::Dictionary,
) -> Result<(), RtspError> {
    let stream_connection_id = stream0
        .get("streamConnectionID")
        .and_then(plist_u64)
        .unwrap_or(0);
    tracing::info!(
        stream_type = 110,
        stream_connection_id,
        "AP2 video stream setup"
    );

    // Seed is either the audio AES key directly (Stage-3) or
    // eaesKey = SHA-512(fairplay_key ‖ ecdh) (full FairPlay + ECDH path).
    let (ekey, eiv) = if let Some(aeskey_audio) = conn
        .ekey
        .or_else(|| conn.shared.video_ekey.read().ok()?.as_ref().copied())
    {
        tracing::debug!("Video key: Stage 3 derivation from aeskey_audio");
        crate::crypto::video_key::derive_stream_key_iv(&aeskey_audio, stream_connection_id)
    } else if let Some(ecdh) = conn.ecdh.as_deref() {
        let fp_key = conn.shared.video_ekey.read().ok().and_then(|k| *k);
        if let Some(fp_key) = fp_key {
            let eaes_key = crate::crypto::video_key::derive_eaes_key(&fp_key, ecdh);
            let (key, iv) =
                crate::crypto::video_key::derive_stream_key_iv(&eaes_key, stream_connection_id);
            tracing::debug!("Video key: 3-step derivation (FairPlay + ECDH)");
            (key, iv)
        } else {
            // iOS 18+ with HomeKit pairing does not send ekey; derivation is unsolved
            // (see AP2-STATUS.md). Decline the stream rather than installing a zeroed key
            // and feeding the app undecryptable "garbage" NAL units.
            return Err(RtspError::unsupported(
                "video: no ekey (iOS 18 with HomeKit pairing): the key can't be derived",
            )
            .report(CryptoError::FairPlay(
                "video stream key derivation: no ekey (iOS 18 HomeKit unsupported)".into(),
            )));
        }
    } else {
        return Err(RtspError::bad_request("video: no encryption keys").report(
            CryptoError::FairPlay(
                "video stream key derivation: no encryption keys available".into(),
            ),
        ));
    };

    let cipher = crate::crypto::video_cipher::VideoCipher::new(&ekey, &eiv);

    let (listener, video_port) = bind_tcp(bind_addr_for(conn))?;
    tracing::info!(video_port, "Video stream TCP port opened");

    if let Some(vh) = &conn.shared.video_handler {
        let session = vh.video_init();
        conn.tasks.push(crate::util::OwnedTask::spawn(
            crate::raop::video_stream::run(listener, cipher, session),
        ));
    }

    stream_resp.insert("dataPort".into(), plist::Value::Integer(video_port.into()));
    Ok(())
}

#[cfg(feature = "ap2-core")]
/// AP2 RECORD: start buffered audio playout.
pub(crate) fn handle_record(
    _conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    tracing::debug!("RECORD");
    response.add_header("Audio-Latency", "0");
    Ok(None)
}

/// `command` to the buffered stream connection `conn` plays, if it plays one.
#[cfg(feature = "ap2-core")]
fn buffered(conn: &RaopConnection, command: crate::raop::buffered_audio::PlayoutCommand) {
    conn.shared.sessions.with(conn.id, |s| {
        if let Stream::Buffered(b) = s {
            b.command(command);
        }
    });
}

#[cfg(feature = "ap2-core")]
/// AP2 SETRATEANCHORTI: set PTP anchor for timed playout.
pub(crate) fn handle_set_rate_anchor_time(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    let dict = &plist_body(request)?;
    tracing::debug!(
        plist = plist_brief(&plist::Value::Dictionary(dict.clone())),
        "SETRATEANCHORTIME"
    );

    let rate = dict.get("rate").and_then(plist_u64).unwrap_or(0) as u32;
    let rtp_time = dict.get("rtpTime").and_then(plist_u64).unwrap_or(0) as u32;
    let net_secs = dict.get("networkTimeSecs").and_then(plist_u64).unwrap_or(0);
    let net_frac = dict.get("networkTimeFrac").and_then(plist_u64).unwrap_or(0);

    // The PTP clock the network time is on (absent: whichever master is heard).
    let timeline = dict
        .get("networkTimeTimelineID")
        .and_then(plist_u64)
        .unwrap_or(0);

    // Convert network time to nanoseconds (saturating: net_secs is peer-supplied).
    let frac_ns = ((net_frac >> 32) * 1_000_000_000) >> 32;
    let anchor_time_ns = net_secs
        .saturating_mul(1_000_000_000)
        .saturating_add(frac_ns);

    if rate & 1 != 0 {
        tracing::info!(
            rtp_time,
            anchor_time_ns,
            timeline = format!("{timeline:016x}"),
            "AP2 play start"
        );
    } else {
        tracing::info!("AP2 play pause");
    }

    buffered(
        conn,
        crate::raop::buffered_audio::PlayoutCommand::SetRate {
            anchor_rtp: rtp_time,
            anchor_time_ns,
            timeline,
            rate,
        },
    );

    Ok(None)
}

#[cfg(feature = "ap2-core")]
/// AP2 SETPEERS: receive PTP peer addresses (informational).
pub(crate) fn handle_set_peers(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
        && let Some(arr) = plist_val.as_array()
    {
        let peers: Vec<&str> = arr.iter().filter_map(|v| v.as_string()).collect();
        tracing::debug!(?peers, "SETPEERS");
    } else if let Some(data) = request.data()
        && let Ok(v) = plist::from_bytes::<plist::Value>(data)
    {
        tracing::debug!(plist = plist_brief(&v), "SETPEERSX");
    }
    Ok(None)
}

#[cfg(feature = "ap2-core")]
/// AP2 FLUSHBUFFERED: flush playout buffer up to sequence/timestamp.
pub(crate) fn handle_flush_buffered(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    let dict = plist_body(request)?;
    let get = |k: &str| dict.get(k).and_then(plist_u64);
    // flushFromSeq absent: an immediate flush
    let from_seq = get("flushFromSeq").map(|v| v as u32);
    // without flushUntilSeq: everything queued
    let until_seq = get("flushUntilSeq").map(|v| v as u32);
    tracing::debug!(
        plist = plist_brief(&plist::Value::Dictionary(dict.clone())),
        "FLUSHBUFFERED"
    );
    buffered(
        conn,
        crate::raop::buffered_audio::PlayoutCommand::Flush {
            from_seq,
            until_seq,
        },
    );
    Ok(None)
}

// --- AP2 POST sub-handlers ---

#[cfg(feature = "ap2-core")]
/// AP2 POST /feedback: empty response (required by protocol).
pub(crate) fn handle_feedback(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    // Only return stream info when audio is actually playing (matches shairport-sync)
    #[cfg(feature = "ap2-core")]
    if conn
        .shared
        .sessions
        .with(conn.id, |s| matches!(s, Stream::Buffered(_)))
        .unwrap_or(false)
    {
        let mut stream_dict = plist::Dictionary::new();
        stream_dict.insert("type".into(), plist::Value::Integer(103_i64.into()));
        stream_dict.insert("sr".into(), plist::Value::Real(44100.0));
        let mut resp_dict = plist::Dictionary::new();
        resp_dict.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream_dict)]),
        );
        return plist_reply(response, &resp_dict);
    }
    let _ = conn;
    Ok(None)
}

#[cfg(feature = "ap2-core")]
/// AP2 POST /command: forward binary plist commands to event channel.
pub(crate) fn handle_command(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
        && let Some(dict) = plist_val.as_dictionary()
    {
        let cmd_type = dict
            .get("type")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown");
        tracing::debug!(cmd_type, "POST /command");
        if cmd_type == "updateMRSupportedCommands" {
            conn.mr_supported.update(dict);
        }
    }
    Ok(None)
}

#[cfg(feature = "ap2-core")]
/// AP2 POST /audioMode: acknowledge audio mode change.
pub(crate) fn handle_audio_mode(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Handled {
    if let Some(data) = request.data()
        && let Ok(plist_val) = plist::from_bytes::<plist::Value>(data)
        && let Some(dict) = plist_val.as_dictionary()
    {
        let mode = dict
            .get("audioMode")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown");
        tracing::debug!(mode, "POST /audioMode");
    }
    Ok(None)
}
