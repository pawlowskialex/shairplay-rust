//! RTSP request dispatch — routes incoming requests to handlers.
//!
//! Uses a compile-time route table for clean, extensible routing.
//! Auth, Apple-Challenge, and logging are handled as middleware
//! before dispatch.

use crate::proto::digest;
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::handlers_ap1::{self as handlers, RaopConnection};
use crate::raop::sessions::Stream;

/// HTTP Digest authentication realm advertised and validated for RTSP auth.
const DIGEST_REALM: &str = "airplay";
/// Server identity advertised on every routed RTSP response.
const RTSP_SERVER_HEADER_VALUE: &str = "AirTunes/105.1";
#[cfg(feature = "ap2-core")]
use crate::raop::handlers_ap2;
#[cfg(feature = "hls")]
use crate::raop::handlers_hls;

/// Handler function signature — all RTSP handlers share this type: `Ok` with the body to send (`None`: none), or
/// why the request failed, answered in one place ([`dispatch`]).
pub(crate) type Handled = Result<Option<Vec<u8>>, RtspError>;
type Handler = fn(&mut RaopConnection, &HttpRequest, &mut HttpResponse) -> Handled;

/// A request that failed: the status it is answered with, what went wrong (for the log), whether the connection
/// closes after it, and the error the application hears of ([`AudioHandler::on_error`]), if it should.
///
/// [`AudioHandler::on_error`]: crate::AudioHandler::on_error
#[derive(Debug)]
pub(crate) struct RtspError {
    status: u16,
    detail: std::borrow::Cow<'static, str>,
    close: bool,
    report: Option<crate::error::ShairplayError>,
}

impl RtspError {
    fn new(status: u16, detail: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self {
            status,
            detail: detail.into(),
            close: false,
            report: None,
        }
    }

    /// 400: the request is malformed or lacks what the method needs.
    pub(crate) fn bad_request(detail: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::new(400, detail)
    }

    /// 415: a stream or format the receiver doesn't take.
    pub(crate) fn unsupported(detail: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::new(415, detail)
    }

    /// 455: the method isn't valid in the connection's state (a SETUP before its ANNOUNCE).
    pub(crate) fn not_now(detail: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::new(455, detail)
    }

    /// 470: the sender isn't authorized (a failed pairing).
    pub(crate) fn unauthorized(detail: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::new(470, detail)
    }

    /// 500: the receiver failed (a socket that wouldn't bind).
    pub(crate) fn internal(detail: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::new(500, detail)
    }

    /// The connection closes after the answer.
    pub(crate) fn closing(mut self) -> Self {
        self.close = true;
        self
    }

    /// The application hears of it (`on_error`).
    pub(crate) fn report(mut self, error: impl Into<crate::error::ShairplayError>) -> Self {
        self.report = Some(error.into());
        self
    }

    fn reason(&self) -> &'static str {
        match self.status {
            400 => "Bad Request",
            415 => "Unsupported Media Type",
            455 => "Method Not Valid in This State",
            470 => "Connection Authorization Required",
            _ => "Internal Server Error",
        }
    }
}

/// `option.ok_or(bad("what"))?`: a missing or malformed part of the request.
pub(crate) fn bad(detail: &'static str) -> RtspError {
    RtspError::bad_request(detail)
}

/// A binary plist body as a dictionary.
#[cfg(feature = "ap2-core")]
pub(crate) fn plist_body(request: &HttpRequest) -> Result<plist::Dictionary, RtspError> {
    let data = request.data().ok_or(bad("no body"))?;
    plist::from_bytes::<plist::Value>(data)
        .ok()
        .and_then(plist::Value::into_dictionary)
        .ok_or(bad("the body isn't a plist dictionary"))
}

/// Result of route resolution.
enum RouteResolution {
    /// Request is handled inline and has no body.
    NoBody,
    /// Request should be passed to a handler function.
    Handler(Handler),
}

/// A single route entry: HTTP method, URL path, handler function.
struct Route {
    method: &'static str,
    path: &'static str,
    handler: Handler,
}

// The compatibility route requires an exact origin-form target, unlike legacy
// routes that deliberately ignore a query string. Both ingress and dispatch use it.
#[cfg(feature = "pipewire-auth-setup-compat")]
const PIPEWIRE_AUTH_SETUP_ROUTE: Route = Route {
    method: "POST",
    path: "/auth-setup",
    handler: super::auth_setup::handle,
};

#[cfg(feature = "pipewire-auth-setup-compat")]
fn pipewire_auth_setup_route(
    conn: &RaopConnection,
    request: &HttpRequest,
) -> Option<&'static Route> {
    if !conn.shared.pipewire_auth_setup_compat {
        return None;
    }
    if conn.paired() {
        return None;
    }
    (request.method() == Some(PIPEWIRE_AUTH_SETUP_ROUTE.method)
        && request.url() == Some(PIPEWIRE_AUTH_SETUP_ROUTE.path))
    .then_some(&PIPEWIRE_AUTH_SETUP_ROUTE)
}

/// How long a request's body may take to arrive once its headers have.
const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How much body a request may carry, by what the route needs, decided when its headers arrive and before any of
/// the body is kept: pairing messages are a few hundred bytes, cover art (AirPlay 1's SET_PARAMETER) and now-playing
/// info with artwork (AirPlay 2's /command) up to about a megabyte, the rest small. Anyone may send any request:
/// 32 MiB for every route was 128 MiB for four connections.
pub(super) fn request_body_policy(
    conn: &RaopConnection,
    request: &HttpRequest,
) -> Result<crate::net::server::RequestBodyPolicy, crate::error::ProtocolError> {
    #[cfg(feature = "pipewire-auth-setup-compat")]
    if pipewire_auth_setup_route(conn, request).is_some() {
        return super::auth_setup::body_policy(request);
    }
    #[cfg(not(feature = "pipewire-auth-setup-compat"))]
    let _ = conn;
    let url = request.url().unwrap_or("");
    let path = url.split('?').next().unwrap_or(url);
    let max_bytes = match (request.method().unwrap_or(""), path) {
        ("POST", "/pair-setup" | "/pair-verify" | "/pair-pin-start" | "/pairings") => 4 * 1024,
        ("SET_PARAMETER", _) | ("POST", "/command") => 1024 * 1024,
        _ => 64 * 1024,
    };
    Ok(crate::net::server::RequestBodyPolicy {
        max_bytes,
        completion_timeout: Some(BODY_TIMEOUT),
    })
}

/// Static route table — checked in order, first match wins.
/// Feature-gated routes are included/excluded at compile time.
const ROUTES: &[Route] = &[
    // --- Authentication & DRM ---
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/pair-setup",
        handler: handlers_ap2::handle_pair_setup,
    },
    #[cfg(not(feature = "ap2-core"))]
    Route {
        method: "POST",
        path: "/pair-setup",
        handler: handlers::handle_pair_setup,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/pair-verify",
        handler: handlers_ap2::handle_pair_verify,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/pair-pin-start",
        handler: handlers_ap2::handle_pair_pin_start,
    },
    #[cfg(not(feature = "ap2-core"))]
    Route {
        method: "POST",
        path: "/pair-verify",
        handler: handlers::handle_pair_verify,
    },
    Route {
        method: "POST",
        path: "/fp-setup",
        handler: handlers::handle_fp_setup,
    },
    // --- AP2 POST endpoints ---
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/pairings",
        handler: handlers_ap2::handle_pairings,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/feedback",
        handler: handlers_ap2::handle_feedback,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/command",
        handler: handlers_ap2::handle_command,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "POST",
        path: "/audioMode",
        handler: handlers_ap2::handle_audio_mode,
    },
    // --- Standard RTSP methods ---
    Route {
        method: "OPTIONS",
        path: "*",
        handler: handlers::handle_options,
    },
    Route {
        method: "ANNOUNCE",
        path: "*",
        handler: handlers::handle_announce,
    },
    Route {
        method: "GET_PARAMETER",
        path: "*",
        handler: handlers::handle_get_parameter,
    },
    Route {
        method: "SET_PARAMETER",
        path: "*",
        handler: handlers::handle_set_parameter,
    },
    // --- AP2 RTSP methods ---
    #[cfg(feature = "ap2-core")]
    Route {
        method: "SETRATEANCHORTIME",
        path: "*",
        handler: handlers_ap2::handle_set_rate_anchor_time,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "SETPEERS",
        path: "*",
        handler: handlers_ap2::handle_set_peers,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "SETPEERSX",
        path: "*",
        handler: handlers_ap2::handle_set_peers,
    },
    #[cfg(feature = "ap2-core")]
    Route {
        method: "FLUSHBUFFERED",
        path: "*",
        handler: handlers_ap2::handle_flush_buffered,
    },
    // --- Info ---
    #[cfg(feature = "ap2-core")]
    Route {
        method: "GET",
        path: "/info",
        handler: handlers_ap2::handle_info,
    },
    // --- HLS (HTTP Live Streaming) ---
    #[cfg(feature = "hls")]
    Route {
        method: "GET",
        path: "/server-info",
        handler: handlers_hls::handle_server_info,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/play",
        handler: handlers_hls::handle_play,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "GET",
        path: "/playback-info",
        handler: handlers_hls::handle_playback_info,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/stop",
        handler: handlers_hls::handle_stop,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/scrub",
        handler: handlers_hls::handle_scrub,
    },
    #[cfg(feature = "hls")]
    Route {
        method: "POST",
        path: "/rate",
        handler: handlers_hls::handle_rate,
    },
];

/// What a sender may ask before pair-verify on a receiver with a PIN: what it is, and pairing with it.
#[cfg(feature = "ap2-core")]
fn open_before_pairing(method: &str, url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url);
    match method {
        "OPTIONS" => true,
        "GET" => path == "/info",
        "POST" => matches!(path, "/pair-setup" | "/pair-verify" | "/pair-pin-start"),
        _ => false,
    }
}

/// Apple-Challenges answered on one connection.
const MAX_CHALLENGES: u8 = 4;

/// Dispatch an RTSP request: authenticate, resolve route, call handler, build response.
pub(crate) fn dispatch(conn: &mut RaopConnection, request: &HttpRequest) -> HttpResponse {
    let method = request.method().unwrap_or("");
    let url = request.url().unwrap_or("");
    let cseq = request.header("CSeq").unwrap_or("0");

    let mut response = new_response(200, "OK", cseq);
    response.add_header("Apple-Jack-Status", "connected; type=analog");

    // --- Middleware: authentication ---
    if method != "OPTIONS" && !conn.shared.password.is_empty() {
        let authorization = request.header("Authorization");
        if !digest::is_valid(
            DIGEST_REALM,
            &conn.shared.password,
            &conn.nonce,
            method,
            url,
            authorization,
        ) {
            let auth_str = format!(
                "Digest realm=\"{}\", nonce=\"{}\"",
                DIGEST_REALM, conn.nonce
            );
            response = new_response(401, "Unauthorized", cseq);
            response.add_header("WWW-Authenticate", &auth_str);
            response.finish(None);
            return response;
        }
    }

    // --- Middleware: with a PIN, only paired controllers ---
    // A PIN means only controllers that paired with it play: everything but finding the receiver and pairing
    // with it waits for pair-verify. Without this a plaintext SETUP (its own stream key) or an AirPlay 1 ANNOUNCE
    // played on a receiver with a PIN.
    #[cfg(feature = "ap2-core")]
    if conn.shared.pin.is_some() && conn.controller().is_none() && !open_before_pairing(method, url)
    {
        tracing::info!(
            method,
            url,
            "refused before pair-verify (the receiver has a PIN)"
        );
        response = new_response(470, "Connection Authorization Required", cseq);
        response.finish(None);
        return response;
    }

    // --- Middleware: Apple-Challenge ---
    // Senders send it on OPTIONS (some on ANNOUNCE), once or twice a connection. Each answer is an RSA private-key
    // operation on the runtime's thread: not on any request, and not without end.
    if let Some(challenge) = request.header("Apple-Challenge")
        && matches!(method, "OPTIONS" | "ANNOUNCE")
        && conn.challenges < MAX_CHALLENGES
        && let Ok(sig) =
            conn.shared
                .rsakey
                .sign_challenge(challenge, &conn.local_addr, &conn.shared.hwaddr)
    {
        conn.challenges += 1;
        response.add_header("Apple-Response", &sig);
    }

    // --- Route resolution ---
    let handled = match resolve_handler(conn, request, method, url) {
        Some(RouteResolution::Handler(handler)) => handler(conn, request, &mut response),
        Some(RouteResolution::NoBody) => Ok(None),
        None => {
            tracing::debug!(method, url, "Unhandled RTSP request");
            response = new_response(404, "Not Found", cseq);
            response.finish(None);
            return response;
        }
    };
    match handled {
        Ok(body) => response.finish(body.as_deref()),
        Err(e) => {
            tracing::warn!(
                method,
                url,
                status = e.status,
                close = e.close,
                "{}",
                e.detail
            );
            if let Some(error) = &e.report {
                conn.shared.handler.on_error(error);
            }
            response = new_response(e.status, e.reason(), cseq);
            if e.close {
                response.add_header("Connection", "close");
                response.set_disconnect(true);
            }
            response.add_header("Content-Length", "0");
            response.finish(None);
        }
    }
    response
}

pub(super) fn new_response(status: u16, message: &str, cseq: &str) -> HttpResponse {
    let mut response = HttpResponse::new("RTSP/1.0", status, message);
    response.add_header("CSeq", cseq);
    response.add_header("Server", RTSP_SERVER_HEADER_VALUE);
    response
}

/// Resolve the handler for a request. Checks the route table first,
/// then falls back to special-case handlers for methods that need
/// custom routing logic (SETUP, RECORD, FLUSH, TEARDOWN).
fn resolve_handler(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    method: &str,
    url: &str,
) -> Option<RouteResolution> {
    #[cfg(feature = "pipewire-auth-setup-compat")]
    if let Some(route) = pipewire_auth_setup_route(conn, request) {
        return Some(RouteResolution::Handler(route.handler));
    }

    // 1. Check static route table (exact path or prefix match for query-string routes)
    for route in ROUTES {
        if route.method == method {
            let path = url.split('?').next().unwrap_or(url);
            if route.path == "*" || route.path == path {
                return Some(RouteResolution::Handler(route.handler));
            }
        }
    }

    // 2. Special-case methods with custom routing logic
    match method {
        "SETUP" => resolve_setup(conn, request).map(RouteResolution::Handler),
        "RECORD" => resolve_record(conn).map(RouteResolution::Handler),
        "FLUSH" => {
            handle_flush_inline(conn, request);
            Some(RouteResolution::NoBody)
        }
        "TEARDOWN" => Some(RouteResolution::Handler(handle_teardown as Handler)),
        _ => None,
    }
}

/// SETUP routing: AP1 (Transport header) vs AP2 (binary plist body).
fn resolve_setup(conn: &RaopConnection, request: &HttpRequest) -> Option<Handler> {
    #[cfg(feature = "ap2-core")]
    {
        let is_plist = request
            .data()
            .map(|d| d.starts_with(b"bplist"))
            .unwrap_or(false);
        if conn.paired() || is_plist {
            return Some(handlers_ap2::handle_setup);
        }
    }
    let _ = (conn, request); // suppress unused warnings without ap2
    Some(handlers::handle_setup)
}

/// RECORD routing: AP2 has its own handler.
fn resolve_record(conn: &RaopConnection) -> Option<Handler> {
    #[cfg(feature = "ap2-core")]
    if conn.paired() {
        return Some(handlers_ap2::handle_record);
    }
    let _ = conn;
    Some(handlers::handle_record)
}

/// FLUSH: RTP-Info `seq=N;rtptime=T`, to the stream the connection plays. AirPlay 1 flushes to the sequence number;
/// AirPlay 2 realtime drops what is before the RTP time (a Mac's: 0.3 s after each stream's SETUP, at its first
/// frame).
fn handle_flush_inline(conn: &mut RaopConnection, request: &HttpRequest) {
    let info = request.header("RTP-Info").unwrap_or("");
    let field = |name: &str| {
        info.split(';')
            .find_map(|p| p.trim().strip_prefix(name))
            .map(str::to_owned)
    };
    conn.shared.sessions.with(conn.id, |stream| match stream {
        Stream::Ap1(rtp) => {
            if let Some(seq) = field("seq=").and_then(|s| s.parse::<i32>().ok()) {
                rtp.flush(seq);
            }
        }
        #[cfg(feature = "ap2-core")]
        Stream::Realtime(r) => r.flush(field("rtptime=").and_then(|t| t.parse::<u32>().ok())),
        #[cfg(feature = "ap2-core")]
        Stream::Buffered(_) => {}
    });
}

/// TEARDOWN: the connection's stream stops, and the connection closes. An AirPlay 2 TEARDOWN whose plist lists
/// `streams` removes only those streams (iOS sends it when a realtime stream is paused, and SETs UP a new one on
/// resume): the audio stops, the session and its connection stay (closing it made the sender drop the speaker). A
/// TEARDOWN stops only its own connection's stream, not whoever plays.
fn handle_teardown(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Handled {
    #[cfg(feature = "ap2-core")]
    let streams_only = _request
        .data()
        .and_then(|d| plist::from_bytes::<plist::Value>(d).ok())
        .is_some_and(|v| v.as_dictionary().is_some_and(|d| d.contains_key("streams")));
    #[cfg(not(feature = "ap2-core"))]
    let streams_only = false;
    tracing::info!(streams_only, "TEARDOWN");
    if !streams_only {
        response.add_header("Connection", "close");
        response.set_disconnect(true);
    }
    conn.announced = None;
    conn.shared.sessions.stop(conn.id);
    Ok(None)
}
