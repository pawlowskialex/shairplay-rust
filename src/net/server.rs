//! Async TCP server with TLS-like encrypt/decrypt hooks for RTSP connections.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::{Instant, timeout_at};

use crate::error::{NetworkError, ProtocolError};
use crate::proto::http::{HttpRequest, HttpResponse, MAX_BODY_BYTES};

const MAX_ENCRYPTED_BUFFER_LEN: usize = 1024 * 1024;

#[cfg(test)]
mod ingestion_tests;

/// Ingestion constraints selected by the connection after request headers arrive.
pub(crate) struct RequestBodyPolicy {
    pub(crate) max_bytes: usize,
    pub(crate) completion_timeout: Option<Duration>,
}

impl Default for RequestBodyPolicy {
    fn default() -> Self {
        Self {
            max_bytes: MAX_BODY_BYTES,
            completion_timeout: None,
        }
    }
}

#[derive(Default)]
struct PendingRequest {
    request: HttpRequest,
    body_deadline: Option<Instant>,
    /// When its first bytes came: its headers have [`HEADER_TIMEOUT`] from then
    started: Option<Instant>,
}

/// Once a request's first bytes arrive, its headers have this long.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection without a session (nothing set up, not paired) may stay quiet.
const IDLE_WITHOUT_SESSION: Duration = Duration::from_secs(30);

/// A running connection, as the accept loop sees it: when it came, whether it holds a session, and how to end it
/// when every slot is taken and a new sender comes.
#[derive(Default)]
struct Slot {
    session: std::sync::atomic::AtomicBool,
    evict: tokio::sync::Notify,
}

type Slots = Arc<std::sync::Mutex<Vec<Arc<Slot>>>>;

/// Every slot is taken: end the oldest connection without a session, if there is one. Idle or half-sent
/// connections can't keep senders out; ones that play or are paired stay.
fn evict_one(slots: &Slots) -> bool {
    let Ok(slots) = slots.lock() else {
        return false;
    };
    match slots
        .iter()
        .find(|s| !s.session.load(std::sync::atomic::Ordering::Relaxed))
    {
        Some(slot) => {
            slot.evict.notify_one();
            true
        }
        None => false,
    }
}

impl PendingRequest {
    fn add_data(
        &mut self,
        handler: &dyn ConnectionHandler,
        data: &[u8],
    ) -> Result<(), ProtocolError> {
        self.started.get_or_insert_with(Instant::now);
        self.request.add_data_with_body_limit(data, |headers| {
            let policy = handler.request_body_policy(headers)?;
            self.body_deadline = policy
                .completion_timeout
                .map(|timeout| Instant::now() + timeout);
            Ok(policy.max_bytes)
        })?;
        if self.request.is_complete() {
            self.body_deadline = None;
        }
        Ok(())
    }
}

async fn write_bad_request_and_close<S: AsyncWrite + Unpin>(
    stream: &mut S,
    handler: Option<&mut dyn ConnectionHandler>,
) {
    let mut response = HttpResponse::new("RTSP/1.0", 400, "Bad Request");
    response.add_header("Connection", "close");
    response.finish(None);
    let wire_out = match handler {
        Some(handler) if handler.is_encrypted() => handler.encrypt_outgoing(response.get_data()),
        _ => response.get_data().to_vec(),
    };
    let _ = stream.write_all(&wire_out).await;
    let _ = stream.shutdown().await;
}

/// Controls how the server binds to network addresses.
///
/// # Examples
/// ```
/// use shairplay::BindConfig;
/// use std::net::IpAddr;
///
/// // Bind to all interfaces (default)
/// let config = BindConfig::default();
///
/// // Bind to a specific IPv4 address
/// let config = BindConfig::new().addrs(["192.168.1.100".parse().unwrap()]);
///
/// // Bind to specific IPv4 + IPv6
/// let config = BindConfig::new()
///     .addrs(["192.168.1.100".parse().unwrap(), "fd00::1".parse().unwrap()]);
///
/// // Bind to a specific port
/// let config = BindConfig::new().port(7000);
/// ```
/// Default RTSP listening port for AirPlay receivers.
pub(crate) const DEFAULT_RTSP_PORT: u16 = 5000;

#[derive(Debug, Clone)]
pub struct BindConfig {
    /// IP addresses to bind to. Empty = bind to all interfaces (0.0.0.0 + \[::\]).
    pub bind_addrs: Vec<IpAddr>,
    /// Port number. Used as starting port for auto-sensing, or exact port if `auto_port` is false.
    pub port: u16,
    /// If true (default), try incrementing ports if the requested port is busy.
    pub auto_port: bool,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            bind_addrs: Vec::new(),
            port: DEFAULT_RTSP_PORT,
            auto_port: true,
        }
    }
}

impl BindConfig {
    /// Create a new default bind configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set specific addresses to bind to. Replaces any previous addresses.
    pub fn addrs(mut self, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.bind_addrs = addrs.into_iter().collect();
        self
    }

    /// Set the port number.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Disable port auto-sensing (fail if exact port is unavailable).
    pub fn exact_port(mut self) -> Self {
        self.auto_port = false;
        self
    }
}

/// Callback trait for HTTP/RTSP connection lifecycle. Equivalent to httpd_callbacks_t.
pub(crate) trait HttpdCallbacks: Send + Sync + 'static {
    /// Called when a new TCP connection is accepted. Return a handler or None to reject.
    ///
    /// Takes `Arc<Self>` so the implementation can hand each connection a cheap
    /// shared handle to server-wide state instead of deep-copying it per connection.
    fn conn_init(
        self: Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<Box<dyn ConnectionHandler>>;
}

/// Per-connection request handler. Equivalent to conn_request + conn_destroy.
pub(crate) trait ConnectionHandler: Send {
    /// Handle an HTTP/RTSP request and return the response.
    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse;

    /// Select bounds or reject header metadata before any request body is retained.
    /// Routing and authentication remain the handler's responsibility.
    fn request_body_policy(
        &self,
        _request: &HttpRequest,
    ) -> Result<RequestBodyPolicy, ProtocolError> {
        Ok(RequestBodyPolicy::default())
    }

    /// Whether the connection holds a session (set something up, or is paired): one that doesn't is closed when
    /// quiet for [`IDLE_WITHOUT_SESSION`], or first when every slot is taken.
    fn has_session(&self) -> bool {
        false
    }

    /// Decrypt incoming raw bytes. Returns decrypted data and bytes consumed.
    /// Default: passthrough (no encryption).
    fn decrypt_incoming(&mut self, data: &[u8]) -> Option<(Vec<u8>, usize)> {
        Some((data.to_vec(), data.len()))
    }

    /// Encrypt outgoing response bytes. Default: passthrough.
    fn encrypt_outgoing(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    /// Whether the connection is in encrypted mode.
    fn is_encrypted(&self) -> bool {
        false
    }

    /// A signal that closes the connection (another sender took over).
    fn close_signal(&self) -> Option<std::sync::Arc<tokio::sync::Notify>> {
        None
    }

    /// Called after a response is written. Activates pending encryption.
    fn after_response(&mut self) {}
}

/// Async TCP server supporting IPv4 and IPv6. Equivalent to httpd_t.
pub(crate) struct HttpServer {
    callbacks: Arc<dyn HttpdCallbacks>,
    max_connections: usize,
    shutdown_tx: Option<watch::Sender<bool>>,
    port: u16,
    running: bool,
    bind_config: BindConfig,
}

impl HttpServer {
    /// Create a new HTTP server with the given callbacks and connection limit.
    pub(crate) fn new(callbacks: Arc<dyn HttpdCallbacks>, max_connections: usize) -> Self {
        Self {
            callbacks,
            max_connections,
            shutdown_tx: None,
            port: 0,
            running: false,
            bind_config: BindConfig::default(),
        }
    }

    /// Set the bind configuration (addresses, port, auto-sensing).
    pub(crate) fn set_bind_config(&mut self, config: BindConfig) {
        self.bind_config = config;
    }

    /// Start listening. Returns the actual port (may differ if auto-sensing).
    pub(crate) async fn start(&mut self, port: u16) -> Result<u16, NetworkError> {
        if self.running {
            return Ok(self.port);
        }

        let bind_port = if port > 0 {
            port
        } else {
            self.bind_config.port
        };
        let auto_port = self.bind_config.auto_port;

        // Determine bind addresses
        let addrs: Vec<IpAddr> = if self.bind_config.bind_addrs.is_empty() {
            // Default: all IPv4 + all IPv6
            vec![
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
        } else {
            self.bind_config.bind_addrs.clone()
        };

        // Bind first listener (with optional port auto-sensing)
        let first = bind_listener(addrs[0], bind_port, auto_port).await?;
        let actual_port = first.local_addr()?.port();

        // Bind remaining listeners on the same port (no auto-sensing)
        let mut listeners = vec![first];
        for &addr in &addrs[1..] {
            match bind_listener(addr, actual_port, false).await {
                Ok(l) => listeners.push(l),
                Err(e) => tracing::warn!(%addr, "Failed to bind additional listener: {e}"),
            }
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        self.port = actual_port;
        self.running = true;

        let callbacks = self.callbacks.clone();
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let slots = Slots::default();

        for listener in listeners {
            if let Ok(addr) = listener.local_addr() {
                tracing::debug!(%addr, "Listener bound");
            }
            spawn_accept_loop(
                listener,
                callbacks.clone(),
                semaphore.clone(),
                slots.clone(),
                shutdown_rx.clone(),
            );
        }

        Ok(actual_port)
    }

    /// Whether the server is currently accepting connections.
    pub(crate) fn is_running(&self) -> bool {
        self.running
    }

    /// The actual port the server is listening on (after auto-sensing).
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Stop the server and close all listeners.
    pub(crate) async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.running = false;
    }
}

/// Try to bind a TCP listener, optionally auto-incrementing the port.
async fn bind_listener(
    addr: IpAddr,
    start_port: u16,
    auto_port: bool,
) -> Result<TcpListener, NetworkError> {
    let mut port = start_port;
    loop {
        match TcpListener::bind(SocketAddr::new(addr, port)).await {
            Ok(listener) => return Ok(listener),
            Err(_e) if auto_port && port < start_port.saturating_add(100) => {
                port += 1;
            }
            Err(e) => return Err(NetworkError::Io(e)),
        }
    }
}
/// Dispatch every complete request currently buffered and write its response.
async fn send_completed_responses<S: AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &mut dyn ConnectionHandler,
    pending: &mut PendingRequest,
) -> bool {
    while pending.request.is_complete() {
        let request = &mut pending.request;
        let method = request.method().unwrap_or("?").to_string();
        let url = request.url().unwrap_or("?").to_string();
        tracing::debug!(%method, %url, body_len = request.data().map_or(0, <[u8]>::len), "RTSP request");
        let response = handler.conn_request(request);
        let status = response.status_code();
        tracing::debug!(%method, %url, status, "RTSP response");
        let response_encrypted = handler.is_encrypted();
        let disconnect = response.get_disconnect();
        let wire_out = if response_encrypted {
            handler.encrypt_outgoing(response.get_data())
        } else {
            response.get_data().to_vec()
        };
        if wire_out.is_empty() {
            tracing::warn!("Response encryption produced no output");
            return false;
        }
        if stream.write_all(&wire_out).await.is_err() {
            return false;
        }
        handler.after_response();
        if disconnect {
            let _ = stream.shutdown().await;
            return false;
        }
        let leftover = request.take_leftover();
        *pending = PendingRequest::default();
        if !leftover.is_empty() && pending.add_data(handler, &leftover).is_err() {
            write_bad_request_and_close(stream, Some(handler)).await;
            return false;
        }
    }
    true
}

async fn add_request_data<S: AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &mut dyn ConnectionHandler,
    pending: &mut PendingRequest,
    data: &[u8],
) -> bool {
    if pending.add_data(handler, data).is_ok() {
        tracing::trace!(
            complete = pending.request.is_complete(),
            headers_complete = pending.request.headers_complete(),
            "Parsed request data"
        );
        return true;
    }
    tracing::warn!(data_len = data.len(), "HTTP parse error");
    write_bad_request_and_close(stream, Some(handler)).await;
    false
}

async fn ingest_encrypted_data<S: AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &mut dyn ConnectionHandler,
    request: &mut PendingRequest,
    raw_buf: &mut Vec<u8>,
    data: &[u8],
) -> bool {
    if data.len() > MAX_ENCRYPTED_BUFFER_LEN.saturating_sub(raw_buf.len()) {
        tracing::warn!("Encrypted buffer exceeded 1 MB, dropping connection");
        return false;
    }
    raw_buf.extend_from_slice(data);
    tracing::trace!(
        raw_len = raw_buf.len(),
        new_bytes = data.len(),
        "Read encrypted data"
    );
    let Some((plain, consumed)) = handler.decrypt_incoming(raw_buf) else {
        tracing::warn!(raw_len = raw_buf.len(), "Decryption failed");
        return false;
    };
    if consumed > raw_buf.len() {
        tracing::warn!(
            consumed,
            available = raw_buf.len(),
            "Decryptor reported invalid byte count"
        );
        return false;
    }
    tracing::trace!(plain_len = plain.len(), consumed, "Decrypted request data");
    raw_buf.drain(..consumed);
    plain.is_empty() || add_request_data(stream, handler, request, &plain).await
}

/// Drive one accepted connection until the peer closes or processing fails.
async fn process_connection<S>(
    mut stream: S,
    mut handler: Box<dyn ConnectionHandler>,
    remote: SocketAddr,
    slot: Arc<Slot>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    let mut request = PendingRequest::default();
    let mut raw_buf = Vec::new(); // accumulates encrypted data

    let mut last_activity = Instant::now();
    loop {
        if !send_completed_responses(&mut stream, handler.as_mut(), &mut request).await {
            break;
        }
        slot.session
            .store(handler.has_session(), std::sync::atomic::Ordering::Relaxed);
        // the one deadline that applies now: a request's headers, its body, or quiet without a session
        let deadline = match request.started {
            Some(t) if !request.request.headers_complete() => Some(t + HEADER_TIMEOUT),
            _ if request.body_deadline.is_some() => request.body_deadline,
            None if !handler.has_session() => Some(last_activity + IDLE_WITHOUT_SESSION),
            _ => None,
        };
        let close = handler.close_signal();
        let closed = async {
            match &close {
                Some(c) => c.notified().await,
                None => std::future::pending().await,
            }
        };
        let read = tokio::select! {
            r = async {
                if let Some(deadline) = deadline {
                    match timeout_at(deadline, stream.read(&mut buf)).await {
                        Ok(result) if Instant::now() < deadline => Some(result),
                        _ => {
                            tracing::info!(%remote, "Closing: too slow or quiet without a session");
                            None
                        }
                    }
                } else {
                    Some(stream.read(&mut buf).await)
                }
            } => r,
            _ = closed => {
                tracing::info!(%remote, "Closing: another sender took over");
                None
            }
            () = slot.evict.notified() => {
                tracing::info!(%remote, "Closing: every slot taken, and this connection holds no session");
                None
            }
        };
        last_activity = Instant::now();
        let Some(read) = read else { break };
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let accepted = if handler.is_encrypted() {
            ingest_encrypted_data(
                &mut stream,
                handler.as_mut(),
                &mut request,
                &mut raw_buf,
                &buf[..n],
            )
            .await
        } else {
            tracing::trace!(n, "Read plaintext data");
            add_request_data(&mut stream, handler.as_mut(), &mut request, &buf[..n]).await
        };
        if !accepted {
            break;
        }
    }
    tracing::info!(%remote, "Connection closed");
}

fn spawn_accept_loop(
    listener: TcpListener,
    callbacks: Arc<dyn HttpdCallbacks>,
    semaphore: Arc<Semaphore>,
    slots: Slots,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote) = match result {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    tracing::info!(%remote, "New connection");
                    crate::net::keepalive(&stream);
                    let local = match stream.local_addr() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let cb = callbacks.clone();
                    let semaphore = semaphore.clone();
                    let slots = slots.clone();
                    tokio::spawn(async move {
                        let permit = match semaphore.clone().try_acquire_owned() {
                            Ok(p) => p,
                            // full: one without a session makes room, if there is one
                            Err(_) if evict_one(&slots) => {
                                match tokio::time::timeout(Duration::from_secs(1), semaphore.acquire_owned()).await {
                                    Ok(Ok(p)) => p,
                                    _ => return,
                                }
                            }
                            Err(_) => {
                                tracing::warn!(%remote, "Max connections reached, all of them with a session");
                                return;
                            }
                        };
                        let _permit = permit;
                        let Some(handler) = cb.conn_init(local, remote) else {
                            return;
                        };
                        let slot = Arc::new(Slot::default());
                        if let Ok(mut s) = slots.lock() {
                            s.push(slot.clone());
                        }
                        process_connection(stream, handler, remote, slot.clone()).await;
                        if let Ok(mut s) = slots.lock() {
                            s.retain(|o| !Arc::ptr_eq(o, &slot));
                        }
                    });
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OkHandler {
        disconnect: bool,
    }
    impl ConnectionHandler for OkHandler {
        fn conn_request(&mut self, _req: &HttpRequest) -> HttpResponse {
            let mut resp = HttpResponse::new("RTSP/1.0", 200, "OK");
            resp.add_header("CSeq", "1");
            resp.set_disconnect(self.disconnect);
            resp.finish(None);
            resp
        }
    }

    #[tokio::test]
    async fn round_trips_a_request() {
        let (mut client, server) = tokio::io::duplex(4096);
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let task = tokio::spawn(process_connection(
            server,
            Box::new(OkHandler { disconnect: false }),
            remote,
            Arc::default(),
        ));

        client
            .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();

        let mut tmp = [0u8; 1024];
        let n = client.read(&mut tmp).await.unwrap();
        let resp = String::from_utf8_lossy(&tmp[..n]);
        assert!(
            resp.starts_with("RTSP/1.0 200"),
            "unexpected response: {resp:?}"
        );

        drop(client); // peer close → server loop ends cleanly
        task.await.unwrap();
    }

    /// Quiet without a session, or a request whose headers never end: the connection goes (four of them held
    /// every slot for good before).
    #[tokio::test(start_paused = true)]
    async fn quiet_or_slow_connections_without_a_session_close() {
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        for (bytes, limit) in [
            (&b""[..], IDLE_WITHOUT_SESSION),
            (&b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"[..], HEADER_TIMEOUT),
        ] {
            let (mut client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(process_connection(
                server,
                Box::new(OkHandler { disconnect: false }),
                remote,
                Arc::default(),
            ));
            client.write_all(bytes).await.unwrap();
            tokio::time::sleep(limit.saturating_sub(Duration::from_secs(1))).await;
            assert!(!task.is_finished());
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(task.is_finished(), "still open after {limit:?}");
        }
    }

    /// Every slot taken: a new connection ends one without a session and takes its place.
    #[tokio::test]
    async fn a_new_sender_takes_the_slot_of_a_connection_without_a_session() {
        struct Callbacks;
        impl HttpdCallbacks for Callbacks {
            fn conn_init(
                self: Arc<Self>,
                _local: SocketAddr,
                _remote: SocketAddr,
            ) -> Option<Box<dyn ConnectionHandler>> {
                Some(Box::new(OkHandler { disconnect: false }))
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_shutdown, receiver) = watch::channel(false);
        spawn_accept_loop(
            listener,
            Arc::new(Callbacks),
            Arc::new(Semaphore::new(1)),
            Slots::default(),
            receiver,
        );
        let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut sender = tokio::net::TcpStream::connect(address).await.unwrap();
        sender
            .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(3), sender.read(&mut tmp))
            .await
            .expect("the new sender got no answer")
            .unwrap();
        assert!(String::from_utf8_lossy(&tmp[..n]).starts_with("RTSP/1.0 200"));
        assert_eq!(
            idle.read(&mut tmp).await.unwrap(),
            0,
            "the idle one was closed"
        );
    }

    #[tokio::test]
    async fn closes_when_handler_sets_disconnect() {
        let (mut client, server) = tokio::io::duplex(4096);
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let task = tokio::spawn(process_connection(
            server,
            Box::new(OkHandler { disconnect: true }),
            remote,
            Arc::default(),
        ));

        client
            .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();

        let mut tmp = [0u8; 1024];
        assert!(
            client.read(&mut tmp).await.unwrap() > 0,
            "expected a response"
        );
        // Handler requested disconnect → server shuts the stream → client sees EOF.
        assert_eq!(
            client.read(&mut tmp).await.unwrap(),
            0,
            "server should have closed"
        );
        task.await.unwrap();
    }

    struct InvalidConsumptionHandler;

    impl ConnectionHandler for InvalidConsumptionHandler {
        fn conn_request(&mut self, _req: &HttpRequest) -> HttpResponse {
            unreachable!("invalid encrypted input must not reach request dispatch")
        }

        fn decrypt_incoming(&mut self, data: &[u8]) -> Option<(Vec<u8>, usize)> {
            Some((Vec::new(), data.len() + 1))
        }

        fn is_encrypted(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn rejects_invalid_decryptor_consumption_without_panicking() {
        let (mut client, server) = tokio::io::duplex(4096);
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let task = tokio::spawn(process_connection(
            server,
            Box::new(InvalidConsumptionHandler),
            remote,
            Arc::default(),
        ));

        client.write_all(b"encrypted").await.unwrap();
        drop(client);
        task.await.unwrap();
    }
}
