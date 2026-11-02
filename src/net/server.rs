//! Async TCP server for the RTSP connections: reading, request bodies within their limits, plain or encrypted
//! framing, answers off the runtime thread.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::{Instant, timeout_at};

use crate::error::{NetworkError, ProtocolError};
use crate::proto::http::{HttpRequest, HttpResponse, MAX_BODY_BYTES};

#[cfg(feature = "ap2-core")]
const MAX_ENCRYPTED_BUFFER_LEN: usize = 1024 * 1024;

/// How long a response may take to go out: a sender that stops reading doesn't hold the connection for good.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// How the connection's bytes are framed: plain, until a pairing turns on HAP's encryption (ChaCha20-Poly1305
/// frames, both ways, from the byte after the response that finished it).
enum Framing {
    Plain,
    #[cfg(feature = "ap2-core")]
    Encrypted {
        channel: Box<crate::crypto::chacha_transport::EncryptedChannel>,
        /// What came that isn't a whole frame yet
        raw: Vec<u8>,
    },
}

impl Framing {
    /// The plaintext in what was read: all of it, or with encryption the whole frames so far (the rest waits for
    /// more). `None`: a frame that doesn't decrypt, or more than [`MAX_ENCRYPTED_BUFFER_LEN`] waiting.
    fn open<'a>(&mut self, data: &'a [u8]) -> Option<std::borrow::Cow<'a, [u8]>> {
        match self {
            Framing::Plain => Some(data.into()),
            #[cfg(feature = "ap2-core")]
            Framing::Encrypted { channel, raw } => {
                if data.len() > MAX_ENCRYPTED_BUFFER_LEN.saturating_sub(raw.len()) {
                    tracing::warn!("Encrypted buffer exceeded 1 MB, dropping connection");
                    return None;
                }
                raw.extend_from_slice(data);
                let Ok((plain, consumed)) = channel.decrypt_ctx.decrypt(raw) else {
                    tracing::warn!(raw_len = raw.len(), "Decryption failed");
                    return None;
                };
                raw.drain(..consumed.min(raw.len()));
                Some(plain.into())
            }
        }
    }

    /// `data` as it goes on the wire. `None` (encryption failed): nothing may go out, the connection ends; plaintext
    /// on an encrypted connection would leak the response and desync the stream.
    fn seal(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Framing::Plain => Some(data.to_vec()),
            #[cfg(feature = "ap2-core")]
            Framing::Encrypted { channel, .. } => channel
                .encrypt_ctx
                .encrypt(data)
                .inspect_err(|e| tracing::warn!("Outgoing encryption failed: {e}"))
                .ok(),
        }
    }
}

/// What a handler answers a request with: the response, and whether the connection is encrypted from then on.
pub(crate) struct Reply {
    pub(crate) response: HttpResponse,
    /// A pairing finished with this response: the connection's bytes after it are encrypted with this channel.
    #[cfg(feature = "ap2-core")]
    pub(crate) encrypt: Option<crate::crypto::chacha_transport::EncryptedChannel>,
}

impl From<HttpResponse> for Reply {
    fn from(response: HttpResponse) -> Self {
        Reply {
            response,
            #[cfg(feature = "ap2-core")]
            encrypt: None,
        }
    }
}

/// `data` to the peer, within [`WRITE_TIMEOUT`].
async fn send<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> bool {
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(data)).await,
        Ok(Ok(()))
    )
}

/// Default RTSP listening port for AirPlay receivers.
pub(crate) const DEFAULT_RTSP_PORT: u16 = 5000;

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
pub(crate) trait ConnectionHandler: Send + 'static {
    /// Answer a complete request. Runs on the blocking pool, not the runtime's thread: answering may sign, decrypt
    /// and pair (RSA, SRP: up to a second on a small CPU), which would hold up every other connection and stream.
    fn request(&mut self, request: &HttpRequest) -> Reply;

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

    /// A signal that closes the connection (another sender took over, its pairing was removed, the server stops).
    fn close_signal(&self) -> Option<std::sync::Arc<tokio::sync::Notify>> {
        None
    }
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
/// One connection between reads: its handler (on the blocking pool while it answers), how its bytes are framed, and
/// the request coming in.
struct Connection {
    handler: Option<Box<dyn ConnectionHandler>>,
    framing: Framing,
    pending: PendingRequest,
}

impl Connection {
    fn new(handler: Box<dyn ConnectionHandler>) -> Self {
        Connection {
            handler: Some(handler),
            framing: Framing::Plain,
            pending: PendingRequest::default(),
        }
    }

    fn handler(&self) -> &dyn ConnectionHandler {
        self.handler
            .as_deref()
            .expect("the handler is back after each answer")
    }

    /// Bytes read, into the request coming in. False: the connection ends (a request refused on its headers is
    /// answered 400 first).
    async fn ingest<S: AsyncWrite + Unpin>(&mut self, stream: &mut S, data: &[u8]) -> bool {
        let Some(plain) = self.framing.open(data) else {
            return false;
        };
        tracing::trace!(n = plain.len(), "Read request data");
        self.add_plain(stream, &plain).await
    }

    async fn add_plain<S: AsyncWrite + Unpin>(&mut self, stream: &mut S, plain: &[u8]) -> bool {
        if plain.is_empty() {
            return true;
        }
        let handler = self
            .handler
            .as_deref()
            .expect("the handler is back after each answer");
        if self.pending.add_data(handler, plain).is_ok() {
            return true;
        }
        tracing::warn!(data_len = plain.len(), "HTTP parse error");
        let mut response = HttpResponse::new("RTSP/1.0", 400, "Bad Request");
        response.add_header("Connection", "close");
        response.finish(None);
        if let Some(wire) = self.framing.seal(response.get_data()) {
            let _ = send(stream, &wire).await;
        }
        let _ = stream.shutdown().await;
        false
    }

    /// Answer every complete request buffered, each on the blocking pool, and write the responses. False: the
    /// connection ends.
    async fn answer<S: AsyncWrite + Unpin>(&mut self, stream: &mut S) -> bool {
        while self.pending.request.is_complete() {
            let mut done = std::mem::take(&mut self.pending);
            let leftover = done.request.take_leftover();
            let method = done.request.method().unwrap_or("?").to_string();
            let url = done.request.url().unwrap_or("?").to_string();
            tracing::debug!(%method, %url, body_len = done.request.data().map_or(0, <[u8]>::len), "RTSP request");
            let Some(mut handler) = self.handler.take() else {
                return false;
            };
            let answered = tokio::task::spawn_blocking(move || {
                let reply = handler.request(&done.request);
                (handler, reply)
            })
            .await;
            let Ok((handler, reply)) = answered else {
                return false;
            };
            self.handler = Some(handler);
            let response = reply.response;
            tracing::debug!(%method, %url, status = response.status_code(), "RTSP response");
            let Some(wire) = self.framing.seal(response.get_data()) else {
                return false;
            };
            if !send(stream, &wire).await {
                return false;
            }
            #[cfg(feature = "ap2-core")]
            if let Some(channel) = reply.encrypt {
                tracing::info!("Encrypted RTSP transport activated");
                self.framing = Framing::Encrypted {
                    channel: Box::new(channel),
                    raw: Vec::new(),
                };
            }
            if response.get_disconnect() {
                let _ = stream.shutdown().await;
                return false;
            }
            if !self.add_plain(stream, &leftover).await {
                return false;
            }
        }
        true
    }
}

/// Drive one accepted connection until the peer closes or processing fails.
async fn process_connection<S>(
    stream: S,
    handler: Box<dyn ConnectionHandler>,
    remote: SocketAddr,
    slot: Arc<Slot>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_connection(stream, Connection::new(handler), remote, slot).await;
}

async fn run_connection<S>(mut stream: S, mut conn: Connection, remote: SocketAddr, slot: Arc<Slot>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    let mut last_activity = Instant::now();
    loop {
        if !conn.answer(&mut stream).await {
            break;
        }
        let has_session = conn.handler().has_session();
        slot.session
            .store(has_session, std::sync::atomic::Ordering::Relaxed);
        // the one deadline that applies now: a request's headers, its body, or quiet without a session
        let request = &conn.pending;
        let deadline = match request.started {
            Some(t) if !request.request.headers_complete() => Some(t + HEADER_TIMEOUT),
            _ if request.body_deadline.is_some() => request.body_deadline,
            None if !has_session => Some(last_activity + IDLE_WITHOUT_SESSION),
            _ => None,
        };
        let close = conn.handler().close_signal();
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
                tracing::info!(%remote, "Closing: another sender took over, its pairing went, or the server stops");
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
        if !conn.ingest(&mut stream, &buf[..n]).await {
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
        fn request(&mut self, _req: &HttpRequest) -> Reply {
            let mut resp = HttpResponse::new("RTSP/1.0", 200, "OK");
            resp.add_header("CSeq", "1");
            resp.set_disconnect(self.disconnect);
            resp.finish(None);
            resp.into()
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

    /// Answers after `delay` with `body`.
    struct SlowHandler {
        delay: Duration,
        body: usize,
    }
    impl ConnectionHandler for SlowHandler {
        fn request(&mut self, _req: &HttpRequest) -> Reply {
            std::thread::sleep(self.delay);
            let mut resp = HttpResponse::new("RTSP/1.0", 200, "OK");
            resp.finish(Some(&vec![b'x'; self.body]));
            resp.into()
        }
    }

    /// A slow answer (RSA, SRP on a small CPU) doesn't hold the runtime's thread: another connection is answered
    /// meanwhile, on the same current-thread runtime.
    #[tokio::test]
    async fn a_slow_answer_does_not_hold_up_other_connections() {
        let remote: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let (mut slow, server) = tokio::io::duplex(4096);
        let slow_task = tokio::spawn(process_connection(
            server,
            Box::new(SlowHandler {
                delay: Duration::from_millis(800),
                body: 1,
            }),
            remote,
            Arc::default(),
        ));
        slow.write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (mut quick, server) = tokio::io::duplex(4096);
        let quick_task = tokio::spawn(process_connection(
            server,
            Box::new(OkHandler { disconnect: true }),
            remote,
            Arc::default(),
        ));
        let started = std::time::Instant::now();
        quick
            .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 256];
        assert!(quick.read(&mut tmp).await.unwrap() > 0);
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "waited for the slow one: {:?}",
            started.elapsed()
        );
        quick_task.await.unwrap();
        assert!(slow.read(&mut tmp).await.unwrap() > 0);
        drop(slow);
        slow_task.await.unwrap();
    }

    /// A peer that stops reading: the response's write gives up after WRITE_TIMEOUT and the connection ends.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_stops_reading_is_dropped() {
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(process_connection(
            server,
            Box::new(SlowHandler {
                delay: Duration::ZERO,
                body: 1 << 20,
            }),
            "127.0.0.1:5000".parse().unwrap(),
            Arc::default(),
        ));
        client
            .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(WRITE_TIMEOUT + Duration::from_secs(1), task)
            .await
            .expect("still writing")
            .unwrap();
    }
}
