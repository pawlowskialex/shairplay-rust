use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::DuplexStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{advance, timeout};

use super::*;

const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Observations {
    policies: AtomicUsize,
    dispatches: AtomicUsize,
    headers: Notify,
}

#[derive(Default)]
struct BoundedHandler {
    observed: Arc<Observations>,
}

impl ConnectionHandler for BoundedHandler {
    fn request_body_policy(
        &self,
        request: &HttpRequest,
    ) -> Result<RequestBodyPolicy, ProtocolError> {
        self.observed.policies.fetch_add(1, Ordering::SeqCst);
        self.observed.headers.notify_one();
        if request.url() != Some("/bounded") {
            return Ok(RequestBodyPolicy::default());
        }
        if request.header("content-length").is_none() {
            return Err(ProtocolError::InvalidRtsp("length required".into()));
        }
        Ok(RequestBodyPolicy {
            max_bytes: 33,
            completion_timeout: Some(BODY_TIMEOUT),
        })
    }

    fn request(&mut self, request: &HttpRequest) -> Reply {
        self.observed.dispatches.fetch_add(1, Ordering::SeqCst);
        let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
        response.add_header(
            "Body-Bytes",
            &request.data().map_or(0, <[u8]>::len).to_string(),
        );
        response.finish(None);
        response.into()
    }
}

fn spawn(handler: BoundedHandler) -> (DuplexStream, JoinHandle<()>) {
    spawn_connection(Connection::new(Box::new(handler)))
}

fn spawn_connection(conn: Connection) -> (DuplexStream, JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let task = tokio::spawn(run_connection(
        server,
        conn,
        "127.0.0.1:5000".parse().unwrap(),
        Arc::default(),
    ));
    (client, task)
}

async fn read_closed(client: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn headers(path: &str, size: usize) -> Vec<u8> {
    format!("POST {path} RTSP/1.0\r\nContent-Length: {size}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn rejects_from_headers_without_waiting_for_body_or_dispatching() {
    for metadata in [
        "",
        "Content-Length: 34\r\n",
        "Content-Length: nope\r\n",
        "Content-Length: 33\r\nContent-Length: 33\r\n",
        "Content-Length: 33\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let handler = BoundedHandler::default();
        let observed = handler.observed.clone();
        let (mut client, task) = spawn(handler);
        let wire = format!("POST /bounded RTSP/1.0\r\n{metadata}\r\n");
        client.write_all(wire.as_bytes()).await.unwrap();
        let response = String::from_utf8(read_closed(&mut client).await).unwrap();
        assert!(
            response.starts_with("RTSP/1.0 400"),
            "{metadata}: {response}"
        );
        assert!(response.contains("Connection: close\r\n"));
        assert_eq!(observed.dispatches.load(Ordering::SeqCst), 0);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn reapplies_policy_to_pipeline_and_preserves_larger_endpoint() {
    let handler = BoundedHandler::default();
    let observed = handler.observed.clone();
    let (mut client, task) = spawn(handler);
    let mut wire = headers("/bounded", 33);
    wire.extend_from_slice(&[1; 33]);
    wire.extend_from_slice(&headers("/large", 128 * 1024));
    wire.resize(wire.len() + 128 * 1024, 0x55);
    wire.extend_from_slice(&headers("/bounded", 34));
    // The invalid last request is already buffered; no further read is required to reject it.
    client.write_all(&wire).await.unwrap();
    let response = String::from_utf8(read_closed(&mut client).await).unwrap();
    assert_eq!(response.matches("RTSP/1.0 200").count(), 2);
    assert_eq!(response.matches("RTSP/1.0 400").count(), 1);
    assert!(response.contains("Body-Bytes: 33\r\n"));
    assert!(response.contains("Body-Bytes: 131072\r\n"));
    assert_eq!(observed.policies.load(Ordering::SeqCst), 3);
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 2);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn absolute_body_deadline_does_not_slide_and_starts_after_headers() {
    let handler = BoundedHandler::default();
    let observed = handler.observed.clone();
    let (mut client, task) = spawn(handler);
    client.write_all(b"POST /bounded R").await.unwrap();
    advance(BODY_TIMEOUT * 2).await;
    assert!(!task.is_finished());
    assert_eq!(observed.policies.load(Ordering::SeqCst), 0);
    client
        .write_all(b"TSP/1.0\r\nContent-Length: 33\r\n\r\n")
        .await
        .unwrap();
    observed.headers.notified().await;
    for _ in 0..4 {
        advance(Duration::from_secs(1)).await;
        client.write_all(b"x").await.unwrap();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
    }
    advance(Duration::from_secs(1)).await;
    assert!(read_closed(&mut client).await.is_empty());
    task.await.unwrap();
    assert_eq!(observed.policies.load(Ordering::SeqCst), 1);
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn completed_body_clears_deadline_and_next_request_gets_its_own() {
    let handler = BoundedHandler::default();
    let observed = handler.observed.clone();
    let mut conn = Connection::new(Box::new(handler));
    let (mut client, mut server) = tokio::io::duplex(1024);
    assert!(conn.ingest(&mut server, &headers("/bounded", 33)).await);
    let first_deadline = conn.pending.body_deadline.unwrap();
    advance(Duration::from_secs(4)).await;
    assert!(conn.ingest(&mut server, &[1; 33]).await);
    assert!(conn.pending.body_deadline.is_none());
    let accepted = conn.answer(&mut server).await;
    assert!(accepted);
    assert!(conn.ingest(&mut server, &headers("/bounded", 33)).await);
    assert_eq!(
        conn.pending.body_deadline.unwrap(),
        first_deadline + Duration::from_secs(4)
    );
    assert_eq!(observed.policies.load(Ordering::SeqCst), 2);
    let mut response = [0; 128];
    assert!(client.read(&mut response).await.unwrap() > 0);
}

struct BoundedCallbacks(Arc<Observations>);

impl HttpdCallbacks for BoundedCallbacks {
    fn conn_init(
        self: Arc<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
    ) -> Option<Box<dyn ConnectionHandler>> {
        Some(Box::new(BoundedHandler {
            observed: self.0.clone(),
        }))
    }
}

#[tokio::test]
async fn deadline_releases_real_tcp_client_slot() {
    let observed = Arc::new(Observations::default());
    let callbacks = Arc::new(BoundedCallbacks(observed.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let semaphore = Arc::new(Semaphore::new(1));
    let (shutdown, receiver) = watch::channel(false);
    spawn_accept_loop(
        listener,
        callbacks,
        semaphore.clone(),
        Slots::default(),
        receiver,
    );
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(&headers("/bounded", 33)).await.unwrap();
    observed.headers.notified().await;
    assert_eq!(semaphore.available_permits(), 0);
    // Real TCP readiness is driven by the OS, not Tokio's virtual test clock.
    let mut response = Vec::new();
    timeout(
        BODY_TIMEOUT + TEST_TIMEOUT,
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.is_empty());
    assert_eq!(semaphore.available_permits(), 1);
    let mut next = tokio::net::TcpStream::connect(address).await.unwrap();
    next.write_all(b"OPTIONS * RTSP/1.0\r\n\r\n").await.unwrap();
    next.shutdown().await.unwrap();
    assert!(read_closed(&mut next).await.starts_with(b"RTSP/1.0 200"));
    shutdown.send(true).unwrap();
}

#[cfg(feature = "ap2-core")]
#[test]
fn encrypted_buffer_limit_is_checked_before_copying() {
    let (_, framing, _) = encrypted_pair();
    let Framing::Encrypted { channel, .. } = framing else {
        unreachable!()
    };
    let mut framing = Framing::Encrypted {
        channel,
        raw: vec![0; MAX_ENCRYPTED_BUFFER_LEN],
    };
    assert!(framing.open(b"x").is_none());
    let Framing::Encrypted { raw, .. } = framing else {
        unreachable!()
    };
    assert_eq!(raw.len(), MAX_ENCRYPTED_BUFFER_LEN);
}

/// A connection already encrypted with a control channel from a fixed secret, and the peer's side of it.
#[cfg(feature = "ap2-core")]
fn encrypted_pair() -> (
    Arc<Observations>,
    Framing,
    crate::crypto::chacha_transport::EncryptedChannel,
) {
    use crate::crypto::chacha_transport::EncryptedChannel;
    let secret = [42; 32];
    let framing = Framing::Encrypted {
        channel: Box::new(EncryptedChannel::control(&secret).unwrap()),
        raw: Vec::new(),
    };
    let client = EncryptedChannel::new(
        &secret,
        "Control-Salt",
        "Control-Write-Encryption-Key",
        "Control-Salt",
        "Control-Read-Encryption-Key",
    )
    .unwrap();
    (Arc::default(), framing, client)
}

#[cfg(feature = "ap2-core")]
fn encrypted_connection(observed: &Arc<Observations>, framing: Framing) -> Connection {
    let mut conn = Connection::new(Box::new(BoundedHandler {
        observed: observed.clone(),
    }));
    conn.framing = framing;
    conn
}

#[cfg(feature = "ap2-core")]
#[tokio::test]
async fn encrypted_fragments_and_pipeline_use_identical_policy() {
    let (observed, framing, mut peer) = encrypted_pair();
    let mut conn = encrypted_connection(&observed, framing);
    let mut wire = headers("/bounded", 33);
    wire.extend_from_slice(&[1; 33]);
    wire.extend_from_slice(&headers("/large", 2048));
    wire.extend_from_slice(&[2; 2048]);
    wire.extend_from_slice(&headers("/bounded", 34));
    let ciphertext = peer.encrypt_ctx.encrypt(&wire).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let mut accepted = true;
    for byte in ciphertext {
        assert!(accepted);
        let ingested = conn.ingest(&mut server, &[byte]).await;
        if !ingested {
            accepted = false;
            break;
        }
        accepted = conn.answer(&mut server).await;
    }
    assert!(!accepted);
    drop(server);
    let response = read_closed(&mut client).await;
    let (plain, consumed) = peer.decrypt_ctx.decrypt(&response).unwrap();
    assert_eq!(consumed, response.len());
    let plain = String::from_utf8(plain).unwrap();
    assert_eq!(plain.matches("RTSP/1.0 200").count(), 2);
    assert_eq!(plain.matches("RTSP/1.0 400").count(), 1);
    assert!(plain.contains("Body-Bytes: 2048\r\n"));
    assert_eq!(observed.policies.load(Ordering::SeqCst), 3);
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "ap2-core")]
#[tokio::test(start_paused = true)]
async fn encrypted_partial_frame_cannot_extend_body_deadline() {
    let (observed, framing, mut peer) = encrypted_pair();
    let (mut client, task) = spawn_connection(encrypted_connection(&observed, framing));
    let wire = peer.encrypt_ctx.encrypt(&headers("/bounded", 33)).unwrap();
    client.write_all(&wire).await.unwrap();
    observed.headers.notified().await;
    advance(Duration::from_secs(4)).await;
    let body = peer.encrypt_ctx.encrypt(&[1; 33]).unwrap();
    client.write_all(&body[..body.len() - 1]).await.unwrap();
    tokio::task::yield_now().await;
    advance(Duration::from_secs(1)).await;
    assert!(read_closed(&mut client).await.is_empty());
    task.await.unwrap();
    assert_eq!(observed.dispatches.load(Ordering::SeqCst), 0);
}
