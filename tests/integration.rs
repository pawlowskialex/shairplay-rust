//! Integration tests: start a real RaopServer, connect via TCP, exercise the RTSP protocol.
//! Tests are serialized to avoid mDNS registration conflicts.

use serial_test::serial;
use std::sync::{Arc, Mutex};
#[cfg(feature = "ap2-core")]
use tokio::io::BufReader;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer, SampleFormat, TrackMetadata};

#[path = "integration/auth_setup.rs"]
mod auth_setup;
#[cfg(feature = "ap2-core")]
#[path = "integration/streams.rs"]
mod streams;
#[allow(dead_code)]
mod support;

struct TestHandler {
    inits: Arc<Mutex<Vec<AudioFormat>>>,
    volumes: Arc<Mutex<Vec<f32>>>,
    metadata: Arc<Mutex<Vec<TrackMetadata>>>,
    coverart: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct TestSession;

impl AudioHandler for TestHandler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        self.inits.lock().unwrap().push(format);
        Box::new(TestSession)
    }
    fn on_volume(&self, volume: f32) {
        self.volumes.lock().unwrap().push(volume);
    }
    fn volume(&self) -> Option<f32> {
        self.volumes.lock().unwrap().last().copied()
    }
    fn on_metadata(&self, metadata: &TrackMetadata) {
        self.metadata.lock().unwrap().push(metadata.clone());
    }
    fn on_coverart(&self, data: &[u8]) {
        self.coverart.lock().unwrap().push(data.to_vec());
    }
}

impl AudioSession for TestSession {
    fn audio(&mut self, _: shairplay::Samples<'_>, _: Option<u64>) {}
}

struct TestState {
    inits: Arc<Mutex<Vec<AudioFormat>>>,
    volumes: Arc<Mutex<Vec<f32>>>,
    metadata: Arc<Mutex<Vec<TrackMetadata>>>,
    coverart: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn start_server() -> (RaopServer, u16, TestState) {
    let inits = Arc::new(Mutex::new(Vec::new()));
    let volumes = Arc::new(Mutex::new(Vec::new()));
    let metadata = Arc::new(Mutex::new(Vec::new()));
    let coverart = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(TestHandler {
        inits: inits.clone(),
        volumes: volumes.clone(),
        metadata: metadata.clone(),
        coverart: coverart.clone(),
    });
    let mut server = RaopServer::builder()
        .mdns(false)
        .name("IntegrationTest")
        .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .port(0)
        .build(handler)
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    let state = TestState {
        inits,
        volumes,
        metadata,
        coverart,
    };
    (server, port, state)
}

async fn send_rtsp(stream: &mut TcpStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

fn assert_server_header(response: &str) {
    assert!(
        response
            .lines()
            .any(|line| line == "Server: AirTunes/105.1"),
        "missing or unexpected Server header in: {response}"
    );
}

fn empty_handler() -> Arc<TestHandler> {
    Arc::new(TestHandler {
        inits: Arc::new(Mutex::new(Vec::new())),
        volumes: Arc::new(Mutex::new(Vec::new())),
        metadata: Arc::new(Mutex::new(Vec::new())),
        coverart: Arc::new(Mutex::new(Vec::new())),
    })
}

#[cfg(feature = "ap2-core")]
fn ap1_builder(name: &str) -> shairplay::RaopServerBuilder {
    RaopServer::builder()
        .mdns(false)
        .name(name)
        .port(0)
        .mode(shairplay::AirPlayMode::AirPlay1)
}

#[cfg(not(feature = "ap2-core"))]
fn ap1_builder(name: &str) -> shairplay::RaopServerBuilder {
    RaopServer::builder().mdns(false).name(name).port(0)
}

fn raop_txt<'a>(info: &'a shairplay::AirPlayServiceInfo, key: &str) -> &'a str {
    info.raop_txt
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_str())
        .expect("expected RAOP TXT record")
}

fn assert_invalid_configuration(
    result: Result<RaopServer, shairplay::ShairplayError>,
    expected: &str,
) {
    match result {
        Err(shairplay::ShairplayError::Server(
            shairplay::error::ServerError::InvalidConfiguration(reason),
        )) => {
            assert_eq!(reason, expected)
        }
        Err(error) => panic!("expected invalid configuration, got {error:?}"),
        Ok(_) => panic!("expected invalid configuration, build succeeded"),
    }
}

#[test]
fn default_hwaddr_is_locally_administered_unicast() {
    let server = RaopServer::builder()
        .mdns(false)
        .name("RandomHwaddrTest")
        .port(0)
        .build(empty_handler())
        .unwrap();
    let info = server.service_info();
    let hwaddr_hex = info.raop_name.split('@').next().unwrap();
    let first_octet = u8::from_str_radix(&hwaddr_hex[..2], 16).unwrap();

    assert_eq!(hwaddr_hex.len(), 12);
    assert_eq!(first_octet & 0x02, 0x02);
    assert_eq!(first_octet & 0x01, 0);
}

#[test]
fn ap1_advertisement_defaults_and_custom_order_are_stable() {
    use shairplay::{Ap1Codec, Ap1Encryption};

    let default = ap1_builder("DefaultAdvertisement")
        .build(empty_handler())
        .unwrap();
    assert_eq!(raop_txt(&default.service_info(), "cn"), "0,1");
    assert_eq!(raop_txt(&default.service_info(), "et"), "0");

    #[cfg(feature = "fairplay")]
    let (encryption, expected_et) = (
        vec![
            Ap1Encryption::FairPlay,
            Ap1Encryption::None,
            Ap1Encryption::Rsa,
        ],
        "3,0,1",
    );
    #[cfg(not(feature = "fairplay"))]
    let (encryption, expected_et) = (vec![Ap1Encryption::None, Ap1Encryption::Rsa], "0,1");
    let custom = ap1_builder("CustomAdvertisement")
        .advertise_codecs([Ap1Codec::Alac, Ap1Codec::Pcm])
        .advertise_encryption(encryption)
        .build(empty_handler())
        .unwrap();
    assert_eq!(raop_txt(&custom.service_info(), "cn"), "1,0");
    assert_eq!(raop_txt(&custom.service_info(), "et"), expected_et);
}

#[test]
fn ap1_advertisement_rejects_empty_and_duplicate_values() {
    use shairplay::{Ap1Codec, Ap1Encryption};

    assert_invalid_configuration(
        ap1_builder("NoCodecs")
            .advertise_codecs(Vec::<Ap1Codec>::new())
            .build(empty_handler()),
        "AP1 codec advertisement cannot be empty",
    );
    assert_invalid_configuration(
        ap1_builder("DuplicateCodecs")
            .advertise_codecs([Ap1Codec::Pcm, Ap1Codec::Pcm])
            .build(empty_handler()),
        "AP1 codec advertisement contains duplicates",
    );
    assert_invalid_configuration(
        ap1_builder("NoEncryption")
            .advertise_encryption(Vec::<Ap1Encryption>::new())
            .build(empty_handler()),
        "AP1 encryption advertisement cannot be empty",
    );
    assert_invalid_configuration(
        ap1_builder("DuplicateEncryption")
            .advertise_encryption([Ap1Encryption::None, Ap1Encryption::None])
            .build(empty_handler()),
        "AP1 encryption advertisement contains duplicates",
    );
}

#[cfg(feature = "ap2-core")]
#[test]
fn ap2_rejects_ap1_advertisement_options_and_keeps_its_fixed_profile() {
    use shairplay::Ap1Codec;

    assert_invalid_configuration(
        RaopServer::builder()
            .mdns(false)
            .name("WrongMode")
            .port(0)
            .advertise_codecs([Ap1Codec::Pcm])
            .build(empty_handler()),
        "AP1 advertisement options require AirPlayMode::AirPlay1",
    );

    let server = RaopServer::builder()
        .mdns(false)
        .name("Ap2Advertisement")
        .port(0)
        .build(empty_handler())
        .unwrap();
    assert_eq!(raop_txt(&server.service_info(), "cn"), "0,1");
    assert_eq!(raop_txt(&server.service_info(), "et"), "0,3,5");
}

#[test]
fn builder_rejects_invalid_hwaddr_length() {
    let result = RaopServer::builder()
        .mdns(false)
        .name("InvalidHwaddrTest")
        .hwaddr(vec![0xAA; 5])
        .build(empty_handler());

    assert!(matches!(
        result,
        Err(shairplay::ShairplayError::Server(
            shairplay::error::ServerError::InvalidHwAddr(5)
        ))
    ));
}

#[tokio::test]
#[serial]
async fn server_start_stop() {
    let (mut server, port, _) = start_server().await;
    assert!(server.is_running());
    assert!(port > 0);

    let info = server.service_info();
    assert_eq!(info.port, port);
    assert_eq!(info.airplay_name, "IntegrationTest");
    assert_eq!(
        info.raop_txt
            .iter()
            .find(|(k, _)| k == "cn")
            .map(|(_, v)| v.as_str()),
        Some("0,1")
    );

    server.stop().await;
    assert!(!server.is_running());
}

#[tokio::test]
#[serial]
async fn tcp_connect_and_options() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let resp = send_rtsp(&mut stream, "OPTIONS * HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;

    assert!(resp.contains("RTSP/1.0 200 OK"), "got: {resp}");
    assert!(resp.contains("CSeq: 1"));
    assert_server_header(&resp);
    assert!(resp.contains("Public:"));
    assert!(resp.contains("ANNOUNCE"));
    assert!(resp.contains("SETUP"));

    server.stop().await;
}

/// Apple-Challenge is answered on OPTIONS, a few times a connection: each answer is an RSA private-key operation.
#[tokio::test]
#[serial]
async fn apple_challenge_is_answered_on_options_a_few_times() {
    let (mut server, port, _) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let challenge = "Apple-Challenge: dGVzdHRlc3R0ZXN0dGVzdA==\r\n";
    let resp = send_rtsp(
        &mut stream,
        &format!("GET_PARAMETER * RTSP/1.0\r\nCSeq: 1\r\n{challenge}\r\n"),
    )
    .await;
    assert!(!resp.contains("Apple-Response"), "got: {resp}");
    for cseq in 2..8 {
        let resp = send_rtsp(
            &mut stream,
            &format!("OPTIONS * RTSP/1.0\r\nCSeq: {cseq}\r\n{challenge}\r\n"),
        )
        .await;
        assert_eq!(
            resp.contains("Apple-Response"),
            cseq < 6,
            "CSeq {cseq}: {resp}"
        );
    }
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn unknown_rtsp_method_returns_404() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let resp = send_rtsp(&mut stream, "BOGUS * RTSP/1.0\r\nCSeq: 7\r\n\r\n").await;

    assert!(resp.contains("RTSP/1.0 404 Not Found"), "got: {resp}");
    assert!(resp.contains("CSeq: 7"));
    assert_server_header(&resp);

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn ap1_record_returns_200() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let resp = send_rtsp(&mut stream, "RECORD /test RTSP/1.0\r\nCSeq: 8\r\n\r\n").await;

    assert!(resp.contains("RTSP/1.0 200 OK"), "got: {resp}");
    assert!(resp.contains("CSeq: 8"));
    // Parity with the AP2 RECORD response (clients expect this header).
    assert!(resp.contains("Audio-Latency: 0"), "got: {resp}");

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn ap1_unencrypted_l16_without_fmtp_initializes_audio() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let sdp = concat!(
        "v=0\r\n",
        "o=PipeWire 0 0 IN IP4 127.0.0.1\r\n",
        "s=AirTunes\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 0 RTP/AVP 96\r\n",
        "a=rtpmap:96 L16/44100/2\r\n",
    );
    let announce = format!(
        "ANNOUNCE rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    );
    let response = send_rtsp(&mut stream, &announce).await;
    assert!(response.contains("RTSP/1.0 200 OK"), "got: {response}");

    let response = send_rtsp(
        &mut stream,
        "SETUP rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=record\r\n\r\n",
    )
    .await;
    assert!(response.contains("RTSP/1.0 200 OK"), "got: {response}");
    assert!(
        response.contains("Transport: RTP/AVP/TCP"),
        "got: {response}"
    );

    {
        let inits = state.inits.lock().unwrap();
        assert_eq!(inits.len(), 1, "expected one initialized audio session");
        assert_eq!(inits[0].format, SampleFormat::F32);
        assert_eq!(inits[0].channels, 2);
        assert_eq!(inits[0].sample_rate, 44_100);
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn ap1_l16_rejects_iv_without_encryption_key() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let sdp = concat!(
        "v=0\r\n",
        "o=PipeWire 0 0 IN IP4 127.0.0.1\r\n",
        "s=AirTunes\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 0 RTP/AVP 96\r\n",
        "a=rtpmap:96 L16/44100/2\r\n",
        "a=aesiv:AAAAAAAAAAAAAAAAAAAAAA==\r\n",
    );
    let announce = format!(
        "ANNOUNCE rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    );
    let response = send_rtsp(&mut stream, &announce).await;
    assert!(
        response.contains("RTSP/1.0 400 Bad Request"),
        "got: {response}"
    );
    assert!(response.contains("Connection: close"), "got: {response}");

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte))
        .await
        .expect("server did not reject incomplete encryption negotiation")
        .unwrap();
    assert_eq!(read, 0, "expected the RTSP connection to close");
    assert!(state.inits.lock().unwrap().is_empty());

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn oversized_header_returns_400_and_closes_connection() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let request = format!(
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nX-Oversized: {}\r\n\r\n",
        "A".repeat(65 * 1024)
    );
    let resp = send_rtsp(&mut stream, &request).await;

    assert!(resp.contains("RTSP/1.0 400 Bad Request"), "got: {resp}");
    assert!(resp.contains("Connection: close"));

    server.stop().await;
}

/// Each route takes the body it needs, refused on its headers: every route took 32 MiB from anyone.
#[tokio::test]
#[serial]
async fn bodies_larger_than_the_route_needs_are_refused_on_their_headers() {
    let (mut server, port, _) = start_server().await;
    for req in [
        "POST /pair-setup RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 5000\r\n\r\n",
        "ANNOUNCE rtsp://x/1 RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: 33554432\r\n\r\n",
        // the default artwork limit, 8 MiB, and a byte
        "SET_PARAMETER rtsp://x/1 RTSP/1.0\r\nCSeq: 1\r\nContent-Type: image/jpeg\r\nContent-Length: 8388609\r\n\r\n",
    ] {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let resp = send_rtsp(&mut stream, req).await;
        assert!(resp.contains("RTSP/1.0 400 Bad Request"), "{req}: {resp}");
        assert!(resp.contains("Connection: close"));
    }
    server.stop().await;
}

/// Sends SET_PARAMETER announcing cover art of `len` bytes (and the art, if `send_art`), then OPTIONS
/// on the same connection; returns both responses' status lines.
async fn coverart_then_options(port: u16, len: usize, send_art: bool) -> (String, String) {
    let mut stream = tokio::io::BufReader::new(
        TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap(),
    );
    let head = format!(
        "SET_PARAMETER rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: 1\r\nContent-Type: image/jpeg\r\nContent-Length: {len}\r\n\r\n"
    );
    stream.get_mut().write_all(head.as_bytes()).await.unwrap();
    if send_art {
        stream
            .get_mut()
            .write_all(&vec![0xa5u8; len])
            .await
            .unwrap();
    }
    let first = read_status_and_headers(&mut stream).await;
    let _ = stream
        .get_mut()
        .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 2\r\n\r\n")
        .await;
    let second = read_status_and_headers(&mut stream).await;
    (first, second)
}

/// The status line of the next response, or "" at the end of the connection; its headers are read
/// and dropped (these responses have no body).
async fn read_status_and_headers(stream: &mut tokio::io::BufReader<TcpStream>) -> String {
    let mut status = String::new();
    if stream.read_line(&mut status).await.unwrap_or(0) == 0 {
        return String::new();
    }
    let mut line = String::new();
    while stream.read_line(&mut line).await.unwrap_or(0) > 2 {
        line.clear();
    }
    status.trim_end().to_string()
}

/// Cover art up to the artwork limit is taken and the connection goes on: the session a sender's
/// playback uses is not cut by its artwork. Above it, the request is refused and the connection
/// closed. The limit is the builder's, or 8 MiB, and at most 32 MiB.
#[tokio::test]
#[serial]
async fn coverart_up_to_the_artwork_limit_keeps_the_connection() {
    const MIB: usize = 1024 * 1024;
    for (limit, expected) in [
        (None, 8 * MIB),
        (Some(64 * 1024), 64 * 1024),
        (Some(usize::MAX), 32 * MIB),
    ] {
        let mut builder = RaopServer::builder()
            .mdns(false)
            .name("IntegrationTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0);
        if let Some(limit) = limit {
            builder = builder.max_artwork_size(limit);
        }
        let mut server = builder.build(empty_handler()).unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;

        let (art, options) = coverart_then_options(port, expected, true).await;
        assert_eq!(art, "RTSP/1.0 200 OK", "{limit:?}: {expected} bytes");
        assert_eq!(
            options, "RTSP/1.0 200 OK",
            "{limit:?}: OPTIONS after the art"
        );

        // refused on its headers: the art isn't sent (unread data at the close would reset the connection)
        let (art, options) = coverart_then_options(port, expected + 1, false).await;
        assert_eq!(
            art, "RTSP/1.0 400 Bad Request",
            "{limit:?}: {expected} + 1 bytes"
        );
        assert_eq!(options, "", "{limit:?}: the connection is closed");
        server.stop().await;
    }
}

#[tokio::test]
#[serial]
async fn pair_setup_returns_public_key() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // Send 32 bytes of dummy pair-setup data
    let body = [0x42u8; 32];
    let req = "POST /pair-setup HTTP/1.0\r\nCSeq: 1\r\nContent-Length: 32\r\nContent-Type: application/octet-stream\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("200 OK"), "got: {resp}");
    assert!(resp.contains("Content-Length: 32")); // Ed25519 public key = 32 bytes

    server.stop().await;
}

#[cfg(feature = "fairplay")]
#[tokio::test]
#[serial]
async fn fp_setup_returns_142_bytes() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // FairPlay setup: 16 bytes with version=3, mode=0
    let mut body = [0u8; 16];
    body[4] = 0x03; // version
    body[14] = 0x00; // mode
    let req = "POST /fp-setup HTTP/1.0\r\nCSeq: 1\r\nContent-Length: 16\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("200 OK"), "got: {resp}");
    assert!(resp.contains("Content-Length: 142")); // FairPlay setup response

    server.stop().await;
}

#[derive(Default)]
struct SessionEvents(Mutex<Vec<&'static str>>, std::sync::atomic::AtomicUsize);

impl AudioHandler for SessionEvents {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        Box::new(TestSession)
    }
    fn on_session_setup(&self, _addr: &str) {
        self.0.lock().unwrap().push("setup");
    }
    fn on_session_end(&self, _addr: &str) {
        self.0.lock().unwrap().push("end");
    }
    fn on_client_disconnected(&self, _addr: &str) {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SessionEvents {
    fn seen(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }

    /// The connection's end is noticed on the server's side, a moment after the client drops it.
    async fn wait_for(&self, expected: &[&str]) {
        for _ in 0..200 {
            if self.seen() == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(self.seen(), expected);
    }

    /// Waits until `n` connections have closed on the server's side.
    async fn wait_for_disconnects(&self, n: usize) {
        for _ in 0..200 {
            if self.1.load(std::sync::atomic::Ordering::SeqCst) >= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("{n} connections did not close");
    }
}

fn announce(sdp: &str) -> String {
    format!(
        "ANNOUNCE rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    )
}

async fn start_session_server() -> (RaopServer, u16, Arc<SessionEvents>) {
    let events = Arc::new(SessionEvents::default());
    let mut server = RaopServer::builder()
        .mdns(false)
        .name("IntegrationTest")
        .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .port(0)
        .build(events.clone())
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    (server, port, events)
}

/// A probe is no session; an ANNOUNCE starts one, once, and its connection's end ends it.
#[tokio::test]
#[serial]
async fn session_hooks_follow_the_connection_that_announced() {
    let (mut server, port, events) = start_session_server().await;

    let mut probe = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let response = send_rtsp(&mut probe, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").await;
    assert!(response.contains("RTSP/1.0 200 OK"), "got: {response}");
    drop(probe);

    let sdp = concat!(
        "v=0\r\n",
        "o=Test 0 0 IN IP4 127.0.0.1\r\n",
        "s=AirTunes\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 0 RTP/AVP 96\r\n",
        "a=rtpmap:96 L16/44100/2\r\n",
    );
    let announce = announce(sdp);
    let mut sender = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    send_rtsp(&mut sender, &announce).await;
    send_rtsp(&mut sender, &announce).await;
    assert_eq!(events.seen(), ["setup"]);

    drop(sender);
    events.wait_for(&["setup", "end"]).await;
    server.stop().await;
}

/// An ANNOUNCE that is refused (here an audio format the receiver doesn't decode) starts no
/// session: neither hook is called, also when the connection then closes.
#[tokio::test]
#[serial]
async fn session_hooks_skip_a_refused_announce() {
    let (mut server, port, events) = start_session_server().await;
    let sdp = concat!(
        "v=0\r\n",
        "o=Test 0 0 IN IP4 127.0.0.1\r\n",
        "s=AirTunes\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 0 RTP/AVP 96\r\n",
        "a=rtpmap:96 NOTACODEC/44100/2\r\n",
    );
    let mut sender = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    send_rtsp(&mut sender, &announce(sdp)).await;
    let mut rest = [0u8; 64];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(2), sender.read(&mut rest));
    assert_eq!(
        closed.await.unwrap().unwrap(),
        0,
        "the server closes the connection"
    );

    events.wait_for_disconnects(1).await;
    assert!(events.seen().is_empty(), "{:?}", events.seen());
    server.stop().await;
}

/// iOS's remote-control-only connections are no session; a first SETUP without that flag is.
#[cfg(feature = "ap2-core")]
#[tokio::test]
#[serial]
async fn session_hooks_skip_remote_control_only_setups() {
    async fn setup(stream: &mut TcpStream, dict: plist::Dictionary) {
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        let head = format!(
            "SETUP rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut buf = [0u8; 4096];
        assert_ne!(stream.read(&mut buf).await.unwrap(), 0);
    }

    let (mut server, port, events) = start_session_server().await;

    let mut remote = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let mut rc_only = plist::Dictionary::new();
    rc_only.insert("isRemoteControlOnly".into(), plist::Value::Boolean(true));
    setup(&mut remote, rc_only).await;
    assert!(events.seen().is_empty());

    let mut sender = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    setup(&mut sender, plist::Dictionary::new()).await;
    assert_eq!(events.seen(), ["setup"]);

    drop(remote);
    drop(sender);
    events.wait_for(&["setup", "end"]).await;
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn unauthorized_without_password_header() {
    let mut server = RaopServer::builder()
        .mdns(false)
        .name("AuthTest")
        .hwaddr([0xAA; 6])
        .port(0)
        .password("secret123")
        .build(empty_handler())
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    // ANNOUNCE without Authorization header should get 401
    let resp = send_rtsp(&mut stream, "ANNOUNCE /test HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;

    assert!(resp.contains("401 Unauthorized"), "got: {resp}");
    assert_server_header(&resp);
    assert!(resp.contains("WWW-Authenticate: Digest"));

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn multiple_connections() {
    let (mut server, port, _) = start_server().await;

    // Open 3 concurrent connections
    let mut streams = Vec::new();
    for _ in 0..3 {
        streams.push(
            TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap(),
        );
    }

    // All should respond to OPTIONS
    for stream in &mut streams {
        let resp = send_rtsp(stream, "OPTIONS * HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;
        assert!(resp.contains("200 OK"));
    }

    server.stop().await;
}

/// The server's stop closes the connections it has, not only its listeners.
#[tokio::test]
#[serial]
async fn stop_closes_the_connections() {
    let (mut server, port, _) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let resp = send_rtsp(&mut stream, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").await;
    assert!(resp.contains("200 OK"));
    server.stop().await;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("the connection outlived the server")
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
#[serial]
async fn teardown_closes_connection() {
    let (mut server, port, _) = start_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let resp = send_rtsp(&mut stream, "TEARDOWN /test HTTP/1.0\r\nCSeq: 1\r\n\r\n").await;
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("Connection: close"));

    // Server must close the connection after TEARDOWN
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("server did not close connection within 2s")
        .unwrap();
    assert_eq!(n, 0, "expected EOF after TEARDOWN");

    server.stop().await;
}

/// A request that fails is answered with its status, not a 200 without a body: a volume that isn't a number and an
/// fp-setup of no known size (400), a SETUP before its ANNOUNCE (455, and the connection closes).
#[tokio::test]
#[serial]
async fn failures_are_answered_with_their_status() {
    let (mut server, port, _) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let body = "volume: nan\r\n";
    let resp = send_rtsp(
        &mut stream,
        &format!(
            "SET_PARAMETER rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: 1\r\nContent-Type: text/parameters\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(resp.starts_with("RTSP/1.0 400 Bad Request"), "got: {resp}");
    #[cfg(feature = "fairplay")]
    {
        let resp = send_rtsp(
            &mut stream,
            "POST /fp-setup RTSP/1.0\r\nCSeq: 2\r\nContent-Length: 3\r\n\r\nabc",
        )
        .await;
        assert!(resp.starts_with("RTSP/1.0 400 Bad Request"), "got: {resp}");
    }
    let resp = send_rtsp(
        &mut stream,
        "SETUP rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/UDP;unicast;mode=record\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("RTSP/1.0 455 Method Not Valid in This State"),
        "got: {resp}"
    );
    assert!(resp.contains("Connection: close"), "got: {resp}");
    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte))
        .await
        .expect("still open")
        .unwrap();
    assert_eq!(n, 0);
    server.stop().await;
}

// --- AirPlay 2 integration tests ---

#[cfg(feature = "ap2-core")]
mod ap2_tests {
    use super::*;
    use crate::support::{TlvType, TlvValues};

    #[tokio::test]
    #[serial]
    async fn ap2_transient_pair_setup() {
        let (mut server, port, _) = start_server().await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        // M1: State=1, Method=0, Flags=0x10 (transient)
        let mut m1_tlv = TlvValues::new();
        m1_tlv.add(TlvType::State as u8, &[1]);
        m1_tlv.add(TlvType::Method as u8, &[0]);
        m1_tlv.add(TlvType::Flags as u8, &[0x10]);
        let m1_body = m1_tlv.encode();

        let req = format!(
            "POST /pair-setup RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            m1_body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(&m1_body).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.contains("200 OK"),
            "M2 should be 200, got: {}",
            &resp[..resp.len().min(100)]
        );

        // Parse M2 response body — find the body after \r\n\r\n
        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body = &buf[header_end..n];
        let m2 = TlvValues::decode(body).expect("M2 should be valid TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b = m2.get_type(TlvType::PublicKey).unwrap();
        assert_eq!(salt.len(), 16);
        assert!(!pk_b.is_empty() && pk_b.len() <= 384);

        server.stop().await;
    }

    /// A POST of a TLV body on `stream`: the TLV that comes back.
    async fn post_tlv(stream: &mut TcpStream, path: &str, cseq: u32, tlv: &TlvValues) -> TlvValues {
        let body = tlv.encode();
        let req = format!(
            "POST {path} RTSP/1.0\r\nCSeq: {cseq}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        let header_end = head.find("\r\n\r\n").unwrap() + 4;
        TlvValues::decode(&buf[header_end..n]).unwrap()
    }

    fn transient_m1() -> TlvValues {
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1.add(TlvType::Flags as u8, &[0x10]);
        m1
    }

    fn wrong_m3() -> TlvValues {
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &[2]);
        m3.add(TlvType::Proof as u8, &[0; 64]);
        m3
    }

    /// A plist SETUP on `stream`: the response's status line.
    async fn setup_status(stream: &mut TcpStream, body: &[u8]) -> String {
        let req = format!(
            "SETUP rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        resp.lines().next().unwrap_or_default().to_string()
    }

    /// AirPlay 2 failures with their status: a SETUP that isn't a plist (400), a realtime stream of a shape the
    /// decoder doesn't take (415); a pair-verify M3 without its M1 gets HAP's error in the TLV.
    #[tokio::test]
    #[serial]
    async fn ap2_failures_are_answered_with_their_status() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        assert_eq!(
            setup_status(&mut stream, b"bplist00 not really").await,
            "RTSP/1.0 400 Bad Request"
        );
        let stream0 = plist::Dictionary::from_iter([
            ("type".to_string(), plist::Value::Integer(96.into())),
            ("spf".to_string(), plist::Value::Integer(1_000_000.into())),
            ("shk".to_string(), plist::Value::Data(vec![7; 32])),
        ]);
        let setup = plist::Dictionary::from_iter([(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream0)]),
        )]);
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &setup).unwrap();
        assert_eq!(
            setup_status(&mut stream, &body).await,
            "RTSP/1.0 415 Unsupported Media Type"
        );
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::EncryptedData as u8, &[0; 32]);
        let m4 = post_tlv(&mut stream, "/pair-verify", 2, &m3).await;
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert_eq!(m4.get_type(TlvType::Error), Some(&[2u8][..]));
        server.stop().await;
    }

    /// One proof per M1, and a limit on failed proofs: each is an online guess at the PIN.
    #[tokio::test]
    #[serial]
    async fn ap2_pair_setup_takes_one_proof_and_a_hundred_failures() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let error = |t: &TlvValues| t.get_type(TlvType::Error).map(<[u8]>::to_vec);
        let mut cseq = 1;
        for _ in 0..100 {
            let m2 = post_tlv(&mut stream, "/pair-setup", cseq, &transient_m1()).await;
            assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
            let m4 = post_tlv(&mut stream, "/pair-setup", cseq + 1, &wrong_m3()).await;
            assert_eq!(error(&m4), Some(vec![2]), "a wrong proof: Authentication");
            // the same M1's state is gone with the first proof
            let again = post_tlv(&mut stream, "/pair-setup", cseq + 2, &wrong_m3()).await;
            assert_eq!(error(&again), Some(vec![2]));
            cseq += 3;
        }
        let refused = post_tlv(&mut stream, "/pair-setup", cseq, &transient_m1()).await;
        assert_eq!(
            error(&refused),
            Some(vec![5]),
            "MaxTries after 100 failures"
        );
        server.stop().await;
    }

    /// With a PIN nothing plays or controls before pair-verify: a plaintext SETUP with its own stream key, or an
    /// AirPlay 1 ANNOUNCE, played before.
    #[tokio::test]
    #[serial]
    async fn ap2_with_a_pin_only_paired_controllers_get_past_pairing() {
        let mut server = RaopServer::builder()
            .mdns(false)
            .name("PinGateTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0)
            .pin("1234")
            .build(empty_handler())
            .unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let status = |r: &str| r.lines().next().unwrap_or("").to_string();
        let ok = send_rtsp(&mut stream, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").await;
        assert_eq!(status(&ok), "RTSP/1.0 200 OK");
        let info = send_rtsp(&mut stream, "GET /info RTSP/1.0\r\nCSeq: 2\r\n\r\n").await;
        assert_eq!(status(&info), "RTSP/1.0 200 OK");
        let sdp = "v=0\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n";
        for (cseq, req) in [
            (
                3,
                format!(
                    "ANNOUNCE rtsp://x/1 RTSP/1.0\r\nCSeq: 3\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                    sdp.len()
                ),
            ),
            (4, "SETUP rtsp://x/1 RTSP/1.0\r\nCSeq: 4\r\nTransport: RTP/AVP/UDP\r\n\r\n".into()),
            (5, "RECORD rtsp://x/1 RTSP/1.0\r\nCSeq: 5\r\n\r\n".into()),
            (
                6,
                "SET_PARAMETER rtsp://x/1 RTSP/1.0\r\nCSeq: 6\r\nContent-Type: text/parameters\r\nContent-Length: 14\r\n\r\nvolume: -10.0\n".into(),
            ),
        ] {
            let r = send_rtsp(&mut stream, &req).await;
            assert_eq!(
                status(&r),
                "RTSP/1.0 470 Connection Authorization Required",
                "CSeq {cseq}: {r}"
            );
        }
        server.stop().await;
    }

    #[test]
    fn ap2_pin_pairing_service_info_advertises_persistent_pairing() {
        let server = RaopServer::builder()
            .mdns(false)
            .name("PersistentPairingTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0)
            .pin("1234")
            .build(empty_handler())
            .unwrap();
        let info = server.service_info();
        let raop = |key: &str| {
            info.raop_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let airplay = |key: &str| {
            info.airplay_txt
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

        let expected_features = if cfg!(feature = "video") {
            "0x527FFEE6,0x0"
        } else {
            "0x405D4A00,0x14340"
        };
        assert_eq!(raop("ft"), Some(expected_features));
        assert_eq!(raop("sf"), Some("0x204"));
        assert_eq!(airplay("features"), Some(expected_features));
        assert_eq!(airplay("flags"), Some("0x204"));
    }

    #[tokio::test]
    #[serial]
    async fn ap2_pair_pin_start_is_acknowledged() {
        let handler = empty_handler();
        let mut server = RaopServer::builder()
            .mdns(false)
            .name("PinStartTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0)
            .pin("1234")
            .build(handler)
            .unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let resp = send_rtsp(
            &mut stream,
            "POST /pair-pin-start RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
        )
        .await;

        assert!(resp.contains("RTSP/1.0 200 OK"), "got: {resp}");
        assert!(resp.contains("CSeq: 1"), "got: {resp}");
        assert!(
            resp.contains("Content-Type: application/octet-stream"),
            "got: {resp}"
        );

        server.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn ap2_full_transient_pair_setup_m1_to_m4() {
        use num_bigint::BigUint;

        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        // Helper to send RTSP and read response
        async fn rtsp_post(
            stream: &mut TcpStream,
            url: &str,
            cseq: u32,
            body: &[u8],
        ) -> (String, Vec<u8>) {
            let req = format!(
                "POST {} RTSP/1.0\r\nCSeq: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                url,
                cseq,
                body.len()
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = stream.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            let header_end = resp.find("\r\n\r\n").map(|p| p + 4).unwrap_or(n);
            let resp_body = buf[header_end..n].to_vec();
            (resp, resp_body)
        }

        // M1: pair-verify (will fail but server accepts it)
        let mut m1_verify = TlvValues::new();
        m1_verify.add(TlvType::State as u8, &[1]);
        m1_verify.add(TlvType::PublicKey as u8, &[0u8; 32]); // dummy key
        let (resp, _) = rtsp_post(&mut stream, "/pair-verify", 0, &m1_verify.encode()).await;
        assert!(resp.contains("200"), "pair-verify M1");

        // M1: pair-setup (transient)
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1.add(TlvType::Flags as u8, &[0x10]);
        let (resp, body) = rtsp_post(&mut stream, "/pair-setup", 1, &m1.encode()).await;
        assert!(resp.contains("200"), "M2 response");
        let m2 = TlvValues::decode(&body).expect("M2 TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b_bytes = m2.get_type(TlvType::PublicKey).unwrap();

        // Client SRP: compute A and M1 proof
        let n_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
        let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        let g = BigUint::from(5u32);
        let mut a_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let big_a = g.modpow(&a, &n);

        let salt_bn = BigUint::from_bytes_be(salt);
        let big_b = BigUint::from_bytes_be(pk_b_bytes);

        // SRP math (simplified — same as pairing_homekit self-test)
        use sha2::{Digest, Sha512};
        fn to_bytes_be(n: &BigUint) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.is_empty() { vec![0] } else { b }
        }
        fn to_padded(n: &BigUint, len: usize) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.len() >= len {
                b
            } else {
                let mut p = vec![0u8; len - b.len()];
                p.extend(&b);
                p
            }
        }
        fn sha512(d: &[u8]) -> [u8; 64] {
            let mut h = Sha512::new();
            h.update(d);
            h.finalize().into()
        }
        fn h_nn_pad(n1: &BigUint, n2: &BigUint, l: usize) -> BigUint {
            let mut b = Vec::new();
            b.extend(&to_padded(n1, l));
            b.extend(&to_padded(n2, l));
            BigUint::from_bytes_be(&sha512(&b))
        }

        let k = h_nn_pad(&n, &g, 384);
        let u = h_nn_pad(&big_a, &big_b, 384);

        let mut h = Sha512::new();
        h.update(b"Pair-Setup");
        h.update(b":");
        h.update(b"3939");
        let ucp = h.finalize();
        let mut buf2 = Vec::new();
        buf2.extend(&to_bytes_be(&salt_bn));
        buf2.extend(&ucp);
        let x = BigUint::from_bytes_be(&sha512(&buf2));

        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = (&big_b + &n - &kgx) % &n;
        let big_s = base.modpow(&(&a + &u * &x), &n);
        let session_key = sha512(&to_bytes_be(&big_s));

        // Calculate M1 proof
        let h_n = sha512(&to_bytes_be(&n));
        let h_g = sha512(&to_bytes_be(&g));
        let mut h_xor = [0u8; 64];
        for i in 0..64 {
            h_xor[i] = h_n[i] ^ h_g[i];
        }
        let h_i = sha512(b"Pair-Setup");
        let mut h = Sha512::new();
        h.update(h_xor);
        h.update(h_i);
        h.update(to_bytes_be(&salt_bn));
        h.update(to_bytes_be(&big_a));
        h.update(to_bytes_be(&big_b));
        h.update(session_key);
        let client_m: [u8; 64] = h.finalize().into();

        // M3: send A + proof
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &to_bytes_be(&big_a));
        m3.add(TlvType::Proof as u8, &client_m);
        let (resp, body) = rtsp_post(&mut stream, "/pair-setup", 2, &m3.encode()).await;
        assert!(resp.contains("200"), "M4 response");

        // Verify M4: State=4, Proof present (no error)
        let m4 = TlvValues::decode(&body).expect("M4 TLV");
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert!(
            m4.get_type(TlvType::Proof).is_some(),
            "M4 should have server proof"
        );
        assert!(
            m4.get_type(TlvType::Error).is_none(),
            "M4 should not have error"
        );

        // Verify server proof
        let server_proof = m4.get_type(TlvType::Proof).unwrap();
        let mut h = Sha512::new();
        h.update(to_bytes_be(&big_a));
        h.update(client_m);
        h.update(session_key);
        let expected_hamk: [u8; 64] = h.finalize().into();
        assert_eq!(
            server_proof,
            &expected_hamk[..],
            "Server proof should match"
        );

        server.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn ap2_get_info_plist_correctness() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        let req = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);

        assert!(resp.contains("200 OK"), "GET /info should be 200 OK");
        assert!(
            resp.contains("Content-Type: application/x-apple-binary-plist"),
            "must return binary plist"
        );

        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body = &buf[header_end..n];

        let cursor = std::io::Cursor::new(body);
        let plist_val = plist::Value::from_reader(cursor).expect("body should be a valid plist");
        let dict = plist_val
            .as_dictionary()
            .expect("plist should be a dictionary");

        assert!(dict.contains_key("pi"), "should contain pairing_id (pi)");
        assert!(dict.contains_key("name"), "should contain name");
        assert!(dict.contains_key("macAddress"), "should contain macAddress");
        assert!(dict.contains_key("deviceID"), "should contain deviceID");

        let pi_val = dict.get("pi").unwrap().as_string().unwrap();
        let name_val = dict.get("name").unwrap().as_string().unwrap();
        let mac_val = dict.get("macAddress").unwrap().as_string().unwrap();

        assert_eq!(name_val, "IntegrationTest");
        assert_eq!(mac_val, "00:11:22:33:44:55");
        assert_eq!(pi_val.len(), 36);

        server.stop().await;
    }

    pub(super) async fn perform_transient_pairing(stream: &mut TcpStream) -> [u8; 64] {
        srp_pair(stream, "3939", true).await
    }

    /// pair-setup M1-M4 with `pin` (transient: the flag, else normal, M5 to follow): the SRP session key.
    async fn srp_pair(stream: &mut TcpStream, pin: &str, transient: bool) -> [u8; 64] {
        use num_bigint::BigUint;
        use sha2::{Digest, Sha512};

        // Helper to send RTSP and read response
        async fn rtsp_post(
            stream: &mut TcpStream,
            url: &str,
            cseq: u32,
            body: &[u8],
        ) -> (String, Vec<u8>) {
            let req = format!(
                "POST {} RTSP/1.0\r\nCSeq: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                url,
                cseq,
                body.len()
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = stream.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]).to_string();
            let header_end = resp.find("\r\n\r\n").map(|p| p + 4).unwrap_or(n);
            let resp_body = buf[header_end..n].to_vec();
            (resp, resp_body)
        }

        // M1: pair-verify (will fail but server accepts it)
        let mut m1_verify = TlvValues::new();
        m1_verify.add(TlvType::State as u8, &[1]);
        m1_verify.add(TlvType::PublicKey as u8, &[0u8; 32]); // dummy key
        let (resp, _) = rtsp_post(stream, "/pair-verify", 0, &m1_verify.encode()).await;
        assert!(resp.contains("200"), "pair-verify M1");

        // M1: pair-setup
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        if transient {
            m1.add(TlvType::Flags as u8, &[0x10]);
        }
        let (resp, body) = rtsp_post(stream, "/pair-setup", 1, &m1.encode()).await;
        assert!(resp.contains("200"), "M2 response");
        let m2 = TlvValues::decode(&body).expect("M2 TLV");
        assert_eq!(m2.get_type(TlvType::State), Some(&[2u8][..]));
        let salt = m2.get_type(TlvType::Salt).unwrap();
        let pk_b_bytes = m2.get_type(TlvType::PublicKey).unwrap();

        // Client SRP: compute A and M1 proof
        let n_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
        let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        let g = BigUint::from(5u32);
        let mut a_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        let big_a = g.modpow(&a, &n);

        let salt_bn = BigUint::from_bytes_be(salt);
        let big_b = BigUint::from_bytes_be(pk_b_bytes);

        // SRP math (simplified — same as pairing_homekit self-test)
        fn to_bytes_be(n: &BigUint) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.is_empty() { vec![0] } else { b }
        }
        fn to_padded(n: &BigUint, len: usize) -> Vec<u8> {
            let b = n.to_bytes_be();
            if b.len() >= len {
                b
            } else {
                let mut p = vec![0u8; len - b.len()];
                p.extend(&b);
                p
            }
        }
        fn sha512(d: &[u8]) -> [u8; 64] {
            let mut h = Sha512::new();
            h.update(d);
            h.finalize().into()
        }
        fn h_nn_pad(n1: &BigUint, n2: &BigUint, l: usize) -> BigUint {
            let mut b = Vec::new();
            b.extend(&to_padded(n1, l));
            b.extend(&to_padded(n2, l));
            BigUint::from_bytes_be(&sha512(&b))
        }

        let k = h_nn_pad(&n, &g, 384);
        let u = h_nn_pad(&big_a, &big_b, 384);

        let mut h = Sha512::new();
        h.update(b"Pair-Setup");
        h.update(b":");
        h.update(pin.as_bytes());
        let ucp = h.finalize();
        let mut buf2 = Vec::new();
        buf2.extend(&to_bytes_be(&salt_bn));
        buf2.extend(&ucp);
        let x = BigUint::from_bytes_be(&sha512(&buf2));

        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = (&big_b + &n - &kgx) % &n;
        let big_s = base.modpow(&(&a + &u * &x), &n);
        let session_key = sha512(&to_bytes_be(&big_s));

        // Calculate M1 proof
        let h_n = sha512(&to_bytes_be(&n));
        let h_g = sha512(&to_bytes_be(&g));
        let mut h_xor = [0u8; 64];
        for i in 0..64 {
            h_xor[i] = h_n[i] ^ h_g[i];
        }
        let h_i = sha512(b"Pair-Setup");
        let mut h = Sha512::new();
        h.update(h_xor);
        h.update(h_i);
        h.update(to_bytes_be(&salt_bn));
        h.update(to_bytes_be(&big_a));
        h.update(to_bytes_be(&big_b));
        h.update(session_key);
        let client_m: [u8; 64] = h.finalize().into();

        // M3: send A + proof
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::PublicKey as u8, &to_bytes_be(&big_a));
        m3.add(TlvType::Proof as u8, &client_m);
        let (resp, body) = rtsp_post(stream, "/pair-setup", 2, &m3.encode()).await;
        assert!(resp.contains("200"), "M4 response");

        // Verify M4: State=4, Proof present (no error)
        let m4 = TlvValues::decode(&body).expect("M4 TLV");
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert!(
            m4.get_type(TlvType::Proof).is_some(),
            "M4 should have server proof"
        );

        session_key
    }

    /// pair-setup M5 with controller `id` and its key `sk` after [`srp_pair`]: M6, decoded.
    async fn pair_m5(
        stream: &mut TcpStream,
        session_key: &[u8; 64],
        id: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> TlvValues {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use ed25519_dalek::Signer;
        let hkdf = |salt: &str, info: &str| {
            let mut out = [0u8; 32];
            hkdf::Hkdf::<sha2::Sha512>::new(Some(salt.as_bytes()), session_key)
                .expand(info.as_bytes(), &mut out)
                .unwrap();
            out
        };
        let device_x = hkdf(
            "Pair-Setup-Controller-Sign-Salt",
            "Pair-Setup-Controller-Sign-Info",
        );
        let pk = sk.verifying_key();
        let signed = [&device_x[..], id.as_bytes(), pk.as_bytes()].concat();
        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, id.as_bytes());
        inner.add(TlvType::PublicKey as u8, pk.as_bytes());
        inner.add(TlvType::Signature as u8, &sk.sign(&signed).to_bytes());
        let key = hkdf("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(b"PS-Msg05");
        let encrypted = chacha20poly1305::ChaCha20Poly1305::new((&key).into())
            .encrypt((&nonce).into(), inner.encode().as_slice())
            .unwrap();
        let mut m5 = TlvValues::new();
        m5.add(TlvType::State as u8, &[5]);
        m5.add(TlvType::EncryptedData as u8, &encrypted);
        post_tlv(stream, "/pair-setup", 5, &m5).await
    }

    /// The identifier the accessory gives in pair-setup's M6 (after [`srp_pair`]'s `session_key`).
    fn m6_accessory(session_key: &[u8; 64], m6: &TlvValues) -> String {
        use chacha20poly1305::aead::{Aead, KeyInit};
        let mut key = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha512>::new(Some(b"Pair-Setup-Encrypt-Salt"), session_key)
            .expand(b"Pair-Setup-Encrypt-Info", &mut key)
            .unwrap();
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(b"PS-Msg06");
        let inner = chacha20poly1305::ChaCha20Poly1305::new((&key).into())
            .decrypt(
                (&nonce).into(),
                m6.get_type(TlvType::EncryptedData).unwrap(),
            )
            .unwrap();
        String::from_utf8(
            TlvValues::decode(&inner)
                .unwrap()
                .get_type(TlvType::Identifier)
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    /// A PIN server with `store`.
    async fn pin_server(store: Arc<dyn shairplay::PairingStore>) -> (RaopServer, u16) {
        let mut server = RaopServer::builder()
            .mdns(false)
            .ptp(false)
            .name("PinPairing")
            .hwaddr([0x02, 0, 0, 0, 0, 0x20])
            .port(0)
            .pin("3939")
            .pairing_store(store)
            .build(empty_handler())
            .unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;
        (server, port)
    }

    /// A store with no room.
    struct Full;
    impl shairplay::PairingStore for Full {
        fn get(&self, _: &str) -> Option<[u8; 32]> {
            None
        }
        fn put(&self, _: &str, _: [u8; 32], _: bool) -> bool {
            false
        }
        fn remove(&self, _: &str) {}
        fn list(&self) -> Vec<(String, [u8; 32], bool)> {
            Vec::new()
        }
    }

    /// pair-setup's M5: a controller is stored as an admin; an identifier already paired with another key is
    /// refused (Authentication), and so is the pairing when the store has no room (MaxPeers): no M6 for a pairing
    /// that wasn't kept.
    #[tokio::test]
    #[serial]
    async fn ap2_pair_setup_m5_stores_refuses_a_taken_identifier_and_a_full_store() {
        use shairplay::{MemoryPairingStore, PairingStore};
        let store = Arc::new(MemoryPairingStore::default());
        let (mut server, port) = pin_server(store.clone()).await;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        let m6 = pair_m5(&mut stream, &key, "phone", &sk).await;
        assert_eq!(m6.get_type(TlvType::State), Some(&[6u8][..]));
        assert!(m6.get_type(TlvType::Error).is_none());
        // the identifier pair-verify gives later, the `pi`
        assert_eq!(m6_accessory(&key, &m6), pairing_id_on(port).await);
        assert_eq!(store.get("phone"), Some(*sk.verifying_key().as_bytes()));
        assert!(store.is_admin("phone"));

        // the same identifier, another key
        let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        let m6 = pair_m5(&mut stream, &key, "phone", &other).await;
        assert_eq!(m6.get_type(TlvType::Error), Some(&[2u8][..]));
        assert_eq!(store.get("phone"), Some(*sk.verifying_key().as_bytes()));
        server.stop().await;

        let (mut server, port) = pin_server(Arc::new(Full)).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        let m6 = pair_m5(&mut stream, &key, "phone", &sk).await;
        assert_eq!(m6.get_type(TlvType::State), Some(&[6u8][..]));
        assert_eq!(m6.get_type(TlvType::Error), Some(&[4u8][..]));
        server.stop().await;
    }

    /// pair-verify on `stream` as controller `id` with its key `sk`: the session's shared secret, from which
    /// the encrypted channel's keys come, and the identifier the accessory gave in M2.
    async fn pair_verify(
        stream: &mut TcpStream,
        id: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> ([u8; 32], String) {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use ed25519_dalek::Signer;
        let eph = x25519_dalek::StaticSecret::from([5u8; 32]);
        let eph_pk = x25519_dalek::PublicKey::from(&eph);
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::PublicKey as u8, eph_pk.as_bytes());
        let m2 = post_tlv(stream, "/pair-verify", 1, &m1).await;
        let server_pk: [u8; 32] = m2.get_type(TlvType::PublicKey).unwrap().try_into().unwrap();
        let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(server_pk));
        let mut key = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha512>::new(Some(b"Pair-Verify-Encrypt-Salt"), shared.as_bytes())
            .expand(b"Pair-Verify-Encrypt-Info", &mut key)
            .unwrap();
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(b"PV-Msg02");
        let m2_inner = chacha20poly1305::ChaCha20Poly1305::new((&key).into())
            .decrypt(
                (&nonce).into(),
                m2.get_type(TlvType::EncryptedData).unwrap(),
            )
            .unwrap();
        let accessory = String::from_utf8(
            TlvValues::decode(&m2_inner)
                .unwrap()
                .get_type(TlvType::Identifier)
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let signed = [eph_pk.as_bytes(), id.as_bytes(), &server_pk[..]].concat();
        let mut inner = TlvValues::new();
        inner.add(TlvType::Identifier as u8, id.as_bytes());
        inner.add(TlvType::Signature as u8, &sk.sign(&signed).to_bytes());
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(b"PV-Msg03");
        let encrypted = chacha20poly1305::ChaCha20Poly1305::new((&key).into())
            .encrypt((&nonce).into(), inner.encode().as_slice())
            .unwrap();
        let mut m3 = TlvValues::new();
        m3.add(TlvType::State as u8, &[3]);
        m3.add(TlvType::EncryptedData as u8, &encrypted);
        let m4 = post_tlv(stream, "/pair-verify", 2, &m3).await;
        assert_eq!(m4.get_type(TlvType::State), Some(&[4u8][..]));
        assert!(m4.get_type(TlvType::Error).is_none(), "pair-verify as {id}");
        (*shared.as_bytes(), accessory)
    }

    /// The `pi` the server on `port` gives in GET /info.
    async fn pairing_id_on(port: u16) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let end = buf[..n].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let info = plist::from_bytes::<plist::Value>(&buf[end..n]).unwrap();
        let get = |k: &str| {
            info.as_dictionary()
                .and_then(|d| d.get(k))
                .and_then(|v| v.as_string())
                .map(str::to_string)
        };
        // the Home app finds its accessory by psi [HW 2026-11-26]: the pi
        assert_eq!(get("psi"), get("pi"), "GET /info's psi");
        get("pi").unwrap()
    }

    /// The controller's side of the encrypted channel after pair-verify's `secret`.
    fn control_channel(secret: &[u8]) -> crate::support::EncryptedChannel {
        crate::support::EncryptedChannel::new(
            secret,
            "Control-Salt",
            "Control-Write-Encryption-Key",
            "Control-Salt",
            "Control-Read-Encryption-Key",
        )
        .unwrap()
    }

    /// `POST path` with `body` of `content_type` on the encrypted channel: the response's head and body.
    async fn post_encrypted(
        stream: &mut TcpStream,
        channel: &mut crate::support::EncryptedChannel,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> (String, Vec<u8>) {
        let mut req = format!(
            "POST {path} RTSP/1.0\r\nCSeq: 9\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        stream
            .write_all(&channel.encrypt_ctx.encrypt(&req).unwrap())
            .await
            .unwrap();
        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let (plain, _) = channel.decrypt_ctx.decrypt(&buf[..n]).unwrap();
        let end = plain.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        (
            String::from_utf8_lossy(&plain[..end]).into_owned(),
            plain[end..].to_vec(),
        )
    }

    /// A [`shairplay::HomeSetup`] that answers `allow` and keeps who asked.
    struct Home {
        allow: bool,
        asked: std::sync::Mutex<Vec<std::net::IpAddr>>,
        /// What `configured` saved, given back by `configuration`
        saved: std::sync::Mutex<shairplay::HomeConfiguration>,
        configured: std::sync::atomic::AtomicUsize,
    }

    impl Home {
        fn new(allow: bool) -> Arc<Self> {
            Arc::new(Self {
                allow,
                asked: Default::default(),
                saved: Default::default(),
                configured: Default::default(),
            })
        }
        fn saved(&self) -> shairplay::HomeConfiguration {
            self.saved.lock().unwrap().clone()
        }
        fn asked(&self) -> usize {
            self.asked.lock().unwrap().len()
        }
    }

    impl shairplay::HomeSetup for Home {
        fn allow_setup(&self, peer: std::net::IpAddr) -> bool {
            self.asked.lock().unwrap().push(peer);
            self.allow
        }
        fn configuration(&self) -> shairplay::HomeConfiguration {
            self.saved()
        }
        fn configured(&self, configuration: &shairplay::HomeConfiguration) {
            *self.saved.lock().unwrap() = configuration.clone();
            self.configured
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A server without a PIN that may be set up for a home, with `store`.
    async fn home_server(
        home: Arc<Home>,
        store: Arc<dyn shairplay::PairingStore>,
    ) -> (RaopServer, u16) {
        let mut server = RaopServer::builder()
            .mdns(false)
            .ptp(false)
            .name("HomeSetup")
            .hwaddr([0x02, 0, 0, 0, 0, 0x22])
            .port(0)
            .home(home)
            .pairing_store(store)
            .build(empty_handler())
            .unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;
        (server, port)
    }

    /// A persistent pair-setup's M1: no Flags.
    fn persistent_m1() -> TlvValues {
        let mut m1 = TlvValues::new();
        m1.add(TlvType::State as u8, &[1]);
        m1.add(TlvType::Method as u8, &[0]);
        m1
    }

    /// Without a PIN, a persistent pair-setup (the Home app's "Add Accessory" with 3939) goes through only if the
    /// application's HomeSetup allows it, and only while no controller is paired: then pair-setup is refused as
    /// Unavailable, without asking. Transient pair-setup stays open.
    #[tokio::test]
    #[serial]
    async fn a_home_is_set_up_once_and_only_when_the_application_allows_it() {
        use shairplay::{MemoryPairingStore, PairingStore};
        let store = Arc::new(MemoryPairingStore::default());
        let refusing = Home::new(false);
        let (mut server, port) = home_server(refusing.clone(), store.clone()).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let m2 = post_tlv(&mut stream, "/pair-setup", 1, &persistent_m1()).await;
        assert_eq!(m2.get_type(TlvType::Error), Some(&[2u8][..]), "refused");
        assert_eq!(
            *refusing.asked.lock().unwrap(),
            ["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        server.stop().await;

        let allowing = Home::new(true);
        let (mut server, port) = home_server(allowing.clone(), store.clone()).await;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        let m6 = pair_m5(&mut stream, &key, "home-admin", &sk).await;
        assert!(m6.get_type(TlvType::Error).is_none(), "set up");
        assert!(store.is_admin("home-admin"));
        assert_eq!(allowing.asked(), 1);

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let m2 = post_tlv(&mut stream, "/pair-setup", 1, &persistent_m1()).await;
        assert_eq!(
            m2.get_type(TlvType::Error),
            Some(&[6u8][..]),
            "paired: Unavailable"
        );
        assert_eq!(allowing.asked(), 1, "not asked once paired");
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        perform_transient_pairing(&mut stream).await;
        server.stop().await;
    }

    /// A pairing-management request (HAP's TLV: State 1, `method`, an identifier, a key, a permission).
    fn pairing_request(method: u8, id: &str, pk: Option<&[u8; 32]>, admin: bool) -> Vec<u8> {
        let mut t = TlvValues::new();
        t.add(TlvType::State as u8, &[1]);
        t.add(TlvType::Method as u8, &[method]);
        if method != 5 {
            t.add(TlvType::Identifier as u8, id.as_bytes());
        }
        if let Some(pk) = pk {
            t.add(TlvType::PublicKey as u8, pk);
            t.add(TlvType::Permissions as u8, &[u8::from(admin)]);
        }
        t.encode()
    }

    /// The home's admin manages its controllers at AirPlay's paths (`/pair-add`, `/pair-list`, `/pair-remove`)
    /// on its verified session; a session that didn't verify as an admin gets Authentication.
    #[tokio::test]
    #[serial]
    async fn the_admin_manages_controllers_at_the_pair_paths() {
        use shairplay::{MemoryPairingStore, PairingStore};
        let store = Arc::new(MemoryPairingStore::default());
        let (mut server, port) = home_server(Home::new(true), store.clone()).await;
        let admin = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        pair_m5(&mut stream, &key, "home-admin", &admin).await;

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let add = TlvValues::decode(&pairing_request(3, "x", Some(&[1; 32]), false)).unwrap();
        let refused = post_tlv(&mut stream, "/pair-add", 1, &add).await;
        assert_eq!(
            refused.get_type(TlvType::Error),
            Some(&[2u8][..]),
            "not verified"
        );

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (secret, _) = pair_verify(&mut stream, "home-admin", &admin).await;
        let mut channel = control_channel(&secret);
        let tlv = "application/pairing+tlv8";
        let member = [3u8; 32];
        let (head, body) = post_encrypted(
            &mut stream,
            &mut channel,
            "/pair-add",
            tlv,
            &pairing_request(3, "member", Some(&member), false),
        )
        .await;
        assert!(head.starts_with("RTSP/1.0 200"), "{head}");
        assert!(
            TlvValues::decode(&body)
                .unwrap()
                .get_type(TlvType::Error)
                .is_none()
        );
        assert_eq!(store.get("member"), Some(member));
        assert!(!store.is_admin("member"));

        let (_, body) = post_encrypted(
            &mut stream,
            &mut channel,
            "/pair-list",
            tlv,
            &pairing_request(5, "", None, false),
        )
        .await;
        let listed = TlvValues::decode(&body).unwrap();
        let ids: Vec<_> = listed
            .entries()
            .filter(|(t, _)| *t == TlvType::Identifier as u8)
            .map(|(_, v)| String::from_utf8(v.to_vec()).unwrap())
            .collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(ids.contains(&"member".to_string()) && ids.contains(&"home-admin".to_string()));

        let (_, body) = post_encrypted(
            &mut stream,
            &mut channel,
            "/pair-remove",
            tlv,
            &pairing_request(4, "member", None, false),
        )
        .await;
        assert!(
            TlvValues::decode(&body)
                .unwrap()
                .get_type(TlvType::Error)
                .is_none()
        );
        assert_eq!(store.get("member"), None);
        server.stop().await;
    }

    /// A home set up on `port` by controller "home-admin": its verified, encrypted session.
    async fn home_admin(port: u16) -> (TcpStream, crate::support::EncryptedChannel) {
        let admin = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        pair_m5(&mut stream, &key, "home-admin", &admin).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (secret, accessory) = pair_verify(&mut stream, "home-admin", &admin).await;
        // the Home app knows the accessory by the identifier /configure gives, its `pi` [HW 2026-11-26: with
        // the device ID instead the iPhone dropped pair-verify after M2 and showed "No Response"]
        assert_eq!(accessory, pairing_id_on(port).await);
        (stream, control_channel(&secret))
    }

    /// `POST /configure` with the Home app's ConfigurationDictionary: the response's head and plist.
    async fn configure(
        stream: &mut TcpStream,
        channel: &mut crate::support::EncryptedChannel,
        access_control: bool,
        level: u64,
    ) -> (String, plist::Dictionary) {
        let mut asked = plist::Dictionary::new();
        asked.insert(
            "Enable_HK_Access_Control".into(),
            plist::Value::Boolean(access_control),
        );
        asked.insert(
            "Access_Control_Level".into(),
            plist::Value::Integer(level.into()),
        );
        asked.insert("Device_Name".into(), plist::Value::String("Kitchen".into()));
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "ConfigurationDictionary".into(),
            plist::Value::Dictionary(asked),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        let (head, answer) = post_encrypted(
            stream,
            channel,
            "/configure",
            "application/x-apple-binary-plist",
            &body,
        )
        .await;
        let answer = plist::from_bytes::<plist::Value>(&answer)
            .ok()
            .and_then(|v| v.into_dictionary())
            .unwrap_or_default();
        (head, answer)
    }

    /// The Home app's `/configure` from the home's admin: the application keeps the configuration, the status
    /// flags say the speaker is set up for the home's access control (bit 10: 0x404), the answer carries the
    /// speaker's identity. Another session's `/configure` is refused, and without a HomeSetup there is none.
    #[tokio::test]
    #[serial]
    async fn the_home_app_configures_the_speaker() {
        let home = Home::new(true);
        let store = Arc::new(shairplay::MemoryPairingStore::default());
        let (mut server, port) = home_server(home.clone(), store).await;
        assert_eq!(airplay_txt(&server.service_info(), "flags"), Some("0x4"));
        let (mut stream, mut channel) = home_admin(port).await;
        let (head, answer) = configure(&mut stream, &mut channel, true, 0).await;
        assert!(head.starts_with("RTSP/1.0 200"), "{head}");
        let info = server.service_info();
        assert_eq!(
            answer.get("Identifier").and_then(|v| v.as_string()),
            airplay_txt(&info, "pi")
        );
        let pk = answer.get("PublicKey").and_then(|v| v.as_data()).unwrap();
        let pk_hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(Some(pk_hex.as_str()), airplay_txt(&info, "pk"));
        assert_eq!(
            answer
                .get("Enable_HK_Access_Control")
                .and_then(|v| v.as_boolean()),
            Some(true)
        );
        assert_eq!(
            home.saved(),
            shairplay::HomeConfiguration {
                access_control: true,
                access: shairplay::HomeAccess::Everyone,
                name: Some("Kitchen".into()),
            }
        );
        assert_eq!(airplay_txt(&info, "flags"), Some("0x404"));
        assert_eq!(airplay_txt(&info, "acl"), Some("0"));

        // not the admin's session
        let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let resp = send_rtsp(
            &mut plain,
            "POST /configure RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("RTSP/1.0 470"), "{resp}");
        server.stop().await;

        let (mut server, port, _) = start_server().await;
        let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let resp = send_rtsp(
            &mut plain,
            "POST /configure RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("RTSP/1.0 404"), "{resp}");
        server.stop().await;
    }

    /// A home for its members only (`Access_Control_Level` 1, `acl=1`): a session that didn't verify as one of
    /// its controllers gets nothing past pairing, and transient pair-setup is refused.
    #[tokio::test]
    #[serial]
    async fn a_home_for_its_members_only_refuses_other_senders() {
        let home = Home::new(true);
        let store = Arc::new(shairplay::MemoryPairingStore::default());
        let (mut server, port) = home_server(home.clone(), store).await;
        let (mut stream, mut channel) = home_admin(port).await;
        configure(&mut stream, &mut channel, true, 1).await;
        assert_eq!(home.saved().access, shairplay::HomeAccess::HomeMembers);
        assert_eq!(airplay_txt(&server.service_info(), "acl"), Some("1"));

        let mut other = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let resp = send_rtsp(&mut other, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").await;
        assert!(resp.starts_with("RTSP/1.0 200"), "OPTIONS: {resp}");
        let m2 = post_tlv(&mut other, "/pair-setup", 2, &transient_m1()).await;
        assert_eq!(
            m2.get_type(TlvType::Error),
            Some(&[2u8][..]),
            "transient refused"
        );
        let resp = send_rtsp(
            &mut other,
            "SETUP rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: 3\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("RTSP/1.0 470"), "SETUP: {resp}");
        server.stop().await;
    }

    /// The home's configuration lasts as long as its pairings: given back at the start while a controller is
    /// paired; gone (the application told) with the last admin's pairing, after which the speaker may be set up
    /// again.
    #[tokio::test]
    #[serial]
    async fn the_home_goes_with_its_last_admin() {
        use shairplay::PairingStore;
        let home = Home::new(true);
        let store = Arc::new(shairplay::MemoryPairingStore::default());
        let (mut server, port) = home_server(home.clone(), store.clone()).await;
        let (mut stream, mut channel) = home_admin(port).await;
        configure(&mut stream, &mut channel, true, 0).await;
        server.stop().await;

        let (mut server, port) = home_server(home.clone(), store.clone()).await;
        assert_eq!(
            airplay_txt(&server.service_info(), "flags"),
            Some("0x404"),
            "restored"
        );
        let admin = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (secret, _) = pair_verify(&mut stream, "home-admin", &admin).await;
        let mut channel = control_channel(&secret);
        post_encrypted(
            &mut stream,
            &mut channel,
            "/pair-remove",
            "application/pairing+tlv8",
            &pairing_request(4, "home-admin", None, false),
        )
        .await;
        assert!(!store.has_any_pairing());
        assert_eq!(home.saved(), shairplay::HomeConfiguration::default());
        assert_eq!(airplay_txt(&server.service_info(), "flags"), Some("0x4"));
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        let m6 = pair_m5(&mut stream, &key, "new-admin", &admin).await;
        assert!(m6.get_type(TlvType::Error).is_none(), "set up again");
        server.stop().await;

        // pairings gone while stopped (another store): a saved configuration counts for nothing at the start
        let stale = Home::new(true);
        stale.saved.lock().unwrap().access_control = true;
        let (mut server, _) =
            home_server(stale, Arc::new(shairplay::MemoryPairingStore::default())).await;
        assert_eq!(airplay_txt(&server.service_info(), "flags"), Some("0x4"));
        server.stop().await;
    }

    /// The Home app's setup as an iPhone does it [HW 2026-11-26]: transient pair-setup, then `/pair-add` of the
    /// home's controller on that session. While no controller is paired and the application allows it, the
    /// controller is stored as the admin and the session is its: `/configure` follows on it. Refused when the
    /// application says no; once paired, another transient session's `/pair-add` is refused without asking.
    #[tokio::test]
    #[serial]
    async fn the_home_app_adds_its_controller_from_a_transient_session() {
        use shairplay::{MemoryPairingStore, PairingStore};
        let tlv = "application/pairing+tlv8";
        let home_key = [4u8; 32];
        let add = pairing_request(3, "home", Some(&home_key), false);

        let refusing = Home::new(false);
        let store = Arc::new(MemoryPairingStore::default());
        let (mut server, port) = home_server(refusing.clone(), store.clone()).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = perform_transient_pairing(&mut stream).await;
        let mut channel = control_channel(&key);
        let (_, body) = post_encrypted(&mut stream, &mut channel, "/pair-add", tlv, &add).await;
        let answer = TlvValues::decode(&body).unwrap();
        assert_eq!(
            answer.get_type(TlvType::Error),
            Some(&[2u8][..]),
            "not allowed"
        );
        assert_eq!(refusing.asked(), 1);
        assert!(!store.has_any_pairing());
        server.stop().await;

        let home = Home::new(true);
        let (mut server, port) = home_server(home.clone(), store.clone()).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = perform_transient_pairing(&mut stream).await;
        let mut channel = control_channel(&key);
        let (head, body) = post_encrypted(&mut stream, &mut channel, "/pair-add", tlv, &add).await;
        assert!(head.starts_with("RTSP/1.0 200"), "{head}");
        assert!(
            TlvValues::decode(&body)
                .unwrap()
                .get_type(TlvType::Error)
                .is_none()
        );
        assert_eq!(store.get("home"), Some(home_key));
        assert!(
            store.is_admin("home"),
            "the home's first controller is its admin"
        );
        assert_eq!(home.asked(), 1);
        let (head, _) = configure(&mut stream, &mut channel, true, 0).await;
        assert!(
            head.starts_with("RTSP/1.0 200"),
            "/configure on the setup's session: {head}"
        );
        assert_eq!(airplay_txt(&server.service_info(), "flags"), Some("0x404"));

        let mut other = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = perform_transient_pairing(&mut other).await;
        let mut channel = control_channel(&key);
        let intruder = pairing_request(3, "intruder", Some(&[5; 32]), true);
        let (_, body) = post_encrypted(&mut other, &mut channel, "/pair-add", tlv, &intruder).await;
        assert_eq!(
            TlvValues::decode(&body).unwrap().get_type(TlvType::Error),
            Some(&[2u8][..]),
            "paired: only the admin adds"
        );
        assert_eq!(home.asked(), 1, "not asked once paired");
        assert_eq!(store.get("intruder"), None);
        server.stop().await;
    }

    /// Without a PIN and without a HomeSetup, a persistent pair-setup is refused: it would prove only the
    /// well-known 3939 and leave whoever asked an admin.
    #[tokio::test]
    #[serial]
    async fn without_a_home_setup_a_persistent_pair_setup_is_refused() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let m2 = post_tlv(&mut stream, "/pair-setup", 1, &persistent_m1()).await;
        assert_eq!(m2.get_type(TlvType::Error), Some(&[2u8][..]));
        server.stop().await;
    }

    fn airplay_txt<'a>(info: &'a shairplay::AirPlayServiceInfo, key: &str) -> Option<&'a str> {
        info.airplay_txt
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The status flags a PIN receiver advertises follow its pairings: `OneTimePairingRequired` (bit 9) alone
    /// until a controller paired, with `DeviceSetupForHKAccessControl` (bit 10) since.
    #[tokio::test]
    #[serial]
    async fn a_first_pairing_changes_the_advertised_status_flags() {
        let (mut server, port) =
            pin_server(Arc::new(shairplay::MemoryPairingStore::default())).await;
        assert_eq!(airplay_txt(&server.service_info(), "flags"), Some("0x204"));
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        pair_m5(&mut stream, &key, "phone", &sk).await;
        let info = server.service_info();
        assert_eq!(airplay_txt(&info, "flags"), Some("0x604"));
        assert_eq!(raop_txt(&info, "sf"), "0x604");
        server.stop().await;
    }

    /// Browsers hear of changed status flags without the receiver restarting: the first pairing's records are
    /// announced again (Linux: mdns-sd, both on this host).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[serial]
    async fn a_first_pairing_is_announced_again() {
        let name = format!("Reannounce{}", std::process::id());
        let mut server = RaopServer::builder()
            .ptp(false)
            .name(&name)
            .hwaddr([0x02, 0, 0, 0, 0, 0x21])
            .port(0)
            .pin("3939")
            .build(empty_handler())
            .unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;
        let browser = mdns_sd::ServiceDaemon::new().unwrap();
        let events = browser.browse("_airplay._tcp.local.").unwrap();
        let flags_seen = |flags: &'static str| {
            let (events, name) = (events.clone(), name.clone());
            tokio::task::spawn_blocking(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while let Ok(event) = events.recv_deadline(deadline) {
                    if let mdns_sd::ServiceEvent::ServiceResolved(info) = event
                        && info.get_fullname().contains(&name)
                        && info.get_property_val_str("flags") == Some(flags)
                    {
                        return true;
                    }
                }
                false
            })
        };
        assert!(flags_seen("0x204").await.unwrap(), "unpaired");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = srp_pair(&mut stream, "3939", false).await;
        pair_m5(&mut stream, &key, "phone", &sk).await;
        assert!(flags_seen("0x604").await.unwrap(), "paired");
        let _ = browser.shutdown();
        server.stop().await;
    }

    #[tokio::test]
    #[serial]
    async fn ap2_remote_control_only_setup() {
        let (mut server, port, _) = start_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        // Perform pairing first to populate conn.ap2_shared_secret and get session key
        let session_key = perform_transient_pairing(&mut stream).await;

        // Derive client-side transport cipher context (swapped write/read relative to server)
        let mut client_cipher = crate::support::EncryptedChannel::new(
            &session_key,
            "Control-Salt",
            "Control-Write-Encryption-Key",
            "Control-Salt",
            "Control-Read-Encryption-Key",
        )
        .unwrap();

        let mut dict = plist::Dictionary::new();
        dict.insert("isRemoteControlOnly".into(), plist::Value::Boolean(true));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &dict).unwrap();

        let req_header = format!(
            "SETUP rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 3\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
            port,
            body.len()
        );
        let mut plaintext = req_header.into_bytes();
        plaintext.extend_from_slice(&body);

        let encrypted_req = client_cipher.encrypt_ctx.encrypt(&plaintext).unwrap();
        stream.write_all(&encrypted_req).await.unwrap();

        // Read and decrypt the response from the server
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let (decrypted_resp, _) = client_cipher.decrypt_ctx.decrypt(&buf[..n]).unwrap();
        let resp = String::from_utf8_lossy(&decrypted_resp).to_string();
        assert!(resp.contains("200 OK"), "SETUP should be 200, got: {resp}");

        let header_end = resp.find("\r\n\r\n").unwrap() + 4;
        let body_bytes = &decrypted_resp[header_end..];
        let cursor = std::io::Cursor::new(body_bytes);
        let plist_val = plist::Value::from_reader(cursor).expect("SETUP body should be plist");
        let resp_dict = plist_val.as_dictionary().expect("should be dictionary");

        assert!(
            resp_dict.contains_key("eventPort"),
            "should contain eventPort"
        );
        let event_port = resp_dict
            .get("eventPort")
            .unwrap()
            .as_unsigned_integer()
            .unwrap();
        assert!(event_port > 0, "eventPort should be valid");

        // Verify we can connect to that event port!
        let event_stream = TcpStream::connect(format!("127.0.0.1:{event_port}")).await;
        assert!(
            event_stream.is_ok(),
            "should be able to connect to eventPort"
        );

        server.stop().await;
    }
}

#[tokio::test]
#[serial]
async fn senders_are_told_the_receivers_volume() {
    let (mut server, port, _) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let get = |cseq: u32| {
        format!(
            "GET_PARAMETER rtsp://127.0.0.1/{port} RTSP/1.0\r\nCSeq: {cseq}\r\nContent-Type: text/parameters\r\nContent-Length: 8\r\n\r\nvolume\r\n"
        )
    };
    let resp = send_rtsp(&mut stream, &get(1)).await;
    assert!(
        resp.ends_with("volume: 0.000000\r\n"),
        "no volume yet: {resp}"
    );

    let body = "volume: -20.000000\r\n";
    let set = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{port} RTSP/1.0\r\nCSeq: 2\r\nContent-Type: text/parameters\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    assert!(send_rtsp(&mut stream, &set).await.contains("200 OK"));
    let resp = send_rtsp(&mut stream, &get(3)).await;
    assert!(resp.ends_with("volume: -20.000000\r\n"), "{resp}");

    #[cfg(feature = "ap2-core")]
    {
        stream
            .write_all(b"GET /info RTSP/1.0\r\nCSeq: 4\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let start = buf[..n].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let info = plist::Value::from_reader(std::io::Cursor::new(&buf[start..n])).unwrap();
        let v = info
            .as_dictionary()
            .unwrap()
            .get("initialVolume")
            .and_then(|v| v.as_real());
        assert_eq!(v, Some(-20.0));
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn set_parameter_volume_calls_handler() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let body = "volume: -20.000000\r\n";
    let req = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 1\r\nContent-Type: text/parameters\r\nContent-Length: {}\r\n\r\n{}",
        port,
        body.len(),
        body
    );
    let resp = send_rtsp(&mut stream, &req).await;
    assert!(resp.contains("200 OK"));

    {
        let volumes = state.volumes.lock().unwrap();
        assert_eq!(volumes.len(), 1);
        assert!((volumes[0] - (-20.0)).abs() < 0.01);
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn set_parameter_metadata_calls_handler() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // Minimal DMAP: mlit container with minm("Test")
    let dmap: &[u8] = &[
        0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0c, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00,
        0x04, 0x54, 0x65, 0x73, 0x74,
    ];
    let header = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-dmap-tagged\r\nContent-Length: {}\r\n\r\n",
        port,
        dmap.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(dmap).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 OK"));

    {
        let meta = state.metadata.lock().unwrap();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].title.as_deref(), Some("Test"));
    }

    server.stop().await;
}

#[tokio::test]
#[serial]
async fn set_parameter_coverart_calls_handler() {
    let (mut server, port, state) = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let jpeg = b"\xff\xd8\xff\xe0fake-jpeg-data";
    let header = format!(
        "SET_PARAMETER rtsp://127.0.0.1/{} RTSP/1.0\r\nCSeq: 1\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
        port,
        jpeg.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(jpeg).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 OK"));

    {
        let art = state.coverart.lock().unwrap();
        assert_eq!(art.len(), 1);
        assert_eq!(&art[0], jpeg);
    }

    server.stop().await;
}

#[tokio::test]
async fn mdns_scope_with_an_unknown_address_refuses_to_start() {
    // 203.0.113.0/24 is reserved for documentation and is on no interface.
    let mut server = ap1_builder("ScopeRefused")
        .mdns_scope(shairplay::MdnsScope::Addrs(vec![
            "203.0.113.7".parse().unwrap(),
        ]))
        .build(empty_handler())
        .unwrap();
    let err = server.start().await.expect_err("scope must be refused");
    assert!(err.to_string().contains("203.0.113.7"), "{err}");
    assert!(!server.is_running(), "no listener may be left behind");
    assert!(server.mdns_scope_applied().is_none());
}

#[tokio::test]
async fn mdns_scope_with_a_wildcard_refuses_to_start() {
    let mut server = ap1_builder("ScopeWildcard")
        .mdns_scope(shairplay::MdnsScope::Addrs(vec![
            "0.0.0.0".parse().unwrap(),
        ]))
        .build(empty_handler())
        .unwrap();
    assert!(server.start().await.is_err());
    assert!(!server.is_running());
}

#[tokio::test]
async fn mdns_scope_on_loopback_starts() {
    // `CI` runners have no Bonjour/Avahi: only a registered service reports a scope
    let announce = std::env::var("CI").is_err();
    let mut server = ap1_builder("ScopeLoopback")
        .mdns(announce)
        .mdns_scope(shairplay::MdnsScope::Addrs(vec![
            "127.0.0.1".parse().unwrap(),
        ]))
        .build(empty_handler())
        .unwrap();
    server.start().await.expect("loopback is on every host");
    assert!(server.is_running());
    if announce {
        assert!(
            matches!(
                server.mdns_scope_applied(),
                Some(shairplay::MdnsScopeApplied::Interfaces(names)) if names.len() == 1
            ),
            "{:?}",
            server.mdns_scope_applied()
        );
    }
    server.stop().await;
}

/// A buffered-audio SETUP advertises the builder's compressed-audio window, 1 MiB unless set.
#[cfg(feature = "ap2-core")]
#[tokio::test]
#[serial]
async fn buffered_setup_advertises_the_audio_buffer_size() {
    for (size, expected) in [(None, 0x10_0000_u64), (Some(256 * 1024), 256 * 1024)] {
        let mut builder = RaopServer::builder()
            .mdns(false)
            .name("IntegrationTest")
            .hwaddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .port(0);
        if let Some(size) = size {
            builder = builder.audio_buffer_size(size);
        }
        let mut server = builder.build(empty_handler()).unwrap();
        server.start().await.unwrap();
        let port = server.service_info().port;
        let mut stream = BufReader::new(
            TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap(),
        );

        let mut stream0 = plist::Dictionary::new();
        stream0.insert("type".into(), plist::Value::Integer(103u64.into()));
        stream0.insert("shk".into(), plist::Value::Data(vec![0; 32]));
        let mut setup = plist::Dictionary::new();
        setup.insert(
            "streams".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream0)]),
        );
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(setup)).unwrap();
        let head = format!(
            "SETUP rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.get_mut().write_all(head.as_bytes()).await.unwrap();
        stream.get_mut().write_all(&body).await.unwrap();

        let response = auth_setup::read_success_response_body(&mut stream).await;
        let answer: plist::Value = plist::from_bytes(&response).unwrap();
        let advertised = answer.as_dictionary().unwrap()["streams"]
            .as_array()
            .unwrap()[0]
            .as_dictionary()
            .unwrap()["audioBufferSize"]
            .as_unsigned_integer()
            .unwrap();
        assert_eq!(advertised, expected);
        server.stop().await;
    }
}
