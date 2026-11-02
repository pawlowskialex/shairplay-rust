//! AirPlay 2 streams end to end: pairing, a stream's SETUP over the encrypted channel, its packets (Apple's encoder's
//! ALAC frames, encrypted as senders do), and the PCM that comes out, bit for bit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer, SampleFormat, Samples};

use crate::support::EncryptedChannel;

/// What the sessions got: their formats, the samples, the flushes.
#[derive(Clone, Default)]
struct Collect {
    formats: Arc<Mutex<Vec<AudioFormat>>>,
    samples: Arc<Mutex<Vec<i16>>>,
    flushes: Arc<AtomicUsize>,
}

impl AudioHandler for Collect {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        self.formats.lock().unwrap().push(format);
        Box::new(self.clone())
    }
}

impl AudioSession for Collect {
    fn audio(&mut self, samples: Samples<'_>, _: Option<u64>) {
        match samples {
            Samples::S16(s) => self.samples.lock().unwrap().extend_from_slice(s),
            _ => panic!("not the S16 the server was built for"),
        }
    }
    fn audio_flush(&mut self) {
        self.flushes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Collect {
    /// Wait until `n` samples came (or 5 s went).
    async fn wait_for(&self, n: usize) -> Vec<i16> {
        for _ in 0..500 {
            if self.samples.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.samples.lock().unwrap().clone()
    }
}

/// A golden vector (tests/data/alac): Apple's encoder's ALAC frames and the PCM they decode to.
struct Golden {
    frames: Vec<Vec<u8>>,
    pcm: Vec<i16>,
}

fn golden() -> Golden {
    let raw: &[u8] = include_bytes!("../data/alac/stereo352.alac");
    let u32_at = |i: usize| u32::from_le_bytes(raw[i..i + 4].try_into().unwrap()) as usize;
    assert_eq!(&raw[..8], b"ALACGV01");
    let cookie_len = u32_at(16);
    let mut p = 20 + cookie_len;
    let n_frames = u32_at(p);
    p += 4;
    let mut frames = Vec::new();
    for _ in 0..n_frames {
        let len = u32_at(p);
        frames.push(raw[p + 4..p + 4 + len].to_vec());
        p += 4 + len;
    }
    let pcm_len = u32_at(p);
    let pcm = raw[p + 4..p + 4 + pcm_len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes(*c))
        .collect();
    Golden { frames, pcm }
}

/// An RTP packet as AirPlay 2 senders encrypt it: `[header 12][ChaCha20-Poly1305 of the frame][tag 16][nonce 8]`, the
/// header's bytes 4..12 authenticated.
fn encrypt(key: &[u8; 32], header: [u8; 12], nonce_tail: u64, frame: &[u8]) -> Vec<u8> {
    let tail = nonce_tail.to_le_bytes();
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&tail);
    let ct = chacha20poly1305::ChaCha20Poly1305::new(key.into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: frame,
                aad: &header[4..12],
            },
        )
        .unwrap();
    [&header[..], &ct, &tail].concat()
}

fn header(first: [u8; 4], ts: u32, ssrc: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[..4].copy_from_slice(&first);
    h[4..8].copy_from_slice(&ts.to_be_bytes());
    h[8..].copy_from_slice(&ssrc.to_be_bytes());
    h
}

/// The sender's end of a paired, encrypted RTSP connection.
struct Sender {
    stream: TcpStream,
    channel: EncryptedChannel,
    cseq: u32,
}

impl Sender {
    async fn pair(port: u16) -> Self {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let key = crate::ap2_tests::perform_transient_pairing(&mut stream).await;
        let channel = EncryptedChannel::new(
            &key,
            "Control-Salt",
            "Control-Write-Encryption-Key",
            "Control-Salt",
            "Control-Read-Encryption-Key",
        )
        .unwrap();
        Sender {
            stream,
            channel,
            cseq: 10,
        }
    }

    /// A request with a plist body: the status line and the plist that comes back, if any.
    async fn request(
        &mut self,
        method: &str,
        body: &plist::Dictionary,
    ) -> (String, Option<plist::Dictionary>) {
        let mut data = Vec::new();
        plist::to_writer_binary(&mut data, body).unwrap();
        self.cseq += 1;
        let mut req = format!(
            "{method} rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: {}\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
            self.cseq,
            data.len()
        )
        .into_bytes();
        req.extend_from_slice(&data);
        let wire = self.channel.encrypt_ctx.encrypt(&req).unwrap();
        self.stream.write_all(&wire).await.unwrap();
        let (mut raw, mut plain) = (Vec::new(), Vec::new());
        loop {
            let mut buf = [0u8; 8192];
            let n = tokio::time::timeout(Duration::from_secs(5), self.stream.read(&mut buf))
                .await
                .expect("no answer")
                .unwrap();
            assert!(n > 0, "closed");
            raw.extend_from_slice(&buf[..n]);
            let (p, used) = self.channel.decrypt_ctx.decrypt(&raw).unwrap();
            raw.drain(..used);
            plain.extend_from_slice(&p);
            let text = String::from_utf8_lossy(&plain).to_string();
            let Some(end) = text.find("\r\n\r\n") else {
                continue;
            };
            let len = text[..end]
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .map_or(0, |v| v.parse::<usize>().unwrap());
            if plain.len() < end + 4 + len {
                continue;
            }
            let status = text.lines().next().unwrap().to_string();
            let body = (len > 0).then(|| {
                plist::from_bytes::<plist::Value>(&plain[end + 4..end + 4 + len])
                    .unwrap()
                    .into_dictionary()
                    .unwrap()
            });
            return (status, body);
        }
    }

    /// SETUP of one stream: its answer.
    async fn setup(&mut self, stream: plist::Dictionary) -> plist::Dictionary {
        let body = plist::Dictionary::from_iter([(
            "streams".to_string(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        )]);
        let (status, answer) = self.request("SETUP", &body).await;
        assert_eq!(status, "RTSP/1.0 200 OK");
        answer
            .unwrap()
            .get("streams")
            .and_then(|s| s.as_array())
            .and_then(|s| s.first())
            .and_then(|s| s.as_dictionary())
            .unwrap()
            .clone()
    }
}

fn port_of(d: &plist::Dictionary, key: &str) -> u16 {
    d.get(key)
        .and_then(|v| v.as_unsigned_integer())
        .unwrap()
        .try_into()
        .unwrap()
}

async fn start(handler: Collect) -> (RaopServer, u16) {
    let mut server = RaopServer::builder()
        .mdns(false)
        .ptp(false)
        .name("StreamTest")
        .hwaddr([0x02, 0, 0, 0, 0, 0x10])
        .port(0)
        .sample_format(SampleFormat::S16)
        .build(Arc::new(handler))
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    (server, port)
}

/// A realtime stream (type 96): SETUP, then packets, one of them forged (a tag that doesn't check, a sequence number
/// far ahead: had it reached the reorder stage, it would have restarted the stream there). The PCM is Apple's.
#[tokio::test]
#[serial]
async fn a_realtime_stream_plays_what_the_sender_encoded() {
    let got = Collect::default();
    let (mut server, port) = start(got.clone()).await;
    let mut sender = Sender::pair(port).await;
    let shk = [0x5a; 32];
    let answer = sender
        .setup(plist::Dictionary::from_iter([
            ("type".to_string(), plist::Value::Integer(96.into())),
            ("shk".to_string(), plist::Value::Data(shk.to_vec())),
            ("spf".to_string(), plist::Value::Integer(352.into())),
            (
                "audioFormat".to_string(),
                plist::Value::Integer(0x40000.into()),
            ),
            ("controlPort".to_string(), plist::Value::Integer(9.into())),
        ]))
        .await;
    let data = port_of(&answer, "dataPort");
    assert!(port_of(&answer, "controlPort") > 0);

    let g = golden();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (k, frame) in g.frames.iter().enumerate() {
        let seq = 1000 + k as u16;
        let s = seq.to_be_bytes();
        let p = encrypt(
            &shk,
            header([0x80, 0x60, s[0], s[1]], k as u32 * 352, 1),
            k as u64,
            frame,
        );
        udp.send_to(&p, ("127.0.0.1", data)).await.unwrap();
        if k == 3 {
            let s = (seq + 500).to_be_bytes();
            let mut forged = encrypt(&[0; 32], header([0x80, 0x60, s[0], s[1]], 0, 1), 99, frame);
            forged[20] ^= 1;
            udp.send_to(&forged, ("127.0.0.1", data)).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let pcm = got.wait_for(g.pcm.len()).await;
    assert_eq!(pcm.len(), g.pcm.len());
    assert!(pcm == g.pcm, "the PCM isn't the encoder's");
    let formats = got.formats.lock().unwrap().clone();
    assert_eq!(formats.len(), 1);
    assert_eq!(
        (
            formats[0].format,
            formats[0].channels,
            formats[0].sample_rate
        ),
        (SampleFormat::S16, 2, 44100)
    );

    // a TEARDOWN of its streams: the stream stops, its session is flushed, the connection stays
    let teardown =
        plist::Dictionary::from_iter([("streams".to_string(), plist::Value::Array(vec![]))]);
    let (status, _) = sender.request("TEARDOWN", &teardown).await;
    assert_eq!(status, "RTSP/1.0 200 OK");
    for _ in 0..100 {
        if got.flushes.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(got.flushes.load(Ordering::SeqCst) > 0, "not flushed");
    let (status, _) = sender.request("SETPEERS", &plist::Dictionary::new()).await;
    assert_eq!(status, "RTSP/1.0 200 OK", "the connection stayed");
    server.stop().await;
}

/// A buffered stream (type 103): SETUP, the frames over its TCP connection, SETRATEANCHORTIME to play (no PTP
/// clock: on the local clock). The PCM is Apple's.
#[tokio::test]
#[serial]
async fn a_buffered_stream_plays_what_the_sender_encoded() {
    let got = Collect::default();
    let (mut server, port) = start(got.clone()).await;
    let mut sender = Sender::pair(port).await;
    let shk = [0xa5; 32];
    let answer = sender
        .setup(plist::Dictionary::from_iter([
            ("type".to_string(), plist::Value::Integer(103.into())),
            ("shk".to_string(), plist::Value::Data(shk.to_vec())),
            ("ct".to_string(), plist::Value::Integer(2.into())),
            ("spf".to_string(), plist::Value::Integer(352.into())),
            (
                "audioFormat".to_string(),
                plist::Value::Integer(0x40000.into()),
            ),
        ]))
        .await;
    assert!(answer.contains_key("audioBufferSize"));
    let mut tcp = TcpStream::connect(("127.0.0.1", port_of(&answer, "dataPort")))
        .await
        .unwrap();

    let g = golden();
    for (k, frame) in g.frames.iter().enumerate() {
        let seq = 0x7F_FFF0u32.wrapping_add(k as u32) & 0x7F_FFFF; // across the 23-bit wrap
        let s = seq.to_be_bytes();
        let p = encrypt(
            &shk,
            header([0x80, s[1], s[2], s[3]], k as u32 * 352, 0x0000_FACE),
            k as u64,
            frame,
        );
        tcp.write_all(&(p.len() as u16 + 2).to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&p).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let play = plist::Dictionary::from_iter([
        ("rate".to_string(), plist::Value::Integer(1.into())),
        ("rtpTime".to_string(), plist::Value::Integer(0.into())),
    ]);
    let (status, _) = sender.request("SETRATEANCHORTIME", &play).await;
    assert_eq!(status, "RTSP/1.0 200 OK");
    let pcm = got.wait_for(g.pcm.len()).await;
    assert_eq!(pcm.len(), g.pcm.len());
    assert!(pcm == g.pcm, "the PCM isn't the encoder's");
    server.stop().await;
}
