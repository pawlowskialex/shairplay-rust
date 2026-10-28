//! AirPlay 2 encrypted event and remote control channels.
//!
//! After initial SETUP, the client connects to the event TCP port.
//! All traffic is encrypted with ChaCha20-Poly1305 using HKDF-derived keys.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::crypto::chacha_transport::EncryptedChannel;
use crate::error::NetworkError;

/// Handle for sending commands through the event channel.
#[derive(Clone)]
pub(crate) struct EventSender {
    // Holding this keeps the mpsc open for the connection's lifetime (stored in `RaopConnection::event_sender`);
    // what goes in is sent to the sender, in order (the `updateInfo` queued at SETUP first).
    tx: mpsc::UnboundedSender<Vec<u8>>,
    cseq: Arc<AtomicU32>, // our requests' CSeq (`updateInfo` is 0)
}

impl EventSender {
    /// Create from an existing channel sender.
    pub(crate) fn from_tx(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            tx,
            cseq: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Push a message to the controller over the encrypted AP2 event channel.
    pub(crate) fn send(&self, data: Vec<u8>) -> Result<(), NetworkError> {
        self.tx
            .send(data)
            .map_err(|_| NetworkError::Mdns("event channel closed".into()))
    }

    /// A `POST /command` to the sender (remote-control commands, volume).
    pub(crate) fn post_command(&self, command: &plist::Dictionary) -> Result<(), NetworkError> {
        let cseq = self.cseq.fetch_add(1, Ordering::Relaxed);
        let msg = command_message(command, cseq)
            .ok_or_else(|| NetworkError::Mdns("command doesn't serialize".into()))?;
        self.send(msg)
    }
}

/// A `POST /command` request with a binary plist body, as the event channel carries them.
pub(crate) fn command_message(command: &plist::Dictionary, cseq: u32) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    plist::to_writer_binary(&mut body, command).ok()?;
    let mut msg = format!(
        "POST /command RTSP/1.0\r\nContent-Length: {}\r\nContent-Type: application/x-apple-binary-plist\r\nCSeq: {cseq}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    msg.extend_from_slice(&body);
    Some(msg)
}

/// Async event channel that accepts one encrypted TCP connection.
pub(crate) struct EventChannel;

impl EventChannel {
    /// Handle a connected event channel stream (public for use from handlers).
    pub(crate) async fn handle_stream(
        stream: TcpStream,
        channel: EncryptedChannel,
        cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        Self::handle(stream, channel, cmd_rx).await;
    }

    async fn handle(
        mut stream: TcpStream,
        mut channel: EncryptedChannel,
        mut cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let mut buf = vec![0u8; 4096];
        let mut encrypted_buf = Vec::new();
        loop {
            tokio::select! {
                result = stream.read(&mut buf) => {
                    match result {
                        Ok(0) => { debug!("Event channel closed by client"); break; }
                        Ok(n) => {
                            encrypted_buf.extend_from_slice(&buf[..n]);
                            debug!(n, "Event channel data received");
                            match channel.decrypt_ctx.decrypt(&encrypted_buf) {
                                Ok((plain, consumed)) => {
                                    if consumed > 0 { encrypted_buf.drain(..consumed); }
                                    if !plain.is_empty() {
                                        // the sender's answers to our requests (`RTSP/1.0 200 OK`)
                                        let first = plain.split(|&b| b == b'\r').next().unwrap_or(&[]);
                                        debug!(len = plain.len(), line = %String::from_utf8_lossy(first), "Event channel message received");
                                    }
                                }
                                Err(e) => { warn!("Event channel decrypt error: {e}"); }
                            }
                        }
                        Err(e) => { warn!("Event channel read error: {e}"); break; }
                    }
                }
                Some(data) = cmd_rx.recv() => {
                    debug!(len = data.len(), "Sending on event channel");
                    let encrypted = match channel.encrypt_ctx.encrypt(&data) {
                        Ok(e) => e,
                        Err(e) => { warn!("Event channel encrypt error: {e}"); break; }
                    };
                    if let Err(e) = stream.write_all(&encrypted).await {
                        warn!("Event channel write error: {e}"); break;
                    }
                }
            }
        }
    }
}
