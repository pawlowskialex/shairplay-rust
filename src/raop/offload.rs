//! Packet offload: hand realtime audio packets (AirPlay 1 RTP, AirPlay 2 realtime) to a coprocessor that decrypts
//! and decodes them, instead of doing it on the receiving thread.
//!
//! The receiver submits each packet as it arrives and collects finished ones in submission order, so a job's
//! latency overlaps the wait for the next packet and the receiving thread never blocks on the coprocessor. An
//! offload that can't take a packet (full, unsupported, failed) returns `false` from [`PacketOffload::submit`] and
//! the packet is processed in software as before. Install one with
//! [`RaopServerBuilder::packet_offload`](crate::RaopServerBuilder::packet_offload).

use std::sync::Arc;

/// The packet cipher of a stream.
#[derive(Clone)]
pub enum OffloadCipher {
    /// Plain RTP payload.
    None,
    /// AirPlay 1: AES-128-CBC over the payload's whole 16-byte blocks, the IV reset for every packet; a tail of
    /// fewer than 16 bytes is in the clear.
    Aes128Cbc { key: [u8; 16], iv: [u8; 16] },
    /// AirPlay 2 realtime: ChaCha20-Poly1305. Packet: `[RTP header 12][ciphertext][tag 16][nonce tail 8]`, nonce
    /// `[0; 4] ++ tail`, AAD the header's bytes 4..12.
    ChaCha20Poly1305 { key: [u8; 32] },
}

/// The stream's ALAC parameters (the SDP fmtp / SETUP values).
#[derive(Clone, Copy, Debug)]
pub struct OffloadAlac {
    pub frame_length: u32,
    pub bit_depth: u8,
    pub pb: u8,
    pub mb: u8,
    pub kb: u8,
    pub channels: u8,
}

/// What an offload is asked to do for every packet of a stream.
#[derive(Clone)]
pub struct OffloadStream {
    pub cipher: OffloadCipher,
    /// Decode ALAC too (else the offload returns the plaintext payload for the software decoder).
    pub alac: Option<OffloadAlac>,
}

/// A finished packet.
pub enum OffloadOutput<'a> {
    /// Decoded interleaved 16-bit samples.
    Pcm(&'a [i16]),
    /// The decrypted payload, for the software decoder.
    Plain(&'a [u8]),
    /// Dropped: authentication failed, the frame didn't decode, or the coprocessor failed.
    Failed,
}

/// A coprocessor's per-stream queue. Packets are whole RTP packets, header included.
pub trait PacketOffload: Send {
    /// Queue a packet under `tag`; `false` if it can't be taken (then the caller processes it itself).
    fn submit(&mut self, tag: u32, packet: &[u8]) -> bool;
    /// Hand over finished packets in submission order, stopping at the first that isn't finished.
    fn collect(&mut self, done: &mut dyn FnMut(u32, OffloadOutput<'_>));
    /// Packets submitted and not yet collected.
    fn in_flight(&self) -> usize;
}

/// Makes a stream's offload, or `None` to process the stream in software.
pub type OffloadFactory =
    Arc<dyn Fn(&OffloadStream) -> Option<Box<dyn PacketOffload>> + Send + Sync>;
