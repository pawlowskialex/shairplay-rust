//! Offload: hand a stream's audio to the application's coprocessor (or its own decoder) instead of decrypting and
//! decoding it on the receiving thread. One trait for every kind of stream: realtime RTP packets (AirPlay 1, AirPlay
//! 2 realtime), and AirPlay 2 buffered ALAC frames or AAC access units.
//!
//! The receiver submits work as it arrives (buffered audio: shortly before it is due) and collects finished work in
//! submission order, so a job's latency overlaps the wait for the next and the receiving thread never blocks on the
//! coprocessor. An offload that can't take a unit (full, unsupported, failed) returns `false` from
//! [`Offload::submit`] and the unit is processed in software as before. Install one with
//! [`RaopServerBuilder::offload`](crate::RaopServerBuilder::offload).

use std::sync::Arc;

/// The packet cipher of a stream.
#[derive(Clone)]
pub enum OffloadCipher {
    /// Plain RTP payload.
    None,
    /// AirPlay 1: AES-128-CBC over the payload's whole 16-byte blocks, the IV reset for every packet; a tail of
    /// fewer than 16 bytes is in the clear.
    Aes128Cbc {
        /// The session's AES key (ANNOUNCE's rsaaeskey, decrypted).
        key: [u8; 16],
        /// Its IV (aesiv).
        iv: [u8; 16],
    },
    /// AirPlay 2 realtime: ChaCha20-Poly1305. Packet: `[RTP header 12][ciphertext][tag 16][nonce tail 8]`, nonce
    /// `[0; 4] ++ tail`, AAD the header's bytes 4..12.
    ChaCha20Poly1305 {
        /// The stream key (SETUP's shk).
        key: [u8; 32],
    },
}

/// The stream's ALAC parameters (the SDP fmtp / SETUP values).
#[derive(Clone, Copy, Debug)]
pub struct OffloadAlac {
    /// Samples a frame.
    pub frame_length: u32,
    /// Bits a sample: 16 or 24.
    pub bit_depth: u8,
    /// Rice parameters: history multiplier,
    pub pb: u8,
    /// initial history,
    pub mb: u8,
    /// and k limit.
    pub kb: u8,
    /// 1 or 2.
    pub channels: u8,
}

/// The work a stream asks of an offload, when it starts.
pub enum OffloadJob<'a> {
    /// Whole RTP packets, header included (AirPlay 1, AirPlay 2 realtime): decrypt, and decode ALAC too if `alac`
    /// (else hand back the plaintext payload for the software decoder).
    Packets {
        /// How the packets are encrypted.
        cipher: &'a OffloadCipher,
        /// The stream's ALAC parameters, to decode.
        alac: Option<&'a OffloadAlac>,
    },
    /// AirPlay 2 buffered ALAC frames, in the clear.
    AlacFrames {
        /// The stream's ALAC parameters.
        alac: &'a OffloadAlac,
        /// Its sample rate.
        sample_rate: u32,
    },
    /// AirPlay 2 buffered AAC-LC access units (no ADTS).
    AacFrames {
        /// The stream's sample rate.
        sample_rate: u32,
        /// Its channels.
        channels: u8,
    },
}

/// A finished unit.
pub enum Decoded<'a> {
    /// Interleaved 16-bit samples.
    S16(&'a [i16]),
    /// Interleaved 24-bit samples, sign-extended to 32 bits.
    S24(&'a [i32]),
    /// The decrypted payload, for the software decoder ([`OffloadJob::Packets`] without `alac`).
    Plain(&'a [u8]),
    /// Dropped: authentication failed, the frame didn't decode, or the coprocessor failed.
    Failed,
}

/// A coprocessor's (or the application's decoder's) per-stream queue.
pub trait Offload: Send {
    /// Queue a unit under `tag`; `false` if it can't be taken now (then it is processed in software, or by
    /// [`decode`](Offload::decode) for AAC).
    fn submit(&mut self, tag: u32, unit: &[u8]) -> bool;
    /// Hand over finished units in submission order, stopping at the first that isn't finished.
    fn collect(&mut self, done: &mut dyn FnMut(u32, Decoded<'_>));
    /// Units submitted and not yet collected.
    fn in_flight(&self) -> usize;
    /// For [`OffloadJob::AacFrames`]: decode an access unit now, one [`submit`](Offload::submit) declined (an
    /// application's AAC decoder replaces the library's: a synchronous one declines every submit and decodes
    /// here). `None` drops the unit. Not called for the other jobs.
    fn decode(&mut self, _unit: &[u8]) -> Option<Vec<i16>> {
        None
    }
}

/// Makes a stream's offload for its job, or `None` to process the stream in software.
pub type OffloadFactory = Arc<dyn Fn(&OffloadJob<'_>) -> Option<Box<dyn Offload>> + Send + Sync>;
