//! Decoders: what turns a stream's units (RTP packets, frames) into samples. Every stream goes through one: the
//! library's own ([`builtin`]) unless the application supplies its own for the stream
//! ([`RaopServerBuilder::decoders`](crate::RaopServerBuilder::decoders)): a coprocessor's, or a decoder the library
//! doesn't have. An application's decoder can fall back to the library's inside itself (when its coprocessor is busy,
//! say): `builtin` makes one for any stream it takes.
//!
//! A decoder is told the units in stream order ([`send`](Decoder::send)) and hands back their samples in the same
//! order ([`receive`](Decoder::receive)), when they are done: at once for the library's decoders, later for one that
//! works in the background ([`background`](Decoder::background)), which lets the receiver go on while it does.

use std::sync::Arc;

use crate::codec::{Decode, Pcm};

/// What a stream carries: its codec, its format, and how its units come.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamInfo {
    /// The codec.
    pub codec: Codec,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Channels.
    pub channels: u8,
    /// Bits a sample at the source (16 or 24).
    pub bit_depth: u8,
    /// How the units come.
    pub framing: Framing,
}

/// A stream's codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Codec {
    /// Apple Lossless, with its parameters.
    Alac(AlacParams),
    /// AAC-LC access units (raw: no ADTS).
    Aac,
    /// Linear PCM: big-endian interleaved 16-bit samples (AirPlay 1's L16).
    Pcm,
}

/// An ALAC stream's parameters (its ALACSpecificConfig: AirPlay 1's fmtp, AirPlay 2's SETUP with Apple's encoder
/// defaults for the rest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlacParams {
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

/// How a stream's units come.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Framing {
    /// Whole RTP packets as they arrived, header included, their payload encrypted with this cipher (AirPlay 1,
    /// AirPlay 2 realtime). A decoder decrypts them too: on a coprocessor that can be part of its job.
    Rtp(Cipher),
    /// The codec's frames, in the clear (AirPlay 2 buffered).
    Frames,
}

/// The cipher of a stream's RTP packets.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cipher {
    /// Plain RTP payload.
    None,
    /// AirPlay 1: AES-128-CBC over the payload's whole 16-byte blocks, the IV reset for every packet; a tail of
    /// fewer than 16 bytes in the clear.
    Aes128Cbc {
        /// The session's AES key (ANNOUNCE's rsaaeskey, decrypted).
        key: [u8; 16],
        /// Its IV (aesiv).
        iv: [u8; 16],
    },
    /// AirPlay 2 realtime: ChaCha20-Poly1305. Packet: `[RTP header 12][ciphertext][tag 16][nonce tail 8]`, nonce
    /// `[0; 4] ++ tail`, AAD the header's bytes 4..12. The receiver has checked the tag of every packet it sends.
    #[cfg(feature = "ap2-core")]
    ChaCha20Poly1305 {
        /// The stream key (SETUP's shk).
        key: [u8; 32],
    },
}

impl std::fmt::Debug for Cipher {
    /// Which cipher, not its key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Cipher::None => "None",
            Cipher::Aes128Cbc { .. } => "Aes128Cbc",
            #[cfg(feature = "ap2-core")]
            Cipher::ChaCha20Poly1305 { .. } => "ChaCha20Poly1305",
        })
    }
}

/// A unit's samples, interleaved.
#[derive(Debug)]
pub enum Decoded {
    /// 16-bit.
    S16(Vec<i16>),
    /// 24-bit, sign-extended to 32 bits.
    S24(Vec<i32>),
    /// Float, -1.0..1.0.
    F32(Vec<f32>),
    /// None: the unit didn't decrypt or decode (it is played as silence, or dropped, as the stream does).
    Failed,
}

/// One stream's decoder.
pub trait Decoder: Send {
    /// The next unit, in stream order.
    fn send(&mut self, unit: &[u8]);
    /// The oldest unit sent and not received, if it is done: units come back in the order they were sent, each
    /// once.
    fn receive(&mut self) -> Option<Decoded>;
    /// Whether units come back later than they are sent (a coprocessor, a thread of its own): then the receiver
    /// sends them ahead of their time. `false`, the default: each is done when `send` returns, and units are sent
    /// as they fall due.
    fn background(&self) -> bool {
        false
    }
    /// Wake `waker` once the next unit is done (at once if it is), if the decoder can tell: a coprocessor's
    /// interrupt, a thread of its own. `false`, the default: it can't, and the receiver looks again every few
    /// milliseconds while units are pending.
    fn wake_on_done(&mut self, _waker: &std::task::Waker) -> bool {
        false
    }
}

/// Makes a stream's decoder, or `None` to leave the stream to the library's ([`builtin`]).
pub type DecoderFactory = Arc<dyn Fn(&StreamInfo) -> Option<Box<dyn Decoder>> + Send + Sync>;

/// The library's decoder for a stream, if it has one: ALAC, PCM, and AAC with the `aac-symphonia` feature; RTP
/// packets decrypted first. It decodes each unit when it is sent.
pub fn builtin(info: &StreamInfo) -> Option<Box<dyn Decoder>> {
    let codec: Box<dyn Decode> = match info.codec {
        Codec::Alac(p) => Box::new(
            crate::codec::alac::AlacConfig::defaults(
                p.frame_length,
                p.bit_depth,
                p.channels,
                info.sample_rate,
            )
            .map(|c| crate::codec::alac::AlacConfig {
                pb: p.pb,
                mb: p.mb,
                kb: p.kb,
                ..c
            })?
            .decoder(),
        ),
        Codec::Pcm => Box::new(crate::codec::L16 {
            channels: info.channels,
        }),
        #[cfg(feature = "aac-symphonia")]
        Codec::Aac => crate::codec::aac::new_decoder(info.sample_rate, info.channels).ok()?,
        #[cfg(not(feature = "aac-symphonia"))]
        Codec::Aac => return None,
    };
    let unit: Box<dyn Decode> = match &info.framing {
        Framing::Rtp(cipher) => Box::new(Rtp {
            cipher: cipher.clone(),
            codec,
        }),
        Framing::Frames => codec,
    };
    Some(Box::new(Immediate::new(unit)))
}

/// RTP packets: the payload decrypted, then the codec.
struct Rtp {
    cipher: Cipher,
    codec: Box<dyn Decode>,
}

impl Decode for Rtp {
    fn decode(&mut self, packet: &[u8]) -> Option<Pcm> {
        let payload = self.cipher.open(packet)?;
        self.codec.decode(&payload)
    }
}

/// A decoder that decodes each unit when it is sent.
struct Immediate {
    decode: Box<dyn Decode>,
    done: std::collections::VecDeque<Decoded>,
}

impl Immediate {
    fn new(decode: Box<dyn Decode>) -> Self {
        Immediate {
            decode,
            done: std::collections::VecDeque::new(),
        }
    }
}

impl Decoder for Immediate {
    fn send(&mut self, unit: &[u8]) {
        self.done.push_back(match self.decode.decode(unit) {
            Some(Pcm::S16(v)) => Decoded::S16(v),
            Some(Pcm::S24(v)) => Decoded::S24(v),
            Some(Pcm::F32(v)) => Decoded::F32(v),
            None => Decoded::Failed,
        });
    }

    fn receive(&mut self) -> Option<Decoded> {
        self.done.pop_front()
    }
}

/// The application's decoder for `info` if it makes one, else the library's.
pub(crate) fn for_stream(
    info: &StreamInfo,
    factory: Option<&DecoderFactory>,
) -> Option<Box<dyn Decoder>> {
    factory.and_then(|f| f(info)).or_else(|| builtin(info))
}

/// A decoder that decodes nothing: a stream nobody can decode plays nothing rather than failing.
pub(crate) fn nothing() -> Box<dyn Decoder> {
    Box::new(Immediate::new(Box::new(Nothing)))
}

struct Nothing;

impl Decode for Nothing {
    fn decode(&mut self, _: &[u8]) -> Option<Pcm> {
        None
    }
}
