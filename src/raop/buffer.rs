//! AP1 RTP packet buffer with AES-CBC decryption and codec decode to signed 16-bit PCM.
//!
//! Incoming RTP packets are queued by sequence number into a fixed-size circular
//! buffer. Each packet is decrypted (AES-128-CBC) and decoded on arrival — either
//! ALAC (`a=rtpmap:… AppleLossless`) or raw PCM (`a=rtpmap:… L16/<rate>/<ch>`).
//! The consumer dequeues packets in order, with silence substitution for missing
//! packets and optional retransmit requests for gaps.

use crate::codec::alac::{AlacConfig, AlacDecoder};
use crate::raop::offload::{
    OffloadAlac, OffloadCipher, OffloadFactory, OffloadOutput, OffloadStream, PacketOffload,
};
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use std::borrow::Cow;

/// AES-128 key length in bytes.
pub const RAOP_AESKEY_LEN: usize = 16;
/// AES-128 IV length in bytes.
pub const RAOP_AESIV_LEN: usize = 16;
/// Maximum RTP packet size (including 12-byte header).
pub(crate) const RAOP_PACKET_LEN: usize = 32768;
/// Number of slots in the circular buffer. Must be a power of two for modulo indexing.
const RAOP_BUFFER_LENGTH: usize = 32;
/// Default silence-frame length (samples per channel) for PCM streams before the
/// first packet establishes the real frame size. 352 matches the classic AirPlay
/// ALAC frame; it is only used to size silence for a missing *first* packet.
const PCM_DEFAULT_FRAME_SAMPLES: usize = 352;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Clone, Copy)]
struct AesSession {
    key: [u8; RAOP_AESKEY_LEN],
    iv: [u8; RAOP_AESIV_LEN],
}

/// Raw-PCM (`L16`) stream configuration, parsed from the SDP `rtpmap` attribute.
#[derive(Debug, Clone)]
pub(crate) struct PcmConfig {
    /// Number of audio channels.
    pub(crate) num_channels: u8,
    /// Sample rate in Hz.
    pub(crate) sample_rate: u32,
}

/// Output stream format, independent of the wire codec. Consumed by the RTP
/// layer to build the [`AudioFormat`](crate::raop::AudioFormat) for `audio_init`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamFormat {
    /// Number of audio channels.
    pub(crate) num_channels: u8,
    /// Source sample rate in Hz.
    pub(crate) sample_rate: u32,
}

/// The negotiated wire codec plus its decoder state.
enum Codec {
    /// Apple Lossless — the classic AirPlay codec. Also covers PipeWire's
    /// `raop.audio.codec=PCM`, which is really uncompressed-ALAC on the wire.
    Alac {
        config: AlacConfig,
        decoder: AlacDecoder,
    },
    /// Raw linear PCM (`L16`): big-endian interleaved S16, no compression.
    Pcm { config: PcmConfig },
}

/// Validated codec parameters parsed from the SDP `rtpmap` attribute.
enum CodecConfig {
    Alac,
    Pcm(PcmConfig),
}

/// A single slot in the circular buffer holding one decoded audio frame.
struct BufferEntry {
    /// Whether this slot contains a valid decoded frame.
    available: bool,
    /// RTP flags byte (first byte of RTP header).
    flags: u8,
    /// RTP payload type byte (second byte of RTP header).
    entry_type: u8,
    /// RTP sequence number.
    seqnum: u16,
    /// RTP timestamp (sample clock).
    timestamp: u32,
    /// RTP synchronization source identifier.
    ssrc: u32,
    /// Decoded S16 audio samples (both codecs are 16-bit). Pre-allocated to the per-entry capacity.
    audio_buffer: Vec<i16>,
    /// Actual number of valid samples in `audio_buffer`.
    audio_buffer_len: usize,
    /// Submitted to the offload and not back yet (under `offload_tag`).
    pending: bool,
    offload_tag: u32,
    /// The packet's length: the same sequence number again with another length is another packet, not a duplicate
    packet_len: usize,
}

/// Compare two RTP sequence numbers with wrapping (handles 16-bit overflow).
/// Returns negative if s1 is before s2, positive if after, zero if equal.
fn seqnum_cmp(s1: u16, s2: u16) -> i16 {
    s1.wrapping_sub(s2) as i16
}

/// Parse the SDP `fmtp` attribute into an ALAC configuration.
/// Format: `96 <frame_length> <compat_version> <bit_depth> <pb> <mb> <kb> <channels> <max_run> <max_frame_bytes> <avg_bitrate> <sample_rate>`.
fn parse_fmtp(fmtp: &str) -> Option<AlacConfig> {
    let vals: Vec<&str> = fmtp.split(' ').collect();
    if vals.len() < 12 {
        return None;
    }
    // Every field must be a valid integer — a non-numeric field is malformed
    // input and must be rejected, not silently coerced to 0 (a 0 here yields a
    // zero-size audio buffer and a 0-channel decoder downstream).
    let p = |i: usize| vals[i].parse::<u32>().ok();
    let config = AlacConfig {
        frame_length: p(1)?,
        compatible_version: p(2)? as u8,
        bit_depth: p(3)? as u8,
        pb: p(4)? as u8,
        mb: p(5)? as u8,
        kb: p(6)? as u8,
        num_channels: p(7)? as u8,
        max_run: p(8)? as u16,
        max_frame_bytes: p(9)?,
        avg_bit_rate: p(10)?,
        sample_rate: p(11)?,
    };
    // Reject configs that would produce degenerate buffers / decoder state.
    if config.frame_length == 0
        || config.num_channels == 0
        || config.bit_depth == 0
        || config.sample_rate == 0
    {
        return None;
    }
    Some(config)
}

/// Parse an `L16/<rate>[/<channels>]` rtpmap encoding into a [`PcmConfig`].
/// Per RFC 3551, `L16` defaults to a single channel when the count is omitted.
fn parse_l16(encoding: &str) -> Option<PcmConfig> {
    let mut parts = encoding.split('/');
    if !parts.next()?.eq_ignore_ascii_case("L16") {
        return None;
    }
    let sample_rate: u32 = parts.next()?.parse().ok()?;
    let num_channels: u8 = match parts.next() {
        Some(ch) => ch.parse().ok()?,
        None => 1,
    };
    if parts.next().is_some() || sample_rate == 0 || num_channels == 0 {
        return None;
    }
    Some(PcmConfig {
        num_channels,
        sample_rate,
    })
}

/// Parse and validate an SDP `rtpmap` value (`"<payload-type> <encoding>"`).
fn parse_codec(rtpmap: &str) -> Option<CodecConfig> {
    let mut fields = rtpmap.split_whitespace();
    fields.next()?.parse::<u8>().ok()?;
    let encoding = fields.next()?;
    if fields.next().is_some() {
        return None;
    }

    let name = encoding.split('/').next()?;
    if name.eq_ignore_ascii_case("AppleLossless") {
        Some(CodecConfig::Alac)
    } else {
        parse_l16(encoding).map(CodecConfig::Pcm)
    }
}

/// Build the 48-byte decoder info block expected by `AlacDecoder::set_info`.
/// Layout matches the ALACSpecificConfig in the Apple ALAC reference decoder.
fn build_decoder_info(config: &AlacConfig) -> [u8; 48] {
    let mut info = [0u8; 48];
    info[24..28].copy_from_slice(&config.frame_length.to_be_bytes());
    info[28] = config.compatible_version;
    info[29] = config.bit_depth;
    info[30] = config.pb;
    info[31] = config.mb;
    info[32] = config.kb;
    info[33] = config.num_channels;
    info[34..36].copy_from_slice(&config.max_run.to_be_bytes());
    info[36..40].copy_from_slice(&config.max_frame_bytes.to_be_bytes());
    info[40..44].copy_from_slice(&config.avg_bit_rate.to_be_bytes());
    info[44..48].copy_from_slice(&config.sample_rate.to_be_bytes());
    info
}

/// Circular RTP packet buffer with decrypt-on-queue and codec decode.
///
/// Packets are inserted by [`queue`](Self::queue) and consumed by
/// [`dequeue`](Self::dequeue). The buffer holds a fixed number of
/// frames. Sequence number wrapping is handled correctly.
///
/// # Audio pipeline
///
/// ```text
/// RTP packet → AES-128-CBC decrypt → ALAC or L16 decode → f32 → buffer slot
/// ```
pub struct RaopBuffer {
    aes: Option<AesSession>,
    codec: Codec,
    is_empty: bool,
    /// Sequence number of the next frame to dequeue (oldest buffered).
    first_seqnum: u16,
    /// Sequence number of the newest buffered frame.
    last_seqnum: u16,
    entries: Vec<BufferEntry>,
    /// Number of f32 samples one decoded frame's buffer can hold (allocation size).
    frame_capacity: usize,
    /// Number of f32 samples to emit when substituting silence for a lost frame.
    /// Constant for ALAC (fixed frame size); tracks the last real frame for PCM.
    silence_samples: usize,
    /// ALAC output bytes, reused for every packet.
    decode_scratch: Vec<u8>,
    /// What [`dequeue`](Self::dequeue) returns: the dequeued frame as f32.
    f32_scratch: Vec<f32>,
    /// A coprocessor decrypting and decoding packets ([`set_offload`](Self::set_offload)).
    offload: Option<Box<dyn PacketOffload>>,
    /// Counts flushes: offload tags are `generation << 16 | seqnum`, so a result for a packet from before a flush
    /// never fills a slot reused after it.
    generation: u16,
}

impl RaopBuffer {
    /// Create a new encrypted buffer from SDP parameters and AES session keys.
    ///
    /// `rtpmap` selects the codec (`AppleLossless` → ALAC, `L16/...` → PCM);
    /// `fmtp` supplies the ALAC config (ignored for PCM). The decoder is
    /// initialized immediately.
    ///
    /// Returns `None` if the (peer-supplied) `rtpmap`/`fmtp` attributes are
    /// malformed or name an unsupported codec.
    pub fn new(
        rtpmap: &str,
        fmtp: &str,
        aes_key: &[u8; RAOP_AESKEY_LEN],
        aes_iv: &[u8; RAOP_AESIV_LEN],
    ) -> Option<Self> {
        Self::build(
            rtpmap,
            fmtp,
            Some(AesSession {
                key: *aes_key,
                iv: *aes_iv,
            }),
        )
    }

    /// Create a new unencrypted buffer from SDP parameters.
    pub fn new_unencrypted(rtpmap: &str, fmtp: &str) -> Option<Self> {
        Self::build(rtpmap, fmtp, None)
    }

    fn build(rtpmap: &str, fmtp: &str, aes: Option<AesSession>) -> Option<Self> {
        let (codec, frame_capacity, silence_samples) = match parse_codec(rtpmap)? {
            CodecConfig::Pcm(config) => {
                // PCM frames are variable-length: size each slot to the largest RTP
                // payload (worst case) so a big packet never overflows the slot.
                let capacity = (RAOP_PACKET_LEN - 12) / 2;
                let silence = PCM_DEFAULT_FRAME_SAMPLES * config.num_channels as usize;
                (Codec::Pcm { config }, capacity, silence)
            }
            CodecConfig::Alac => {
                let config = parse_fmtp(fmtp)?;
                // ALAC outputs one f32 per sample: frame_length × channels.
                let frame_samples = config.frame_length as usize * config.num_channels as usize;
                let mut decoder =
                    AlacDecoder::new(config.bit_depth as i32, config.num_channels as i32);
                decoder.set_info(&build_decoder_info(&config));
                (
                    Codec::Alac { config, decoder },
                    frame_samples,
                    frame_samples,
                )
            }
        };

        let entries = (0..RAOP_BUFFER_LENGTH)
            .map(|_| BufferEntry {
                available: false,
                flags: 0,
                entry_type: 0,
                seqnum: 0,
                timestamp: 0,
                ssrc: 0,
                audio_buffer: vec![0i16; frame_capacity],
                audio_buffer_len: 0,
                pending: false,
                offload_tag: 0,
                packet_len: 0,
            })
            .collect();

        Some(Self {
            aes,
            codec,
            is_empty: true,
            first_seqnum: 0,
            last_seqnum: 0,
            entries,
            frame_capacity,
            silence_samples,
            decode_scratch: Vec::new(),
            f32_scratch: Vec::new(),
            offload: None,
            generation: 0,
        })
    }

    /// Ask `factory` for an offload for this stream (ALAC streams only); without one, or if it declines, every
    /// packet is decrypted and decoded here.
    pub(crate) fn set_offload(&mut self, factory: Option<&OffloadFactory>) {
        self.offload = None;
        let (Some(factory), Codec::Alac { config, .. }) = (factory, &self.codec) else {
            return;
        };
        let stream = OffloadStream {
            cipher: match self.aes {
                Some(a) => OffloadCipher::Aes128Cbc {
                    key: a.key,
                    iv: a.iv,
                },
                None => OffloadCipher::None,
            },
            alac: Some(OffloadAlac {
                frame_length: config.frame_length,
                bit_depth: config.bit_depth,
                pb: config.pb,
                mb: config.mb,
                kb: config.kb,
                channels: config.num_channels,
            }),
        };
        self.offload = factory(&stream);
    }

    /// Packets with the offload.
    pub(crate) fn in_flight(&self) -> usize {
        self.offload.as_ref().map_or(0, |o| o.in_flight())
    }

    /// Move finished offload results into their slots.
    fn collect_offload(&mut self) {
        let Some(mut off) = self.offload.take() else {
            return;
        };
        off.collect(&mut |tag, out| {
            let idx = (tag & 0xFFFF) as usize % RAOP_BUFFER_LENGTH;
            if !self.entries[idx].pending || self.entries[idx].offload_tag != tag {
                return;
            }
            self.entries[idx].pending = false;
            let n = match out {
                OffloadOutput::Pcm(pcm) => {
                    let e = &mut self.entries[idx];
                    let n = pcm.len().min(e.audio_buffer.len());
                    e.audio_buffer[..n].copy_from_slice(&pcm[..n]);
                    n
                }
                OffloadOutput::Plain(payload) => self.decode_into(idx, payload).max(0) as usize,
                OffloadOutput::Failed => 0,
            };
            self.entries[idx].audio_buffer_len = n;
            self.entries[idx].available = n > 0;
        });
        self.offload = Some(off);
    }

    /// Returns the output stream format (channels + source sample rate).
    pub(crate) fn format(&self) -> StreamFormat {
        match &self.codec {
            Codec::Alac { config, .. } => StreamFormat {
                num_channels: config.num_channels,
                sample_rate: config.sample_rate,
            },
            Codec::Pcm { config } => StreamFormat {
                num_channels: config.num_channels,
                sample_rate: config.sample_rate,
            },
        }
    }

    /// Queue an RTP packet: decrypt, decode (ALAC or L16), store f32 in buffer.
    ///
    /// Returns 1 on success, 0 if duplicate/stale, -1 if packet is malformed.
    /// If the sequence number is far ahead of the current window, the buffer is
    /// flushed to avoid stalling on lost packets.
    pub fn queue(&mut self, data: &[u8], use_seqnum: bool) -> i32 {
        let datalen = data.len();
        if !(12..=RAOP_PACKET_LEN).contains(&datalen) {
            return -1;
        }

        // Extract sequence number from RTP header bytes 2-3 (big-endian).
        let seqnum = if use_seqnum {
            ((data[2] as u16) << 8) | data[3] as u16
        } else {
            self.first_seqnum
        };

        // Drop packets older than our current window.
        if !self.is_empty && seqnum_cmp(seqnum, self.first_seqnum) < 0 {
            return 0;
        }
        // If too far ahead, flush the buffer to resync.
        if seqnum_cmp(
            seqnum,
            self.first_seqnum.wrapping_add(RAOP_BUFFER_LENGTH as u16),
        ) >= 0
        {
            self.flush(seqnum as i32);
        }

        let idx = seqnum as usize % RAOP_BUFFER_LENGTH;
        // Skip duplicates: a resend of what is here or with the offload. A sender may send a placeholder and the
        // frame under the same sequence number, in either order (one test sender opens with two 8-byte payloads):
        // a frame decoded here stays, and one with the offload is replaced only by a longer packet.
        if seqnum_cmp(self.entries[idx].seqnum, seqnum) == 0
            && (self.entries[idx].available
                || (self.entries[idx].pending && self.entries[idx].packet_len >= datalen))
        {
            return 0;
        }
        if self.entries[idx].pending {
            // the offload's result for the replaced packet must not be taken for this one: a new tag
            self.generation = self.generation.wrapping_add(1);
        }

        // A failed replacement must not leave stale data available in this slot.
        self.entries[idx].available = false;
        self.entries[idx].pending = false;
        self.entries[idx].audio_buffer_len = 0;

        let tag = (self.generation as u32) << 16 | seqnum as u32;
        if let Some(off) = self.offload.as_mut()
            && off.submit(tag, data)
        {
            self.entries[idx].pending = true;
            self.entries[idx].offload_tag = tag;
            self.mark(idx, data, seqnum, 0);
            return 1;
        }

        // AES-128-CBC decrypt: only full 16-byte blocks are encrypted,
        // trailing bytes (< 16) are sent in the clear.
        let payload = &data[12..];
        let encrypted_len = (payload.len() / 16) * 16;

        // Unencrypted sessions borrow the payload directly. Encrypted sessions
        // allocate only when at least one complete AES block is present.
        let packet_buf: Cow<[u8]> = if let (Some(aes), true) = (self.aes, encrypted_len > 0) {
            let decryptor = Aes128CbcDec::new((&aes.key).into(), (&aes.iv).into());
            let mut buf = payload.to_vec();
            decryptor
                .decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf[..encrypted_len])
                .unwrap_or(&[]);
            Cow::Owned(buf)
        } else {
            Cow::Borrowed(payload)
        };

        let num_samples = self.decode_into(idx, &packet_buf);
        if num_samples <= 0 {
            return num_samples;
        }
        self.mark(idx, data, seqnum, num_samples as usize);
        self.entries[idx].available = true;
        1
    }

    /// Record a slot's RTP header and length and move the buffer window.
    fn mark(&mut self, idx: usize, data: &[u8], seqnum: u16, num_samples: usize) {
        let entry = &mut self.entries[idx];
        entry.flags = data[0];
        entry.entry_type = data[1];
        entry.seqnum = seqnum;
        entry.packet_len = data.len();
        entry.timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        entry.ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        entry.audio_buffer_len = num_samples;

        // Update buffer window.
        if self.is_empty {
            self.first_seqnum = seqnum;
            self.last_seqnum = seqnum;
            self.is_empty = false;
        }
        if seqnum_cmp(seqnum, self.last_seqnum) > 0 {
            self.last_seqnum = seqnum;
        }
    }

    /// Decode a decrypted payload into slot `idx`: the number of samples, 0 for an undecodable frame, -1 for a
    /// malformed L16 payload.
    fn decode_into(&mut self, idx: usize, packet_buf: &[u8]) -> i32 {
        // Decode into the slot's s16 buffer.
        let capacity = self.frame_capacity;
        let num_samples = match &mut self.codec {
            Codec::Alac { decoder, .. } => {
                // ALAC decode → S16LE bytes → samples.
                let s16_buf = &mut self.decode_scratch;
                s16_buf.resize(capacity * 2, 0);
                let output_size = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder.decode_frame(packet_buf, s16_buf)
                }))
                .unwrap_or(0);
                if output_size == 0 {
                    return 0;
                }
                let limit = output_size.min(s16_buf.len());
                let out = &mut self.entries[idx].audio_buffer;
                let mut n = 0;
                for (chunk, out_sample) in s16_buf[..limit]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .zip(out.iter_mut())
                {
                    *out_sample = i16::from_le_bytes(*chunk);
                    n += 1;
                }
                n
            }
            Codec::Pcm { config } => {
                // Raw L16: big-endian (network order) interleaved S16.
                let frame_width = usize::from(config.num_channels) * size_of::<i16>();
                if packet_buf.is_empty() || !packet_buf.len().is_multiple_of(frame_width) {
                    return -1;
                }
                let out = &mut self.entries[idx].audio_buffer;
                let mut n = 0;
                for (chunk, out_sample) in packet_buf.as_chunks::<2>().0.iter().zip(out.iter_mut())
                {
                    *out_sample = i16::from_be_bytes(*chunk);
                    n += 1;
                }
                if n == 0 {
                    return 0;
                }
                // Remember this frame size so a lost packet substitutes a
                // similarly-sized block of silence rather than a fixed guess.
                self.silence_samples = n;
                n
            }
        };

        num_samples as i32
    }

    /// Dequeue the next frame in sequence order, as f32 (a conversion of
    /// [`dequeue_s16`](Self::dequeue_s16)'s samples).
    pub fn dequeue(&mut self, no_resend: bool) -> Option<&[f32]> {
        let len = self.dequeue_s16(no_resend)?.len();
        let idx = self.first_seqnum.wrapping_sub(1) as usize % RAOP_BUFFER_LENGTH;
        self.f32_scratch.clear();
        self.f32_scratch.extend(
            self.entries[idx].audio_buffer[..len]
                .iter()
                .map(|&s| s as f32 / 32768.0),
        );
        Some(&self.f32_scratch)
    }

    /// Dequeue the next frame in sequence order.
    ///
    /// Returns the decoded signed 16-bit samples, or `None` if the buffer is empty.
    /// If the next frame is missing and `no_resend` is false, returns `None`
    /// to allow time for a retransmit. If `no_resend` is true (or the buffer
    /// is full), substitutes silence for the missing frame.
    pub fn dequeue_s16(&mut self, no_resend: bool) -> Option<&[i16]> {
        self.collect_offload();
        let buflen = seqnum_cmp(self.last_seqnum, self.first_seqnum) as i32 + 1;
        if self.is_empty || buflen <= 0 {
            return None;
        }

        let idx = self.first_seqnum as usize % RAOP_BUFFER_LENGTH;
        // The next frame is still with the offload: wait for it (the offload fails it if it hangs).
        if self.entries[idx].pending {
            return None;
        }
        // Wait for retransmit unless buffer is full or retransmits are disabled.
        if !no_resend && !self.entries[idx].available && (buflen as usize) < RAOP_BUFFER_LENGTH {
            return None;
        }

        self.first_seqnum = self.first_seqnum.wrapping_add(1);

        // Substitute silence for missing frames.
        if !self.entries[idx].available {
            let size = self.silence_samples.min(self.frame_capacity);
            self.entries[idx].audio_buffer[..size].fill(0);
            self.entries[idx].audio_buffer_len = size;
        }
        self.entries[idx].available = false;
        let len = self.entries[idx].audio_buffer_len;
        self.entries[idx].audio_buffer_len = 0;
        Some(&self.entries[idx].audio_buffer[..len])
    }

    /// Flush the buffer.
    ///
    /// If `next_seq` is a valid 16-bit value (0..=0xFFFF), the buffer resets to expect that sequence number next,
    /// and the frames from it on that are already here stay: a sender streams right after RECORD, so its first
    /// packets can be queued before the flush RECORD asks for (they played as silence). Otherwise the buffer is
    /// fully emptied.
    pub fn flush(&mut self, next_seq: i32) {
        let keep = (0..=0xffff).contains(&next_seq) && !self.is_empty;
        let ns = next_seq as u16;
        let (old_last, mut kept_last) = (self.last_seqnum, None);
        for entry in &mut self.entries {
            if keep
                && (entry.available || entry.pending)
                && seqnum_cmp(entry.seqnum, ns) >= 0
                && seqnum_cmp(entry.seqnum, old_last) <= 0
            {
                if kept_last.is_none_or(|k| seqnum_cmp(entry.seqnum, k) > 0) {
                    kept_last = Some(entry.seqnum);
                }
                continue;
            }
            entry.available = false;
            entry.pending = false;
            entry.audio_buffer_len = 0;
        }
        self.generation = self.generation.wrapping_add(1);
        if !(0..=0xffff).contains(&next_seq) {
            self.is_empty = true;
        } else {
            self.first_seqnum = ns;
            self.last_seqnum = kept_last.unwrap_or(ns.wrapping_sub(1));
        }
    }
}

#[cfg(test)]
mod offload_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Finishes packets only when told to; "decodes" a packet to samples equal to its sequence number.
    struct Mock {
        queue: Arc<Mutex<Vec<(u32, bool)>>>, // (tag, finished)
    }

    impl PacketOffload for Mock {
        fn submit(&mut self, tag: u32, _packet: &[u8]) -> bool {
            self.queue.lock().unwrap().push((tag, false));
            true
        }
        fn collect(&mut self, done: &mut dyn FnMut(u32, OffloadOutput<'_>)) {
            let mut q = self.queue.lock().unwrap();
            while let Some(&(tag, true)) = q.first() {
                let pcm = vec![(tag & 0xFFFF) as i16; 4];
                done(tag, OffloadOutput::Pcm(&pcm));
                q.remove(0);
            }
        }
        fn in_flight(&self) -> usize {
            self.queue.lock().unwrap().len()
        }
    }

    fn packet(seq: u16) -> Vec<u8> {
        let mut p = vec![0u8; 12 + 32];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p
    }

    /// What the mock offload was handed: (sequence number, decline).
    type Submitted = Arc<Mutex<Vec<(u32, bool)>>>;

    fn buffer() -> (RaopBuffer, Submitted) {
        let mut b =
            RaopBuffer::new_unencrypted("96 AppleLossless", "96 352 0 16 40 10 14 2 255 0 0 44100")
                .unwrap();
        let queue = Arc::new(Mutex::new(Vec::new()));
        let q2 = queue.clone();
        let factory: OffloadFactory = Arc::new(move |s: &OffloadStream| {
            assert!(matches!(s.cipher, OffloadCipher::None));
            assert_eq!(s.alac.unwrap().frame_length, 352);
            Some(Box::new(Mock { queue: q2.clone() }) as Box<dyn PacketOffload>)
        });
        b.set_offload(Some(&factory));
        (b, queue)
    }

    fn finish(q: &Arc<Mutex<Vec<(u32, bool)>>>, n: usize) {
        for e in q.lock().unwrap().iter_mut().take(n) {
            e.1 = true;
        }
    }

    #[test]
    fn pending_packets_are_waited_for_then_delivered_in_order() {
        let (mut b, q) = buffer();
        for seq in 10..13 {
            assert_eq!(b.queue(&packet(seq), true), 1);
        }
        assert_eq!(b.in_flight(), 3);
        // nothing finished: the head is pending, so no silence is substituted even without resends
        assert!(b.dequeue_s16(true).is_none());
        finish(&q, 2);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[10; 4]);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[11; 4]);
        assert!(b.dequeue_s16(true).is_none());
        finish(&q, 1);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[12; 4]);
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn results_from_before_a_flush_are_ignored() {
        let (mut b, q) = buffer();
        assert_eq!(b.queue(&packet(20), true), 1);
        b.flush(-1);
        // the same sequence number again after the flush: a new tag (generation)
        assert_eq!(b.queue(&packet(20), true), 1);
        finish(&q, 1); // the stale one finishes first: dropped
        assert!(b.dequeue_s16(true).is_none());
        finish(&q, 2);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[20; 4]);
    }

    #[test]
    fn a_flush_keeps_what_is_already_here_from_its_sequence_number_on() {
        // RECORD's flush to 31 arrives after the sender's first packets: 30 goes, 31 and 32 play
        let (mut b, q) = buffer();
        for seq in 30..33 {
            assert_eq!(b.queue(&packet(seq), true), 1);
        }
        b.flush(31);
        finish(&q, 3);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[31; 4]);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[32; 4]);
        assert!(b.dequeue_s16(true).is_none());
    }

    #[test]
    fn another_packet_under_a_pending_sequence_number_replaces_it() {
        // a sender's placeholder, then the frame: the placeholder's result is not taken for the frame
        let (mut b, q) = buffer();
        let mut placeholder = packet(40);
        placeholder.truncate(20);
        assert_eq!(b.queue(&placeholder, true), 1);
        assert_eq!(b.queue(&packet(40), true), 1);
        assert_eq!(q.lock().unwrap().len(), 2);
        finish(&q, 2);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[40; 4]);
        assert!(b.dequeue_s16(true).is_none());
    }

    #[test]
    fn a_placeholder_after_the_frame_does_not_replace_it() {
        let (mut b, q) = buffer();
        let mut placeholder = packet(50);
        placeholder.truncate(20);
        assert_eq!(b.queue(&packet(50), true), 1);
        assert_eq!(b.queue(&placeholder, true), 0);
        finish(&q, 1);
        assert_eq!(b.dequeue_s16(true).unwrap(), &[50; 4]);
    }

    #[test]
    fn a_duplicate_of_a_pending_packet_is_not_resubmitted() {
        let (mut b, q) = buffer();
        assert_eq!(b.queue(&packet(5), true), 1);
        assert_eq!(b.queue(&packet(5), true), 0);
        assert_eq!(q.lock().unwrap().len(), 1);
    }
}
