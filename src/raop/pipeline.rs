//! The stages every audio stream shares, between its source and the application's session:
//!
//! ```text
//! source -> Decoding: units in order through the stream's decoder (crate::decoder) -> Output: mixdown, resampling,
//! the session's format, the play time from the stream's Timeline
//! ```
//!
//! The sources differ: AirPlay 1 and AirPlay 2 realtime are RTP over UDP in sequence order ([`Reorder`], lost
//! packets asked for again), AirPlay 1 over TCP comes in order, AirPlay 2 buffered is TCP with frames queued until
//! they are due. What they hand on is the same: units (a packet, a frame) in order, each with the silence owed for
//! units before it that never came.
//!
//! [`Reorder`]: crate::raop::reorder::Reorder

use std::collections::VecDeque;

use crate::codec::Pcm;
use crate::decoder::{Cipher, Decoded, Decoder};
use crate::raop::{AudioFormat, AudioHandler, AudioSession, SampleFormat};

/// RTP fixed header length (bytes).
pub(crate) const RTP_HEADER_LEN: usize = 12;
/// AirPlay 2: the nonce's last 8 bytes after the ciphertext (bytes).
#[cfg(feature = "ap2-core")]
pub(crate) const NONCE_TRAIL_LEN: usize = 8;
/// AirPlay 2: the Poly1305 tag at the end of the ciphertext (bytes).
#[cfg(feature = "ap2-core")]
pub(crate) const POLY1305_TAG_LEN: usize = 16;

impl Cipher {
    /// A packet's payload in the clear; `None` if it is too short or (AirPlay 2) its tag doesn't check.
    pub(crate) fn open<'a>(&self, packet: &'a [u8]) -> Option<std::borrow::Cow<'a, [u8]>> {
        let payload = packet.get(RTP_HEADER_LEN..)?;
        match self {
            Cipher::None => Some(payload.into()),
            Cipher::Aes128Cbc { key, iv } => {
                use aes::cipher::{BlockModeDecrypt, KeyIvInit};
                let whole = payload.len() / 16 * 16;
                if whole == 0 {
                    return Some(payload.into());
                }
                let mut buf = payload.to_vec();
                cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
                    .decrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut buf[..whole])
                    .ok()?;
                Some(buf.into())
            }
            #[cfg(feature = "ap2-core")]
            Cipher::ChaCha20Poly1305 { key } => {
                use chacha20poly1305::KeyInit;
                decrypt_rtp_chacha(&chacha20poly1305::ChaCha20Poly1305::new(key.into()), packet)
                    .map(Into::into)
            }
        }
    }

    #[cfg(feature = "ap2-core")]
    /// Whether an AirPlay 2 packet is the sender's (its tag checks), without decrypting it: packets are
    /// authenticated before they go into the reorder stage, where anyone's would hold the stream up. The other
    /// ciphers authenticate nothing: true.
    pub(crate) fn authentic(&self, packet: &[u8]) -> bool {
        match self {
            Cipher::ChaCha20Poly1305 { key } => chacha_tag_checks(key, packet),
            _ => true,
        }
    }
}

/// Decrypt an AirPlay 2 RTP packet (ChaCha20-Poly1305): `[RTP header 12][ciphertext][tag 16][nonce tail 8]`, the
/// nonce `[0; 4] ++ tail`, the header's bytes 4..12 the AAD. `None` if it is too short or the tag fails.
#[cfg(feature = "ap2-core")]
pub(crate) fn decrypt_rtp_chacha(
    cipher: &chacha20poly1305::ChaCha20Poly1305,
    packet: &[u8],
) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, Payload};
    let n = packet.len();
    if n <= RTP_HEADER_LEN + NONCE_TRAIL_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&packet[n - NONCE_TRAIL_LEN..]);
    cipher
        .decrypt(
            chacha20poly1305::Nonce::from_slice(&nonce),
            Payload {
                msg: &packet[RTP_HEADER_LEN..n - NONCE_TRAIL_LEN],
                aad: &packet[4..12],
            },
        )
        .ok()
}

/// The Poly1305 tag of an AirPlay 2 RTP packet checked, the payload left encrypted (RFC 8439: the one-time key
/// from ChaCha20's block 0, over the AAD and the ciphertext padded to 16, then their lengths).
#[cfg(feature = "ap2-core")]
fn chacha_tag_checks(key: &[u8; 32], packet: &[u8]) -> bool {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use poly1305::universal_hash::{KeyInit, UniversalHash};
    let n = packet.len();
    if n < RTP_HEADER_LEN + POLY1305_TAG_LEN + NONCE_TRAIL_LEN {
        return false;
    }
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&packet[n - NONCE_TRAIL_LEN..]);
    let (aad, ct) = (
        &packet[4..12],
        &packet[RTP_HEADER_LEN..n - POLY1305_TAG_LEN - NONCE_TRAIL_LEN],
    );
    let tag = &packet[n - POLY1305_TAG_LEN - NONCE_TRAIL_LEN..n - NONCE_TRAIL_LEN];
    let mut one_time = zeroize::Zeroizing::new([0u8; 32]);
    chacha20::ChaCha20::new(key.into(), (&nonce).into()).apply_keystream(&mut *one_time);
    let mut mac = poly1305::Poly1305::new((&*one_time).into());
    mac.update_padded(aad);
    mac.update_padded(ct);
    let mut lengths = poly1305::Block::default();
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    mac.update(&[lengths]);
    subtle::ConstantTimeEq::ct_eq(mac.finalize().as_slice(), tag).into()
}

/// A waker that notifies `notify`: a decoder's "a unit is done" ([`Decoder::wake_on_done`]) for a receive loop's
/// select. A wake before the loop waits isn't lost (the notify keeps it).
pub(crate) fn notify_waker(notify: &std::sync::Arc<tokio::sync::Notify>) -> std::task::Waker {
    struct W(std::sync::Arc<tokio::sync::Notify>);
    impl std::task::Wake for W {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.notify_one();
        }
    }
    std::task::Waker::from(std::sync::Arc::new(W(notify.clone())))
}

/// One unit in the stream's decoder: sent, or received back.
struct Entry {
    seq: u32,
    ts: u32,
    /// Units of silence owed before it (lost ones the source gave up on)
    fill: u32,
    /// Decoded only to prime a lapped decoder: not played
    preroll: bool,
    /// Flushed while it was in the decoder: its samples are dropped when they come
    keep: bool,
    /// The samples once received (`None`: it didn't decrypt or decode)
    done: Option<Option<Pcm>>,
}

/// A unit out of the decoder, in order.
#[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
pub(crate) struct Unit {
    pub(crate) seq: u32,
    pub(crate) ts: u32,
    pub(crate) fill: u32,
    /// The samples; `None`: it didn't decrypt or decode
    pub(crate) pcm: Option<Pcm>,
    /// Decoded to prime the decoder after a discontinuity: not to be played
    pub(crate) preroll: bool,
}

/// A stream's decoding: its units into the decoder in order, with what the stream needs to know of each (its
/// sequence number and RTP time, the silence owed before it), and back out in order once decoded. The receiver
/// never waits on the decoder: what is done is taken as it is.
pub(crate) struct Decoding {
    decoder: Box<dyn Decoder>,
    queue: VecDeque<Entry>,
    /// A lapped codec (AAC): the first unit after a discontinuity in `seq` only primes it
    lapped: bool,
    next_seq: Option<u32>,
    seq_mask: u32,
}

impl Decoding {
    pub(crate) fn new(decoder: Box<dyn Decoder>) -> Self {
        Decoding {
            decoder,
            queue: VecDeque::new(),
            lapped: false,
            next_seq: None,
            seq_mask: u32::MAX,
        }
    }

    /// The codec is lapped (AAC): see [`Unit::preroll`]. Sequence numbers count modulo `seq_mask + 1`.
    #[cfg(feature = "ap2-core")]
    pub(crate) fn lapped(mut self, seq_mask: u32) -> Self {
        self.lapped = true;
        self.seq_mask = seq_mask;
        self
    }

    /// Units in the decoder that will come out (sent or done, not flushed).
    #[cfg(feature = "ap2-core")]
    pub(crate) fn len(&self) -> usize {
        self.queue.iter().filter(|e| e.keep).count()
    }

    /// Units sent and not back from the decoder yet.
    pub(crate) fn waiting(&self) -> bool {
        self.queue.iter().any(|e| e.done.is_none())
    }

    /// The decoder works in the background: units go to it ahead of their time ([`Decoder::background`]).
    #[cfg(feature = "ap2-core")]
    pub(crate) fn background(&self) -> bool {
        self.decoder.background()
    }

    /// Ask the decoder to wake `waker` when a unit is done; `false` if it can't tell (then look again shortly).
    pub(crate) fn wake_on_done(&mut self, waker: &std::task::Waker) -> bool {
        self.decoder.wake_on_done(waker)
    }

    /// A unit, after `fill` units of silence.
    pub(crate) fn push(&mut self, seq: u32, ts: u32, fill: u32, unit: &[u8]) {
        let preroll = self.lapped && self.next_seq != Some(seq);
        self.next_seq = Some(seq.wrapping_add(1) & self.seq_mask);
        self.decoder.send(unit);
        self.queue.push_back(Entry {
            seq,
            ts,
            fill,
            preroll,
            keep: true,
            done: None,
        });
    }

    /// What the decoder has done, into its entries (in order: they come back as they were sent).
    pub(crate) fn collect(&mut self) {
        while let Some(i) = self.queue.iter().position(|e| e.done.is_none()) {
            let Some(out) = self.decoder.receive() else {
                break;
            };
            let pcm = match out {
                Decoded::S16(s) => Some(Pcm::S16(s)),
                Decoded::S24(s) => Some(Pcm::S24(s)),
                Decoded::F32(s) => Some(Pcm::F32(s)),
                Decoded::Failed => None,
            };
            self.queue[i].done = Some(pcm);
        }
        // flushed units whose samples came: gone (the ones still out wait for theirs, to keep the order)
        while self
            .queue
            .front()
            .is_some_and(|e| !e.keep && e.done.is_some())
        {
            self.queue.pop_front();
        }
    }

    /// The next unit's RTP time and whether it is decoded, without taking it.
    #[cfg(feature = "ap2-core")]
    pub(crate) fn peek(&self) -> Option<(u32, bool)> {
        self.queue
            .iter()
            .find(|e| e.keep)
            .map(|e| (e.ts, e.done.is_some()))
    }

    /// The next unit, if it is decoded.
    pub(crate) fn pop(&mut self) -> Option<Unit> {
        self.collect();
        loop {
            self.queue.front()?.done.as_ref()?;
            let e = self.queue.pop_front()?;
            if !e.keep {
                continue; // flushed: its samples go
            }
            return Some(Unit {
                seq: e.seq,
                ts: e.ts,
                fill: e.fill,
                pcm: e.done.flatten(),
                preroll: e.preroll,
            });
        }
    }

    /// Drop the units `drop(seq, ts)` picks (those still in the decoder when their samples come).
    pub(crate) fn flush(&mut self, mut drop: impl FnMut(u32, u32) -> bool) {
        for e in self.queue.iter_mut() {
            if drop(e.seq, e.ts) {
                e.keep = false;
            }
        }
        self.queue.retain(|e| e.keep || e.done.is_none());
    }
}

/// What a stream's samples go out as: the builder's output options.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OutputConfig {
    /// Resample to this rate, or play at the stream's
    pub(crate) sample_rate: Option<u32>,
    /// Mix down to at most this many channels
    pub(crate) max_channels: Option<u8>,
    /// The session's sample format
    pub(crate) format: SampleFormat,
}

/// A stream's source format.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Source {
    pub(crate) sample_rate: u32,
    pub(crate) channels: u8,
    pub(crate) bits: u8,
}

/// The application's session for one stream: the samples shaped (mixdown, resampling) and in its format, with their
/// play times. When it goes, what the session still holds is flushed (the stream stopped: its queued audio is not to
/// play), unless it was [`finish`](Self::finish)ed.
pub(crate) struct Output {
    session: Option<Box<dyn AudioSession>>,
    format: AudioFormat,
    src_channels: u8,
    /// Silence took the place of missing audio: what comes next fades in
    fade_in: bool,
    #[cfg(feature = "resample")]
    resampler: Option<crate::codec::resample::StreamResampler>,
}

/// Frames audio fades in over after silence that took the place of missing audio (5.8 ms at 44.1 kHz).
const FADE_IN: usize = 256;

impl Output {
    /// The handler's session for a stream from `source`.
    pub(crate) fn new(handler: &dyn AudioHandler, source: Source, config: &OutputConfig) -> Self {
        let channels = config
            .max_channels
            .map_or(source.channels, |m| source.channels.min(m.max(1)));
        let rate = config.sample_rate.unwrap_or(source.sample_rate);
        #[cfg(feature = "resample")]
        let resampler = (rate != source.sample_rate)
            .then(|| {
                crate::codec::resample::StreamResampler::new(
                    source.sample_rate,
                    rate,
                    channels as usize,
                )
            })
            .flatten();
        #[cfg(not(feature = "resample"))]
        let rate = {
            if rate != source.sample_rate {
                tracing::warn!(
                    from = source.sample_rate,
                    to = rate,
                    "Resampling needs the resample feature; playing at the stream's rate"
                );
            }
            source.sample_rate
        };
        let format = AudioFormat {
            format: config.format.resolve(source.bits),
            channels,
            sample_rate: rate,
        };
        tracing::info!(?format, ?source, "Audio session initialized");
        Output {
            session: Some(handler.audio_init(format)),
            format,
            src_channels: source.channels,
            fade_in: false,
            #[cfg(feature = "resample")]
            resampler,
        }
    }

    /// Samples to the session, to play at `play_at_ns` if the stream is on a timeline.
    pub(crate) fn play(&mut self, mut pcm: Pcm, play_at_ns: Option<u64>) {
        if std::mem::take(&mut self.fade_in) {
            pcm.fade_in(usize::from(self.src_channels), FADE_IN);
        }
        let pcm = crate::codec::shape(
            pcm,
            self.src_channels,
            self.format.channels,
            #[cfg(feature = "resample")]
            &mut self.resampler,
        );
        if let Some(s) = self.session.as_mut() {
            pcm.deliver(s.as_mut(), self.format.format, play_at_ns);
        }
    }

    /// `frames` frames of silence (lost audio, played so the output's queue keeps its length); what plays next
    /// fades in. On a timeline lost audio needs none: the next play time leaves the hole.
    pub(crate) fn silence(&mut self, frames: usize, play_at_ns: Option<u64>) {
        if frames > 0 {
            let n = frames * usize::from(self.src_channels);
            self.play(Pcm::S16(vec![0; n]), play_at_ns);
            self.fade_in = true;
        }
    }

    /// What the session holds goes (a flush, a pause).
    pub(crate) fn flush(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.audio_flush();
        }
    }

    /// The session goes without a flush: what it holds still plays (a new format follows on).
    #[cfg(feature = "ap2-core")]
    pub(crate) fn finish(mut self) {
        self.session = None;
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Where a stream's RTP times fall on the local clock ([`now_ns`](crate::util::now_ns)'s).
#[cfg(feature = "ap2-core")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Timeline {
    /// RTP time `rtp` plays at network time `net_ns` of PTP clock `clock` (local once the clock is followed)
    Network { clock: u64, net_ns: u64, rtp: u32 },
    /// No followed clock: RTP time `rtp` plays at local time `local_ns`
    Local { local_ns: u64, rtp: u32 },
}

#[cfg(feature = "ap2-core")]
impl Timeline {
    /// The local time RTP time `ts` plays at, `offset_ns` later, at `rate` frames a second; `None` until the
    /// network clock is followed.
    pub(crate) fn play_at(self, ts: u32, rate: u32, offset_ns: i64) -> Option<u64> {
        let rate = i128::from(rate.max(1));
        let at = |base: u64, rtp: u32| {
            let frames = i128::from(ts.wrapping_sub(rtp) as i32);
            (i128::from(base) + i128::from(offset_ns) + frames * 1_000_000_000 / rate).max(0) as u64
        };
        match self {
            Timeline::Network { clock, net_ns, rtp } => {
                crate::net::ptp::follower().to_local(clock, at(net_ns, rtp))
            }
            Timeline::Local { local_ns, rtp } => Some(at(local_ns, rtp)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Jobs = Arc<Mutex<VecDeque<(u8, bool)>>>; // (value, finished)

    /// Works in the background: a unit is done when the test says; "decodes" it to 4 samples of its first byte (a
    /// one-byte unit doesn't decode).
    struct Background {
        jobs: Jobs,
    }

    impl Decoder for Background {
        fn send(&mut self, unit: &[u8]) {
            let v = if unit.len() > 1 { unit[0] } else { 0 };
            self.jobs.lock().unwrap().push_back((v, false));
        }
        fn receive(&mut self) -> Option<Decoded> {
            let mut q = self.jobs.lock().unwrap();
            let &(v, true) = q.front()? else {
                return None;
            };
            q.pop_front();
            if v == 0 {
                return Some(Decoded::Failed);
            }
            Some(Decoded::S16(vec![i16::from(v); 4]))
        }
        fn background(&self) -> bool {
            true
        }
    }

    fn decoding() -> (Decoding, Jobs) {
        let jobs = Jobs::default();
        let d = Decoding::new(Box::new(Background { jobs: jobs.clone() }));
        (d, jobs)
    }

    fn finish(q: &Jobs, n: usize) {
        for e in q.lock().unwrap().iter_mut().take(n) {
            e.1 = true;
        }
    }

    fn out(d: &mut Decoding) -> Vec<Option<i16>> {
        std::iter::from_fn(|| d.pop())
            .map(|u| u.pcm.map(|p| p.into_s16()[0]))
            .collect()
    }

    #[test]
    fn units_come_out_in_order_when_done() {
        let (mut d, q) = decoding();
        d.push(0, 0, 0, &[10, 0]);
        d.push(1, 0, 0, &[11]); // doesn't decode
        d.push(2, 0, 0, &[12, 0]);
        assert!(out(&mut d).is_empty() && d.waiting());
        finish(&q, 2);
        assert_eq!(out(&mut d), [Some(10), None]);
        finish(&q, 1);
        assert_eq!(out(&mut d), [Some(12)]);
        assert!(!d.waiting());
    }

    #[test]
    fn flushed_units_samples_are_dropped_wherever_they_are() {
        let (mut d, q) = decoding();
        for k in 20..24u8 {
            d.push(u32::from(k), 0, 0, &[k, 0]);
        }
        d.flush(|seq, _| seq == 20 || seq == 22); // the first, and one in the middle
        finish(&q, 4);
        assert_eq!(out(&mut d), [Some(21), Some(23)]);
        d.flush(|_, _| true);
        d.push(24, 0, 0, &[24, 0]);
        finish(&q, 1);
        assert_eq!(out(&mut d), [Some(24)]);
    }

    #[cfg(feature = "ap2-core")]
    #[test]
    fn after_a_discontinuity_a_lapped_decoders_first_unit_only_primes_it() {
        let (d, q) = decoding();
        let mut d = d.lapped(0x7F_FFFF);
        for seq in [5, 6, 9, 10] {
            d.push(seq, 0, 0, &[seq as u8, 0]);
        }
        finish(&q, 4);
        let preroll: Vec<bool> = std::iter::from_fn(|| d.pop()).map(|u| u.preroll).collect();
        assert_eq!(preroll, [true, false, true, false]);
    }

    #[cfg(feature = "ap2-core")]
    #[test]
    fn the_tag_is_checked_without_decrypting() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let key = [7u8; 32];
        let header = [0x80, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        let tail = [9u8; 8];
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&tail);
        let ct = chacha20poly1305::ChaCha20Poly1305::new((&key).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: b"alac payload bytes",
                    aad: &header[4..12],
                },
            )
            .unwrap();
        let packet = [&header[..], &ct, &tail].concat();
        let cipher = Cipher::ChaCha20Poly1305 { key };
        assert!(cipher.authentic(&packet));
        assert_eq!(
            cipher.open(&packet).as_deref(),
            Some(&b"alac payload bytes"[..])
        );
        for i in [4, 12, packet.len() - 9, packet.len() - 1] {
            let mut bad = packet.clone();
            bad[i] ^= 1;
            assert!(!cipher.authentic(&bad), "byte {i} changed");
        }
        assert!(!cipher.authentic(&packet[..30]));
    }

    #[test]
    fn aes_cbc_leaves_the_tail_in_the_clear() {
        use aes::cipher::{BlockModeEncrypt, KeyIvInit};
        let (key, iv) = ([1u8; 16], [2u8; 16]);
        let plain: Vec<u8> = (0..37).collect();
        let mut enc = plain.clone();
        cbc::Encryptor::<aes::Aes128>::new((&key).into(), (&iv).into())
            .encrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut enc[..32], 32)
            .unwrap();
        let packet = [&[0u8; 12][..], &enc].concat();
        let cipher = Cipher::Aes128Cbc { key, iv };
        assert_eq!(cipher.open(&packet).as_deref(), Some(&plain[..]));
    }
}
