//! The stages every audio stream shares, between its source and the application's session:
//!
//! ```text
//! source -> (decrypt) -> Decoder: in order, the offload first, the library's decoder for the rest -> Output: mixdown,
//! resampling, the session's format, the play time from the stream's Timeline
//! ```
//!
//! The sources differ: AirPlay 1 and AirPlay 2 realtime are RTP over UDP in sequence order ([`Reorder`], lost
//! packets asked for again), AirPlay 1 over TCP comes in order, AirPlay 2 buffered is TCP with frames queued until
//! they are due. What they hand on is the same: units (a packet, a frame) in order, each with the silence owed for
//! units before it that never came.
//!
//! [`Reorder`]: crate::raop::reorder::Reorder

use std::collections::VecDeque;

use crate::codec::{Decode, Pcm};
use crate::raop::offload::{Decoded, Offload};
use crate::raop::{AudioFormat, AudioHandler, AudioSession, SampleFormat};

/// RTP fixed header length (bytes).
pub(crate) const RTP_HEADER_LEN: usize = 12;
/// AirPlay 2: the nonce's last 8 bytes after the ciphertext (bytes).
#[cfg(feature = "ap2-core")]
pub(crate) const NONCE_TRAIL_LEN: usize = 8;
/// AirPlay 2: the Poly1305 tag at the end of the ciphertext (bytes).
#[cfg(feature = "ap2-core")]
pub(crate) const POLY1305_TAG_LEN: usize = 16;

/// How a stream's RTP payloads are encrypted.
#[derive(Clone)]
pub(crate) enum RtpCipher {
    /// In the clear
    None,
    /// AirPlay 1: AES-128-CBC over the payload's whole 16-byte blocks, the IV reset for every packet; a tail of fewer
    /// than 16 bytes in the clear.
    Aes128Cbc { key: [u8; 16], iv: [u8; 16] },
    /// AirPlay 2: ChaCha20-Poly1305, `[RTP header 12][ciphertext][tag 16][nonce tail 8]`, nonce `[0; 4] ++ tail`, the
    /// header's bytes 4..12 authenticated.
    #[cfg(feature = "ap2-core")]
    ChaCha20Poly1305 { key: [u8; 32] },
}

impl RtpCipher {
    /// What an offload is told of it.
    pub(crate) fn offload(&self) -> crate::raop::offload::OffloadCipher {
        use crate::raop::offload::OffloadCipher;
        match *self {
            RtpCipher::None => OffloadCipher::None,
            RtpCipher::Aes128Cbc { key, iv } => OffloadCipher::Aes128Cbc { key, iv },
            #[cfg(feature = "ap2-core")]
            RtpCipher::ChaCha20Poly1305 { key } => OffloadCipher::ChaCha20Poly1305 { key },
        }
    }

    /// A packet's payload in the clear; `None` if it is too short or (AirPlay 2) its tag doesn't check.
    pub(crate) fn open<'a>(&self, packet: &'a [u8]) -> Option<std::borrow::Cow<'a, [u8]>> {
        let payload = packet.get(RTP_HEADER_LEN..)?;
        match self {
            RtpCipher::None => Some(payload.into()),
            RtpCipher::Aes128Cbc { key, iv } => {
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
            RtpCipher::ChaCha20Poly1305 { key } => {
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
            #[cfg(feature = "ap2-core")]
            RtpCipher::ChaCha20Poly1305 { key } => chacha_tag_checks(key, packet),
            _ => {
                let _ = packet;
                true
            }
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

/// The library's decoding of an RTP packet: decrypt, then the codec.
pub(crate) struct RtpDecode {
    pub(crate) cipher: RtpCipher,
    pub(crate) codec: Box<dyn Decode>,
}

impl RtpDecode {
    /// The codec alone, for a payload the offload decrypted ([`Decoded::Plain`]).
    fn decode_plain(&mut self, payload: &[u8]) -> Option<Pcm> {
        self.codec.decode(payload)
    }
}

impl Decode for RtpDecode {
    fn decode(&mut self, packet: &[u8]) -> Option<Pcm> {
        let payload = self.cipher.open(packet)?;
        self.codec.decode(&payload)
    }
}

/// A waker that notifies `notify`: an offload's "a unit is done" ([`Decoder::wake_on_done`]) for a receive loop's
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

/// A decoder that decodes nothing: a stream whose decoder couldn't be made plays nothing rather than failing.
#[cfg(feature = "ap2-core")]
pub(crate) struct NoDecoder;

#[cfg(feature = "ap2-core")]
impl Decode for NoDecoder {
    fn decode(&mut self, _: &[u8]) -> Option<Pcm> {
        None
    }
}

/// How a stream's units are decoded when the offload doesn't take them.
pub(crate) enum Library {
    /// RTP packets (AirPlay 1, AirPlay 2 realtime): decrypted and decoded here
    Packets(RtpDecode),
    /// Frames in the clear (AirPlay 2 buffered)
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
    Frames(Box<dyn Decode>),
    /// None: the offload decodes everything, what it doesn't take ahead too (`Offload::decode`: the application's
    /// AAC decoder)
    #[cfg(feature = "ap2-core")]
    Offload,
}

/// One unit in the decoder: submitted to the offload, or decoded.
struct Entry {
    tag: u32,
    seq: u32,
    ts: u32,
    /// Units of silence owed before it (lost ones the source gave up on)
    fill: u32,
    len: usize,
    /// Decoded only to prime a lapped decoder: not played
    preroll: bool,
    state: State,
}

enum State {
    Pending,
    Done(Option<Pcm>),
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

/// A stream's decoding, in order: each unit goes to the offload when it takes it, else to the library's decoder at
/// once; finished units come out in the order they went in, whichever decoded them. The receiving thread never
/// waits on the offload: results are collected as they are ready.
pub(crate) struct Decoder {
    offload: Option<Box<dyn Offload>>,
    library: Library,
    queue: VecDeque<Entry>,
    next_tag: u32,
    /// A lapped codec (AAC): the first unit after a discontinuity in `seq` only primes it
    lapped: bool,
    next_seq: Option<u32>,
    seq_mask: u32,
    /// AirPlay 1's late packets: a unit that came out empty may be replaced by a later one under its sequence
    /// number, so an empty one is held until a unit after it has decoded
    replaceable: bool,
}

impl Decoder {
    pub(crate) fn new(offload: Option<Box<dyn Offload>>, library: Library) -> Self {
        Decoder {
            offload,
            library,
            queue: VecDeque::new(),
            next_tag: 0,
            lapped: false,
            next_seq: None,
            seq_mask: u32::MAX,
            replaceable: false,
        }
    }

    #[cfg(feature = "ap2-core")]
    /// The codec is lapped (AAC): see [`Unit::preroll`]. Sequence numbers count modulo `seq_mask + 1`.
    pub(crate) fn lapped(mut self, seq_mask: u32) -> Self {
        self.lapped = true;
        self.seq_mask = seq_mask;
        self
    }

    /// Late units may replace empty ones: see [`replace`](Self::replace).
    pub(crate) fn replaceable(mut self) -> Self {
        self.replaceable = true;
        self
    }

    #[cfg(feature = "ap2-core")]
    pub(crate) fn has_offload(&self) -> bool {
        self.offload.is_some()
    }

    #[cfg(feature = "ap2-core")]
    /// Units in the decoder (submitted, or decoded and not out yet).
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    /// Units with the offload.
    pub(crate) fn waiting(&self) -> bool {
        self.queue.iter().any(|e| matches!(e.state, State::Pending))
    }

    /// Ask the offload to wake `waker` when a unit finishes; `false` if it can't tell (then look again shortly).
    pub(crate) fn wake_on_done(&mut self, waker: &std::task::Waker) -> bool {
        self.offload.as_mut().is_some_and(|o| o.wake_on_done(waker))
    }

    /// The decoder's next tag.
    fn tag(&mut self) -> u32 {
        let t = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        t
    }

    /// A unit, after `fill` units of silence. `true`: the offload took it; `false`: decoded here, now.
    pub(crate) fn push(&mut self, seq: u32, ts: u32, fill: u32, unit: &[u8]) -> bool {
        let preroll = self.lapped && self.next_seq != Some(seq);
        self.next_seq = Some(seq.wrapping_add(1) & self.seq_mask);
        let tag = self.tag();
        let (taken, state) = self.start(tag, unit);
        self.queue.push_back(Entry {
            tag,
            seq,
            ts,
            fill,
            len: unit.len(),
            preroll,
            state,
        });
        taken
    }

    fn start(&mut self, tag: u32, unit: &[u8]) -> (bool, State) {
        if let Some(o) = self.offload.as_mut()
            && o.submit(tag, unit)
        {
            return (true, State::Pending);
        }
        (false, State::Done(self.decode_now(unit)))
    }

    /// A unit the offload didn't take, decoded now.
    fn decode_now(&mut self, unit: &[u8]) -> Option<Pcm> {
        match &mut self.library {
            Library::Packets(d) => d.decode(unit),
            Library::Frames(d) => d.decode(unit),
            #[cfg(feature = "ap2-core")]
            Library::Offload => self.offload.as_mut()?.decode(unit).map(Pcm::S16),
        }
    }

    /// AirPlay 1: a packet under sequence number `seq` came again (the reorder stage had let one through). A sender
    /// may open with placeholders under the first sequence numbers and send the frames under the same numbers after
    /// them: one that is here and came out empty is replaced, one with the offload by a longer packet (with a new
    /// tag: the placeholder's result is not taken for it); a decoded one stays. `false`: not taken.
    pub(crate) fn replace(&mut self, seq: u32, unit: &[u8]) -> bool {
        let Some(i) = self.queue.iter().position(|e| e.seq == seq) else {
            return false;
        };
        let replace = match &self.queue[i].state {
            State::Done(Some(_)) => false,
            State::Done(None) => true,
            State::Pending => unit.len() > self.queue[i].len,
        };
        if !replace {
            return false;
        }
        let tag = self.tag();
        let (_, state) = self.start(tag, unit);
        let e = &mut self.queue[i];
        (e.tag, e.len, e.state) = (tag, unit.len(), state);
        true
    }

    /// Finished units from the offload into their entries.
    pub(crate) fn collect(&mut self) {
        let Some(mut off) = self.offload.take() else {
            return;
        };
        let mut done: Vec<(u32, Decoded2)> = Vec::new();
        off.collect(&mut |tag, out| {
            done.push((
                tag,
                match out {
                    Decoded::S16(s) => Decoded2::Pcm(Pcm::S16(s.to_vec())),
                    Decoded::S24(s) => Decoded2::Pcm(Pcm::S24(s.to_vec())),
                    Decoded::Plain(p) => Decoded2::Plain(p.to_vec()),
                    Decoded::Failed => Decoded2::Failed,
                },
            ));
        });
        self.offload = Some(off);
        for (tag, out) in done {
            let pcm = match out {
                Decoded2::Pcm(p) => Some(p),
                Decoded2::Plain(p) => match &mut self.library {
                    Library::Packets(d) => d.decode_plain(&p),
                    _ => None,
                },
                Decoded2::Failed => None,
            };
            // a unit flushed, or replaced, while it was out: its result is dropped
            if let Some(e) = self
                .queue
                .iter_mut()
                .find(|e| e.tag == tag && matches!(e.state, State::Pending))
            {
                e.state = State::Done(pcm);
            }
        }
    }

    #[cfg(feature = "ap2-core")]
    /// The next unit's RTP time and whether it is decoded, without taking it.
    pub(crate) fn peek(&self) -> Option<(u32, bool)> {
        self.queue
            .front()
            .map(|e| (e.ts, matches!(e.state, State::Done(_))))
    }

    /// The next unit, if it is decoded (see [`replaceable`](Self::replaceable) for the empty ones it holds).
    pub(crate) fn pop(&mut self) -> Option<Unit> {
        self.collect();
        let head = self.queue.front()?;
        match &head.state {
            State::Pending => return None,
            State::Done(None)
                if self.replaceable
                    && !self
                        .queue
                        .iter()
                        .skip(1)
                        .any(|e| matches!(e.state, State::Done(Some(_)))) =>
            {
                return None;
            }
            State::Done(_) => {}
        }
        let e = self.queue.pop_front()?;
        let State::Done(pcm) = e.state else {
            return None;
        };
        Some(Unit {
            seq: e.seq,
            ts: e.ts,
            fill: e.fill,
            pcm,
            preroll: e.preroll,
        })
    }

    /// Drop the units `drop(seq, ts)` picks; their results, if they are out, are ignored when they come.
    pub(crate) fn flush(&mut self, mut drop: impl FnMut(u32, u32) -> bool) {
        self.queue.retain(|e| !drop(e.seq, e.ts));
    }
}

/// [`Decoded`] with the buffers copied out of the offload.
enum Decoded2 {
    Pcm(Pcm),
    Plain(Vec<u8>),
    Failed,
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
    #[cfg(feature = "resample")]
    resampler: Option<crate::codec::resample::StreamResampler>,
}

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
            #[cfg(feature = "resample")]
            resampler,
        }
    }

    /// Samples to the session, to play at `play_at_ns` if the stream is on a timeline.
    pub(crate) fn play(&mut self, pcm: Pcm, play_at_ns: Option<u64>) {
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

    /// `frames` frames of silence (lost audio, played so the output's queue keeps its length).
    pub(crate) fn silence(&mut self, frames: usize, play_at_ns: Option<u64>) {
        if frames > 0 {
            let n = frames * usize::from(self.src_channels);
            self.play(Pcm::S16(vec![0; n]), play_at_ns);
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

    /// "Decodes" a unit to 4 samples of its first byte; an empty unit doesn't decode.
    struct Bytes;
    impl Decode for Bytes {
        fn decode(&mut self, unit: &[u8]) -> Option<Pcm> {
            unit.first()
                .filter(|_| unit.len() > 1)
                .map(|&b| Pcm::S16(vec![i16::from(b); 4]))
        }
    }

    /// Takes units, finishes them only when told; "decodes" a unit to 4 samples of its first byte.
    struct Mock(Arc<Mutex<VecDeque<(u32, u8, bool)>>>); // (tag, value, finished)

    impl Offload for Mock {
        fn submit(&mut self, tag: u32, unit: &[u8]) -> bool {
            if unit.len() == 1 {
                return false; // declined: the library decodes it
            }
            self.0.lock().unwrap().push_back((tag, unit[0], false));
            true
        }
        fn collect(&mut self, done: &mut dyn FnMut(u32, Decoded<'_>)) {
            let mut q = self.0.lock().unwrap();
            while let Some(&(tag, v, true)) = q.front() {
                done(tag, Decoded::S16(&[i16::from(v); 4]));
                q.pop_front();
            }
        }
        fn in_flight(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    type Queue = Arc<Mutex<VecDeque<(u32, u8, bool)>>>;

    fn decoder() -> (Decoder, Queue) {
        let q = Queue::default();
        let d = Decoder::new(
            Some(Box::new(Mock(q.clone()))),
            Library::Frames(Box::new(Bytes)),
        );
        (d, q)
    }

    fn finish(q: &Queue, n: usize) {
        for e in q.lock().unwrap().iter_mut().take(n) {
            e.2 = true;
        }
    }

    fn out(d: &mut Decoder) -> Vec<Option<i16>> {
        std::iter::from_fn(|| d.pop())
            .map(|u| u.pcm.map(|p| p.into_s16()[0]))
            .collect()
    }

    #[test]
    fn units_come_out_in_order_whoever_decodes_them() {
        let (mut d, q) = decoder();
        assert!(d.push(0, 0, 0, &[10, 0]));
        assert!(!d.push(1, 0, 0, &[11])); // declined: decoded here, now, but waits for 10
        assert!(d.push(2, 0, 0, &[12, 0]));
        assert!(out(&mut d).is_empty() && d.waiting());
        finish(&q, 1);
        // 11 alone came out empty (one byte: Bytes doesn't decode it)
        assert_eq!(out(&mut d), [Some(10), None]);
        finish(&q, 2);
        assert_eq!(out(&mut d), [Some(12)]);
        assert!(!d.waiting());
    }

    #[test]
    fn results_of_flushed_units_are_dropped() {
        let (mut d, q) = decoder();
        d.push(20, 0, 0, &[20, 0]);
        d.flush(|seq, _| seq < 21);
        d.push(21, 0, 0, &[21, 0]);
        finish(&q, 2);
        assert_eq!(out(&mut d), [Some(21)]);
    }

    #[test]
    fn a_placeholder_is_replaced_by_the_frame_a_decoded_frame_is_not() {
        let (mut d, q) = decoder();
        let mut d2 = Decoder::new(None, Library::Frames(Box::new(Bytes))).replaceable();
        // with the offload: the longer packet replaces the pending placeholder; its result isn't taken for the frame
        d = d.replaceable();
        d.push(40, 0, 0, &[1, 0]);
        assert!(d.replace(40, &[40, 0, 0]));
        assert!(!d.replace(40, &[41, 0])); // shorter: no
        finish(&q, 2);
        assert_eq!(out(&mut d), [Some(40)]);
        // in software: an empty one waits for a unit after it, and may be replaced meanwhile
        d2.push(1, 0, 0, &[9]);
        assert!(out(&mut d2).is_empty(), "held: it may be a placeholder");
        assert!(d2.replace(1, &[1, 0]));
        d2.push(2, 0, 0, &[2, 0]);
        assert!(!d2.replace(2, &[3, 0])); // decoded: stays
        d2.push(3, 0, 0, &[7]); // a bad unit mid-stream ...
        d2.push(4, 0, 0, &[4, 0]); // ... comes out empty once one after it decodes
        assert_eq!(out(&mut d2), [Some(1), Some(2), None, Some(4)]);
    }

    #[cfg(feature = "ap2-core")]
    #[test]
    fn after_a_discontinuity_a_lapped_decoders_first_unit_only_primes_it() {
        let mut d = Decoder::new(None, Library::Frames(Box::new(Bytes))).lapped(0x7F_FFFF);
        for seq in [5, 6, 9, 10] {
            d.push(seq, 0, 0, &[seq as u8, 0]);
        }
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
        let cipher = RtpCipher::ChaCha20Poly1305 { key };
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
        let cipher = RtpCipher::Aes128Cbc { key, iv };
        assert_eq!(cipher.open(&packet).as_deref(), Some(&plain[..]));
    }
}
