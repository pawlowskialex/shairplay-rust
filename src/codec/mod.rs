//! Audio codec implementations (ALAC, AAC, resampling).

pub(crate) mod alac;
#[cfg(feature = "resample")]
pub(crate) mod resample;

#[cfg(feature = "ap2-core")]
pub(crate) mod aac;

use crate::raop::{AudioSession, SampleFormat};

#[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
/// Decoded interleaved PCM in whichever format the decoder produced. The pipelines carry it as is
/// and convert once, at delivery, to the session's [`SampleFormat`] (or to f32 where mixdown or
/// resampling needs it), so an integer decoder feeding an S16 session never touches floating point.
#[derive(Debug, Clone)]
pub(crate) enum Pcm {
    F32(Vec<f32>),
    S16(Vec<i16>),
    /// 24-bit samples, sign-extended (24-bit ALAC)
    S24(Vec<i32>),
}

#[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
impl Pcm {
    pub(crate) fn into_f32(self) -> Vec<f32> {
        match self {
            Pcm::F32(v) => v,
            Pcm::S16(v) => v.iter().map(|&s| s as f32 / 32768.0).collect(),
            Pcm::S24(v) => v.iter().map(|&s| s as f32 / 8_388_608.0).collect(),
        }
    }

    pub(crate) fn into_s16(self) -> Vec<i16> {
        match self {
            Pcm::S16(v) => v,
            Pcm::F32(v) => v
                .iter()
                .map(|&x| (x.clamp(-1.0, 1.0) * 32767.0) as i16)
                .collect(),
            // rounded to the nearest 16-bit value (no float on the way)
            Pcm::S24(v) => v
                .iter()
                .map(|&s| ((s + 128) >> 8).clamp(-32768, 32767) as i16)
                .collect(),
        }
    }

    /// 32-bit samples, the sample in the top bits (no float on the way from integer ones).
    pub(crate) fn into_s32(self) -> Vec<i32> {
        match self {
            Pcm::S16(v) => v.iter().map(|&s| (s as i32) << 16).collect(),
            Pcm::S24(v) => v.iter().map(|&s| s << 8).collect(),
            Pcm::F32(v) => v
                .iter()
                .map(|&x| (x.clamp(-1.0, 1.0) as f64 * 2_147_483_647.0) as i32)
                .collect(),
        }
    }

    /// 16-bit little-endian PCM bytes (what the ALAC decoder writes) as samples.
    pub(crate) fn from_s16le(bytes: &[u8]) -> Self {
        Pcm::S16(
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| i16::from_le_bytes(*c))
                .collect(),
        )
    }

    /// Hand the samples to the session with the time they should play (16-bit sessions; others untimed).
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
    pub(crate) fn deliver_timed(
        self,
        session: &mut dyn AudioSession,
        format: SampleFormat,
        play_at_ns: Option<u64>,
    ) {
        match (play_at_ns, format) {
            (Some(t), SampleFormat::S16 | SampleFormat::Integer) => {
                session.audio_process_timed_s16(&self.into_s16(), t)
            }
            (Some(t), SampleFormat::S32) => session.audio_process_timed_s32(&self.into_s32(), t),
            _ => self.deliver(session, format),
        }
    }

    /// Hand the samples to the session in its format (`Integer` unresolved: as `S16`).
    pub(crate) fn deliver(self, session: &mut dyn AudioSession, format: SampleFormat) {
        match (self, format) {
            (Pcm::S16(v), SampleFormat::S16 | SampleFormat::Integer) => {
                session.audio_process_s16(&v)
            }
            (Pcm::F32(v), SampleFormat::F32) => session.audio_process(&v),
            (p, SampleFormat::S16 | SampleFormat::Integer) => {
                session.audio_process_s16(&p.into_s16())
            }
            (p, SampleFormat::S32) => session.audio_process_s32(&p.into_s32()),
            (p, SampleFormat::F32) => session.audio_process(&p.into_f32()),
        }
    }
}

#[cfg(feature = "ap2-core")]
/// Mixdown and resampling for the AP2 pipelines, applied only when the output needs them; otherwise
/// the samples pass through untouched (and stay integer).
pub(crate) fn shape(
    pcm: Pcm,
    src_channels: u8,
    out_channels: u8,
    #[cfg(feature = "resample")] resampler: &mut Option<resample::StreamResampler>,
) -> Pcm {
    #[cfg(feature = "resample")]
    let resampling = resampler.is_some();
    #[cfg(not(feature = "resample"))]
    let resampling = false;
    if src_channels <= out_channels && !resampling {
        return pcm;
    }
    #[cfg(feature = "resample")]
    {
        Pcm::F32(resample::mixdown_and_resample(
            pcm.into_f32(),
            src_channels,
            out_channels,
            resampler,
        ))
    }
    #[cfg(not(feature = "resample"))]
    {
        Pcm::F32(mixdown(
            &pcm.into_f32(),
            src_channels as usize,
            out_channels as usize,
        ))
    }
}

#[cfg(any(feature = "ap2-core", feature = "resample"))]
/// ITU-R BS.775 downmix coefficient (−3 dB) applied to centre and surround
/// channels when folding 5.1/7.1 into stereo.
const DOWNMIX_3DB: f32 = 0.707;

#[cfg(any(feature = "ap2-core", feature = "resample"))]
/// Mix down multi-channel F32 audio to fewer channels.
/// Uses ITU-R BS.775 downmix coefficients for 5.1 and 7.1.
pub(crate) fn mixdown(input: &[f32], in_channels: usize, out_channels: usize) -> Vec<f32> {
    if in_channels == out_channels {
        return input.to_vec();
    }
    if out_channels != 2 {
        return input.to_vec();
    }

    let frames = input.len() / in_channels;
    let mut output = Vec::with_capacity(frames * 2);
    let k: f32 = DOWNMIX_3DB;

    for frame in input.chunks_exact(in_channels) {
        let (l, r) = match in_channels {
            6 => {
                let fl = frame[0];
                let fr = frame[1];
                let fc = frame[2];
                let rl = frame[4];
                let rr = frame[5];
                (fl + k * fc + k * rl, fr + k * fc + k * rr)
            }
            8 => {
                let fl = frame[0];
                let fr = frame[1];
                let fc = frame[2];
                let sl = frame[4];
                let sr = frame[5];
                let rl = frame[6];
                let rr = frame[7];
                (fl + k * fc + k * sl + k * rl, fr + k * fc + k * sr + k * rr)
            }
            _ => (frame[0], frame.get(1).copied().unwrap_or(frame[0])),
        };
        output.push(l.clamp(-1.0, 1.0));
        output.push(r.clamp(-1.0, 1.0));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Got {
        s16: Vec<i16>,
        s32: Vec<i32>,
        timed: Option<u64>,
    }
    impl AudioSession for Got {
        fn audio_process(&mut self, _: &[f32]) {
            panic!("float delivery");
        }
        fn audio_process_s16(&mut self, s: &[i16]) {
            self.s16.extend_from_slice(s);
        }
        fn audio_process_s32(&mut self, s: &[i32]) {
            self.s32.extend_from_slice(s);
        }
        fn audio_process_timed_s32(&mut self, s: &[i32], at: u64) {
            self.timed = Some(at);
            self.audio_process_s32(s);
        }
    }

    #[test]
    fn integer_follows_the_source_depth() {
        assert_eq!(SampleFormat::Integer.resolve(16), SampleFormat::S16);
        assert_eq!(SampleFormat::Integer.resolve(24), SampleFormat::S32);
        assert_eq!(SampleFormat::S16.resolve(24), SampleFormat::S16);
        assert_eq!(SampleFormat::F32.resolve(24), SampleFormat::F32);
    }

    #[test]
    fn s32_keeps_24_bits() {
        let mut got = Got::default();
        Pcm::S24(vec![0x7F_FFFF, -0x80_0000, 1, -1]).deliver_timed(
            &mut got,
            SampleFormat::S32,
            Some(7),
        );
        assert_eq!(got.s32, [0x7FFF_FF00, i32::MIN, 0x100, -0x100]);
        assert_eq!(got.timed, Some(7));
        Pcm::S16(vec![-32768, 1]).deliver(&mut got, SampleFormat::S32);
        assert_eq!(&got.s32[4..], [i32::MIN, 0x1_0000]);
        assert!(got.s16.is_empty());
    }

    #[test]
    fn integer_unresolved_is_s16() {
        let mut got = Got::default();
        Pcm::S24(vec![0x12_3480]).deliver(&mut got, SampleFormat::Integer);
        assert_eq!(got.s16, [0x1235]);
        assert!(got.s32.is_empty());
    }
}
