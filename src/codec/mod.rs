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
}

#[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
impl Pcm {
    pub(crate) fn into_f32(self) -> Vec<f32> {
        match self {
            Pcm::F32(v) => v,
            Pcm::S16(v) => v.iter().map(|&s| s as f32 / 32768.0).collect(),
        }
    }

    pub(crate) fn into_s16(self) -> Vec<i16> {
        match self {
            Pcm::S16(v) => v,
            Pcm::F32(v) => v
                .iter()
                .map(|&x| (x.clamp(-1.0, 1.0) * 32767.0) as i16)
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

    /// Hand the samples to the session in its format.
    pub(crate) fn deliver(self, session: &mut dyn AudioSession, format: SampleFormat) {
        match (self, format) {
            (Pcm::S16(v), SampleFormat::S16) => session.audio_process_s16(&v),
            (Pcm::F32(v), SampleFormat::F32) => session.audio_process(&v),
            (p, SampleFormat::S16) => session.audio_process_s16(&p.into_s16()),
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
