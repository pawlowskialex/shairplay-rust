//! Public types and traits for the AirPlay server.

use std::sync::Arc;

/// Runtime protocol mode selection.
///
/// When the `ap2` feature is enabled, this controls whether the server
/// advertises itself as an AirPlay 1 (classic) or AirPlay 2 receiver.
/// Both modes share the same RTSP listener — the difference is in mDNS
/// advertisement and feature negotiation.
#[cfg(feature = "ap2-core")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AirPlayMode {
    /// Classic AirPlay 1: ALAC/AAC over RTP, RSA encryption, NTP timing.
    AirPlay1,
    /// AirPlay 2: buffered audio, ChaCha20 encryption, SRP pairing, PTP timing.
    #[default]
    AirPlay2,
}

/// Audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Decoded PCM (f32 interleaved). Always delivered regardless of AP1/AP2.
    Pcm,
}

/// AirPlay 1 wire codec advertised in the `_raop._tcp` `cn` TXT record.
///
/// The receiver auto-detects the actual codec per connection from the SDP
/// `rtpmap`; this only controls what is *advertised*. When several are
/// advertised, their order is preserved because sender selection policies vary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Codec {
    /// Raw linear PCM / `L16` (`cn=0`).
    Pcm,
    /// Apple Lossless (`cn=1`).
    Alac,
}

impl Ap1Codec {
    /// The `cn` TXT record digit for this codec.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Codec::Pcm => "0",
            Ap1Codec::Alac => "1",
        }
    }
}

/// AirPlay 1 encryption / authentication mode advertised in the `et` TXT record.
///
/// The receiver auto-dispatches on what a sender actually negotiates (RSA
/// `rsaaeskey`, FairPlay `fpaeskey`, or no key at all); this only controls what
/// is *advertised*. Sender preference rules vary, so advertise only modes the
/// deployment intends to accept.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Encryption {
    /// No encryption (`et=0`). Audio passes through undecrypted.
    None,
    /// RSA session-key exchange (`et=1`, `a=rsaaeskey`).
    Rsa,
    /// FairPlay DRM (`et=3`, `POST /fp-setup` + `a=fpaeskey`).
    FairPlay,
}

impl Ap1Encryption {
    /// The `et` TXT record digit for this mode.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Encryption::None => "0",
            Ap1Encryption::Rsa => "1",
            Ap1Encryption::FairPlay => "3",
        }
    }
}

/// Sample format of the decoded PCM handed to [`AudioSession`]
/// ([`RaopServerBuilder::sample_format`](crate::RaopServerBuilder::sample_format)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SampleFormat {
    /// 32-bit float, through [`AudioSession::audio_process`]. The default.
    #[default]
    F32,
    /// Signed 16-bit, through [`AudioSession::audio_process_s16`]. On CPUs without an FPU this
    /// keeps the whole path integer: ALAC and raw L16 produce 16-bit samples, and
    /// float conversion happens only where mixdown or resampling needs it.
    S16,
}

impl SampleFormat {
    /// Bits per sample.
    pub const fn bits(self) -> u8 {
        match self {
            SampleFormat::F32 => 32,
            SampleFormat::S16 => 16,
        }
    }
}

/// Audio format descriptor passed to [`AudioHandler::audio_init`].
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Audio codec (always PCM for decoded output).
    pub codec: AudioCodec,
    /// Bits per sample: 32 for [`SampleFormat::F32`] (`&[f32]`), 16 for [`SampleFormat::S16`] (`&[i16]`).
    pub bits: u8,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Trait for receiving AirPlay events and creating audio sessions.
///
/// `AudioHandler` is `Send + Sync` — all callbacks can be called from any thread
/// without blocking audio delivery. Metadata, volume, and artwork callbacks are
/// called directly from the RTSP handler thread, never from the audio path.
///
/// A new [`AudioSession`] is created for each audio stream via
/// [`audio_init`](AudioHandler::audio_init). The session only receives PCM samples.
pub trait AudioHandler: Send + Sync + 'static {
    /// Called when a new audio stream starts. Return a session to receive PCM data.
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;

    // --- Metadata events (called from RTSP thread, never blocks audio) ---

    /// Volume change in dB (0.0 = max, -144.0 = mute).
    fn on_volume(&self, _volume: f32) {}
    /// The receiver's volume now, in the same dB (-30.0 ..= 0.0, -144.0 = mute): what a sender is told when it asks
    /// (AirPlay 2 GET /info `initialVolume`, AirPlay 1 GET_PARAMETER `volume`), so it starts from the receiver's
    /// level instead of its own. `None` (the default): not told (GET_PARAMETER answers 0.0, full volume).
    fn volume(&self) -> Option<f32> {
        None
    }
    /// Track metadata (parsed from DMAP).
    fn on_metadata(&self, _metadata: &crate::proto::dmap::TrackMetadata) {}
    /// Album artwork (JPEG or PNG).
    fn on_coverart(&self, _coverart: &[u8]) {}
    /// Playback progress (start, current, end in RTP timestamps at 44100 Hz).
    fn on_progress(&self, _start: u32, _current: u32, _end: u32) {}
    /// A remote control interface is available: AP1 DACP, AP2 commands on the session's event channel.
    fn on_remote_control(&self, _remote: Arc<dyn RemoteControl>) {}

    // --- Connection lifecycle ---

    /// Called when a client connects.
    fn on_client_connected(&self, _addr: &str) {}
    /// Called when a client disconnects.
    fn on_client_disconnected(&self, _addr: &str) {}
    /// Called when a sender starts a session: AirPlay 2's first SETUP (no `streams`) unless `isRemoteControlOnly`
    /// (iOS opens those to show and control what a receiver plays, from Control Center or the Home app, without
    /// making it the output), AirPlay 1's ANNOUNCE. Not for the probes and remote-control connections.
    fn on_session_setup(&self, _addr: &str) {}
    /// Called when the connection that started a session (`on_session_setup`) closes: the sender let go of this
    /// receiver as its output. Its remote-control-only connections may stay open.
    fn on_session_end(&self, _addr: &str) {}
    /// Called when the library hits a runtime error on a connection — e.g. a
    /// pairing/pair-verify failure, a FairPlay or session-key decrypt failure, a
    /// rejected stream format, or an audio-decoder init failure. Fired at most
    /// once per failure (never per audio packet). Default: log at warn level.
    fn on_error(&self, error: &crate::error::ShairplayError) {
        tracing::warn!(%error, "AirPlay error");
    }
}

/// Storage for paired device keys. Implement this to persist pairing across restarts.
///
/// Without persistence, iPhones that previously paired will send encrypted data
/// on connect and fail because the server has no cached keys.
#[cfg(feature = "ap2-core")]
pub trait PairingStore: Send + Sync + 'static {
    /// Look up a paired device's Ed25519 public key by device ID.
    fn get(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Save a paired device's Ed25519 public key.
    fn put(&self, device_id: &str, public_key: [u8; 32]);
    /// Remove a paired device.
    fn remove(&self, device_id: &str);

    /// Returns `true` once at least one controller is paired.
    ///
    /// Used to advertise `OneTimePairingRequired` (statusFlags bit 9) only until
    /// the first successful pairing, so already-paired controllers reconnect via
    /// pair-verify instead of being nudged back into setup. The default returns
    /// `false` (always advertise setup-required when a PIN is configured); the
    /// built-in [`MemoryPairingStore`] overrides it, and persistent stores should
    /// too.
    fn has_any_pairing(&self) -> bool {
        false
    }

    /// Save a controller with its permission (HAP: a controller paired by pair-setup is an admin; one added by an
    /// admin through `/pairings` may not be). `false`: the store has no room (`/pairings` answers MaxPeers). The
    /// default ignores the permission and always has room.
    fn put_controller(&self, device_id: &str, public_key: [u8; 32], admin: bool) -> bool {
        let _ = admin;
        self.put(device_id, public_key);
        true
    }

    /// Whether a paired controller may manage pairings. The default: every paired controller is an admin.
    fn is_admin(&self, device_id: &str) -> bool {
        self.get(device_id).is_some()
    }

    /// Every paired controller: (identifier, public key, admin), for `/pairings`' ListPairings. The default lists
    /// none (listing then answers with no controllers).
    fn list(&self) -> Vec<(String, [u8; 32], bool)> {
        Vec::new()
    }

    /// Load the accessory's persistent Ed25519 **identity** seed, if one was saved.
    ///
    /// This is the server's *own* long-term secret (distinct from the paired peer
    /// keys handled by [`get`](Self::get)/[`put`](Self::put)). Returning `Some`
    /// keeps the accessory's identity — and therefore its advertised `pk` — stable
    /// across restarts so already-paired devices don't need to re-pair.
    ///
    /// The default returns `None`: the server then generates a fresh random
    /// identity on each start and offers it to [`save_identity`](Self::save_identity).
    /// Implement both methods to persist the identity. (To reproduce the legacy
    /// insecure behaviour, return the zero-padded device id as the seed.)
    fn load_identity(&self) -> Option<[u8; 32]> {
        None
    }

    /// Persist the accessory's Ed25519 identity seed generated at startup.
    ///
    /// The default is a no-op (identity is not persisted). Implement together with
    /// [`load_identity`](Self::load_identity) to keep a stable identity.
    fn save_identity(&self, _seed: [u8; 32]) {}
}

/// In-memory pairing store (lost on restart). Use for testing or wrap with file I/O.
#[cfg(feature = "ap2-core")]
#[derive(Default)]
pub struct MemoryPairingStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, ([u8; 32], bool)>>,
}

#[cfg(feature = "ap2-core")]
impl PairingStore for MemoryPairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).map(|k| k.0)
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        self.put_controller(device_id, public_key, true);
    }
    fn put_controller(&self, device_id: &str, public_key: [u8; 32], admin: bool) -> bool {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), (public_key, admin));
        }
        true
    }
    fn is_admin(&self, device_id: &str) -> bool {
        self.keys
            .lock()
            .is_ok_and(|k| k.get(device_id).is_some_and(|k| k.1))
    }
    fn list(&self) -> Vec<(String, [u8; 32], bool)> {
        self.keys
            .lock()
            .map(|k| {
                k.iter()
                    .map(|(id, (pk, a))| (id.clone(), *pk, *a))
                    .collect()
            })
            .unwrap_or_default()
    }
    fn has_any_pairing(&self) -> bool {
        self.keys.lock().map(|k| !k.is_empty()).unwrap_or(false)
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
        }
    }
}

/// Per-connection audio session — hot path only.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
/// Only receives decoded PCM samples and flush events. All metadata, volume,
/// and artwork events go to [`AudioHandler`] instead.
pub trait AudioSession: Send + Sync {
    /// Receive decoded f32 interleaved PCM audio samples.
    fn audio_process(&mut self, samples: &[f32]);
    /// Receive decoded signed 16-bit interleaved PCM. Called instead of
    /// [`audio_process`](Self::audio_process) when the server was built with [`SampleFormat::S16`]; the
    /// default converts to f32 and calls `audio_process`.
    fn audio_process_s16(&mut self, samples: &[i16]) {
        let f: Vec<f32> = samples.iter().map(|&s| s as f32 / 32768.0).collect();
        self.audio_process(&f);
    }
    /// 16-bit PCM like [`audio_process_s16`](Self::audio_process_s16), with the time its first frame should
    /// leave the speaker: local wall-clock nanoseconds since the epoch (`SystemTime`), from the stream's network
    /// timeline (AirPlay 2 buffered audio with a PTP clock followed). Sessions that can schedule their output play it
    /// then (multi-room sync); the default ignores the time.
    fn audio_process_timed_s16(&mut self, samples: &[i16], play_at_ns: u64) {
        let _ = play_at_ns;
        self.audio_process_s16(samples);
    }
    /// Flush the audio buffer (e.g. on seek).
    fn audio_flush(&mut self) {}
}

/// Playback command to send to the source device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Start playback.
    Play,
    /// Pause playback.
    Pause,
    /// Skip to next track.
    NextTrack,
    /// Skip to previous track.
    PreviousTrack,
    /// Set volume (0-100).
    SetVolume(u8),
    /// Toggle shuffle mode.
    ToggleShuffle,
    /// Toggle repeat mode.
    ToggleRepeat,
    /// Stop playback.
    Stop,
}

/// Unified remote control interface for AP1 (DACP) and AP2 (MediaRemote).
pub trait RemoteControl: Send + Sync {
    /// Send a playback command to the source device.
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError>;
    /// Commands the source device supports. AP1 returns all; AP2 returns advertised set.
    fn available_commands(&self) -> Vec<RemoteCommand>;
}
