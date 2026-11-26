//! AirPlay server builder and lifecycle.

use super::config::Ap1Advertisement;
use super::connection::RaopShared;
use super::types::*;
use crate::crypto::pairing::Pairing;
use crate::crypto::rsa::RsaKey;
use crate::error::{ServerError, ShairplayError};
use crate::net::mdns::{AirPlayServiceInfo, MdnsService};
use crate::net::mdns_scope::{self, MdnsScope, MdnsScopeApplied};
use crate::net::server::{BindConfig, HttpServer};
use std::sync::Arc;

const AIRPORT_KEY: &str = include_str!("../../airport.key");

/// `RaopServerBuilder::max_artwork_size` unless set.
const DEFAULT_MAX_ARTWORK_SIZE: usize = 8 * 1024 * 1024;
/// The most `max_artwork_size` may be: the largest body the transport takes for any request.
const MAX_ARTWORK_SIZE: usize = crate::proto::http::MAX_BODY_BYTES;

fn airport_rsakey() -> Arc<RsaKey> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Arc<RsaKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        Arc::new(RsaKey::from_pem(AIRPORT_KEY).expect("built-in airport.key is invalid"))
    })
    .clone()
}

fn random_hwaddr() -> Vec<u8> {
    use rand::Rng;

    let mut hwaddr = [0u8; super::MAX_HWADDR_LEN];
    rand::rng().fill_bytes(&mut hwaddr);
    // Locally administered, unicast MAC address.
    hwaddr[0] = (hwaddr[0] | 0x02) & !0x01;
    hwaddr.to_vec()
}

#[cfg(feature = "ap2-core")]
fn derive_pi_from_hwaddr(hwaddr: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hwaddr);
    let hash = hasher.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0],
        hash[1],
        hash[2],
        hash[3],
        hash[4],
        hash[5],
        (hash[6] & 0x0f) | 0x40, // version 4
        hash[7],
        (hash[8] & 0x3f) | 0x80, // variant 1
        hash[9],
        hash[10],
        hash[11],
        hash[12],
        hash[13],
        hash[14],
        hash[15]
    )
}

/// Builder for [`RaopServer`].
pub struct RaopServerBuilder {
    max_clients: usize,
    mdns: bool,
    #[cfg(feature = "ap2-core")]
    ptp: crate::net::ptp::PtpOptions,
    #[cfg(feature = "ap2-core")]
    buffered_offset_ns: i64,
    #[cfg(feature = "ap2-core")]
    realtime_latency_ns: Option<i64>,
    hwaddr: Option<Vec<u8>>,
    identity: crate::raop::DeviceIdentity,
    password: Option<String>,
    #[cfg(feature = "pipewire-auth-setup-compat")]
    pipewire_auth_setup_compat: bool,
    name: String,
    bind: BindConfig,
    mdns_scope: MdnsScope,
    #[cfg(feature = "ap2-core")]
    pairing_store: Option<Arc<dyn PairingStore>>,
    #[cfg(feature = "ap2-core")]
    home: Option<Arc<dyn HomeSetup>>,
    #[cfg(feature = "ap2-core")]
    mode: AirPlayMode,
    output_sample_rate: Option<u32>,
    output_max_channels: Option<u8>,
    output_format: crate::raop::SampleFormat,
    audio_buffer_size: u32,
    max_artwork_size: usize,
    decoders: Option<crate::decoder::DecoderFactory>,
    ap1_codecs: Option<Vec<Ap1Codec>>,
    ap1_encryption: Option<Vec<Ap1Encryption>>,
    #[cfg(feature = "ap2-core")]
    pin: Option<String>,
    #[cfg(feature = "video")]
    video_handler: Option<Arc<dyn crate::raop::video::VideoHandler>>,
    #[cfg(feature = "hls")]
    hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
}

impl Default for RaopServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RaopServerBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            max_clients: 10,
            mdns: true,
            #[cfg(feature = "ap2-core")]
            ptp: crate::net::ptp::PtpOptions::default(),
            #[cfg(feature = "ap2-core")]
            buffered_offset_ns: 0,
            #[cfg(feature = "ap2-core")]
            realtime_latency_ns: None,
            hwaddr: None,
            identity: crate::raop::DeviceIdentity::default(),
            password: None,
            #[cfg(feature = "pipewire-auth-setup-compat")]
            pipewire_auth_setup_compat: false,
            name: "Shairplay".to_string(),
            bind: BindConfig::default(),
            mdns_scope: MdnsScope::default(),
            #[cfg(feature = "ap2-core")]
            pairing_store: None,
            #[cfg(feature = "ap2-core")]
            home: None,
            #[cfg(feature = "ap2-core")]
            mode: AirPlayMode::default(),
            output_sample_rate: None,
            output_max_channels: None,
            output_format: crate::raop::SampleFormat::F32,
            audio_buffer_size: 0x10_0000,
            max_artwork_size: DEFAULT_MAX_ARTWORK_SIZE,
            decoders: None,
            ap1_codecs: None,
            ap1_encryption: None,
            #[cfg(feature = "ap2-core")]
            pin: None,
            #[cfg(feature = "video")]
            video_handler: None,
            #[cfg(feature = "hls")]
            hls_handler: None,
        }
    }

    /// Set the maximum number of concurrent connections. Default: 10.
    pub fn max_clients(mut self, n: usize) -> Self {
        self.max_clients = n;
        self
    }
    /// Announce the receiver over mDNS (Bonjour) when it starts. Default: true; tests turn it off.
    pub fn mdns(mut self, on: bool) -> Self {
        self.mdns = on;
        self
    }

    /// Run the PTP sink on UDP 319/320 (AirPlay 2's clock). Default: true. Without it a sender's buffered audio
    /// starts seconds late and plays on the local clock.
    #[cfg(feature = "ap2-core")]
    pub fn ptp(mut self, on: bool) -> Self {
        self.ptp.sink = on;
        self
    }

    /// Append every PTP clock sample to this file as CSV (clock, sequence, master ns, local ns, task ns): for
    /// measuring the clock follower.
    #[cfg(feature = "ap2-core")]
    pub fn ptp_log(mut self, path: impl Into<String>) -> Self {
        self.ptp.log = Some(path.into());
        self
    }

    /// Measure the path delay to the PTP master with a Delay_Req a second. Default: true.
    #[cfg(feature = "ap2-core")]
    pub fn ptp_delay_req(mut self, on: bool) -> Self {
        self.ptp.delay_req = on;
        self
    }

    /// Play buffered audio this much later than its network time (ms, may be negative). Default: 0, at its time,
    /// as Apple's receivers do: for measurements.
    #[cfg(feature = "ap2-core")]
    pub fn buffered_offset_ms(mut self, ms: f64) -> Self {
        self.buffered_offset_ns = (ms * 1e6) as i64;
        self
    }

    /// Play realtime audio this long after its network time (ms), instead of the latency the sender asks for (its
    /// SETUP's latencyMin, else 11025 frames): for measurements.
    #[cfg(feature = "ap2-core")]
    pub fn realtime_latency_ms(mut self, ms: f64) -> Self {
        self.realtime_latency_ns = Some((ms * 1e6) as i64);
        self
    }

    /// How the receiver presents itself to senders: model, maker, serial number, firmware (default: an Apple TV).
    pub fn identity(mut self, identity: crate::raop::DeviceIdentity) -> Self {
        self.identity = identity;
        self
    }
    /// Set the 6-byte hardware address for mDNS registration.
    pub fn hwaddr(mut self, addr: impl Into<Vec<u8>>) -> Self {
        self.hwaddr = Some(addr.into());
        self
    }
    /// Set an optional HTTP Digest authentication password.
    pub fn password(mut self, pw: impl Into<String>) -> Self {
        self.password = Some(pw.into());
        self
    }

    /// Opt into the fixed PipeWire `/auth-setup` probe acknowledgement.
    ///
    /// Disabled by default, even when the Cargo feature is compiled in. This is
    /// experimental classic-RAOP compatibility, not MFi receiver authentication
    /// or audio encryption. Discovery and HTTP Digest requirements stay unchanged.
    /// Password-protected PipeWire interoperability is not established.
    ///
    /// With `ap2` compiled in, enabling this requires `AirPlayMode::AirPlay1`;
    /// already AP2-paired connections remain excluded. Debug builds use the same gates.
    #[cfg(feature = "pipewire-auth-setup-compat")]
    pub fn pipewire_auth_setup_compat(mut self, enabled: bool) -> Self {
        self.pipewire_auth_setup_compat = enabled;
        self
    }
    /// Set the RTSP listening port. Default: 5000.
    pub fn port(mut self, port: u16) -> Self {
        self.bind.port = port;
        self
    }
    /// Set full bind configuration (address, port, auto-sensing, IPv6).
    pub fn bind(mut self, config: BindConfig) -> Self {
        self.bind = config;
        self
    }
    /// Limit the mDNS announcement to the interfaces that carry the given addresses.
    /// Default: [`MdnsScope::All`], the announcement goes out on every interface.
    ///
    /// [`BindConfig`] limits the listeners only. Without this setting the records
    /// still leave on every interface, so a receiver bound to `eth0` is announced on
    /// `nebula1` as well. Pass the same addresses (or [`MdnsScope::from_bind`]) to
    /// keep both in step.
    ///
    /// `start()` fails if an address matches no interface of the host. It never falls
    /// back to announcing everywhere. After `start()`,
    /// [`RaopServer::mdns_scope_applied`] reports what applies. On Linux and other
    /// platforms (`mdns-sd`) the announcement leaves only on those interfaces. On macOS
    /// (Bonjour) each service is registered once per interface index, which limits its
    /// service records; the address records of the host belong to the system and stay on
    /// every interface.
    pub fn mdns_scope(mut self, scope: MdnsScope) -> Self {
        self.mdns_scope = scope;
        self
    }
    /// Set the AirPlay display name. Default: "Shairplay".
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set a pairing store for persisting device keys across restarts.
    /// Without this, iPhones must re-pair on every server restart.
    #[cfg(feature = "ap2-core")]
    pub fn pairing_store(mut self, store: Arc<dyn PairingStore>) -> Self {
        self.pairing_store = Some(store);
        self
    }

    /// Let the speaker be set up for a home in Apple's Home app ("Add Accessory" without a code): a persistent
    /// pair-setup with 3939, while no controller is paired, if `home` allows it ([`HomeSetup`]). Only without a
    /// PIN (with one, pair-setup proves it). Persist the pairings ([`pairing_store`](Self::pairing_store)), or
    /// the home's controllers are forgotten at the next start.
    #[cfg(feature = "ap2-core")]
    pub fn home(mut self, home: Arc<dyn HomeSetup>) -> Self {
        self.home = Some(home);
        self
    }

    /// Set the AirPlay protocol mode. Default: [`AirPlayMode::AirPlay2`].
    ///
    /// Use [`AirPlayMode::AirPlay1`] to advertise as a classic receiver even
    /// when the `ap2` feature is compiled in.
    #[cfg(feature = "ap2-core")]
    pub fn mode(mut self, mode: AirPlayMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the desired output sample rate. The library resamples to this rate.
    /// Default: source native rate (no resampling).
    pub fn output_sample_rate(mut self, rate: u32) -> Self {
        self.output_sample_rate = Some(rate);
        self
    }

    /// Set the maximum output channels. Sources with more channels are mixed down.
    /// Sources with fewer channels are passed through (no upmixing).
    /// Default: pass through native channel count.
    pub fn output_max_channels(mut self, channels: u8) -> Self {
        self.output_max_channels = Some(channels);
        self
    }

    /// Set the sample format sessions receive ([`AudioSession::audio`](crate::AudioSession::audio)):
    /// [`SampleFormat::F32`](crate::SampleFormat::F32) (default), [`SampleFormat::S16`](crate::SampleFormat::S16)
    /// or [`SampleFormat::S32`](crate::SampleFormat::S32), which keep integer decoders' output integer end to
    /// end, or [`SampleFormat::Integer`](crate::SampleFormat::Integer): `S16` or `S32` by the source's depth.
    pub fn sample_format(mut self, format: crate::raop::SampleFormat) -> Self {
        self.output_format = format;
        self
    }

    /// Set the AirPlay 2 buffered-audio window advertised to senders, in bytes of compressed audio.
    /// It controls how much encoded audio the sender may send ahead of playout; it does not set or
    /// bound the receiver's PCM buffer or total local memory use. Default: 1 MiB (about 33 s of
    /// 256 kb/s AAC).
    pub fn audio_buffer_size(mut self, bytes: u32) -> Self {
        self.audio_buffer_size = bytes;
        self
    }

    /// Set the largest body a sender may send with cover art, in bytes: AirPlay 1's `SET_PARAMETER`
    /// (`image/jpeg`, `image/png`, and the DMAP metadata and volume on the same method) and AirPlay 2's
    /// `POST /command` (now-playing info, which can include artwork). A request announcing a larger
    /// body is refused with 400 Bad Request when its headers arrive and its connection closed, which
    /// ends that sender's session, so the limit should be above the largest artwork the senders in
    /// use send. Default: 8 MiB. At most 32 MiB, the largest body any request may have; a larger
    /// value is taken as 32 MiB.
    ///
    /// Each connection may hold one such body while it arrives (10 s at most), so the receiver's
    /// memory for them is up to `max_clients` times this.
    pub fn max_artwork_size(mut self, bytes: usize) -> Self {
        self.max_artwork_size = bytes.min(MAX_ARTWORK_SIZE);
        self
    }

    /// The application's decoders ([`crate::decoder`]): `factory` is asked for each stream with its
    /// [`StreamInfo`](crate::decoder::StreamInfo) and makes its decoder, or leaves the stream to the library's
    /// ([`builtin`](crate::decoder::builtin)), which it may also use inside its own (a fallback).
    pub fn decoders(mut self, factory: crate::decoder::DecoderFactory) -> Self {
        self.decoders = Some(factory);
        self
    }

    /// Set the AP1 codecs advertised in the `_raop._tcp` `cn` TXT record.
    ///
    /// The receiver auto-detects the actual codec per connection from the SDP,
    /// so this only affects discovery and negotiation. The supplied order is
    /// preserved. By default, PCM and ALAC are advertised (`cn=0,1`). Empty or
    /// duplicate lists are rejected by [`build`](Self::build).
    ///
    /// When the `ap2` feature is enabled, also select
    /// `AirPlayMode::AirPlay1`. AP2 has a separate, fixed capability profile.
    pub fn advertise_codecs(mut self, codecs: impl Into<Vec<Ap1Codec>>) -> Self {
        self.ap1_codecs = Some(codecs.into());
        self
    }

    /// Set the AP1 encryption/auth modes advertised in the `et` TXT record.
    ///
    /// The receiver auto-dispatches on what a sender actually negotiates, so
    /// this only affects discovery and negotiation. The supplied order is
    /// preserved. The interoperability-focused default advertises unencrypted
    /// transport only (`et=0`); pass [`Ap1Encryption::Rsa`] and/or
    /// `Ap1Encryption::FairPlay` (feature `fairplay`) to opt into encrypted AP1
    /// transport. Empty or
    /// duplicate lists are rejected by [`build`](Self::build).
    ///
    /// When the `ap2` feature is enabled, also select
    /// `AirPlayMode::AirPlay1`. AP2 has a separate, fixed capability profile.
    pub fn advertise_encryption(mut self, encryption: impl Into<Vec<Ap1Encryption>>) -> Self {
        self.ap1_encryption = Some(encryption.into());
        self
    }

    #[cfg(feature = "ap2-core")]
    /// Require normal HomeKit pair-setup with this one-time PIN.
    ///
    /// Without a PIN, AP2 uses the shairport-sync-style transient pairing
    /// profile. Setting a PIN changes mDNS/GET /info status flags so clients
    /// perform persistent M1-M6 pair-setup and later use pair-verify, and only
    /// controllers that did may play or control the receiver: until pair-verify
    /// a connection gets `OPTIONS`, `GET /info` and the pairing requests, the
    /// rest answers 470. AirPlay 1 senders can't pair, so they don't play.
    pub fn pin(mut self, pin: impl Into<String>) -> Self {
        self.pin = Some(pin.into());
        self
    }

    #[cfg(feature = "video")]
    /// Set a video handler for screen mirroring (experimental).
    pub fn video_handler(mut self, handler: Arc<dyn crate::raop::video::VideoHandler>) -> Self {
        self.video_handler = Some(handler);
        self
    }

    #[cfg(feature = "hls")]
    /// Set an HLS handler for YouTube/video URL playback.
    pub fn hls_handler(mut self, handler: Arc<dyn crate::raop::hls::HlsHandler>) -> Self {
        self.hls_handler = Some(handler);
        self
    }

    /// Build the server with the given audio handler.
    pub fn build(self, handler: Arc<dyn AudioHandler>) -> Result<RaopServer, ShairplayError> {
        if self.max_clients == 0 {
            return Err(ServerError::MaxClients(0).into());
        }
        if let Some(password) = self.password.as_ref()
            && password.len() > super::MAX_PASSWORD_LEN
        {
            return Err(ServerError::InvalidPassword(password.len()).into());
        }
        #[cfg(feature = "ap2-core")]
        if self.mode == AirPlayMode::AirPlay2
            && (self.ap1_codecs.is_some() || self.ap1_encryption.is_some())
        {
            return Err(ServerError::InvalidConfiguration(
                "AP1 advertisement options require AirPlayMode::AirPlay1",
            )
            .into());
        }
        #[cfg(all(feature = "ap2-core", feature = "pipewire-auth-setup-compat"))]
        if self.pipewire_auth_setup_compat && self.mode != AirPlayMode::AirPlay1 {
            return Err(ServerError::InvalidConfiguration(
                "PipeWire auth-setup compatibility requires AirPlayMode::AirPlay1",
            )
            .into());
        }
        let ap1_advertisement = Ap1Advertisement::try_new(self.ap1_codecs, self.ap1_encryption)?;
        let rsakey = airport_rsakey();
        let pairing = Arc::new(Pairing::generate()?);
        let hwaddr = match self.hwaddr {
            Some(addr) if addr.len() == super::MAX_HWADDR_LEN => addr,
            Some(addr) => return Err(ServerError::InvalidHwAddr(addr.len()).into()),
            None => random_hwaddr(),
        };

        #[cfg(feature = "ap2-core")]
        let pairing_id = derive_pi_from_hwaddr(&hwaddr);
        #[cfg(feature = "ap2-core")]
        let device_id = crate::util::hwaddr_airplay(&hwaddr);
        #[cfg(feature = "ap2-core")]
        let airplay_name = self.name.clone();

        #[cfg(feature = "ap2-core")]
        let pairing_store: Arc<dyn PairingStore> = self
            .pairing_store
            .unwrap_or_else(|| Arc::new(MemoryPairingStore::default()));
        // Resolve the accessory's long-term identity once: reuse a persisted seed
        // if the store has one, otherwise generate a random seed and hand it back
        // for persistence. (A store with no identity persistence — e.g. the default
        // in-memory one — yields a fresh identity each start; persist it via
        // `PairingStore::load_identity`/`save_identity` to avoid re-pairing.)
        #[cfg(feature = "ap2-core")]
        let identity_seed = pairing_store.load_identity().unwrap_or_else(|| {
            let seed = crate::crypto::pairing_homekit::generate_identity_seed();
            pairing_store.save_identity(seed);
            seed
        });

        // a home's configuration lasts as long as its pairings
        #[cfg(feature = "ap2-core")]
        let home_config = match &self.home {
            Some(home) if pairing_store.has_any_pairing() => home.configuration(),
            _ => Default::default(),
        };

        let shared = Arc::new(RaopShared {
            identity: self.identity.clone(),
            rsakey,
            pairing,
            hwaddr: hwaddr.clone(),
            password: self.password.unwrap_or_default(),
            #[cfg(feature = "pipewire-auth-setup-compat")]
            pipewire_auth_setup_compat: self.pipewire_auth_setup_compat,
            handler,
            #[cfg(feature = "ap2-core")]
            pairing_store,
            #[cfg(feature = "ap2-core")]
            identity_seed,
            output_sample_rate: self.output_sample_rate,
            output_max_channels: self.output_max_channels,
            #[cfg(feature = "ap2-core")]
            buffered_offset_ns: self.buffered_offset_ns,
            #[cfg(feature = "ap2-core")]
            realtime_latency_ns: self.realtime_latency_ns,
            output_format: self.output_format,
            audio_buffer_size: self.audio_buffer_size,
            max_artwork_size: self.max_artwork_size,
            decoders: self.decoders.clone(),
            #[cfg(feature = "ap2-core")]
            srp_spare: {
                let spare = crate::crypto::pairing_homekit::SrpSpare::new(self.pin.clone());
                spare.refill(std::time::Duration::ZERO);
                spare
            },
            #[cfg(feature = "ap2-core")]
            pair_failures: std::sync::atomic::AtomicU32::new(0),
            #[cfg(feature = "ap2-core")]
            pin: self.pin,
            #[cfg(feature = "ap2-core")]
            home_config: std::sync::RwLock::new(home_config),
            #[cfg(feature = "ap2-core")]
            home: self.home,
            #[cfg(feature = "video")]
            video_handler: self.video_handler,
            #[cfg(feature = "video")]
            video_ekey: Arc::new(std::sync::RwLock::new(None)),
            #[cfg(feature = "video")]
            video_eiv: Arc::new(std::sync::RwLock::new(None)),
            #[cfg(feature = "ap2-core")]
            pairing_id,
            #[cfg(feature = "ap2-core")]
            device_id,
            #[cfg(feature = "ap2-core")]
            airplay_name,
            #[cfg(feature = "hls")]
            hls_handler: self.hls_handler,
            sessions: Default::default(),
            #[cfg(feature = "ap2-core")]
            records_changed: tokio::sync::Notify::new(),
        });

        let mut httpd = HttpServer::new(shared.clone(), self.max_clients);
        httpd.set_bind_config(self.bind.clone());

        Ok(RaopServer {
            shared,
            httpd,
            mdns: None,
            mdns_applied: None,
            reannouncer: None,
            mdns_scope: self.mdns_scope,
            bind: self.bind,
            advert: Advert {
                name: self.name,
                hwaddr,
                ap1_advertisement,
                #[cfg(feature = "ap2-core")]
                mode: self.mode,
            },
            announce: self.mdns,
            #[cfg(feature = "ap2-core")]
            ptp: self.ptp,
        })
    }
}

/// The main AirPlay/RAOP server.
///
/// Listens for RTSP connections, handles pairing and encryption,
/// decodes audio, and delivers f32 PCM samples via [`AudioSession`].
/// Automatically registers mDNS services for network discovery.
pub struct RaopServer {
    pub(crate) shared: Arc<RaopShared>,
    httpd: HttpServer,
    /// The registered services; the reannouncer registers them again when their records change
    mdns: Option<Arc<std::sync::Mutex<MdnsService>>>,
    mdns_applied: Option<MdnsScopeApplied>,
    reannouncer: Option<tokio::task::JoinHandle<()>>,
    mdns_scope: MdnsScope,
    bind: BindConfig,
    advert: Advert,
    /// mDNS on start (the builder's mdns)
    announce: bool,
    #[cfg(feature = "ap2-core")]
    ptp: crate::net::ptp::PtpOptions,
}

impl RaopServer {
    /// Create a new server builder.
    pub fn builder() -> RaopServerBuilder {
        RaopServerBuilder::new()
    }

    /// Start the server: bind ports, register mDNS services, begin accepting connections.
    ///
    /// mDNS registration is skipped when the builder's `mdns(false)` turned it off.
    ///
    /// A [`MdnsScope`] that cannot be resolved to interfaces fails here, before any
    /// port is bound.
    pub async fn start(&mut self) -> Result<(), ShairplayError> {
        // Validated even when mDNS registration is skipped, so a wrong scope never
        // depends on the environment.
        let scope_plan = mdns_scope::plan(&self.mdns_scope)?;

        let _actual_port = self.httpd.start(self.bind.port).await?;

        // AirPlay 2 PTP sink: accept the sender's clock on 319/320 so it doesn't
        // stall the buffered-audio start. No-op if the ports can't be bound.
        #[cfg(feature = "ap2-core")]
        if self.advert.mode == AirPlayMode::AirPlay2 {
            crate::net::ptp::spawn_ptp_sink(&self.ptp).await;
        }

        if self.announce {
            let info = self.service_info();
            let mut mdns = MdnsService::new(scope_plan.as_ref())?;
            mdns.register_raop(&info)?;
            #[cfg(feature = "ap2-core")]
            if self.advert.mode == AirPlayMode::AirPlay2 {
                mdns.register_airplay(&info)?;
            }
            self.mdns_applied = Some(mdns.applied().clone());
            let mdns = Arc::new(std::sync::Mutex::new(mdns));
            #[cfg(feature = "ap2-core")]
            if self.advert.mode == AirPlayMode::AirPlay2 {
                self.reannouncer = Some(tokio::spawn(reannounce(
                    self.shared.clone(),
                    self.advert.clone(),
                    self.httpd.port(),
                    mdns.clone(),
                )));
            }
            self.mdns = Some(mdns);
        }

        Ok(())
    }

    /// What was done with the requested [`MdnsScope`], or `None` while no mDNS service
    /// is registered (not started, or skipped with the builder's `mdns(false)`).
    pub fn mdns_scope_applied(&self) -> Option<&MdnsScopeApplied> {
        self.mdns_applied.as_ref()
    }

    /// Whether the server is currently running.
    pub fn is_running(&self) -> bool {
        self.httpd.is_running()
    }

    /// Stop the server: unregister mDNS services, close all listeners, stop every stream and close every
    /// connection.
    pub async fn stop(&mut self) {
        if let Some(task) = self.reannouncer.take() {
            task.abort();
            let _ = task.await;
        }
        self.mdns_applied = None;
        if let Some(mdns) = self.mdns.take() {
            // the reannouncer, the only other holder, has ended
            let mdns = Arc::try_unwrap(mdns).ok().and_then(|m| m.into_inner().ok());
            if let Some(mut mdns) = mdns {
                mdns.unregister_all().await;
            }
        }
        self.httpd.stop().await;
        self.shared.sessions.close_all();
    }

    /// Get the mDNS service info for this server.
    pub fn service_info(&self) -> AirPlayServiceInfo {
        self.advert.service_info(&self.shared, self.httpd.port())
    }
}

/// What the mDNS records are made of besides the shared state.
#[derive(Clone)]
struct Advert {
    name: String,
    hwaddr: Vec<u8>,
    ap1_advertisement: Ap1Advertisement,
    #[cfg(feature = "ap2-core")]
    mode: AirPlayMode,
}

impl Advert {
    /// The services' records as they are now, for a server on `port`.
    fn service_info(&self, shared: &RaopShared, port: u16) -> AirPlayServiceInfo {
        #[cfg(feature = "ap2-core")]
        if self.mode == AirPlayMode::AirPlay2 {
            let (_, vk) = crate::crypto::pairing_homekit::identity_keypair(&shared.identity_seed);
            let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            return AirPlayServiceInfo::new_airplay2(
                &self.name,
                port,
                &self.hwaddr,
                !shared.password.is_empty(),
                &pk_hex,
                &shared.pairing_id,
                shared.features(),
                shared.status_flags(),
                shared.home_configuration().access.level(),
                &shared.identity,
            );
        }
        AirPlayServiceInfo::new_with_ap1_advertisement(
            &self.name,
            port,
            &self.hwaddr,
            !shared.password.is_empty(),
            &self.ap1_advertisement,
            &shared.identity,
        )
    }
}

/// Registers the services again each time their records change ([`RaopShared::reannounce`]), so browsers see
/// the status flags as they are: a sender reads them to choose how to pair.
#[cfg(feature = "ap2-core")]
async fn reannounce(
    shared: Arc<RaopShared>,
    advert: Advert,
    port: u16,
    mdns: Arc<std::sync::Mutex<MdnsService>>,
) {
    let mut announced = advert.service_info(&shared, port);
    loop {
        shared.records_changed.notified().await;
        let info = advert.service_info(&shared, port);
        if info == announced {
            continue;
        }
        let Ok(mut mdns) = mdns.lock() else {
            return;
        };
        match mdns.update(&info) {
            Ok(()) => tracing::info!("mDNS: records announced again"),
            Err(e) => tracing::warn!("mDNS: announcing the new records failed: {e}"),
        }
        announced = info;
    }
}

#[cfg(test)]
mod primitive_tests {
    use super::*;

    #[test]
    fn random_hwaddr_is_locally_administered_unicast_and_random() {
        let a = random_hwaddr();
        let b = random_hwaddr();
        assert_eq!(a.len(), super::super::MAX_HWADDR_LEN);
        for h in [&a, &b] {
            assert_eq!(h[0] & 0x02, 0x02, "locally administered bit");
            assert_eq!(h[0] & 0x01, 0x00, "unicast bit");
        }
        assert_ne!(a, b);
    }

    #[cfg(feature = "ap2-core")]
    #[test]
    fn pairing_id_known_answer() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"abc");
        let digest: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        assert_eq!(
            derive_pi_from_hwaddr(&[1, 2, 3, 4, 5, 6]),
            "7192385c-3c06-45de-95bb-9476ce1d9074"
        );
        assert_ne!(
            derive_pi_from_hwaddr(&[1, 2, 3, 4, 5, 7]),
            derive_pi_from_hwaddr(&[1, 2, 3, 4, 5, 6])
        );
    }
}
