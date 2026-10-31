//! RAOP/AirPlay server core — connection handling, audio pipeline, and public API.

pub use crate::proto::dmap::TrackMetadata;

#[cfg(feature = "ap2-core")]
pub mod audio_pipeline;
#[cfg(feature = "pipewire-auth-setup-compat")]
mod auth_setup;
pub mod buffer;
#[cfg(feature = "ap2-core")]
pub mod buffered_audio;
#[cfg(feature = "ap2-core")]
pub(crate) mod event_channel;
pub(crate) mod handlers_ap1;
#[cfg(feature = "ap2-core")]
pub(crate) mod handlers_ap2;
#[cfg(feature = "hls")]
pub(crate) mod handlers_hls;
#[cfg(feature = "hls")]
pub mod hls;
pub(crate) mod ntp;
pub mod offload;
#[cfg(feature = "ap2-core")]
pub(crate) mod realtime_audio;
pub(crate) mod reorder;
pub(crate) mod rtp;
mod rtsp;
#[cfg(feature = "video")]
pub mod video;
#[cfg(feature = "video")]
pub(crate) mod video_stream;

pub(crate) mod config;

/// Maximum hardware address length in bytes.
pub(crate) const MAX_HWADDR_LEN: usize = 6;
/// Maximum password length in bytes.
pub(crate) const MAX_PASSWORD_LEN: usize = 64;
/// Maximum HTTP Digest nonce length in bytes.
pub(crate) const MAX_NONCE_LEN: usize = 32;

mod types;
pub use types::*;

mod connection;
mod server;
pub use server::{RaopServer, RaopServerBuilder};

pub(crate) struct DacpRemoteControl {
    client: crate::dacp::DacpClient,
}

impl DacpRemoteControl {
    /// Create a new DACP remote control client for the given iPhone.
    pub(crate) fn new(dacp_id: &str, active_remote: &str, remote_addr: &[u8]) -> Self {
        let mut client = crate::dacp::DacpClient::new(dacp_id, active_remote);
        let ip = match remote_addr.len() {
            4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                remote_addr[0],
                remote_addr[1],
                remote_addr[2],
                remote_addr[3],
            )),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(remote_addr);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        client.discover_from_remote(ip);
        Self { client }
    }
}

/// AirPlay 2's remote control: `sendMediaRemoteCommand` requests on the session's event channel (what Apple's
/// receivers send, "Sending MediaRemote command ... back to sender"; shairport-sync's remote.c): a MediaRemote
/// command number with its options, or the receiver's volume (`dvlc`, 0.0-1.0) so the sender's slider follows it.
#[cfg(feature = "ap2-core")]
pub(crate) struct Ap2RemoteControl {
    events: event_channel::EventSender,
    group: Option<String>, // the session's group UUID (SETUP `groupUUID`): the command's destination
    supported: std::sync::Arc<SupportedCommands>,
}

/// The commands the sender takes now (POST /command `updateMRSupportedCommands`, sent whenever they change: next
/// track is off with nothing queued, a podcast app takes skips instead): MediaRemote command number -> enabled, and
/// a skip's preferred interval (s). Empty until the first update: then every command is sent.
#[cfg(feature = "ap2-core")]
#[derive(Default)]
pub(crate) struct SupportedCommands(
    std::sync::Mutex<std::collections::HashMap<u64, (bool, Option<f64>)>>,
);

#[cfg(feature = "ap2-core")]
impl SupportedCommands {
    /// `params.mrSupportedCommandsFromSender`: one binary plist per command (`kCommandInfoCommandKey`,
    /// `kCommandInfoEnabledKey`, options with `kMRMediaRemoteCommandInfoPreferredIntervalsKey` for the skips).
    pub(crate) fn update(&self, dict: &plist::Dictionary) {
        let Some(cmds) = dict
            .get("params")
            .and_then(|p| p.as_dictionary())
            .and_then(|p| p.get("mrSupportedCommandsFromSender"))
            .and_then(|v| v.as_array())
        else {
            return;
        };
        let mut map = std::collections::HashMap::new();
        for info in cmds.iter().filter_map(|c| c.as_data()) {
            let Ok(plist::Value::Dictionary(info)) = plist::from_bytes::<plist::Value>(info) else {
                continue;
            };
            let Some(n) = info
                .get("kCommandInfoCommandKey")
                .and_then(|v| v.as_unsigned_integer())
            else {
                continue;
            };
            let enabled = info
                .get("kCommandInfoEnabledKey")
                .and_then(|v| v.as_boolean())
                .unwrap_or(true);
            let interval = info
                .get("kCommandInfoOptionsKey")
                .and_then(|o| o.as_dictionary())
                .and_then(|o| o.get("kMRMediaRemoteCommandInfoPreferredIntervalsKey"))
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| {
                    v.as_real()
                        .or_else(|| v.as_signed_integer().map(|i| i as f64))
                });
            map.insert(n, (enabled, interval));
        }
        tracing::debug!(
            enabled = ?{ let mut v: Vec<_> = map.iter().filter(|(_, e)| e.0).map(|(n, _)| *n).collect(); v.sort(); v },
            "the sender's commands"
        );
        *self.0.lock().unwrap() = map;
    }

    /// The command to send for `primary` (next / previous track): it if the sender takes it (or hasn't said), else
    /// the skip it takes (with its interval), else none.
    fn pick(&self, primary: u64, skip: u64) -> Option<(u64, Option<f64>)> {
        let map = self.0.lock().unwrap();
        if map.is_empty() || map.get(&primary).is_none_or(|e| e.0) {
            return Some((primary, None));
        }
        match map.get(&skip) {
            Some(&(true, interval)) => Some((skip, Some(interval.unwrap_or(15.0)))),
            _ => None,
        }
    }

    fn takes(&self, n: u64) -> bool {
        let map = self.0.lock().unwrap();
        map.is_empty() || map.get(&n).is_none_or(|e| e.0)
    }
}

#[cfg(feature = "ap2-core")]
impl Ap2RemoteControl {
    pub(crate) fn new(
        events: event_channel::EventSender,
        group: Option<String>,
        supported: std::sync::Arc<SupportedCommands>,
    ) -> Self {
        Self {
            events,
            group,
            supported,
        }
    }

    /// The command's options: its ID, redirected (from a receiver), to the session's group.
    fn options(&self) -> plist::Dictionary {
        let mut o = plist::Dictionary::new();
        o.insert(
            "kMRMediaRemoteOptionSendOptionsNumber".into(),
            plist::Value::Integer(0.into()),
        );
        o.insert(
            "kMRMediaRemoteOptionCommandID".into(),
            plist::Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
        );
        o.insert(
            "kMRMediaRemoteOptionIsRedirectingCommand".into(),
            plist::Value::Boolean(true),
        );
        if let Some(archive) = self.group.as_deref().and_then(keyed_archive_of) {
            o.insert(
                "kMRMediaRemoteOptionDestinationDeviceUIDs".into(),
                plist::Value::Data(archive),
            );
        }
        o
    }
}

/// An NSKeyedArchiver archive (binary plist) of an NSMutableArray holding one string.
#[cfg(feature = "ap2-core")]
fn keyed_archive_of(s: &str) -> Option<Vec<u8>> {
    use plist::{Dictionary, Uid, Value};
    let uid = |n| Value::Uid(Uid::new(n));
    let array = Dictionary::from_iter([
        ("NS.objects".to_string(), Value::Array(vec![uid(2)])),
        ("$class".to_string(), uid(3)),
    ]);
    let class = Dictionary::from_iter([
        (
            "$classname".to_string(),
            Value::String("NSMutableArray".into()),
        ),
        (
            "$classes".to_string(),
            Value::Array(
                ["NSMutableArray", "NSArray", "NSObject"]
                    .map(|c| Value::String(c.into()))
                    .to_vec(),
            ),
        ),
    ]);
    let archive = Dictionary::from_iter([
        ("$version".to_string(), Value::Integer(100000.into())),
        (
            "$archiver".to_string(),
            Value::String("NSKeyedArchiver".into()),
        ),
        (
            "$top".to_string(),
            Value::Dictionary(Dictionary::from_iter([("root".to_string(), uid(1))])),
        ),
        (
            "$objects".to_string(),
            Value::Array(vec![
                Value::String("$null".into()),
                Value::Dictionary(array),
                Value::String(s.into()),
                Value::Dictionary(class),
            ]),
        ),
    ]);
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &archive).ok()?;
    Some(out)
}

#[cfg(feature = "ap2-core")]
impl RemoteControl for Ap2RemoteControl {
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError> {
        let mut c = plist::Dictionary::new();
        c.insert(
            "type".into(),
            plist::Value::String("sendMediaRemoteCommand".into()),
        );
        if let RemoteCommand::SetVolume(v) = cmd {
            let unit = plist::Value::Real(f64::from(v.min(100)) / 100.0);
            c.insert("value".into(), plist::Value::String("dvlc".into()));
            c.insert("volume".into(), unit.clone());
            c.insert(
                "params".into(),
                plist::Value::Dictionary(plist::Dictionary::from_iter([(
                    "volume".to_string(),
                    unit,
                )])),
            );
        } else {
            // MRMediaRemoteCommand numbers; next / previous track fall back to the skips (17 / 18: forward /
            // backward by an interval) when the sender takes only those
            let picked = match cmd {
                RemoteCommand::Play => Some((0, None)),
                RemoteCommand::Pause => Some((1, None)),
                RemoteCommand::PlayPause => Some((2, None)),
                RemoteCommand::Stop => Some((3, None)),
                RemoteCommand::NextTrack => self.supported.pick(4, 17),
                RemoteCommand::PreviousTrack => self.supported.pick(5, 18),
                RemoteCommand::ToggleShuffle => Some((6, None)), // advance the shuffle mode
                RemoteCommand::ToggleRepeat => Some((7, None)),  // advance the repeat mode
                RemoteCommand::SetVolume(_) => unreachable!(),
            };
            let Some((n, interval)) = picked else {
                tracing::info!(
                    ?cmd,
                    "the sender takes neither this command nor a skip now: not sent"
                );
                return Ok(());
            };
            if n == 17 || n == 18 {
                tracing::info!(?cmd, skip = n, interval, "the sender takes a skip instead");
            }
            c.insert(
                "modernMediaRemoteCommand".into(),
                plist::Value::String(n.to_string()),
            );
            let mut options = self.options();
            if let Some(s) = interval {
                options.insert(
                    "kMRMediaRemoteOptionSkipInterval".into(),
                    plist::Value::Real(s),
                );
            }
            c.insert("params".into(), plist::Value::Dictionary(options));
        }
        self.events
            .post_command(&c)
            .map_err(crate::error::ShairplayError::Network)
    }

    fn available_commands(&self) -> Vec<RemoteCommand> {
        let s = &self.supported;
        let mut v = vec![RemoteCommand::SetVolume(0)];
        for (cmd, n) in [
            (RemoteCommand::Play, 0),
            (RemoteCommand::Pause, 1),
            (RemoteCommand::PlayPause, 2),
            (RemoteCommand::Stop, 3),
            (RemoteCommand::ToggleShuffle, 6),
            (RemoteCommand::ToggleRepeat, 7),
        ] {
            if s.takes(n) {
                v.push(cmd);
            }
        }
        if s.pick(4, 17).is_some() {
            v.push(RemoteCommand::NextTrack);
        }
        if s.pick(5, 18).is_some() {
            v.push(RemoteCommand::PreviousTrack);
        }
        v
    }
}

impl RemoteControl for DacpRemoteControl {
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError> {
        let result = match cmd {
            // not playpause: a play to a sender that plays (a receiver resuming it) would pause it
            RemoteCommand::Play => self.client.play_blocking(),
            RemoteCommand::Pause => self.client.pause_blocking(),
            RemoteCommand::PlayPause => self.client.play_pause_blocking(),
            RemoteCommand::NextTrack => self.client.next_blocking(),
            RemoteCommand::PreviousTrack => self.client.prev_blocking(),
            RemoteCommand::SetVolume(v) => self.client.set_volume_blocking(v),
            RemoteCommand::ToggleShuffle => self.client.set_shuffle_blocking(true),
            RemoteCommand::ToggleRepeat => self.client.set_repeat_blocking(1),
            RemoteCommand::Stop => self.client.stop_blocking(),
        };
        result.map_err(crate::error::ShairplayError::Network)
    }

    fn available_commands(&self) -> Vec<RemoteCommand> {
        vec![
            RemoteCommand::Play,
            RemoteCommand::Pause,
            RemoteCommand::PlayPause,
            RemoteCommand::NextTrack,
            RemoteCommand::PreviousTrack,
            RemoteCommand::SetVolume(0),
            RemoteCommand::ToggleShuffle,
            RemoteCommand::ToggleRepeat,
            RemoteCommand::Stop,
        ]
    }
}

#[cfg(all(test, feature = "ap2-core"))]
mod ap2_remote_tests {
    use super::*;

    fn sent(cmd: RemoteCommand) -> plist::Dictionary {
        sent_to(cmd, Default::default()).unwrap()
    }

    /// What the remote sends for `cmd` to a sender that takes `supported`, if anything.
    fn sent_to(
        cmd: RemoteCommand,
        supported: std::sync::Arc<SupportedCommands>,
    ) -> Option<plist::Dictionary> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let remote = Ap2RemoteControl::new(
            event_channel::EventSender::from_tx(tx),
            Some("GROUP-1".into()),
            supported,
        );
        remote.send_command(cmd).unwrap();
        let msg = rx.try_recv().ok()?;
        let start = msg.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(msg.starts_with(b"POST /command RTSP/1.0\r\n"));
        plist::from_bytes::<plist::Value>(&msg[start..])
            .unwrap()
            .into_dictionary()
    }

    /// An `updateMRSupportedCommands` body: (command, enabled, preferred interval).
    fn supported(cmds: &[(u64, bool, Option<i64>)]) -> std::sync::Arc<SupportedCommands> {
        let infos = cmds
            .iter()
            .map(|&(n, enabled, interval)| {
                let mut d = plist::Dictionary::new();
                d.insert(
                    "kCommandInfoCommandKey".into(),
                    plist::Value::Integer(n.into()),
                );
                d.insert(
                    "kCommandInfoEnabledKey".into(),
                    plist::Value::Boolean(enabled),
                );
                if let Some(i) = interval {
                    let o = plist::Dictionary::from_iter([(
                        "kMRMediaRemoteCommandInfoPreferredIntervalsKey".to_string(),
                        plist::Value::Array(vec![plist::Value::Integer(i.into())]),
                    )]);
                    d.insert("kCommandInfoOptionsKey".into(), plist::Value::Dictionary(o));
                }
                let mut b = Vec::new();
                plist::Value::Dictionary(d)
                    .to_writer_binary(&mut b)
                    .unwrap();
                plist::Value::Data(b)
            })
            .collect();
        let params = plist::Dictionary::from_iter([(
            "mrSupportedCommandsFromSender".to_string(),
            plist::Value::Array(infos),
        )]);
        let body = plist::Dictionary::from_iter([(
            "params".to_string(),
            plist::Value::Dictionary(params),
        )]);
        let s = std::sync::Arc::new(SupportedCommands::default());
        s.update(&body);
        s
    }

    fn command(c: &plist::Dictionary) -> (&str, Option<f64>) {
        let params = c.get("params").and_then(|v| v.as_dictionary()).unwrap();
        (
            c.get("modernMediaRemoteCommand")
                .and_then(|v| v.as_string())
                .unwrap(),
            params
                .get("kMRMediaRemoteOptionSkipInterval")
                .and_then(|v| v.as_real()),
        )
    }

    #[test]
    fn next_track_falls_back_to_the_skip_the_sender_takes() {
        // a podcast app: no next track, skips of 30 s
        let s = supported(&[
            (4, false, None),
            (5, false, None),
            (17, true, Some(30)),
            (18, true, Some(15)),
        ]);
        let c = sent_to(RemoteCommand::NextTrack, s.clone()).unwrap();
        assert_eq!(command(&c), ("17", Some(30.0)));
        let c = sent_to(RemoteCommand::PreviousTrack, s).unwrap();
        assert_eq!(command(&c), ("18", Some(15.0)));
        // Music with the next track queued: next track as it is
        let s = supported(&[(4, true, None), (17, false, Some(30))]);
        assert_eq!(
            command(&sent_to(RemoteCommand::NextTrack, s).unwrap()),
            ("4", None)
        );
        // nothing to skip to and no skips: nothing sent
        let s = supported(&[(4, false, None), (17, false, Some(30))]);
        assert!(sent_to(RemoteCommand::NextTrack, s).is_none());
        // not told yet: sent
        assert_eq!(command(&sent(RemoteCommand::NextTrack)), ("4", None));
    }

    #[test]
    fn a_key_is_a_media_remote_command_to_the_group() {
        let c = sent(RemoteCommand::Pause);
        assert_eq!(
            c.get("type").and_then(|v| v.as_string()),
            Some("sendMediaRemoteCommand")
        );
        assert_eq!(
            c.get("modernMediaRemoteCommand")
                .and_then(|v| v.as_string()),
            Some("1")
        );
        let params = c.get("params").and_then(|v| v.as_dictionary()).unwrap();
        let archive = params
            .get("kMRMediaRemoteOptionDestinationDeviceUIDs")
            .and_then(|v| v.as_data())
            .unwrap();
        let archive: plist::Value = plist::from_bytes(archive).unwrap();
        let objects = archive
            .as_dictionary()
            .unwrap()
            .get("$objects")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(objects[2].as_string(), Some("GROUP-1"));
    }

    #[test]
    fn the_volume_goes_as_dvlc() {
        let c = sent(RemoteCommand::SetVolume(35));
        assert_eq!(c.get("value").and_then(|v| v.as_string()), Some("dvlc"));
        assert_eq!(c.get("volume").and_then(|v| v.as_real()), Some(0.35));
    }
}
