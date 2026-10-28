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
}

#[cfg(feature = "ap2-core")]
impl Ap2RemoteControl {
    pub(crate) fn new(events: event_channel::EventSender, group: Option<String>) -> Self {
        Self { events, group }
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
            // MRMediaRemoteCommand numbers
            let n = match cmd {
                RemoteCommand::Play => 0,
                RemoteCommand::Pause => 1,
                RemoteCommand::Stop => 3,
                RemoteCommand::NextTrack => 4,
                RemoteCommand::PreviousTrack => 5,
                RemoteCommand::ToggleShuffle => 6, // advance the shuffle mode
                RemoteCommand::ToggleRepeat => 7,  // advance the repeat mode
                RemoteCommand::SetVolume(_) => unreachable!(),
            };
            c.insert(
                "modernMediaRemoteCommand".into(),
                plist::Value::String(n.to_string()),
            );
            c.insert("params".into(), plist::Value::Dictionary(self.options()));
        }
        self.events
            .post_command(&c)
            .map_err(crate::error::ShairplayError::Network)
    }

    fn available_commands(&self) -> Vec<RemoteCommand> {
        vec![
            RemoteCommand::Play,
            RemoteCommand::Pause,
            RemoteCommand::NextTrack,
            RemoteCommand::PreviousTrack,
            RemoteCommand::SetVolume(0),
            RemoteCommand::ToggleShuffle,
            RemoteCommand::ToggleRepeat,
            RemoteCommand::Stop,
        ]
    }
}

impl RemoteControl for DacpRemoteControl {
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError> {
        let result = match cmd {
            // not playpause: a play to a sender that plays (a receiver resuming it) would pause it
            RemoteCommand::Play => self.client.play_blocking(),
            RemoteCommand::Pause => self.client.pause_blocking(),
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let remote = Ap2RemoteControl::new(
            event_channel::EventSender::from_tx(tx),
            Some("GROUP-1".into()),
        );
        remote.send_command(cmd).unwrap();
        let msg = rx.try_recv().unwrap();
        let start = msg.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(msg.starts_with(b"POST /command RTSP/1.0\r\n"));
        plist::from_bytes::<plist::Value>(&msg[start..])
            .unwrap()
            .into_dictionary()
            .unwrap()
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
