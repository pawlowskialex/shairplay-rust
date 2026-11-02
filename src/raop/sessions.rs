//! The server's connections and the stream each one plays, in one place: which stream stops when another starts,
//! which connections a removed pairing or the server's stop closes, and that every stream's tasks end with it.

use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// A stream a connection plays. Dropping it stops it: its tasks end (sockets closed, the session flushed).
pub(crate) enum Stream {
    /// AirPlay 1 (RTP over UDP or TCP), from ANNOUNCE and SETUP
    Ap1(crate::raop::rtp::RaopRtp),
    /// AirPlay 2 realtime (type 96)
    #[cfg(feature = "ap2-core")]
    Realtime(crate::raop::realtime_audio::RealtimeStream),
    /// AirPlay 2 buffered (type 103)
    #[cfg(feature = "ap2-core")]
    Buffered(crate::raop::buffered_audio::BufferedStream),
}

/// One connection: who the sender is (AirPlay 2: the SETUP's `deviceID`, else its address), the controller it was
/// verified as, how to close it, and the stream it plays.
struct Entry {
    conn: u64,
    sender: String,
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
    controller: Option<String>,
    close: Arc<Notify>,
    stream: Option<Stream>,
}

/// Every open connection of a server.
#[derive(Default)]
pub(crate) struct Sessions(Mutex<Vec<Entry>>);

impl Sessions {
    fn entries(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Connection `conn` opened, from `sender`; `close` ends it.
    pub(crate) fn open(&self, conn: u64, sender: String, close: Arc<Notify>) {
        self.entries().push(Entry {
            conn,
            sender,
            controller: None,
            close,
            stream: None,
        });
    }

    /// Connection `conn` ended: its stream stops.
    pub(crate) fn close(&self, conn: u64) {
        let gone: Vec<Entry> = {
            let mut entries = self.entries();
            let (gone, kept) = std::mem::take(&mut *entries)
                .into_iter()
                .partition(|e| e.conn == conn);
            *entries = kept;
            gone
        };
        drop(gone); // outside the lock: a stream's end flushes its session
    }

    /// Connection `conn`'s sender says who it is (AirPlay 2: `deviceID`).
    #[cfg(feature = "ap2-core")]
    pub(crate) fn set_sender(&self, conn: u64, sender: &str) {
        if let Some(e) = self.entries().iter_mut().find(|e| e.conn == conn) {
            e.sender = sender.to_string();
        }
    }

    /// Connection `conn` was verified as paired controller `controller`.
    #[cfg(feature = "ap2-core")]
    pub(crate) fn verified(&self, conn: u64, controller: &str) {
        if let Some(e) = self.entries().iter_mut().find(|e| e.conn == conn) {
            e.controller = Some(controller.to_string());
        }
    }

    /// Connection `conn` plays `stream`: every other stream stops, and a connection of another sender that played
    /// one is closed. The newest sender takes the speaker, as with Apple's receivers; the one before sees the
    /// speaker go instead of believing it still plays. The same sender's other connections (iOS keeps several:
    /// Happy Eyeballs, remote control) stay open.
    pub(crate) fn play(&self, conn: u64, stream: Stream) {
        let mut stopped = Vec::new();
        {
            let mut entries = self.entries();
            let Some(sender) = entries
                .iter()
                .find(|e| e.conn == conn)
                .map(|e| e.sender.clone())
            else {
                return; // the connection is gone: the stream with it
            };
            for e in entries.iter_mut() {
                if e.conn == conn {
                    stopped.extend(e.stream.replace(stream));
                    break;
                }
            }
            // `stream` is in place: the loop above found the entry
            for e in entries.iter_mut().filter(|e| e.conn != conn) {
                let Some(old) = e.stream.take() else {
                    continue;
                };
                stopped.push(old);
                if e.sender != sender {
                    tracing::info!(from = %e.sender, to = %sender, "Another sender takes over: closing its connection");
                    e.close.notify_one();
                }
            }
        }
        drop(stopped);
    }

    /// Connection `conn`'s stream stops; the connection stays (a TEARDOWN of its streams only).
    pub(crate) fn stop(&self, conn: u64) {
        let stopped = self
            .entries()
            .iter_mut()
            .find(|e| e.conn == conn)
            .and_then(|e| e.stream.take());
        drop(stopped);
    }

    /// `f` on connection `conn`'s stream, if it plays one.
    pub(crate) fn with<R>(&self, conn: u64, f: impl FnOnce(&mut Stream) -> R) -> Option<R> {
        self.entries()
            .iter_mut()
            .find(|e| e.conn == conn)
            .and_then(|e| e.stream.as_mut())
            .map(f)
    }

    /// Whether connection `conn` plays a stream.
    pub(crate) fn plays(&self, conn: u64) -> bool {
        self.with(conn, |_| ()).is_some()
    }

    /// Close every connection verified as `controller` (its pairing was removed).
    #[cfg(feature = "ap2-core")]
    pub(crate) fn close_controller(&self, controller: &str) {
        for e in self
            .entries()
            .iter()
            .filter(|e| e.controller.as_deref() == Some(controller))
        {
            e.close.notify_one();
        }
    }

    /// The server stops: every stream stops and every connection closes.
    pub(crate) fn close_all(&self) {
        let stopped: Vec<Stream> = self
            .entries()
            .iter_mut()
            .filter_map(|e| {
                e.close.notify_one();
                e.stream.take()
            })
            .collect();
        drop(stopped);
    }
}

#[cfg(all(test, feature = "ap2-core"))]
mod tests {
    use super::*;
    use crate::raop::buffered_audio::BufferedStream;

    fn open(s: &Sessions, conn: u64, sender: &str) -> Arc<Notify> {
        let close = Arc::new(Notify::new());
        s.open(conn, sender.into(), close.clone());
        close
    }

    /// Whether `n` was notified (a permit is waiting).
    fn notified(n: &Notify) -> bool {
        let f = n.notified();
        tokio::pin!(f);
        f.as_mut().enable()
    }

    #[tokio::test]
    async fn the_newest_stream_plays_and_another_senders_connection_closes() {
        let s = Sessions::default();
        let (mac, phone, phone2) = (
            open(&s, 1, "mac"),
            open(&s, 2, "phone"),
            open(&s, 3, "phone"),
        );
        let (a, mut a_stopped) = BufferedStream::probe();
        s.play(1, Stream::Buffered(a));
        assert!(s.plays(1));
        let (b, mut b_stopped) = BufferedStream::probe();
        s.play(2, Stream::Buffered(b));
        assert!(a_stopped.stopped());
        assert!(!s.plays(1) && s.plays(2));
        assert!(notified(&mac), "the Mac's connection closes");
        // the same sender's other connection takes the stream over: nothing closes
        let (c, _) = BufferedStream::probe();
        s.play(3, Stream::Buffered(c));
        assert!(b_stopped.stopped());
        assert!(!notified(&phone) && !notified(&phone2));
    }

    #[tokio::test]
    async fn a_teardown_stops_only_its_own_connections_stream() {
        let s = Sessions::default();
        open(&s, 1, "mac");
        open(&s, 2, "phone");
        let (a, mut probe) = BufferedStream::probe();
        s.play(1, Stream::Buffered(a));
        s.stop(2);
        assert!(!probe.stopped());
        s.stop(1);
        assert!(probe.stopped());
    }

    #[tokio::test]
    async fn the_servers_stop_and_a_removed_pairing_close_their_connections() {
        let s = Sessions::default();
        let (a, b) = (open(&s, 1, "mac"), open(&s, 2, "phone"));
        s.verified(2, "phone-controller");
        s.close_controller("phone-controller");
        assert!(!notified(&a) && notified(&b));
        let (stream, mut probe) = BufferedStream::probe();
        s.play(1, Stream::Buffered(stream));
        s.close_all();
        assert!(notified(&a) && probe.stopped());
        s.close(1);
        s.close(2);
        assert!(s.entries().is_empty());
    }
}
