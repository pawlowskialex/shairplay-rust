//! Realtime RTP packets in sequence order, with lost ones asked for again on the sender's control port: AirPlay 2's
//! realtime streams and AirPlay 1 over UDP.

use tokio::net::UdpSocket;
use tracing::info;

/// RTP payload type of a retransmit request (AirPlay's, from the receiver to the sender's control port) and of its
/// answer (the resent packet, on our control port behind a 4-byte header).
const RESEND_PAYLOAD_TYPE: u8 = 0x55;
const RESENT_PAYLOAD_TYPE: u8 = 0x56;
const RESENT_HEADER_LEN: usize = 4;

/// Ask for `count` packets from sequence number `first`: 0x80, 0xd5 (marker | 0x55), our own sequence number (1),
/// then first and count, big-endian.
fn resend_request(first: u16, count: u16) -> [u8; 8] {
    let mut r = [0x80, 0x80 | RESEND_PAYLOAD_TYPE, 0, 1, 0, 0, 0, 0];
    r[4..6].copy_from_slice(&first.to_be_bytes());
    r[6..8].copy_from_slice(&count.to_be_bytes());
    r
}

/// Where retransmit requests go and their answers come from: our control socket (its port went to the sender as
/// `controlPort`) and the sender's control port (its `controlPort` in the stream SETUP).
pub(crate) struct Retransmit {
    pub(crate) socket: UdpSocket,
    pub(crate) sender: std::net::SocketAddr,
}

impl Retransmit {
    /// Ask the sender for what `reorder` found missing.
    pub(crate) async fn ask(&self, reorder: &mut Reorder) {
        for (first, count) in reorder.take_requests() {
            let _ = self
                .socket
                .send_to(&resend_request(first, count), self.sender)
                .await;
        }
    }
}

/// The original packet in a resend answer (0x80 0xd6 seq, then the packet); `None` for anything else on the control
/// port (sync packets).
pub(crate) fn resent_packet(p: &[u8]) -> Option<&[u8]> {
    (p.len() > RESENT_HEADER_LEN && p[1] & 0x7f == RESENT_PAYLOAD_TYPE)
        .then(|| &p[RESENT_HEADER_LEN..])
}

#[derive(Default, Debug, PartialEq)]
struct ReorderStats {
    packets: u32,   // arrived, resent ones included
    missing: u32,   // sequence numbers found missing
    asked: u32,     // retransmit requests (packets asked for, repeats included)
    recovered: u32, // missing ones that arrived in time
    wait_us: u64,   // their total wait from the first ask (the average tells the round trip)
    wait_max_us: u64,
    gap_max_us: u64, // the longest time without any packet arriving (network stalls)
    filled: u32,     // given up on: played as silence
    late: u32,       // arrived after their place was played (or twice)
}

/// Realtime packets in sequence order. A packet behind a gap is held while the gap is asked for again (`ASK_AGAIN`
/// later once more); after `GIVE_UP`, or with `max_held` packets waiting, the gap is played as silence (the output
/// queue has to cover the wait, a few hundred ms). A jump of more than `MAX_GAP` is a new start (a flush), not a
/// loss. Without retransmits (`hold` false) gaps are given up at once.
pub(crate) struct Reorder {
    hold: bool,
    max_held: usize,
    next: Option<u64>, // extended sequence number of the next packet to play
    held: std::collections::BTreeMap<u64, Vec<u8>>, // arrived beyond a gap
    asked: std::collections::BTreeMap<u64, (std::time::Instant, std::time::Instant, u8)>, // missing: first, last ask, asks
    requests: Vec<(u16, u16)>,
    last_arrival: Option<std::time::Instant>,
    stats: ReorderStats,
}

const ASK_AGAIN: std::time::Duration = std::time::Duration::from_millis(50);
const GIVE_UP: std::time::Duration = std::time::Duration::from_millis(120);
const MAX_GAP: u64 = 64;

impl Reorder {
    pub(crate) fn new(hold: bool, max_held: usize) -> Self {
        Reorder {
            hold,
            max_held,
            next: None,
            held: std::collections::BTreeMap::default(),
            asked: std::collections::BTreeMap::default(),
            requests: Vec::new(),
            last_arrival: None,
            stats: ReorderStats::default(),
        }
    }

    pub(crate) fn holding(&self) -> bool {
        !self.held.is_empty()
    }

    fn take_requests(&mut self) -> Vec<(u16, u16)> {
        std::mem::take(&mut self.requests)
    }

    /// An arriving packet; whatever can be played now (with the silence before it) goes to `out`. False when it
    /// came too late (its place was played) or twice: not taken.
    pub(crate) fn push(
        &mut self,
        seq: u16,
        packet: &[u8],
        now: std::time::Instant,
        out: &mut Vec<(u32, Vec<u8>)>,
    ) -> bool {
        self.stats.packets += 1;
        if let Some(t) = self.last_arrival.replace(now) {
            self.stats.gap_max_us = self
                .stats
                .gap_max_us
                .max(now.duration_since(t).as_micros() as u64);
        }
        let next = *self.next.get_or_insert(seq as u64 + 0x10000);
        // the extended number nearest to `next`
        let ext = (next as i64 + (seq.wrapping_sub(next as u16) as i16) as i64) as u64;
        if ext < next || self.held.contains_key(&ext) {
            self.stats.late += 1;
            return false;
        }
        if ext - next > MAX_GAP {
            // a new start: play what is held (gaps in it as silence), then go on from here
            self.give_up_all(out);
            self.asked.clear();
            self.next = Some(ext);
        }
        if let Some((t0, _, _)) = self.asked.remove(&ext) {
            let w = now.duration_since(t0).as_micros() as u64;
            self.stats.recovered += 1;
            self.stats.wait_us += w;
            self.stats.wait_max_us = self.stats.wait_max_us.max(w);
        }
        self.held.insert(ext, packet.to_vec());
        self.release(out);
        // newly missing: everything below the newest held packet that is neither held nor asked for
        if let Some(&top) = self.held.keys().next_back() {
            let mut run: Option<(u64, u64)> = None;
            for m in self.next.unwrap()..top {
                if self.held.contains_key(&m) || self.asked.contains_key(&m) {
                    continue;
                }
                self.stats.missing += 1;
                self.asked.insert(m, (now, now, 1));
                run = match run {
                    Some((a, b)) if b == m => Some((a, m + 1)),
                    Some((a, b)) => {
                        self.ask(a, b);
                        Some((m, m + 1))
                    }
                    None => Some((m, m + 1)),
                };
            }
            if let Some((a, b)) = run {
                self.ask(a, b);
            }
        }
        if !self.hold {
            self.give_up_all(out);
        }
        true
    }

    /// Time passing: ask again, or give up on gaps that waited long enough.
    pub(crate) fn tick(&mut self, now: std::time::Instant, out: &mut Vec<(u32, Vec<u8>)>) {
        let again: Vec<u64> = self
            .asked
            .iter()
            .filter(|(_, (_, last, n))| *n < 2 && now.duration_since(*last) >= ASK_AGAIN)
            .map(|(&m, _)| m)
            .collect();
        for m in again {
            if let Some(e) = self.asked.get_mut(&m) {
                e.1 = now;
                e.2 += 1;
            }
            self.ask(m, m + 1);
        }
        while let Some(next) = self.next {
            let Some((&first, _)) = self.held.iter().next() else {
                break;
            };
            let waited = self
                .asked
                .get(&next)
                .map_or(GIVE_UP, |(t, _, _)| now.duration_since(*t));
            if waited < GIVE_UP && self.held.len() <= self.max_held {
                break;
            }
            self.skip_to(first, out);
        }
    }

    fn ask(&mut self, from: u64, to: u64) {
        if self.hold {
            self.stats.asked += (to - from) as u32;
            self.requests.push((from as u16, (to - from) as u16));
        }
    }

    /// Play the held packets that are next in line.
    fn release(&mut self, out: &mut Vec<(u32, Vec<u8>)>) {
        while let Some(next) = self.next {
            let Some(p) = self.held.remove(&next) else {
                break;
            };
            out.push((0, p));
            self.next = Some(next + 1);
        }
    }

    /// Give up on everything before `first` (held): silence for it, then play on.
    fn skip_to(&mut self, first: u64, out: &mut Vec<(u32, Vec<u8>)>) {
        let next = self.next.unwrap();
        let fill = (first - next) as u32;
        self.stats.filled += fill;
        for m in next..first {
            self.asked.remove(&m);
        }
        let p = self.held.remove(&first).unwrap();
        out.push((fill, p));
        self.next = Some(first + 1);
        self.release(out);
    }

    /// A flush: `next` is the first packet that stays (held ones before it go), without one everything goes and the
    /// next packet starts over.
    pub(crate) fn flush(&mut self, next: Option<u16>) {
        match (next, self.next) {
            (Some(n), Some(cur)) => {
                let ext = (cur as i64 + (n.wrapping_sub(cur as u16) as i16) as i64) as u64;
                // what went out from it on stays out
                let ext = ext.max(cur);
                self.held.retain(|&k, _| k >= ext);
                self.asked.retain(|&k, _| k >= ext);
                self.next = Some(ext);
            }
            _ => {
                self.held.clear();
                self.asked.clear();
                self.next = next.map(|n| n as u64 + 0x10000);
            }
        }
    }

    /// The counts since the last report, to the log.
    pub(crate) fn report(&mut self, stream: &str) {
        let s = std::mem::take(&mut self.stats);
        info!(
            packets = s.packets,
            missing = s.missing,
            asked = s.asked,
            recovered = s.recovered,
            wait_avg_ms = s.wait_us / 1000 / s.recovered.max(1) as u64,
            wait_max_ms = s.wait_max_us / 1000,
            gap_max_ms = s.gap_max_us / 1000,
            filled = s.filled,
            late = s.late,
            "{stream} 10 s"
        );
    }

    fn give_up_all(&mut self, out: &mut Vec<(u32, Vec<u8>)>) {
        while let Some((&first, _)) = self.held.iter().next() {
            self.skip_to(first, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_HELD: usize = 48;

    use std::time::{Duration, Instant};

    fn seqs(out: &[(u32, Vec<u8>)]) -> Vec<(u32, u8)> {
        out.iter().map(|(f, p)| (*f, p[0])).collect()
    }

    #[test]
    fn resend_request_bytes() {
        assert_eq!(
            resend_request(0x1234, 3),
            [0x80, 0xd5, 0, 1, 0x12, 0x34, 0, 3]
        );
    }

    #[test]
    fn in_order_packets_pass_straight_through() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        for s in 10..15u16 {
            r.push(s, &[s as u8], t, &mut out);
        }
        assert_eq!(
            seqs(&out),
            vec![(0, 10), (0, 11), (0, 12), (0, 13), (0, 14)]
        );
        assert!(!r.holding() && r.take_requests().is_empty());
    }

    #[test]
    fn a_gap_is_asked_for_and_filled_by_the_resent_packet() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(4, &[4], t, &mut out); // 2 and 3 missing
        r.push(5, &[5], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1)]);
        assert_eq!(r.take_requests(), vec![(2, 2)]);
        r.push(2, &[2], t + Duration::from_millis(10), &mut out);
        r.push(3, &[3], t + Duration::from_millis(11), &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (0, 2), (0, 3), (0, 4), (0, 5)]);
        assert_eq!(
            (r.stats.missing, r.stats.recovered, r.stats.filled),
            (2, 2, 0)
        );
        assert!(!r.holding());
    }

    #[test]
    fn asks_once_more_then_gives_up_with_silence() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(3, &[3], t, &mut out);
        assert_eq!(r.take_requests(), vec![(2, 1)]);
        r.tick(t + ASK_AGAIN, &mut out);
        assert_eq!(r.take_requests(), vec![(2, 1)]);
        r.tick(t + ASK_AGAIN * 2, &mut out); // asked twice already: not again
        assert!(r.take_requests().is_empty());
        assert_eq!(seqs(&out), vec![(0, 1)]);
        r.tick(t + GIVE_UP, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (1, 3)]);
        r.push(2, &[2], t + GIVE_UP, &mut out); // too late now
        assert_eq!((r.stats.filled, r.stats.late, r.stats.asked), (1, 1, 2));
    }

    #[test]
    fn without_retransmits_gaps_are_silence_at_once() {
        let (mut r, t, mut out) = (Reorder::new(false, MAX_HELD), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(4, &[4], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (2, 4)]);
        assert!(r.take_requests().is_empty() && !r.holding());
    }

    #[test]
    fn sequence_numbers_wrap() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(65534, &[0xfe], t, &mut out);
        r.push(0, &[0], t, &mut out); // 65535 missing
        assert_eq!(r.take_requests(), vec![(65535, 1)]);
        r.push(65535, &[0xff], t, &mut out);
        r.push(1, &[1], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 0xfe), (0, 0xff), (0, 0), (0, 1)]);
    }

    #[test]
    fn a_big_jump_is_a_new_start_not_a_loss() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(100, &[1], t, &mut out);
        r.push(5000, &[2], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (0, 2)]);
        assert!(r.take_requests().is_empty());
        assert_eq!((r.stats.missing, r.stats.filled), (0, 0));
    }

    #[test]
    fn a_flush_drops_what_is_held_before_its_point() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(1, &[1], t, &mut out);
        r.push(3, &[3], t, &mut out); // 2 missing
        r.push(6, &[6], t, &mut out); // 4, 5 missing
        r.take_requests();
        r.flush(Some(5));
        r.tick(t, &mut out); // 3 and the ask for 2 and 4 gone, 5 still awaited
        assert_eq!(seqs(&out), vec![(0, 1)]);
        r.tick(t + GIVE_UP, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (1, 6)]);
        r.push(7, &[7], t, &mut out);
        assert_eq!(seqs(&out)[2..], [(0, 7)]);
    }

    #[test]
    fn a_flush_behind_what_went_out_changes_nothing() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        for s in 10..13u16 {
            r.push(s, &[s as u8], t, &mut out);
        }
        r.flush(Some(11));
        r.push(13, &[13], t, &mut out);
        assert!(r.take_requests().is_empty());
        assert_eq!(out.len(), 4);
        assert!(!r.push(12, &[12], t, &mut out)); // a second packet under 12: not taken
    }

    #[test]
    fn a_flush_without_a_point_starts_over() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(10, &[10], t, &mut out);
        r.push(12, &[12], t, &mut out);
        r.flush(None);
        assert!(!r.holding());
        r.push(3, &[3], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 10), (0, 3)]);
    }

    #[test]
    fn too_many_held_gives_up_early() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(0, &[0], t, &mut out);
        for s in 2..=(MAX_HELD as u16 + 2) {
            r.push(s, &[s as u8], t, &mut out);
        }
        r.tick(t, &mut out); // well before GIVE_UP
        assert_eq!(out.len(), MAX_HELD + 2);
        assert_eq!(out[1].0, 1); // packet 1 as silence
        assert!(!r.holding());
    }
}
