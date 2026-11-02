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
    pub(crate) async fn ask<T>(&self, reorder: &mut Reorder<T>) {
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

/// Realtime packets (or what was made of them: `T`) in sequence order. A packet behind a gap is held while the gap
/// is asked for again (`ASK_AGAIN` later once more, then every `ASK_LATER`, `MAX_ASKS` times in all, a run of missing
/// ones in one request); after `GIVE_UP` (or the stream's longer [`wait`](Self::wait)), or with `max_held` packets
/// waiting, the gap is played as silence (the output queue has to cover the wait). A jump of more than `MAX_GAP`, or
/// than what may be held, is a new start (a flush), not a loss. Without retransmits (`hold` false) gaps are given up
/// at once.
pub(crate) struct Reorder<T = Vec<u8>> {
    hold: bool,
    max_held: usize,
    give_up: std::time::Duration,
    next: Option<u64>, // extended sequence number of the next packet to play
    held: std::collections::BTreeMap<u64, T>, // arrived beyond a gap
    asked: std::collections::BTreeMap<u64, (std::time::Instant, std::time::Instant, u8)>, // missing: first, last ask, asks
    requests: Vec<(u16, u16)>,
    last_arrival: Option<std::time::Instant>,
    stats: ReorderStats,
}

const ASK_AGAIN: std::time::Duration = std::time::Duration::from_millis(50);
const ASK_LATER: std::time::Duration = std::time::Duration::from_millis(250);
/// A missing packet is asked for at most this often (at once, after `ASK_AGAIN`, then every `ASK_LATER`).
const MAX_ASKS: u8 = 4;
const GIVE_UP: std::time::Duration = std::time::Duration::from_millis(120);
const MAX_GAP: u64 = 64;

impl<T> Reorder<T> {
    pub(crate) fn new(hold: bool, max_held: usize) -> Self {
        Reorder {
            hold,
            max_held,
            give_up: GIVE_UP,
            next: None,
            held: std::collections::BTreeMap::default(),
            asked: std::collections::BTreeMap::default(),
            requests: Vec::new(),
            last_arrival: None,
            stats: ReorderStats::default(),
        }
    }

    /// A stream that plays well after its packets arrive (on the sender's timeline) waits for a gap up to `wait`
    /// instead of `GIVE_UP` (and gives it up sooner through [`tick_until`](Self::tick_until)), holding what comes
    /// behind it meanwhile (`packets_per_s`): a packet or a resend that is late but still before its time plays.
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
    pub(crate) fn wait(&mut self, wait: std::time::Duration, packets_per_s: u32) {
        self.give_up = wait.max(GIVE_UP);
        let held = self.give_up.as_millis() as usize * packets_per_s as usize / 1000;
        self.max_held = self.max_held.max(held + held / 8);
    }

    pub(crate) fn holding(&self) -> bool {
        !self.held.is_empty()
    }

    fn take_requests(&mut self) -> Vec<(u16, u16)> {
        std::mem::take(&mut self.requests)
    }

    /// Whether a packet arriving now still has a place (it isn't played, given up or held already): one that hasn't
    /// is counted as a late arrival, and isn't worth decrypting or decoding (a stream that decodes before ordering
    /// asks first: in a catch-up after a stall most of what arrives is late, or a resend of what came meanwhile).
    #[cfg_attr(not(feature = "ap2-core"), allow(dead_code))]
    pub(crate) fn wants(&mut self, seq: u16, now: std::time::Instant) -> bool {
        let Some(next) = self.next else {
            return true;
        };
        let ext = nearest(next, seq);
        if ext >= next && !self.held.contains_key(&ext) {
            return true;
        }
        self.arrived(now);
        self.stats.late += 1;
        false
    }

    fn arrived(&mut self, now: std::time::Instant) {
        self.stats.packets += 1;
        if let Some(t) = self.last_arrival.replace(now) {
            self.stats.gap_max_us = self
                .stats
                .gap_max_us
                .max(now.duration_since(t).as_micros() as u64);
        }
    }

    /// An arriving packet; whatever can be played now (with the silence before it) goes to `out`. False when it
    /// came too late (its place was played) or twice: not taken.
    pub(crate) fn push(
        &mut self,
        seq: u16,
        packet: T,
        now: std::time::Instant,
        out: &mut Vec<(u32, T)>,
    ) -> bool {
        self.arrived(now);
        let next = *self.next.get_or_insert(seq as u64 + 0x10000);
        let ext = nearest(next, seq);
        if ext < next || self.held.contains_key(&ext) {
            self.stats.late += 1;
            return false;
        }
        if ext - next > MAX_GAP.max(self.max_held as u64) {
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
        self.held.insert(ext, packet);
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
    pub(crate) fn tick(&mut self, now: std::time::Instant, out: &mut Vec<(u32, T)>) {
        self.tick_until(now, out, |_, _| false);
    }

    /// As [`tick`](Self::tick), and a gap is also given up once `due(first, missing)` says so: `first` is what is
    /// held right behind it, `missing` how many are missing before that (a stream on a timeline gives up a gap
    /// shortly before it plays).
    pub(crate) fn tick_until(
        &mut self,
        now: std::time::Instant,
        out: &mut Vec<(u32, T)>,
        due: impl Fn(&T, u64) -> bool,
    ) {
        // asked again in runs of consecutive numbers, one request each (a stall leaves hundreds missing)
        let again: Vec<u64> = self
            .asked
            .iter()
            .filter(|(_, (_, last, n))| {
                *n < MAX_ASKS
                    && now.duration_since(*last) >= if *n < 2 { ASK_AGAIN } else { ASK_LATER }
            })
            .map(|(&m, _)| m)
            .collect();
        let mut run: Option<(u64, u64)> = None;
        for m in again {
            if let Some(e) = self.asked.get_mut(&m) {
                e.1 = now;
                e.2 += 1;
            }
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
        while let Some(next) = self.next {
            let Some((&first, held)) = self.held.iter().next() else {
                break;
            };
            let waited = self
                .asked
                .get(&next)
                .map_or(self.give_up, |(t, _, _)| now.duration_since(*t));
            if waited < self.give_up && self.held.len() <= self.max_held && !due(held, first - next)
            {
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
    fn release(&mut self, out: &mut Vec<(u32, T)>) {
        while let Some(next) = self.next {
            let Some(p) = self.held.remove(&next) else {
                break;
            };
            out.push((0, p));
            self.next = Some(next + 1);
        }
    }

    /// Give up on everything before `first` (held): silence for it, then play on.
    fn skip_to(&mut self, first: u64, out: &mut Vec<(u32, T)>) {
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

    fn give_up_all(&mut self, out: &mut Vec<(u32, T)>) {
        while let Some((&first, _)) = self.held.iter().next() {
            self.skip_to(first, out);
        }
    }
}

/// The extended sequence number of `seq` nearest to `next`.
fn nearest(next: u64, seq: u16) -> u64 {
    (next as i64 + (seq.wrapping_sub(next as u16) as i16) as i64) as u64
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
            r.push(s, vec![s as u8], t, &mut out);
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
        r.push(1, vec![1], t, &mut out);
        r.push(4, vec![4], t, &mut out); // 2 and 3 missing
        r.push(5, vec![5], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1)]);
        assert_eq!(r.take_requests(), vec![(2, 2)]);
        r.push(2, vec![2], t + Duration::from_millis(10), &mut out);
        r.push(3, vec![3], t + Duration::from_millis(11), &mut out);
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
        r.push(1, vec![1], t, &mut out);
        r.push(3, vec![3], t, &mut out);
        assert_eq!(r.take_requests(), vec![(2, 1)]);
        r.tick(t + ASK_AGAIN, &mut out);
        assert_eq!(r.take_requests(), vec![(2, 1)]);
        r.tick(t + ASK_AGAIN * 2, &mut out); // asked twice already: not again
        assert!(r.take_requests().is_empty());
        assert_eq!(seqs(&out), vec![(0, 1)]);
        r.tick(t + GIVE_UP, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (1, 3)]);
        r.push(2, vec![2], t + GIVE_UP, &mut out); // too late now
        assert_eq!((r.stats.filled, r.stats.late, r.stats.asked), (1, 1, 2));
    }

    #[test]
    fn without_retransmits_gaps_are_silence_at_once() {
        let (mut r, t, mut out) = (Reorder::new(false, MAX_HELD), Instant::now(), Vec::new());
        r.push(1, vec![1], t, &mut out);
        r.push(4, vec![4], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (2, 4)]);
        assert!(r.take_requests().is_empty() && !r.holding());
    }

    #[test]
    fn sequence_numbers_wrap() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(65534, vec![0xfe], t, &mut out);
        r.push(0, vec![0], t, &mut out); // 65535 missing
        assert_eq!(r.take_requests(), vec![(65535, 1)]);
        r.push(65535, vec![0xff], t, &mut out);
        r.push(1, vec![1], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 0xfe), (0, 0xff), (0, 0), (0, 1)]);
    }

    #[test]
    fn a_big_jump_is_a_new_start_not_a_loss() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(100, vec![1], t, &mut out);
        r.push(5000, vec![2], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (0, 2)]);
        assert!(r.take_requests().is_empty());
        assert_eq!((r.stats.missing, r.stats.filled), (0, 0));
    }

    #[test]
    fn a_flush_drops_what_is_held_before_its_point() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(1, vec![1], t, &mut out);
        r.push(3, vec![3], t, &mut out); // 2 missing
        r.push(6, vec![6], t, &mut out); // 4, 5 missing
        r.take_requests();
        r.flush(Some(5));
        r.tick(t, &mut out); // 3 and the ask for 2 and 4 gone, 5 still awaited
        assert_eq!(seqs(&out), vec![(0, 1)]);
        r.tick(t + GIVE_UP, &mut out);
        assert_eq!(seqs(&out), vec![(0, 1), (1, 6)]);
        r.push(7, vec![7], t, &mut out);
        assert_eq!(seqs(&out)[2..], [(0, 7)]);
    }

    #[test]
    fn a_flush_behind_what_went_out_changes_nothing() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        for s in 10..13u16 {
            r.push(s, vec![s as u8], t, &mut out);
        }
        r.flush(Some(11));
        r.push(13, vec![13], t, &mut out);
        assert!(r.take_requests().is_empty());
        assert_eq!(out.len(), 4);
        assert!(!r.push(12, vec![12], t, &mut out)); // a second packet under 12: not taken
    }

    #[test]
    fn a_flush_without_a_point_starts_over() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(10, vec![10], t, &mut out);
        r.push(12, vec![12], t, &mut out);
        r.flush(None);
        assert!(!r.holding());
        r.push(3, vec![3], t, &mut out);
        assert_eq!(seqs(&out), vec![(0, 10), (0, 3)]);
    }

    /// A stream that plays a second or more after its packets arrive waits for a gap that long: a resend 600 ms late
    /// still fills it, asked for again every `ASK_LATER` meanwhile, and the 100 packets held behind it are no new start.
    #[test]
    fn a_stream_that_plays_later_waits_longer_for_a_gap() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.wait(Duration::from_secs(1), 125);
        r.push(0, vec![0], t, &mut out);
        for s in 2..=101u16 {
            r.push(s, vec![s as u8], t, &mut out);
        }
        assert_eq!(r.take_requests(), vec![(1, 1)]);
        let mut asks = 1;
        for ms in (10..=600).step_by(10) {
            r.tick(t + Duration::from_millis(ms), &mut out);
            asks += r.take_requests().len();
        }
        assert_eq!(asks, 4, "at once, after 50 ms, then every 250 ms");
        assert_eq!(out.len(), 1, "still waiting for 1");
        r.push(1, vec![1], t + Duration::from_millis(600), &mut out);
        assert_eq!(out.len(), 102);
        assert!(out.iter().all(|(fill, _)| *fill == 0));
        assert_eq!((r.stats.recovered, r.stats.filled), (1, 0));
        // a gap nobody fills: silence at the wait
        r.push(103, vec![103], t + Duration::from_millis(600), &mut out);
        r.tick(t + Duration::from_millis(1500), &mut out);
        assert!(r.holding());
        r.tick(t + Duration::from_millis(1600), &mut out);
        assert_eq!(out.last().map(|(f, p)| (*f, p[0])), Some((1, 103)));
    }

    /// A gap is given up as soon as its deadline says so, long before the wait runs out.
    #[test]
    fn a_gap_is_given_up_at_its_deadline() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.wait(Duration::from_secs(2), 125);
        r.push(0, vec![0], t, &mut out);
        r.push(3, vec![3], t, &mut out); // 1 and 2 missing
        // "due" once what is held right behind the gap is packet 3 with 2 missing before it, from 30 ms on
        let due = |now: Instant| {
            move |held: &Vec<u8>, missing: u64| {
                held[0] == 3 && missing == 2 && now >= t + Duration::from_millis(30)
            }
        };
        r.tick_until(
            t + Duration::from_millis(20),
            &mut out,
            due(t + Duration::from_millis(20)),
        );
        assert!(r.holding());
        r.tick_until(
            t + Duration::from_millis(30),
            &mut out,
            due(t + Duration::from_millis(30)),
        );
        assert_eq!(seqs(&out), vec![(0, 0), (2, 3)]);
    }

    /// What was played, given up or is held has no place any more: not wanted, counted late.
    #[test]
    fn only_packets_with_a_place_are_wanted() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        assert!(r.wants(5, t), "nothing seen yet");
        r.push(5, vec![5], t, &mut out);
        r.push(7, vec![7], t, &mut out); // 6 missing, 7 held
        assert!(!r.wants(5, t) && !r.wants(7, t));
        assert!(r.wants(6, t) && r.wants(8, t));
        assert_eq!((r.stats.packets, r.stats.late), (4, 2));
    }

    /// A run of missing packets is asked for again in one request, and no more than `MAX_ASKS` times.
    #[test]
    fn a_run_is_asked_for_again_in_one_request_a_few_times() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.wait(Duration::from_secs(2), 125);
        r.push(10, vec![10], t, &mut out);
        r.push(20, vec![20], t, &mut out); // 11..20 missing
        let mut requests = r.take_requests();
        for ms in (10..=1500).step_by(10) {
            r.tick(t + Duration::from_millis(ms), &mut out);
            requests.extend(r.take_requests());
        }
        assert_eq!(requests, vec![(11, 9); MAX_ASKS as usize]);
    }

    #[test]
    fn too_many_held_gives_up_early() {
        let (mut r, t, mut out) = (Reorder::new(true, MAX_HELD), Instant::now(), Vec::new());
        r.push(0, vec![0], t, &mut out);
        for s in 2..=(MAX_HELD as u16 + 2) {
            r.push(s, vec![s as u8], t, &mut out);
        }
        r.tick(t, &mut out); // well before GIVE_UP
        assert_eq!(out.len(), MAX_HELD + 2);
        assert_eq!(out[1].0, 1); // packet 1 as silence
        assert!(!r.holding());
    }
}
