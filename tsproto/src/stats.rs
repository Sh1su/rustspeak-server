//! Per-connection traffic statistics, grouped like TeamSpeak's connection info:
//! speech (voice), keepalive (ping/pong) and control (commands, acks).

use std::collections::VecDeque;
use std::time::Instant;

use crate::packet::PacketType;

pub const SPEECH: usize = 0;
pub const KEEPALIVE: usize = 1;
pub const CONTROL: usize = 2;

pub fn kind_of(t: PacketType) -> usize {
    match t {
        PacketType::Voice | PacketType::VoiceWhisper => SPEECH,
        PacketType::Ping | PacketType::Pong => KEEPALIVE,
        _ => CONTROL,
    }
}

#[derive(Clone)]
struct Bucket {
    sec: u64,
    sent: [u64; 3],
    recv: [u64; 3],
}

#[derive(Clone)]
pub struct Stats {
    pub packets_sent: [u64; 3],
    pub bytes_sent: [u64; 3],
    pub packets_recv: [u64; 3],
    pub bytes_recv: [u64; 3],
    /// Command packets we had to send again (our outgoing loss estimate)
    pub resent: u64,
    expected: [u64; 3],
    received: [u64; 3],
    last_id: [Option<u16>; 3],
    buckets: VecDeque<Bucket>,
    start: Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            packets_sent: [0; 3],
            bytes_sent: [0; 3],
            packets_recv: [0; 3],
            bytes_recv: [0; 3],
            resent: 0,
            expected: [0; 3],
            received: [0; 3],
            last_id: [None; 3],
            buckets: VecDeque::new(),
            start: Instant::now(),
        }
    }
}

impl Stats {
    fn bucket(&mut self) -> &mut Bucket {
        let sec = self.start.elapsed().as_secs();
        if self.buckets.back().map(|b| b.sec) != Some(sec) {
            self.buckets.push_back(Bucket { sec, sent: [0; 3], recv: [0; 3] });
            while self.buckets.len() > 62 {
                self.buckets.pop_front();
            }
        }
        self.buckets.back_mut().unwrap()
    }

    pub fn on_send(&mut self, kind: usize, bytes: usize) {
        self.packets_sent[kind] += 1;
        self.bytes_sent[kind] += bytes as u64;
        self.bucket().sent[kind] += bytes as u64;
    }

    pub fn on_recv(&mut self, kind: usize, bytes: usize) {
        self.packets_recv[kind] += 1;
        self.bytes_recv[kind] += bytes as u64;
        self.bucket().recv[kind] += bytes as u64;
    }

    /// Track sequential packet ids (voice, ping) to estimate incoming loss.
    pub fn on_recv_id(&mut self, kind: usize, id: u16) {
        match self.last_id[kind] {
            None => {
                self.expected[kind] += 1;
                self.received[kind] += 1;
                self.last_id[kind] = Some(id);
            }
            Some(last) => {
                let d = id.wrapping_sub(last);
                if d > 0 && d < 1000 {
                    self.expected[kind] += d as u64;
                    self.last_id[kind] = Some(id);
                } else if d >= 1000 && d < 0x8000 {
                    // Big jump (e.g. a new talk burst after silence): restart counting
                    self.expected[kind] += 1;
                    self.last_id[kind] = Some(id);
                }
                // late / reordered packets still count as received
                self.received[kind] = (self.received[kind] + 1).min(self.expected[kind]);
            }
        }
    }

    /// Incoming packet loss (0.0 - 1.0) for a category.
    pub fn loss_in(&self, kind: usize) -> f64 {
        if self.expected[kind] == 0 {
            return 0.0;
        }
        (1.0 - self.received[kind] as f64 / self.expected[kind] as f64).clamp(0.0, 1.0)
    }

    pub fn loss_in_total(&self) -> f64 {
        let e: u64 = self.expected.iter().sum();
        let r: u64 = self.received.iter().sum();
        if e == 0 { 0.0 } else { (1.0 - r as f64 / e as f64).clamp(0.0, 1.0) }
    }

    /// Outgoing loss estimate from command resends.
    pub fn loss_out(&self) -> f64 {
        let sent = self.packets_sent[CONTROL];
        if sent == 0 { 0.0 } else { (self.resent as f64 / sent as f64).clamp(0.0, 1.0) }
    }

    /// Bytes in the last complete second: (sent, received) per category.
    pub fn last_second(&self) -> ([u64; 3], [u64; 3]) {
        let now = self.start.elapsed().as_secs();
        self.buckets
            .iter()
            .find(|b| b.sec + 1 == now)
            .map(|b| (b.sent, b.recv))
            .unwrap_or(([0; 3], [0; 3]))
    }

    /// Average bytes per second over the last minute: (sent, received) per category.
    pub fn last_minute(&self) -> ([u64; 3], [u64; 3]) {
        let now = self.start.elapsed().as_secs();
        let span = now.clamp(1, 60);
        let mut s = [0u64; 3];
        let mut r = [0u64; 3];
        for b in self.buckets.iter().filter(|b| b.sec < now && b.sec + 60 >= now) {
            for k in 0..3 {
                s[k] += b.sent[k];
                r[k] += b.recv[k];
            }
        }
        (s.map(|x| x / span), r.map(|x| x / span))
    }
}
