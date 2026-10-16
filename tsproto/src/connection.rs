//! Sans-IO packet layer shared by client and server: encryption, packet ids /
//! generations, acks, resends, fragmentation, ping/pong.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::crypto::{self, SharedSecret, FAKE_KEY, FAKE_NONCE};
use crate::packet::*;
use crate::quicklz;
use crate::stats::{self, Stats};
use crate::MAX_PACKET_SIZE;

const RECV_WINDOW: u16 = 1024;
const MAX_COMMAND_SIZE: usize = 4 << 20;
pub const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum Event {
    /// A complete (reassembled, decompressed) command. `low` = CommandLow.
    Command { text: String, low: bool },
    /// Voice payload exactly as received (see the client/server for its layout).
    Voice { whisper: bool, payload: Vec<u8>, unencrypted: bool },
    Init(Vec<u8>),
}

#[derive(Clone, Copy, Default)]
struct IdState {
    next: u16,
    gen: u32,
}

struct Unacked {
    data: Vec<u8>,
    first_sent: Instant,
    last_sent: Instant,
    tries: u32,
}

#[derive(Default)]
struct CmdIn {
    started: bool,
    queue: BTreeMap<u16, (u8, Vec<u8>)>,
    frag: Option<(u8, Vec<u8>)>,
}

pub struct Connection {
    /// Direction of the packets *we* send.
    pub out_dir: Dir,
    /// Our client id (only meaningful for C2S headers).
    pub client_id: u16,
    pub secret: Option<SharedSecret>,
    out_ids: [IdState; 9],
    in_ids: [IdState; 9],
    cmd_in: [CmdIn; 2],
    unacked: BTreeMap<(u8, u16), Unacked>,
    pings: BTreeMap<u16, Instant>,
    pub rtt: Option<Duration>,
    pub last_recv: Instant,
    pub stats: Stats,
}

impl Connection {
    pub fn new(out_dir: Dir) -> Self {
        let mut c = Connection {
            out_dir,
            client_id: 0,
            secret: None,
            out_ids: Default::default(),
            in_ids: Default::default(),
            cmd_in: Default::default(),
            unacked: BTreeMap::new(),
            pings: BTreeMap::new(),
            rtt: None,
            last_recv: Instant::now(),
            stats: Stats::default(),
        };
        if out_dir == Dir::C2S {
            // `clientinitiv` (inside init step 4) counts as command 0.
            c.out_ids[PacketType::Command as usize].next = 1;
        } else {
            c.in_ids[PacketType::Command as usize].next = 1;
        }
        c
    }

    fn in_dir(&self) -> Dir {
        self.out_dir.reverse()
    }

    fn next_out(&mut self, t: PacketType) -> (u16, u32) {
        let s = &mut self.out_ids[t as usize];
        let r = (s.next, s.gen);
        s.next = s.next.wrapping_add(1);
        if s.next == 0 {
            s.gen = s.gen.wrapping_add(1);
        }
        r
    }

    fn peek_out(&self, t: PacketType) -> u16 {
        self.out_ids[t as usize].next
    }

    fn in_generation(&self, t: PacketType, id: u16) -> u32 {
        let s = self.in_ids[t as usize];
        if id >= s.next {
            if id - s.next > 0x8000 { s.gen.wrapping_sub(1) } else { s.gen }
        } else if s.next - id > 0x8000 {
            s.gen.wrapping_add(1)
        } else {
            s.gen
        }
    }

    fn advance_in(&mut self, t: PacketType, id: u16) {
        let gen = self.in_generation(t, id);
        let s = &mut self.in_ids[t as usize];
        if gen > s.gen || (gen == s.gen && id >= s.next) {
            s.gen = gen;
            s.next = id.wrapping_add(1);
            if s.next == 0 {
                s.gen = s.gen.wrapping_add(1);
            }
        }
    }

    /// Build one packet. Packets without FLAG_UNENCRYPTED are EAX encrypted
    /// with the shared secret, or with the fake key before the handshake.
    pub fn encode(&mut self, ptype: PacketType, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (id, gen) = self.next_out(ptype);
        let pkt = self.encode_with_id(ptype, flags, id, gen, payload);
        self.stats.on_send(stats::kind_of(ptype), pkt.len());
        pkt
    }

    fn encode_with_id(&self, ptype: PacketType, flags: u8, id: u16, gen: u32, payload: &[u8]) -> Vec<u8> {
        let mut h = Header { mac: [0; 8], packet_id: id, client_id: self.client_id, ptype, flags };
        if flags & FLAG_UNENCRYPTED != 0 {
            h.mac = self.secret.as_ref().map(|s| s.mac).unwrap_or([0; 8]);
            return h.write(self.out_dir, payload);
        }
        let (key, nonce) = match &self.secret {
            Some(s) => s.key_nonce(self.out_dir, ptype, id, gen),
            None => (FAKE_KEY, FAKE_NONCE),
        };
        let mut data = payload.to_vec();
        h.mac = crypto::encrypt(&key, &nonce, &h.meta(self.out_dir), &mut data);
        h.write(self.out_dir, &data)
    }

    /// Send a command (fragmented if needed). All returned packets are tracked for resend.
    pub fn send_command(&mut self, text: &str, low: bool) -> Vec<Vec<u8>> {
        let ptype = if low { PacketType::CommandLow } else { PacketType::Command };
        let base_flags = if self.out_dir == Dir::C2S { FLAG_NEWPROTOCOL } else { 0 };
        let max = MAX_PACKET_SIZE - self.out_dir.header_len();
        let data = text.as_bytes();
        let chunks: Vec<&[u8]> = if data.is_empty() { vec![data] } else { data.chunks(max).collect() };
        let n = chunks.len();
        let now = Instant::now();
        let mut out = Vec::with_capacity(n);
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut flags = base_flags;
            if n > 1 && (i == 0 || i == n - 1) {
                flags |= FLAG_FRAGMENTED;
            }
            let id = self.peek_out(ptype);
            let pkt = self.encode(ptype, flags, chunk);
            self.unacked.insert(
                (ptype as u8, id),
                Unacked { data: pkt.clone(), first_sent: now, last_sent: now, tries: 0 },
            );
            out.push(pkt);
        }
        out
    }

    /// C->S voice: `vid u16 | codec u8 | data`.
    pub fn send_voice_c2s(&mut self, codec: u8, data: &[u8]) -> Vec<u8> {
        let id = self.peek_out(PacketType::Voice);
        let mut p = id.to_be_bytes().to_vec();
        p.push(codec);
        p.extend_from_slice(data);
        self.encode(PacketType::Voice, 0, &p)
    }

    /// S->C voice: `vid u16 | talker clid u16 | codec u8 | data`.
    pub fn send_voice_s2c(&mut self, from: u16, codec: u8, data: &[u8], whisper: bool) -> Vec<u8> {
        let t = if whisper { PacketType::VoiceWhisper } else { PacketType::Voice };
        let id = self.peek_out(t);
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&from.to_be_bytes());
        p.push(codec);
        p.extend_from_slice(data);
        self.encode(t, 0, &p)
    }

    pub fn ping(&mut self) -> Vec<u8> {
        let id = self.peek_out(PacketType::Ping);
        self.pings.insert(id, Instant::now());
        while self.pings.len() > 16 {
            let k = *self.pings.keys().next().unwrap();
            self.pings.remove(&k);
        }
        self.encode(PacketType::Ping, FLAG_UNENCRYPTED, &[])
    }

    fn decrypt(&self, h: &Header, payload: &[u8]) -> Result<Vec<u8>> {
        if h.flags & FLAG_UNENCRYPTED != 0 {
            if matches!(h.ptype, PacketType::Command | PacketType::CommandLow | PacketType::Ack | PacketType::AckLow) {
                bail!("refusing unencrypted {:?}", h.ptype);
            }
            return Ok(payload.to_vec());
        }
        let meta = h.meta(self.in_dir());
        if let Some(s) = &self.secret {
            let gen = self.in_generation(h.ptype, h.packet_id);
            let (key, nonce) = s.key_nonce(self.in_dir(), h.ptype, h.packet_id, gen);
            let mut d = payload.to_vec();
            if crypto::decrypt(&key, &nonce, &meta, &mut d, &h.mac).is_ok() {
                return Ok(d);
            }
        }
        // Packets around the key switch (clientek and its ack) still use the fake key.
        let mut d = payload.to_vec();
        crypto::decrypt(&FAKE_KEY, &FAKE_NONCE, &meta, &mut d, &h.mac)?;
        Ok(d)
    }

    /// Process one received datagram. Returns events and packets to send back.
    pub fn handle_packet(&mut self, raw: &[u8]) -> Result<(Vec<Event>, Vec<Vec<u8>>)> {
        let (h, payload) = Header::parse(raw, self.in_dir())?;
        let mut events = Vec::new();
        let mut replies = Vec::new();
        if h.ptype == PacketType::Init {
            events.push(Event::Init(payload.to_vec()));
            return Ok((events, replies));
        }
        let data = self.decrypt(&h, payload)?;
        self.stats.on_recv(stats::kind_of(h.ptype), raw.len());
        if matches!(h.ptype, PacketType::Voice | PacketType::VoiceWhisper | PacketType::Ping) {
            self.stats.on_recv_id(stats::kind_of(h.ptype), h.packet_id);
        }
        self.last_recv = Instant::now();
        match h.ptype {
            PacketType::Ping => {
                self.advance_in(h.ptype, h.packet_id);
                replies.push(self.encode(PacketType::Pong, FLAG_UNENCRYPTED, &h.packet_id.to_be_bytes()));
            }
            PacketType::Pong => {
                self.advance_in(h.ptype, h.packet_id);
                if data.len() >= 2 {
                    let id = u16::from_be_bytes([data[0], data[1]]);
                    if let Some(t) = self.pings.remove(&id) {
                        self.rtt = Some(t.elapsed());
                    }
                }
            }
            PacketType::Ack | PacketType::AckLow => {
                self.advance_in(h.ptype, h.packet_id);
                if data.len() >= 2 {
                    let id = u16::from_be_bytes([data[0], data[1]]);
                    let t = if h.ptype == PacketType::Ack { PacketType::Command } else { PacketType::CommandLow };
                    self.unacked.remove(&(t as u8, id));
                }
            }
            PacketType::Voice | PacketType::VoiceWhisper => {
                self.advance_in(h.ptype, h.packet_id);
                events.push(Event::Voice {
                    whisper: h.ptype == PacketType::VoiceWhisper,
                    payload: data,
                    unencrypted: h.flags & FLAG_UNENCRYPTED != 0,
                });
            }
            PacketType::Command | PacketType::CommandLow => {
                let low = h.ptype == PacketType::CommandLow;
                let idx = low as usize;
                let ack_t = if low { PacketType::AckLow } else { PacketType::Ack };
                if !self.cmd_in[idx].started {
                    // The first command id is 1 for C->S Command (clientinitiv was 0) and 0 otherwise;
                    // tolerate a peer that starts one lower than expected.
                    self.cmd_in[idx].started = true;
                    let s = &mut self.in_ids[h.ptype as usize];
                    if h.packet_id.wrapping_add(1) == s.next {
                        s.next = h.packet_id;
                    }
                }
                let next = self.in_ids[h.ptype as usize].next;
                let dist = h.packet_id.wrapping_sub(next);
                if dist >= 0x8000 {
                    // Duplicate of something already delivered: the ack got lost.
                    replies.push(self.encode(ack_t, 0, &h.packet_id.to_be_bytes()));
                    return Ok((events, replies));
                }
                if dist >= RECV_WINDOW {
                    return Ok((events, replies));
                }
                replies.push(self.encode(ack_t, 0, &h.packet_id.to_be_bytes()));
                self.cmd_in[idx].queue.insert(h.packet_id, (h.flags, data));
                self.drain_commands(h.ptype, low, &mut events)?;
            }
            PacketType::Init => unreachable!(),
        }
        Ok((events, replies))
    }

    fn drain_commands(&mut self, t: PacketType, low: bool, events: &mut Vec<Event>) -> Result<()> {
        let idx = low as usize;
        loop {
            let next = self.in_ids[t as usize].next;
            let Some((flags, data)) = self.cmd_in[idx].queue.remove(&next) else { break };
            self.advance_in(t, next);
            let st = &mut self.cmd_in[idx];
            let whole = match st.frag.take() {
                None if flags & FLAG_FRAGMENTED != 0 => {
                    st.frag = Some((flags, data));
                    None
                }
                None => Some((flags, data)),
                Some((first_flags, mut buf)) => {
                    buf.extend_from_slice(&data);
                    if buf.len() > MAX_COMMAND_SIZE {
                        bail!("fragmented command too large");
                    }
                    if flags & FLAG_FRAGMENTED != 0 {
                        Some((first_flags, buf))
                    } else {
                        st.frag = Some((first_flags, buf));
                        None
                    }
                }
            };
            if let Some((flags, buf)) = whole {
                let buf = if flags & FLAG_COMPRESSED != 0 { quicklz::decompress(&buf, MAX_COMMAND_SIZE)? } else { buf };
                events.push(Event::Command { text: String::from_utf8_lossy(&buf).into_owned(), low });
            }
        }
        Ok(())
    }

    /// Packets due for resend. Errors when a command stayed unacknowledged too long.
    pub fn poll_resend(&mut self, now: Instant) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for u in self.unacked.values_mut() {
            if now.duration_since(u.first_sent) > TIMEOUT {
                bail!("command not acknowledged within {:?}", TIMEOUT);
            }
            let rto = Duration::from_millis((500u64 << u.tries.min(3)).min(4000));
            if now.duration_since(u.last_sent) >= rto {
                u.last_sent = now;
                u.tries += 1;
                out.push(u.data.clone());
            }
        }
        for p in &out {
            self.stats.on_send(stats::CONTROL, p.len());
            self.stats.resent += 1;
        }
        Ok(out)
    }

    pub fn has_unacked(&self) -> bool {
        !self.unacked.is_empty()
    }

    pub fn timed_out(&self) -> bool {
        self.last_recv.elapsed() > TIMEOUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Connection, Connection) {
        let mut c = Connection::new(Dir::C2S);
        let mut s = Connection::new(Dir::S2C);
        let sec = SharedSecret::ed25519(&[7u8; 32], &[1; 10], &[2; 54]);
        c.secret = Some(sec.clone());
        s.secret = Some(sec);
        c.client_id = 3;
        (c, s)
    }

    #[test]
    fn fragmented_command_out_of_order() {
        let (mut c, mut s) = pair();
        let text = format!("sendtextmessage targetmode=3 msg={}", "x".repeat(2000));
        let mut pkts = c.send_command(&text, false);
        pkts.reverse();
        let mut got = Vec::new();
        for p in pkts {
            let (ev, acks) = s.handle_packet(&p).unwrap();
            for a in acks {
                c.handle_packet(&a).unwrap();
            }
            got.extend(ev);
        }
        assert_eq!(got.len(), 1);
        match &got[0] {
            Event::Command { text: t, .. } => assert_eq!(t, &text),
            e => panic!("{e:?}"),
        }
        assert!(!c.has_unacked());
    }

    #[test]
    fn voice_and_ping() {
        let (mut c, mut s) = pair();
        let v = c.send_voice_c2s(4, b"opus");
        let (ev, _) = s.handle_packet(&v).unwrap();
        assert!(matches!(&ev[0], Event::Voice { payload, .. } if &payload[2..] == b"\x04opus"));
        let p = c.ping();
        let (_, pong) = s.handle_packet(&p).unwrap();
        c.handle_packet(&pong[0]).unwrap();
        assert!(c.rtt.is_some());
    }

    #[test]
    fn fake_key_before_handshake() {
        let mut c = Connection::new(Dir::C2S);
        let mut s = Connection::new(Dir::S2C);
        let pk = c.send_command("clientek ek=a proof=b", false);
        let (ev, _) = s.handle_packet(&pk[0]).unwrap();
        assert!(matches!(&ev[0], Event::Command { text, .. } if text.starts_with("clientek")));
    }
}
