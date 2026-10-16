//! Low-level "Init1" handshake (packet type 8, MAC = "TS3INIT1", packet id 101).
//!
//! ```text
//! C->S 0:  version u32 | 0x00 | timestamp u32 | random0[4] | zeros[8]                 (21)
//! S->C 1:  0x01 | server_cookie[16] | reversed(random0)[4]                          (21)
//! C->S 2:  version u32 | 0x02 | server_cookie[16] | reversed(random0)[4]          (25)
//! S->C 3:  0x03 | x[64] | n[64] | level u32 | server_data[100]                       (233)
//! C->S 4:  version u32 | 0x04 | x | n | level | server_data | y[64] | clientinitiv   (301+)
//! ```
//! `y = x^(2^level) mod n` (an RSA-style time-lock puzzle against flooding).

use anyhow::{bail, Result};
use num_bigint::{BigUint, RandBigInt};
use rand::RngCore;

use crate::packet::{Dir, Header, PacketType, FLAG_UNENCRYPTED};

pub const INIT_MAC: [u8; 8] = *b"TS3INIT1";
pub const INIT_PACKET_ID: u16 = 101;
/// Version timestamp the client puts in front of every C->S init packet (3.5.0 era).
pub const INIT_VERSION: u32 = 1566914096;

pub fn wrap(dir: Dir, payload: &[u8]) -> Vec<u8> {
    Header {
        mac: INIT_MAC,
        packet_id: INIT_PACKET_ID,
        client_id: 0,
        ptype: PacketType::Init,
        flags: FLAG_UNENCRYPTED,
    }
    .write(dir, payload)
}

fn be64(n: &BigUint) -> [u8; 64] {
    let b = n.to_bytes_be();
    let mut out = [0u8; 64];
    let l = b.len().min(64);
    out[64 - l..].copy_from_slice(&b[b.len() - l..]);
    out
}

pub fn solve(x: &[u8], n: &[u8], level: u32) -> [u8; 64] {
    let n = BigUint::from_bytes_be(n);
    let mut y = BigUint::from_bytes_be(x);
    for _ in 0..level {
        y = (&y * &y) % &n;
    }
    be64(&y)
}

// ---------------------------------------------------------------- client side

pub struct ClientInit {
    random0: [u8; 4],
}

impl ClientInit {
    pub fn start() -> (Self, Vec<u8>) {
        let mut random0 = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut random0);
        let mut p = INIT_VERSION.to_be_bytes().to_vec();
        p.push(0);
        p.extend_from_slice(&(crate::unix_now() as u32).to_be_bytes());
        p.extend_from_slice(&random0);
        p.extend_from_slice(&[0u8; 8]);
        (ClientInit { random0 }, p)
    }

    /// Handle a S->C init payload. Returns the next C->S payload, and `true`
    /// once step 4 (which carries `clientinitiv`) has been produced.
    pub fn handle(&mut self, payload: &[u8], clientinitiv: &str) -> Result<(Vec<u8>, bool)> {
        let Some(&step) = payload.first() else { bail!("empty init packet") };
        let mut out = INIT_VERSION.to_be_bytes().to_vec();
        match step {
            1 if payload.len() >= 21 => {
                let mut rev = self.random0;
                rev.reverse();
                if payload[17..21] != rev {
                    bail!("init step 1: random0 mismatch");
                }
                out.push(2);
                out.extend_from_slice(&payload[1..21]);
                Ok((out, false))
            }
            3 if payload.len() >= 233 => {
                let x = &payload[1..65];
                let n = &payload[65..129];
                let level = u32::from_be_bytes(payload[129..133].try_into().unwrap());
                if level > 1_000_000 {
                    bail!("init puzzle level {level} unreasonably high");
                }
                out.push(4);
                out.extend_from_slice(&payload[1..233]);
                out.extend_from_slice(&solve(x, n, level));
                out.extend_from_slice(clientinitiv.as_bytes());
                Ok((out, true))
            }
            127 => bail!("server requested an init restart"),
            s => bail!("unexpected init step {s} ({} bytes)", payload.len()),
        }
    }
}

// ---------------------------------------------------------------- server side

pub struct ServerInit {
    pub cookie: [u8; 16],
    pub x: [u8; 64],
    pub n: [u8; 64],
    pub level: u32,
    pub server_data: [u8; 100],
}

pub enum ServerInitResult {
    Reply(Vec<u8>),
    /// Step 4 verified; contains the `clientinitiv` command text.
    Done(String),
}

impl ServerInit {
    pub fn new(level: u32) -> Self {
        let mut rng = rand::thread_rng();
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);
        // n: random odd 512 bit modulus, x < n
        let mut nb = [0u8; 64];
        rng.fill_bytes(&mut nb);
        nb[0] |= 0x80;
        nb[63] |= 1;
        let n = BigUint::from_bytes_be(&nb);
        let x = rng.gen_biguint_below(&n);
        let mut server_data = [0u8; 100];
        rng.fill_bytes(&mut server_data);
        ServerInit { cookie, x: be64(&x), n: nb, level, server_data }
    }

    pub fn handle(&self, payload: &[u8]) -> Result<ServerInitResult> {
        if payload.len() < 5 {
            bail!("init packet too short");
        }
        let step = payload[4];
        match step {
            0 if payload.len() >= 21 => {
                let mut rev = [0u8; 4];
                rev.copy_from_slice(&payload[9..13]);
                rev.reverse();
                let mut out = vec![1u8];
                out.extend_from_slice(&self.cookie);
                out.extend_from_slice(&rev);
                Ok(ServerInitResult::Reply(out))
            }
            2 if payload.len() >= 25 => {
                if payload[5..21] != self.cookie {
                    bail!("init step 2: cookie mismatch");
                }
                let mut out = vec![3u8];
                out.extend_from_slice(&self.x);
                out.extend_from_slice(&self.n);
                out.extend_from_slice(&self.level.to_be_bytes());
                out.extend_from_slice(&self.server_data);
                Ok(ServerInitResult::Reply(out))
            }
            4 if payload.len() >= 301 => {
                if payload[5..69] != self.x || payload[69..133] != self.n || payload[137..237] != self.server_data {
                    bail!("init step 4: echoed puzzle mismatch");
                }
                if payload[237..301] != solve(&self.x, &self.n, self.level) {
                    bail!("init step 4: wrong puzzle solution");
                }
                Ok(ServerInitResult::Done(String::from_utf8_lossy(&payload[301..]).into_owned()))
            }
            s => bail!("unexpected init step {s} ({} bytes)", payload.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_init() {
        let srv = ServerInit::new(50);
        let (mut cli, p0) = ClientInit::start();
        let ServerInitResult::Reply(p1) = srv.handle(&p0).unwrap() else { panic!() };
        let (p2, _) = cli.handle(&p1, "").unwrap();
        let ServerInitResult::Reply(p3) = srv.handle(&p2).unwrap() else { panic!() };
        let (p4, done) = cli.handle(&p3, "clientinitiv alpha=x").unwrap();
        assert!(done);
        let ServerInitResult::Done(cmd) = srv.handle(&p4).unwrap() else { panic!() };
        assert_eq!(cmd, "clientinitiv alpha=x");
    }
}
