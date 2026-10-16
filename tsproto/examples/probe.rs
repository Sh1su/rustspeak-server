//! Interop probe against a real server: init handshake, then clientek variants,
//! logging every packet the server sends back.
//!
//! usage: probe <addr> <variant>
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use tsproto::crypto::{self, EdKey};
use tsproto::identity::Identity;
use tsproto::packet::{Dir, Header};
use tsproto::{b64, init, license, unb64, Command, Connection, Event};

fn main() -> anyhow::Result<()> {
    let addr = std::env::args().nth(1).unwrap_or("127.0.0.1:29987".into());
    let variant = std::env::args().nth(2).unwrap_or_default();
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(&addr)?;
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut id = Identity::generate();
    id.upgrade_level(8);
    let alpha: [u8; 10] = crypto::random_bytes();
    let iv = Command::new("clientinitiv").arg("alpha", b64(&alpha)).arg("omega", id.omega()).arg("ot", 1).arg("ip", "").to_string();
    let (mut ci, p0) = init::ClientInit::start();
    s.send(&init::wrap(Dir::C2S, &p0))?;
    let mut conn = Connection::new(Dir::C2S);
    let mut buf = [0u8; 2048];
    let start = Instant::now();
    let mut sent_ek = false;
    while start.elapsed() < Duration::from_secs(6) {
        let Ok(n) = s.recv(&mut buf) else { continue };
        let d = buf[..n].to_vec();
        let (h, _) = Header::parse(&d, Dir::S2C)?;
        println!("<- {:?} id={} flags={:#x} len={}", h.ptype, h.packet_id, h.flags, n);
        if h.flags & 0x80 == 0 { let meta = h.meta(Dir::S2C); let mut a = d[11..].to_vec(); let fake = crypto::decrypt(&crypto::FAKE_KEY, &crypto::FAKE_NONCE, &meta, &mut a, &h.mac).is_ok(); let real = conn.secret.as_ref().map(|sec| { let (k, nn) = sec.key_nonce(Dir::S2C, h.ptype, h.packet_id, 0); let mut b = d[11..].to_vec(); crypto::decrypt(&k, &nn, &meta, &mut b, &h.mac).is_ok() }); println!("   fake={fake} real={real:?} payload={:02x?}", if fake { &a[..a.len().min(8)] } else { &[][..] }); }
        let (evs, replies) = match conn.handle_packet(&d) {
            Ok(r) => r,
            Err(e) => {
                println!("   (undecryptable: {e})");
                continue;
            }
        };
        for r in replies {
            s.send(&r)?;
        }
        for ev in evs {
            match ev {
                Event::Init(p) => {
                    let (next, _) = ci.handle(&p, &iv)?;
                    s.send(&init::wrap(Dir::C2S, &next))?;
                }
                Event::Command { text, .. } => {
                    println!("   cmd: {}", &text[..text.len().min(200)]);
                    let cmd = Command::parse(&text, true);
                    if cmd.name == "initivexpand2" && !sent_ek {
                        sent_ek = true;
                        let beta = unb64(cmd.get("beta").unwrap())?;
                        let l = unb64(cmd.get("l").unwrap())?;
                        let blocks = license::parse(&l)?;
                        let key = if variant.len() == 5 { derive_variant(&variant, &blocks) } else { license::derive_public_key(&tsproto::TS_ROOT_KEY, &blocks)? };
                        let ek = EdKey::generate();
                        let mut signed = ek.public().to_vec();
                        signed.extend_from_slice(&beta);
                        let ek_cmd = Command::new("clientek").arg("ek", b64(&ek.public())).arg("proof", b64(&id.sign(&signed)));
                        for p in conn.send_command(&ek_cmd.to_string(), false) {
                            s.send(&p)?;
                        }
                        let mut shared = ek.shared_secret(&key);
                        if variant == "neg" || variant.ends_with("n") {
                            shared = (-tsproto::crypto::decode_point(&shared)?).compress().0;
                        }
                        if variant != "fakeinit" { conn.secret = Some(tsproto::crypto::SharedSecret::ed25519(&shared, &alpha, &beta)); }
                        println!("   sent clientek (variant '{variant}')");
                        let init = Command::new("clientinit").arg("client_nickname", "Probe").arg("client_version", "3.?.? [Build: 5680278000]").arg("client_platform", "Windows").arg("client_input_hardware", 1).arg("client_output_hardware", 1).arg("client_default_channel", "").arg("client_default_channel_password", "").arg("client_server_password", "").arg("client_meta_data", "").arg("client_version_sign", "DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg==").arg("client_key_offset", id.offset).arg("client_nickname_phonetic", "").arg("client_default_token", "").arg("hwid", "923f136fb1e22ae6ce95e60255529c00,d13231b1bc33edfecfb9169cc7a63bcc");
                        let mut text = init.to_string(); if variant == "short" { text = text.replace(" client_nickname_phonetic= client_default_token=", "").replace(" client_meta_data=", ""); text = text.split(" hwid=").next().unwrap().to_string(); }
                        println!("   clientinit is {} bytes", text.len());
                        for p in conn.send_command(&text, false) { s.send(&p)?; }
                        println!("   sent clientinit");
                    }
                }
                Event::Voice { .. } => {}
            }
        }
        for p in conn.poll_resend(Instant::now()).unwrap_or_default() {
            s.send(&p)?;
        }
    }
    Ok(())
}

fn pt(b: &[u8], neg: bool) -> tsproto::curve25519_dalek::EdwardsPoint {
    let p = tsproto::curve25519_dalek::edwards::CompressedEdwardsY(b.try_into().unwrap()).decompress().unwrap();
    if neg { -p } else { p }
}

/// variant: sign(root) sign(block1) sign(block2) hash_start(0|1) n|p   e.g. "---1p"
fn derive_variant(v: &str, blocks: &[license::Block]) -> tsproto::curve25519_dalek::EdwardsPoint {
    use sha2::{Digest, Sha512};
    let c: Vec<char> = v.chars().collect();
    let start = if c[3] == '0' { 0 } else { 1 };
    let mut acc = pt(&tsproto::TS_ROOT_KEY, c[0] == '-');
    for (i, b) in blocks.iter().enumerate() {
        let h = Sha512::digest(&b.raw[start..]);
        let mut hb = [0u8; 32];
        hb.copy_from_slice(&h[..32]);
        let sc = tsproto::curve25519_dalek::Scalar::from_bytes_mod_order(crypto::clamp(hb));
        acc = pt(&b.key, c[1 + i.min(1)] == '-') * sc + acc;
    }
    acc
}
