//! Packet encryption (AES-128 EAX with an 8 byte tag) and key derivation.

use aes::Aes128;
use anyhow::{anyhow, Result};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use eax::aead::consts::U8;
use eax::aead::{AeadInPlace, KeyInit};
use eax::Eax;
use rand::RngCore;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

use crate::packet::{Dir, PacketType};

type Aes128Eax8 = Eax<Aes128, U8>;

/// Key/nonce used for packets before the shared secret is known.
/// The 32 byte string `c:\windows\system\firewall32.cpl` (ts3server @0x7b26c8),
/// split into key and nonce. Verified by decrypting a live `initivexpand2`.
pub const FAKE_KEY: [u8; 16] = *br"c:\windows\syste";
pub const FAKE_NONCE: [u8; 16] = *br"m\firewall32.cpl";

pub fn encrypt(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], data: &mut Vec<u8>) -> [u8; 8] {
    let cipher = Aes128Eax8::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), ad, data)
        .expect("EAX encryption cannot fail");
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&tag);
    mac
}

pub fn decrypt(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], data: &mut [u8], mac: &[u8; 8]) -> Result<()> {
    let cipher = Aes128Eax8::new(key.into());
    cipher
        .decrypt_in_place_detached(nonce.into(), ad, data, mac.into())
        .map_err(|_| anyhow!("packet MAC mismatch"))
}

/// Shared IV + MAC established by the handshake.
#[derive(Clone)]
pub struct SharedSecret {
    /// 20 bytes for the legacy P-256 handshake, 64 bytes for the Ed25519 one.
    pub iv: Vec<u8>,
    /// Used as MAC of unencrypted packets (ping/pong, unencrypted voice).
    pub mac: [u8; 8],
}

impl SharedSecret {
    fn finish(iv: Vec<u8>) -> Self {
        let mut mac = [0u8; 8];
        mac.copy_from_slice(&Sha1::digest(&iv)[..8]);
        SharedSecret { iv, mac }
    }

    /// Legacy (`initivexpand`, protocol before 3.1): ECDH over P-256.
    /// `ecdh_x` is the 32 byte x coordinate, alpha/beta are 10 bytes each.
    pub fn legacy(ecdh_x: &[u8], alpha: &[u8], beta: &[u8]) -> Self {
        let mut iv = Sha1::digest(ecdh_x).to_vec();
        for (i, b) in alpha.iter().take(10).enumerate() {
            iv[i] ^= b;
        }
        for (i, b) in beta.iter().take(10).enumerate() {
            iv[10 + i] ^= b;
        }
        Self::finish(iv)
    }

    /// Current (`initivexpand2`): Ed25519 point multiplication, alpha = 10 bytes, beta = 54 bytes.
    pub fn ed25519(shared: &[u8; 32], alpha: &[u8], beta: &[u8]) -> Self {
        let mut iv = Sha512::digest(shared).to_vec();
        for (i, b) in alpha.iter().take(10).enumerate() {
            iv[i] ^= b;
        }
        for (i, b) in beta.iter().take(54).enumerate() {
            iv[10 + i] ^= b;
        }
        Self::finish(iv)
    }

    /// Per-packet key/nonce. `dir` is the direction the packet travels in.
    pub fn key_nonce(&self, dir: Dir, ptype: PacketType, packet_id: u16, generation: u32) -> ([u8; 16], [u8; 16]) {
        let mut temp = Vec::with_capacity(6 + self.iv.len());
        temp.push(if dir == Dir::C2S { 0x31 } else { 0x30 });
        temp.push(ptype as u8);
        temp.extend_from_slice(&generation.to_be_bytes());
        temp.extend_from_slice(&self.iv);
        let h = Sha256::digest(&temp);
        let mut key = [0u8; 16];
        let mut nonce = [0u8; 16];
        key.copy_from_slice(&h[..16]);
        nonce.copy_from_slice(&h[16..32]);
        key[0] ^= (packet_id >> 8) as u8;
        key[1] ^= packet_id as u8;
        (key, nonce)
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// Ed25519 helpers. Points are decoded as-is (no ref10-style negation); this was
// confirmed against ts3server 3.13.8, which only accepts `clientinit` with this convention.

pub fn decode_point(bytes: &[u8]) -> Result<EdwardsPoint> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("ed25519 key must be 32 bytes"))?;
    CompressedEdwardsY(arr).decompress().ok_or_else(|| anyhow!("invalid ed25519 point"))
}

pub fn clamp(mut b: [u8; 32]) -> [u8; 32] {
    b[0] &= 248;
    b[31] &= 63;
    b[31] |= 64;
    b
}

/// A temporary Ed25519 key pair (client `ek`, or a license block key).
pub struct EdKey {
    pub scalar: Scalar,
}

impl EdKey {
    pub fn generate() -> Self {
        EdKey { scalar: Scalar::from_bytes_mod_order(clamp(random_bytes())) }
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        EdKey { scalar: Scalar::from_bytes_mod_order(b) }
    }
    pub fn public(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.scalar).compress().0
    }
    /// `other` must already be decoded with [`decode_point`].
    pub fn shared_secret(&self, other: &EdwardsPoint) -> [u8; 32] {
        (other * self.scalar).compress().0
    }
}

// ---------------------------------------------------------------------------
// Identity security level ("hashcash"): number of leading zero bits (LSB first per byte)
// of SHA1(omega_base64 || decimal(offset)).

pub fn security_level(omega_b64: &str, offset: u64) -> u32 {
    let mut h = Sha1::new();
    h.update(omega_b64.as_bytes());
    h.update(offset.to_string().as_bytes());
    let hash = h.finalize();
    let mut res = 0;
    for &b in hash.iter() {
        if b == 0 {
            res += 8;
        } else {
            res += b.trailing_zeros();
            break;
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eax_roundtrip() {
        let mut d = b"hello".to_vec();
        let mac = encrypt(&FAKE_KEY, &FAKE_NONCE, b"ad", &mut d);
        decrypt(&FAKE_KEY, &FAKE_NONCE, b"ad", &mut d, &mac).unwrap();
        assert_eq!(d, b"hello");
    }

    #[test]
    fn ed_shared() {
        let a = EdKey::generate();
        let b = EdKey::generate();
        let sa = a.shared_secret(&decode_point(&b.public()).unwrap());
        let sb = b.shared_secret(&decode_point(&a.public()).unwrap());
        assert_eq!(sa, sb);
    }
}
