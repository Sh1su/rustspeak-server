//! License chain (`l=` in `initivexpand2`). Each block contributes to an
//! implicitly certified Ed25519 key: `key_i = point_i * H(block_i) + key_{i-1}`,
//! starting at the root key. The last derived key is the server's ephemeral key.

use anyhow::{bail, Result};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::crypto::{clamp, decode_point, EdKey};

/// License timestamps are stored relative to this unix time.
pub const TIMESTAMP_OFFSET: u64 = 0x50e2_2700;

#[derive(Debug, Clone)]
pub struct Block {
    pub raw: Vec<u8>,
    pub block_type: u8,
    pub key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub issuer: Option<String>,
}

impl Block {
    fn hash_scalar(&self) -> Scalar {
        let h = Sha512::digest(&self.raw[1..]);
        let mut b = [0u8; 32];
        b.copy_from_slice(&h[..32]);
        Scalar::from_bytes_mod_order(clamp(b))
    }
}

fn cstr(d: &[u8]) -> Result<(String, usize)> {
    let Some(end) = d.iter().position(|&b| b == 0) else { bail!("unterminated license string") };
    Ok((String::from_utf8_lossy(&d[..end]).into_owned(), end + 1))
}

pub fn parse(data: &[u8]) -> Result<Vec<Block>> {
    if data.first() != Some(&1) {
        bail!("unsupported license version {:?}", data.first());
    }
    let mut d = &data[1..];
    let mut blocks = Vec::new();
    while !d.is_empty() {
        if d.len() < 42 {
            bail!("license block truncated");
        }
        if d[0] != 0 {
            bail!("unsupported license key type {}", d[0]);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&d[1..33]);
        let block_type = d[33];
        let nb = u32::from_be_bytes(d[34..38].try_into().unwrap()) as u64 + TIMESTAMP_OFFSET;
        let na = u32::from_be_bytes(d[38..42].try_into().unwrap()) as u64 + TIMESTAMP_OFFSET;
        let c = &d[42..];
        let (issuer, clen) = match block_type {
            0 => {
                if c.len() < 4 {
                    bail!("intermediate block truncated");
                }
                let (s, l) = cstr(&c[4..])?;
                (Some(s), 4 + l)
            }
            1 | 3 => {
                let (s, l) = cstr(c)?;
                (Some(s), l)
            }
            2 => {
                if c.len() < 5 {
                    bail!("server block truncated");
                }
                let (s, l) = cstr(&c[5..])?;
                (Some(s), 5 + l)
            }
            // Ephemeral block: 32 in ts3server 3.13.8 (observed), 7 in older descriptions.
            7 | 32 => (None, 0),
            8 => {
                if c.len() < 2 {
                    bail!("ts5 server block truncated");
                }
                let mut p = 2;
                for _ in 0..c[1] {
                    let Some(&l) = c.get(p) else { bail!("ts5 property truncated") };
                    p += 1 + l as usize;
                }
                if p > c.len() {
                    bail!("ts5 property truncated");
                }
                (None, p)
            }
            t => bail!("unknown license block type {t}"),
        };
        let len = 42 + clen;
        blocks.push(Block { raw: d[..len].to_vec(), block_type, key, not_before: nb, not_after: na, issuer });
        d = &d[len..];
    }
    Ok(blocks)
}

/// Derive the final public key of a chain, starting at `root`.
pub fn derive_public_key(root: &[u8; 32], blocks: &[Block]) -> Result<EdwardsPoint> {
    let mut parent = decode_point(root)?;
    for b in blocks {
        parent = decode_point(&b.key)? * b.hash_scalar() + parent;
    }
    Ok(parent)
}

/// Create a one-block chain (ephemeral block) under our own root key.
/// Returns the encoded chain and the matching private key.
pub fn create_chain(root: &EdKey, valid_secs: u64) -> (Vec<u8>, EdKey) {
    let block_key = EdKey::generate();
    let now = crate::unix_now().saturating_sub(TIMESTAMP_OFFSET);
    let mut raw = vec![0u8];
    raw.extend_from_slice(&block_key.public());
    raw.push(32);
    raw.extend_from_slice(&(now.saturating_sub(60) as u32).to_be_bytes());
    raw.extend_from_slice(&((now + valid_secs) as u32).to_be_bytes());
    let block = Block { raw: raw.clone(), block_type: 32, key: block_key.public(), not_before: 0, not_after: 0, issuer: None };
    let secret = block_key.scalar * block.hash_scalar() + root.scalar;
    let mut chain = vec![1u8];
    chain.extend_from_slice(&raw);
    (chain, EdKey { scalar: secret })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_chain_derives_matching_key() {
        let root = EdKey::generate();
        let (chain, server_key) = create_chain(&root, 3600);
        let blocks = parse(&chain).unwrap();
        let derived = derive_public_key(&root.public(), &blocks).unwrap();
        // Client side: ek * derived; server side: server_key * decode(ek)
        let ek = EdKey::generate();
        let c = ek.shared_secret(&derived);
        let s = server_key.shared_secret(&decode_point(&ek.public()).unwrap());
        assert_eq!(c, s);
    }
}
