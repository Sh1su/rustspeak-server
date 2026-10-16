//! Minimal DER for libtomcrypt's `ecc_export` format, which TeamSpeak uses for `omega`:
//! `SEQUENCE { BIT STRING(1 bit: private?), INTEGER key_size(32), INTEGER x, INTEGER y [, INTEGER k] }`

use anyhow::{bail, Result};

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

fn push_int(out: &mut Vec<u8>, be: &[u8]) {
    let mut s = be;
    while s.len() > 1 && s[0] == 0 {
        s = &s[1..];
    }
    let pad = s[0] & 0x80 != 0;
    out.push(0x02);
    push_len(out, s.len() + pad as usize);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(s);
}

/// Encode a P-256 key. `k` = private scalar (only for private exports).
pub fn encode_ecc(x: &[u8], y: &[u8], k: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![0x03, 0x02, 0x07, if k.is_some() { 0x80 } else { 0x00 }];
    body.extend_from_slice(&[0x02, 0x01, 0x20]);
    push_int(&mut body, x);
    push_int(&mut body, y);
    if let Some(k) = k {
        push_int(&mut body, k);
    }
    let mut out = vec![0x30];
    push_len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let d = self.0;
        if d.len() < 2 {
            bail!("DER truncated");
        }
        let tag = d[0];
        let (len, hl) = match d[1] {
            l if l < 0x80 => (l as usize, 2),
            0x81 if d.len() >= 3 => (d[2] as usize, 3),
            0x82 if d.len() >= 4 => (((d[2] as usize) << 8) | d[3] as usize, 4),
            _ => bail!("DER length unsupported"),
        };
        if d.len() < hl + len {
            bail!("DER truncated");
        }
        self.0 = &d[hl + len..];
        Ok((tag, &d[hl..hl + len]))
    }
}

fn to32(int: &[u8]) -> Result<[u8; 32]> {
    let mut s = int;
    while s.len() > 32 && s[0] == 0 {
        s = &s[1..];
    }
    if s.len() > 32 {
        bail!("integer too large");
    }
    let mut out = [0u8; 32];
    out[32 - s.len()..].copy_from_slice(s);
    Ok(out)
}

pub struct EccKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub k: Option<[u8; 32]>,
}

pub fn decode_ecc(der: &[u8]) -> Result<EccKey> {
    let (tag, seq) = Reader(der).tlv()?;
    if tag != 0x30 {
        bail!("expected SEQUENCE");
    }
    let mut r = Reader(seq);
    let (t, bits) = r.tlv()?;
    if t != 0x03 || bits.len() < 2 {
        bail!("expected BIT STRING");
    }
    let private = bits[1] & 0x80 != 0;
    let (t, _size) = r.tlv()?;
    if t != 0x02 {
        bail!("expected key size");
    }
    let (_, x) = r.tlv()?;
    let (_, y) = r.tlv()?;
    let k = if private { Some(to32(r.tlv()?.1)?) } else { None };
    Ok(EccKey { x: to32(x)?, y: to32(y)?, k })
}
