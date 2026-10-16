//! QuickLZ 1.5 decompression (levels 1 and 3). The server compresses large
//! command packets (e.g. the initial `channellist`) and sets FLAG_COMPRESSED.

use anyhow::{bail, Result};

const HASH_VALUES: usize = 4096;

fn rd(d: &[u8], at: usize, n: usize) -> u32 {
    let mut v = 0u32;
    for i in 0..n {
        v |= (*d.get(at + i).unwrap_or(&0) as u32) << (8 * i);
    }
    v
}

pub fn decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>> {
    let Some(&flags) = data.first() else { bail!("empty quicklz buffer") };
    let hl = if flags & 2 != 0 { 9 } else { 3 };
    if data.len() < hl {
        bail!("quicklz header truncated");
    }
    let (csize, dsize) = if hl == 9 {
        (rd(data, 1, 4) as usize, rd(data, 5, 4) as usize)
    } else {
        (data[1] as usize, data[2] as usize)
    };
    if dsize > max_size {
        bail!("quicklz output too large ({dsize})");
    }
    if csize > data.len() {
        bail!("quicklz input truncated");
    }
    let src = &data[..csize];
    if flags & 1 == 0 {
        if src.len() < hl + dsize {
            bail!("quicklz stored block truncated");
        }
        return Ok(src[hl..hl + dsize].to_vec());
    }
    let level = (flags >> 2) & 3;
    if level != 1 && level != 3 {
        bail!("unsupported quicklz level {level}");
    }

    let mut out: Vec<u8> = Vec::with_capacity(dsize);
    let mut s = hl;
    let mut cword: u32 = 1;
    let mut table = vec![0usize; HASH_VALUES];
    let mut last_hashed: isize = -1;
    let last_matchstart = dsize as isize - 1 - 6 - 4;

    let update_hash = |out: &Vec<u8>, table: &mut Vec<usize>, last_hashed: &mut isize, upto: isize| {
        while *last_hashed < upto {
            *last_hashed += 1;
            let f = rd(out, *last_hashed as usize, 3);
            table[(((f >> 12) ^ f) as usize) & (HASH_VALUES - 1)] = *last_hashed as usize;
        }
    };

    loop {
        if s > src.len() {
            bail!("quicklz input overrun");
        }
        if cword == 1 {
            cword = rd(src, s, 4);
            s += 4;
        }
        let fetch = rd(src, s, 4);
        if cword & 1 == 1 {
            cword >>= 1;
            let (from, len) = if level == 1 {
                let off = table[((fetch >> 4) & 0xfff) as usize];
                let len = if fetch & 0xf != 0 {
                    s += 2;
                    (fetch & 0xf) as usize + 2
                } else {
                    let l = *src.get(s + 2).unwrap_or(&0) as usize;
                    s += 3;
                    l
                };
                (off, len)
            } else {
                let (offset, len, adv) = if fetch & 3 == 0 {
                    ((fetch & 0xff) >> 2, 3, 1)
                } else if fetch & 2 == 0 {
                    ((fetch & 0xffff) >> 2, 3, 2)
                } else if fetch & 1 == 0 {
                    ((fetch & 0xffff) >> 6, ((fetch >> 2) & 15) + 3, 2)
                } else if fetch & 127 != 3 {
                    ((fetch >> 7) & 0x1ffff, ((fetch >> 2) & 0x1f) + 2, 3)
                } else {
                    (fetch >> 15, ((fetch >> 7) & 255) + 3, 4)
                };
                s += adv;
                let Some(from) = out.len().checked_sub(offset as usize) else { bail!("quicklz bad offset") };
                (from, len as usize)
            };
            if from >= out.len() || out.len() + len > dsize {
                bail!("quicklz bad match");
            }
            for i in 0..len {
                let b = out[from + i];
                out.push(b);
            }
            if level == 1 {
                let start = (out.len() - len) as isize;
                update_hash(&out, &mut table, &mut last_hashed, start);
                last_hashed = out.len() as isize - 1;
            }
        } else if (out.len() as isize) < last_matchstart {
            let Some(&b) = src.get(s) else { bail!("quicklz input overrun") };
            out.push(b);
            s += 1;
            cword >>= 1;
            if level == 1 {
                update_hash(&out, &mut table, &mut last_hashed, out.len() as isize - 3);
            }
        } else {
            while out.len() < dsize {
                if cword == 1 {
                    s += 4;
                    cword = 1 << 31;
                }
                let Some(&b) = src.get(s) else { bail!("quicklz input overrun") };
                out.push(b);
                s += 1;
                cword >>= 1;
            }
            return Ok(out);
        }
    }
}

/// "Compress" by emitting a stored (uncompressed) QuickLZ block.
pub fn store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 9);
    if data.len() + 3 <= 255 {
        out.extend_from_slice(&[0x04, (data.len() + 3) as u8, data.len() as u8]);
    } else {
        out.push(0x06);
        out.extend_from_slice(&((data.len() + 9) as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_roundtrip() {
        let d = b"channellist cid=1 channel_name=Default".repeat(20);
        assert_eq!(decompress(&store(&d), 1 << 20).unwrap(), d);
    }
}
