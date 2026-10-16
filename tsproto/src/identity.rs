//! Client/server identity: a P-256 key pair plus a hashcash offset.

use anyhow::{anyhow, Context, Result};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha1::{Digest, Sha1};
use std::path::Path;

use crate::{b64, crypto, der, unb64};

#[derive(Clone)]
pub struct Identity {
    pub key: SecretKey,
    pub offset: u64,
}

impl Identity {
    pub fn generate() -> Self {
        Identity { key: SecretKey::random(&mut OsRng), offset: 0 }
    }

    /// Public key in TeamSpeak's DER format, base64 encoded (`omega`).
    pub fn omega(&self) -> String {
        public_omega(&self.key.public_key())
    }

    pub fn uid(&self) -> String {
        uid_from_omega(&self.omega())
    }

    pub fn level(&self) -> u32 {
        crypto::security_level(&self.omega(), self.offset)
    }

    /// Increase the offset until the security level is at least `target`.
    pub fn upgrade_level(&mut self, target: u32) {
        let omega = self.omega();
        while crypto::security_level(&omega, self.offset) < target {
            self.offset += 1;
        }
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sk = SigningKey::from(&self.key);
        let sig: Signature = sk.sign(data);
        sig.to_der().as_bytes().to_vec()
    }

    /// x coordinate of the P-256 ECDH result (legacy handshake).
    pub fn ecdh(&self, other: &PublicKey) -> [u8; 32] {
        let s = p256::ecdh::diffie_hellman(self.key.to_nonzero_scalar(), other.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(s.raw_secret_bytes());
        out
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = format!("key={}\noffset={}\n", b64(&self.key.to_bytes()), self.offset);
        std::fs::write(path, s).with_context(|| format!("writing {}", path.display()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let mut key = None;
        let mut offset = 0;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("key=") {
                key = Some(SecretKey::from_slice(&unb64(v)?)?);
            } else if let Some(v) = line.strip_prefix("offset=") {
                offset = v.trim().parse()?;
            }
        }
        Ok(Identity { key: key.ok_or_else(|| anyhow!("identity file has no key"))?, offset })
    }

    pub fn load_or_create(path: &Path, level: u32) -> Result<Self> {
        let mut id = if path.exists() { Self::load(path)? } else { Self::generate() };
        if id.level() < level {
            id.upgrade_level(level);
            id.save(path)?;
        } else if !path.exists() {
            id.save(path)?;
        }
        Ok(id)
    }
}

pub fn public_omega(pk: &PublicKey) -> String {
    let p = pk.to_encoded_point(false);
    b64(&der::encode_ecc(p.x().unwrap(), p.y().unwrap(), None))
}

pub fn parse_omega(omega_b64: &str) -> Result<PublicKey> {
    let k = der::decode_ecc(&unb64(omega_b64)?)?;
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&k.x);
    sec1.extend_from_slice(&k.y);
    Ok(PublicKey::from_sec1_bytes(&sec1)?)
}

pub fn uid_from_omega(omega_b64: &str) -> String {
    b64(&Sha1::digest(omega_b64.as_bytes()))
}

pub fn verify(pk: &PublicKey, data: &[u8], sig_der: &[u8]) -> Result<()> {
    let sig = Signature::from_der(sig_der)?;
    VerifyingKey::from(pk).verify(data, &sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omega_roundtrip_and_sign() {
        let id = Identity::generate();
        let pk = parse_omega(&id.omega()).unwrap();
        assert_eq!(pk, id.key.public_key());
        let sig = id.sign(b"data");
        verify(&pk, b"data", &sig).unwrap();
    }
}
