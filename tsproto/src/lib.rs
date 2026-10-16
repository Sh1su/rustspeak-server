//! TeamSpeak 3 voice protocol, as spoken by ts3server 3.13.x and the TeamSpeak 3/6 clients.
//!
//! The layout and constants in here were cross-checked against the shipped binaries
//! (see `PROTOCOL.md` in the workspace root for the evidence and the open questions).

pub mod command;
pub mod connection;
pub mod crypto;
pub mod der;
pub mod identity;
pub mod init;
pub mod license;
pub mod packet;
pub mod quicklz;
pub mod stats;

pub use command::Command;
pub use connection::{Connection, Event};
pub use packet::{Dir, PacketType};

/// Maximum size of one UDP datagram, including the header.
pub const MAX_PACKET_SIZE: usize = 500;

/// Ed25519 root key of the official TeamSpeak license chain.
/// Found verbatim in `ts3server` (file offset 0x808020) and in the TS6 client core.
pub const TS_ROOT_KEY: [u8; 32] = [
    0xcd, 0x0d, 0xe2, 0xae, 0xd4, 0x63, 0x45, 0x50, 0x9a, 0x7e, 0x3c, 0xfd, 0x8f, 0x68, 0xb3, 0xdc,
    0x75, 0x55, 0xb2, 0x9d, 0xcc, 0xec, 0x73, 0xcd, 0x18, 0x75, 0x0f, 0x99, 0x38, 0x12, 0x40, 0x8a,
];

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn unb64(data: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(data.trim())?)
}

/// Passwords (server and channel) travel as `base64(sha1(password))`.
pub fn hash_password(pw: &str) -> String {
    use sha1::Digest;
    if pw.is_empty() {
        return String::new();
    }
    b64(&sha1::Sha1::digest(pw.as_bytes()))
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub use curve25519_dalek;
pub use p256;
