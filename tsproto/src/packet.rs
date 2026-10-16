//! Low-level packet header.
//!
//! ```text
//! client -> server:  MAC[8] | packet_id u16 BE | client_id u16 BE | type|flags u8   (13 bytes)
//! server -> client:  MAC[8] | packet_id u16 BE |                    type|flags u8   (11 bytes)
//! ```
//! The header without the MAC is the associated data of the EAX encryption.

use anyhow::{bail, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    Voice = 0,
    VoiceWhisper = 1,
    Command = 2,
    CommandLow = 3,
    Ping = 4,
    Pong = 5,
    Ack = 6,
    AckLow = 7,
    Init = 8,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        use PacketType::*;
        Some(match v {
            0 => Voice,
            1 => VoiceWhisper,
            2 => Command,
            3 => CommandLow,
            4 => Ping,
            5 => Pong,
            6 => Ack,
            7 => AckLow,
            8 => Init,
            _ => return None,
        })
    }
    pub fn is_command(self) -> bool {
        matches!(self, PacketType::Command | PacketType::CommandLow)
    }
}

pub const FLAG_UNENCRYPTED: u8 = 0x80;
pub const FLAG_COMPRESSED: u8 = 0x40;
pub const FLAG_NEWPROTOCOL: u8 = 0x20;
pub const FLAG_FRAGMENTED: u8 = 0x10;

/// Direction a packet travels in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    C2S,
    S2C,
}

impl Dir {
    pub fn header_len(self) -> usize {
        match self {
            Dir::C2S => 13,
            Dir::S2C => 11,
        }
    }
    pub fn reverse(self) -> Dir {
        match self {
            Dir::C2S => Dir::S2C,
            Dir::S2C => Dir::C2S,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub mac: [u8; 8],
    pub packet_id: u16,
    pub client_id: u16, // only on the wire for C2S
    pub ptype: PacketType,
    pub flags: u8,
}

impl Header {
    pub fn parse(data: &[u8], dir: Dir) -> Result<(Header, &[u8])> {
        let hl = dir.header_len();
        if data.len() < hl {
            bail!("packet too short ({} bytes)", data.len());
        }
        let mut mac = [0u8; 8];
        mac.copy_from_slice(&data[..8]);
        let packet_id = u16::from_be_bytes([data[8], data[9]]);
        let (client_id, tf) = match dir {
            Dir::C2S => (u16::from_be_bytes([data[10], data[11]]), data[12]),
            Dir::S2C => (0, data[10]),
        };
        let Some(ptype) = PacketType::from_u8(tf & 0x0f) else {
            bail!("unknown packet type {}", tf & 0x0f)
        };
        Ok((Header { mac, packet_id, client_id, ptype, flags: tf & 0xf0 }, &data[hl..]))
    }

    /// Header bytes without the MAC (the AEAD associated data).
    pub fn meta(&self, dir: Dir) -> Vec<u8> {
        let mut v = Vec::with_capacity(5);
        v.extend_from_slice(&self.packet_id.to_be_bytes());
        if dir == Dir::C2S {
            v.extend_from_slice(&self.client_id.to_be_bytes());
        }
        v.push(self.ptype as u8 | self.flags);
        v
    }

    pub fn write(&self, dir: Dir, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(dir.header_len() + payload.len());
        v.extend_from_slice(&self.mac);
        v.extend_from_slice(&self.meta(dir));
        v.extend_from_slice(payload);
        v
    }
}
