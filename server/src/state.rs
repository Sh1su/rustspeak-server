//! Persistent server data (replaces the sqlite database of the original server).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tsproto::crypto::EdKey;
use tsproto::identity::Identity;
use tsproto::{b64, unb64};

pub use crate::perms::{Group, CG_ADMIN, CG_GUEST, SG_ADMIN, SG_GUEST};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Channel {
    pub id: u64,
    pub parent: u64,
    /// Id of the sibling directly above (0 = first), as in `channel_order`.
    pub order: u64,
    pub name: String,
    #[serde(default)]
    pub topic: String,
    #[serde(default)]
    pub description: String,
    /// `base64(sha1(password))` as sent by clients, empty = no password.
    #[serde(default)]
    pub password: String,
    #[serde(default = "minus_one")]
    pub max_clients: i32,
    #[serde(default = "default_codec")]
    pub codec: u8,
    #[serde(default = "default_quality")]
    pub codec_quality: u8,
    #[serde(default)]
    pub needed_talk_power: i32,
    #[serde(default)]
    pub needed_join_power: i32,
    #[serde(default = "yes")]
    pub permanent: bool,
    #[serde(default)]
    pub semi_permanent: bool,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub icon_id: u32,
}

fn minus_one() -> i32 {
    -1
}
fn default_codec() -> u8 {
    4 // Opus voice
}
fn default_quality() -> u8 {
    6
}
fn yes() -> bool {
    true
}

impl Channel {
    pub fn new(id: u64, parent: u64, order: u64, name: &str) -> Self {
        Channel {
            id,
            parent,
            order,
            name: name.into(),
            topic: String::new(),
            description: String::new(),
            password: String::new(),
            max_clients: -1,
            codec: default_codec(),
            codec_quality: default_quality(),
            needed_talk_power: 0,
            needed_join_power: 0,
            permanent: true,
            semi_permanent: false,
            is_default: false,
            icon_id: 0,
        }
    }

    /// Temporary = deleted when the last client leaves.
    pub fn temporary(&self) -> bool {
        !self.permanent && !self.semi_permanent
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbClient {
    pub dbid: u64,
    pub uid: String,
    pub nickname: String,
    pub created: u64,
    pub last_connected: u64,
    pub total_connections: u64,
    #[serde(default)]
    pub server_groups: Vec<u64>,
    #[serde(default)]
    pub last_ip: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelGroupMember {
    pub cid: u64,
    pub dbid: u64,
    pub cgid: u64,
}

/// API key for a bot client (see `bot.rs`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BotKey {
    pub id: u32,
    pub key: String,
    pub name: String,
    pub created: u64,
}

/// Privilege key ("token"): grants a server group, or a channel group in a channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
    /// 0 = server group, 1 = channel group
    pub kind: u8,
    pub group: u64,
    #[serde(default)]
    pub channel: u64,
    pub created: u64,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ban {
    pub id: u64,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub reason: String,
    pub created: u64,
    /// Seconds, 0 = permanent
    pub duration: u64,
    #[serde(default)]
    pub invoker: String,
}

impl Ban {
    pub fn active(&self, now: u64) -> bool {
        self.duration == 0 || self.created + self.duration > now
    }
}

#[derive(Serialize, Deserialize)]
pub struct State {
    pub name: String,
    pub welcome_message: String,
    pub max_clients: u32,
    #[serde(default)]
    pub password: String,
    pub created: u64,
    pub unique_id: String,
    pub query_password: String,
    pub identity_key: String,
    pub identity_offset: u64,
    pub license_root: String,
    pub next_channel_id: u64,
    pub next_client_dbid: u64,
    pub channels: Vec<Channel>,
    pub clients: Vec<DbClient>,
    #[serde(default = "crate::perms::default_server_groups")]
    pub server_groups: Vec<Group>,
    #[serde(default = "crate::perms::default_channel_groups")]
    pub channel_groups: Vec<Group>,
    #[serde(default = "default_sg")]
    pub default_server_group: u64,
    #[serde(default = "default_cg")]
    pub default_channel_group: u64,
    #[serde(default)]
    pub channel_group_members: Vec<ChannelGroupMember>,
    #[serde(default = "first_group_id")]
    pub next_group_id: u64,
    #[serde(default)]
    pub tokens: Vec<Token>,
    #[serde(default)]
    pub bot_keys: Vec<BotKey>,
    #[serde(default)]
    pub bans: Vec<Ban>,
    /// Uploaded icons: id (CRC32 of the PNG, like TeamSpeak) -> base64 PNG
    #[serde(default)]
    pub icons: std::collections::BTreeMap<u32, String>,
    #[serde(default)]
    pub hostbanner_url: String,
    #[serde(default)]
    pub hostbanner_gfx_url: String,
    #[serde(default)]
    pub hostbanner_gfx_interval: u32,
    /// 0 = no adjust, 1 = adjust (ignore aspect), 2 = adjust (keep aspect)
    #[serde(default = "two")]
    pub hostbanner_mode: u8,
    /// Bumped when new permissions need to be added to the default groups.
    #[serde(default)]
    pub perms_version: u32,
    #[serde(default = "one")]
    pub next_ban_id: u64,
    #[serde(skip)]
    pub path: PathBuf,
}

fn default_sg() -> u64 {
    SG_GUEST
}
fn default_cg() -> u64 {
    CG_GUEST
}
fn first_group_id() -> u64 {
    10
}
fn one() -> u64 {
    1
}
fn two() -> u8 {
    2
}

pub const PERMS_VERSION: u32 = 5;

pub fn random_token(len: usize) -> String {
    rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(len).map(char::from).collect()
}

impl State {
    pub fn load_or_create(path: &Path) -> Result<(State, bool)> {
        if path.exists() {
            let s = std::fs::read_to_string(path)?;
            let mut st: State = serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
            st.path = path.to_owned();
            if st.migrate() {
                st.save()?;
            }
            return Ok((st, false));
        }
        let mut id = Identity::generate();
        id.upgrade_level(8);
        let root = EdKey::generate();
        let mut default = Channel::new(1, 0, 0, "Default Channel");
        default.is_default = true;
        default.topic = "Default Channel has no topic".into();
        let st = State {
            name: "TeamSpeak ]I[ Server (Rust)".into(),
            welcome_message: "Welcome to TeamSpeak, check [URL]www.teamspeak.com[/URL] for latest information".into(),
            max_clients: 32,
            password: String::new(),
            created: tsproto::unix_now(),
            unique_id: id.uid(),
            query_password: random_token(8),
            identity_key: b64(&id.key.to_bytes()),
            identity_offset: id.offset,
            license_root: b64(&root.scalar.to_bytes()),
            next_channel_id: 2,
            next_client_dbid: 1,
            channels: vec![default],
            clients: Vec::new(),
            server_groups: crate::perms::default_server_groups(),
            channel_groups: crate::perms::default_channel_groups(),
            default_server_group: SG_GUEST,
            default_channel_group: CG_GUEST,
            channel_group_members: Vec::new(),
            next_group_id: first_group_id(),
            tokens: Vec::new(),
            bot_keys: Vec::new(),
            bans: Vec::new(),
            next_ban_id: 1,
            icons: Default::default(),
            hostbanner_url: String::new(),
            hostbanner_gfx_url: String::new(),
            hostbanner_gfx_interval: 0,
            hostbanner_mode: 2,
            perms_version: PERMS_VERSION,
            path: path.to_owned(),
        };
        st.save()?;
        Ok((st, true))
    }

    /// Bring files written by older versions up to date.
    /// Returns true when something changed and the file should be rewritten.
    fn migrate(&mut self) -> bool {
        let changed = self.perms_version < PERMS_VERSION;
        if self.perms_version < PERMS_VERSION {
            // Give the built-in groups the permissions introduced since the file was written.
            let new_perms = ["b_virtualserver_modify_hostbanner", "b_icon_manage", "b_channel_modify_icon", "i_icon_id", "b_client_remoteaddress_view", "b_client_video_stream", "b_client_video_watch", "b_virtualserver_bot_manage"];
            for (list, defaults) in [(&mut self.server_groups, crate::perms::default_server_groups()), (&mut self.channel_groups, crate::perms::default_channel_groups())] {
                for g in list.iter_mut() {
                    let Some(d) = defaults.iter().find(|d| d.id == g.id) else { continue };
                    for p in new_perms {
                        if let (Some(v), false) = (d.get(p), g.perms.contains_key(p)) {
                            g.perms.insert(p.to_string(), v);
                        }
                    }
                }
            }
            self.perms_version = PERMS_VERSION;
        }
        for c in self.clients.iter_mut() {
            if c.server_groups.is_empty() {
                c.server_groups.push(self.default_server_group);
            }
        }
        for ch in self.channels.iter_mut() {
            if !ch.permanent && !ch.semi_permanent {
                ch.permanent = true;
            }
        }
        // Banners are external links only; drop images uploaded by older versions.
        let mut changed = changed;
        if !self.hostbanner_gfx_url.is_empty() && !is_web_url(&self.hostbanner_gfx_url) {
            self.hostbanner_gfx_url.clear();
            changed = true;
        }
        changed
    }

    pub fn save(&self) -> Result<()> {
        let mut copy = serde_json::to_value(self)?;
        if let Some(chs) = copy.get_mut("channels").and_then(|c| c.as_array_mut()) {
            chs.retain(|c| c.get("permanent").and_then(|p| p.as_bool()).unwrap_or(true));
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&copy)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn identity(&self) -> Result<Identity> {
        Ok(Identity {
            key: tsproto::p256::SecretKey::from_slice(&unb64(&self.identity_key)?)?,
            offset: self.identity_offset,
        })
    }

    pub fn root_key(&self) -> Result<EdKey> {
        let b: [u8; 32] = unb64(&self.license_root)?.try_into().map_err(|_| anyhow::anyhow!("bad root key"))?;
        Ok(EdKey::from_bytes(b))
    }

    pub fn channel(&self, id: u64) -> Option<&Channel> {
        self.channels.iter().find(|c| c.id == id)
    }

    pub fn channel_mut(&mut self, id: u64) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|c| c.id == id)
    }

    pub fn default_channel(&self) -> u64 {
        self.channels.iter().find(|c| c.is_default).or(self.channels.first()).map(|c| c.id).unwrap_or(1)
    }

    /// Channels in tree order (parents before children, siblings by `order` chain).
    pub fn ordered_channels(&self) -> Vec<&Channel> {
        let mut out = Vec::new();
        self.push_children(0, &mut out);
        out
    }

    fn push_children<'a>(&'a self, parent: u64, out: &mut Vec<&'a Channel>) {
        let mut sibs: Vec<&Channel> = self.channels.iter().filter(|c| c.parent == parent).collect();
        let mut prev = 0;
        while !sibs.is_empty() {
            let i = sibs.iter().position(|c| c.order == prev).unwrap_or(0);
            let c = sibs.remove(i);
            prev = c.id;
            out.push(c);
            self.push_children(c.id, out);
        }
    }

    pub fn last_sibling(&self, parent: u64) -> u64 {
        self.ordered_channels().iter().filter(|c| c.parent == parent).last().map(|c| c.id).unwrap_or(0)
    }

    /// Remove channel `id` and its subchannels; fixes the order chain. Returns removed ids.
    pub fn remove_channel(&mut self, id: u64) -> Vec<u64> {
        let mut removed = vec![];
        let children: Vec<u64> = self.channels.iter().filter(|c| c.parent == id).map(|c| c.id).collect();
        for c in children {
            removed.extend(self.remove_channel(c));
        }
        if let Some(pos) = self.channels.iter().position(|c| c.id == id) {
            let ch = self.channels.remove(pos);
            for c in self.channels.iter_mut() {
                if c.parent == ch.parent && c.order == ch.id {
                    c.order = ch.order;
                }
            }
            self.channel_group_members.retain(|m| m.cid != id);
            removed.push(id);
        }
        removed
    }

    pub fn db_client(&mut self, uid: &str, nickname: &str, ip: &str) -> &mut DbClient {
        let now = tsproto::unix_now();
        if let Some(i) = self.clients.iter().position(|c| c.uid == uid) {
            let c = &mut self.clients[i];
            c.nickname = nickname.into();
            c.last_connected = now;
            c.total_connections += 1;
            c.last_ip = ip.into();
            return c;
        }
        let dbid = self.next_client_dbid;
        self.next_client_dbid += 1;
        self.clients.push(DbClient {
            dbid,
            uid: uid.into(),
            nickname: nickname.into(),
            created: now,
            last_connected: now,
            total_connections: 1,
            server_groups: vec![self.default_server_group],
            last_ip: ip.into(),
        });
        self.clients.last_mut().unwrap()
    }

    pub fn server_group(&self, id: u64) -> Option<&Group> {
        self.server_groups.iter().find(|g| g.id == id)
    }

    pub fn channel_group(&self, id: u64) -> Option<&Group> {
        self.channel_groups.iter().find(|g| g.id == id)
    }

    pub fn channel_group_of(&self, dbid: u64, cid: u64) -> u64 {
        self.channel_group_members
            .iter()
            .find(|m| m.dbid == dbid && m.cid == cid)
            .map(|m| m.cgid)
            .unwrap_or(self.default_channel_group)
    }

    pub fn set_channel_group(&mut self, dbid: u64, cid: u64, cgid: u64) {
        self.channel_group_members.retain(|m| !(m.dbid == dbid && m.cid == cid));
        if cgid != self.default_channel_group {
            self.channel_group_members.push(ChannelGroupMember { cid, dbid, cgid });
        }
    }

    pub fn add_token(&mut self, kind: u8, group: u64, channel: u64, description: &str) -> String {
        let token = random_token(40);
        self.tokens.push(Token { token: token.clone(), kind, group, channel, created: tsproto::unix_now(), description: description.into() });
        token
    }

    pub fn active_ban(&self, uid: &str, ip: &str) -> Option<&Ban> {
        let now = tsproto::unix_now();
        self.bans
            .iter()
            .find(|b| b.active(now) && ((!b.uid.is_empty() && b.uid == uid) || (!b.ip.is_empty() && b.ip == ip)))
    }
}

/// True for an external `http://` or `https://` link (used for the server banner).
pub fn is_web_url(s: &str) -> bool {
    let l = s.trim().to_ascii_lowercase();
    (l.starts_with("https://") || l.starts_with("http://")) && l.len() > l.find("://").unwrap() + 3 && !s.chars().any(char::is_whitespace)
}
