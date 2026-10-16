//! Virtual server: UDP voice protocol, client handshake, command handling, voice relay.
//! Group/permission/token/ban management lives in `admin.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use tsproto::crypto::{self, decode_point, EdKey, SharedSecret};
use tsproto::identity::{self, Identity};
use tsproto::init::{self, ServerInit, ServerInitResult};
use tsproto::p256::PublicKey;
use tsproto::{b64, license, unb64, Command, Connection, Dir, Event};

use crate::perms::{self, Group, PERMS};
use crate::state::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Handshake {
    /// `initivexpand` (P-256 ECDH, no license chain). Works without a TeamSpeak license.
    Legacy,
    /// `initivexpand2` (Ed25519 + license chain signed by our own root key).
    Ed25519,
}

pub struct Config {
    pub port: u16,
    pub min_security_level: u32,
    pub puzzle_level: u32,
    pub handshake: Handshake,
}

/// TeamSpeak error ids (the ones we use).
pub mod err {
    pub type E = (u32, &'static str);
    pub const OK: E = (0, "ok");
    pub const CMD_NOT_FOUND: E = (256, "command not found");
    pub const INVALID_CLIENT: E = (512, "invalid clientID");
    pub const NICK_IN_USE: E = (513, "nickname is already in use");
    pub const INVALID_LOGIN: E = (520, "invalid loginname or password");
    pub const INVALID_CHANNEL: E = (768, "invalid channelID");
    pub const ALREADY_IN_CHANNEL: E = (770, "already member of channel");
    pub const CHANNEL_NAME_IN_USE: E = (771, "channel name is already in use");
    pub const CHANNEL_NOT_EMPTY: E = (772, "channel not empty");
    pub const CHANNEL_FULL: E = (777, "channel maxclient reached");
    pub const CHANNEL_PASSWORD: E = (781, "invalid channel password");
    pub const SERVER_FULL: E = (1027, "max clients protocol limit reached");
    pub const EMPTY_RESULT: E = (1281, "database empty result set");
    pub const DUPLICATE: E = (1282, "database duplicate entry");
    pub const INVALID_PARAM: E = (1538, "invalid parameter");
    pub const PARAM_MISSING: E = (1540, "parameter not found");
    pub const SERVER_PASSWORD: E = (1796, "invalid server password");
    pub const IDENTITY_LEVEL: E = (2049, "client security level too low");
    pub const INVALID_GROUP: E = (2560, "invalid group ID");
    pub const PERMISSIONS: E = (2568, "insufficient client permissions");
    pub const NOT_LOGGED_IN: E = (2568, "insufficient client permissions");
    pub const INVALID_TOKEN: E = (2817, "invalid privilege key");
    pub const BANNED: E = (3329, "connection failed, you are banned");
}
pub use err::E;

#[derive(Clone)]
pub struct ClientInfo {
    pub clid: u16,
    pub dbid: u64,
    pub uid: String,
    pub nickname: String,
    pub channel: u64,
    pub channel_group: u64,
    pub server_groups: Vec<u64>,
    pub talk_power: i32,
    pub input_muted: bool,
    pub output_muted: bool,
    pub input_hw: bool,
    pub output_hw: bool,
    pub away: bool,
    pub away_msg: String,
    pub recording: bool,
    pub description: String,
    pub version: String,
    pub platform: String,
    pub ip: String,
    pub connected_at: Instant,
    pub last_active: Instant,
    pub last_talked: Option<Instant>,
}

enum Stage {
    Init(ServerInit),
    AwaitEk { alpha: Vec<u8>, beta: Vec<u8>, key: EdKey, client_pub: PublicKey, omega: String },
    AwaitInit { omega: String },
    Connected(Box<ClientInfo>),
}

struct Peer {
    conn: Connection,
    stage: Stage,
    created: Instant,
    last_ping: Instant,
    /// Bot clients get their commands as text lines instead of UDP packets.
    bot: Option<mpsc::UnboundedSender<String>>,
}

/// Who triggered an action (for `invokerid`/`invokername`/`invokeruid`).
#[derive(Clone)]
pub enum Invoker {
    Server,
    Client(u16),
    Query(String),
}

pub struct QueryRequest {
    pub cmd: Command,
    pub session: crate::query::Session,
    pub reply: oneshot::Sender<(String, crate::query::Session)>,
}

pub struct Server {
    sock: Arc<UdpSocket>,
    pub cfg: Config,
    pub st: State,
    identity: Identity,
    root: EdKey,
    peers: HashMap<SocketAddr, Peer>,
    clid_addr: HashMap<u16, SocketAddr>,
    pub started: Instant,
    /// Video relay (hub + announced TCP port), if enabled.
    pub video: Option<(crate::video::SharedHub, u16)>,
}

pub fn b(v: bool) -> &'static str {
    if v { "1" } else { "0" }
}

pub fn kv(pairs: &[(&str, String)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

impl Server {
    pub fn new(sock: UdpSocket, cfg: Config, st: State) -> Result<Self> {
        Ok(Server {
            identity: st.identity()?,
            root: st.root_key()?,
            sock: Arc::new(sock),
            cfg,
            st,
            peers: HashMap::new(),
            clid_addr: HashMap::new(),
            started: Instant::now(),
            video: None,
        })
    }

    pub async fn run(mut self, mut queries: mpsc::Receiver<QueryRequest>, mut bots: mpsc::Receiver<crate::bot::BotRequest>) -> Result<()> {
        let sock = self.sock.clone();
        let mut buf = vec![0u8; 2048];
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, addr)) => self.on_datagram(addr, &buf[..n]),
                    // Windows reports ICMP port-unreachable as ConnectionReset on UDP sockets.
                    Err(e) => debug!("recv error: {e}"),
                },
                _ = tick.tick() => self.on_tick(),
                Some(b) = bots.recv() => self.on_bot(b),
                Some(q) = queries.recv() => {
                    let mut session = q.session;
                    let out = self.exec_query(&q.cmd, &mut session);
                    let _ = q.reply.send((out, session));
                }
            }
        }
    }

    // ------------------------------------------------------------------ transport

    fn send_raw(&self, addr: SocketAddr, pkts: Vec<Vec<u8>>) {
        for p in pkts {
            if let Err(e) = self.sock.try_send_to(&p, addr) {
                debug!("send to {addr}: {e}");
            }
        }
    }

    fn send_cmd_addr(&mut self, addr: SocketAddr, cmd: &Command) {
        let Some(peer) = self.peers.get_mut(&addr) else { return };
        let text = cmd.to_string();
        if let Some(bot) = &peer.bot {
            let _ = bot.send(text);
            return;
        }
        debug!("-> {addr}: {}", truncate(&text));
        let pkts = peer.conn.send_command(&text, false);
        self.send_raw(addr, pkts);
    }

    pub fn send_cmd(&mut self, clid: u16, cmd: &Command) {
        if let Some(&addr) = self.clid_addr.get(&clid) {
            self.send_cmd_addr(addr, cmd);
        }
    }

    pub fn broadcast(&mut self, cmd: &Command, except: Option<u16>) {
        let ids: Vec<u16> = self.clid_addr.keys().copied().filter(|&c| Some(c) != except).collect();
        for id in ids {
            self.send_cmd(id, cmd);
        }
    }

    pub fn clients(&self) -> impl Iterator<Item = &ClientInfo> {
        self.peers.values().filter_map(|p| match &p.stage {
            Stage::Connected(c) => Some(c.as_ref()),
            _ => None,
        })
    }

    pub fn online_ids(&self) -> Vec<u16> {
        self.clients().map(|c| c.clid).collect()
    }

    pub fn client(&self, clid: u16) -> Option<&ClientInfo> {
        let addr = self.clid_addr.get(&clid)?;
        match &self.peers.get(addr)?.stage {
            Stage::Connected(c) => Some(c),
            _ => None,
        }
    }

    pub fn client_mut(&mut self, clid: u16) -> Option<&mut ClientInfo> {
        let addr = self.clid_addr.get(&clid)?;
        match &mut self.peers.get_mut(addr)?.stage {
            Stage::Connected(c) => Some(c),
            _ => None,
        }
    }

    fn on_datagram(&mut self, addr: SocketAddr, data: &[u8]) {
        if !self.peers.contains_key(&addr) {
            // Only a fresh init step 0 may open a connection.
            let is_init0 = data.len() >= 13 + 21 && data[..8] == init::INIT_MAC && data[12] & 0x0f == 8 && data[13 + 4] == 0;
            if !is_init0 {
                return;
            }
            if self.peers.len() > 4 * self.st.max_clients as usize + 64 {
                return;
            }
            self.peers.insert(addr, self.new_peer());
        }
        let peer = self.peers.get_mut(&addr).unwrap();
        let (events, replies) = match peer.conn.handle_packet(data) {
            Ok(r) => r,
            Err(e) => {
                debug!("{addr}: dropped packet: {e}");
                return;
            }
        };
        self.send_raw(addr, replies);
        for ev in events {
            if let Err(e) = self.on_event(addr, ev) {
                warn!("{addr}: {e:#}");
                self.disconnect(addr, 3, "protocol error", Invoker::Server);
                return;
            }
        }
    }

    fn new_peer(&self) -> Peer {
        Peer {
            conn: Connection::new(Dir::S2C),
            stage: Stage::Init(ServerInit::new(self.cfg.puzzle_level)),
            created: Instant::now(),
            last_ping: Instant::now(),
            bot: None,
        }
    }

    fn on_event(&mut self, addr: SocketAddr, ev: Event) -> Result<()> {
        match ev {
            Event::Init(payload) => self.on_init(addr, payload),
            Event::Command { text, .. } => {
                debug!("<- {addr}: {}", truncate(&text));
                let cmd = Command::parse(&text, true);
                let Some(peer) = self.peers.get(&addr) else { return Ok(()) };
                match (&peer.stage, cmd.name.as_str()) {
                    (Stage::AwaitEk { .. }, "clientek") => self.on_clientek(addr, &cmd),
                    (Stage::AwaitInit { .. }, "clientinit") => self.on_clientinit(addr, &cmd),
                    (Stage::Connected(c), _) => {
                        let clid = c.clid;
                        let r = self.client_command(clid, &cmd);
                        if let Some(&addr) = self.clid_addr.get(&clid) {
                            let rc = cmd.get("return_code").map(|s| s.to_string());
                            self.send_error(addr, r.err().unwrap_or(err::OK), rc);
                        }
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            Event::Voice { whisper, payload, .. } => {
                self.on_voice(addr, whisper, &payload);
                Ok(())
            }
        }
    }

    fn send_error(&mut self, addr: SocketAddr, e: E, return_code: Option<String>) {
        let mut c = Command::new("error").arg("id", e.0).arg("msg", e.1);
        if let Some(rc) = return_code {
            c.push("return_code", rc);
        }
        self.send_cmd_addr(addr, &c);
    }

    // ------------------------------------------------------------------ handshake

    fn on_init(&mut self, addr: SocketAddr, payload: Vec<u8>) -> Result<()> {
        let peer = self.peers.get_mut(&addr).unwrap();
        if payload.len() >= 5 && payload[4] == 0 && !matches!(peer.stage, Stage::Init(_)) {
            // The client restarted the handshake.
            self.disconnect(addr, 3, "reconnect", Invoker::Server);
            self.peers.insert(addr, self.new_peer());
        }
        let peer = self.peers.get_mut(&addr).unwrap();
        let Stage::Init(si) = &peer.stage else { return Ok(()) };
        match si.handle(&payload)? {
            ServerInitResult::Reply(p) => {
                self.send_raw(addr, vec![init::wrap(Dir::S2C, &p)]);
                Ok(())
            }
            ServerInitResult::Done(cmd) => self.on_clientinitiv(addr, &Command::parse(&cmd, true)),
        }
    }

    fn on_clientinitiv(&mut self, addr: SocketAddr, cmd: &Command) -> Result<()> {
        if cmd.name != "clientinitiv" {
            return Err(anyhow!("expected clientinitiv, got {}", cmd.name));
        }
        let alpha = unb64(cmd.get("alpha").ok_or_else(|| anyhow!("no alpha"))?)?;
        let omega = cmd.get("omega").ok_or_else(|| anyhow!("no omega"))?.to_string();
        let client_pub = identity::parse_omega(&omega)?;
        let new_protocol = cmd.get("ot") == Some("1") && self.cfg.handshake == Handshake::Ed25519;
        let peer = self.peers.get_mut(&addr).unwrap();
        if new_protocol {
            let beta = crypto::random_bytes::<54>().to_vec();
            let (chain, key) = license::create_chain(&self.root, 7 * 86400);
            let reply = Command::new("initivexpand2")
                .arg("l", b64(&chain))
                .arg("beta", b64(&beta))
                .arg("omega", self.identity.omega())
                .arg("ot", 1)
                .arg("proof", b64(&self.identity.sign(&chain)))
                .arg("tvd", "")
                .arg("root", b64(&self.root.public()));
            peer.stage = Stage::AwaitEk { alpha, beta, key, client_pub, omega };
            self.send_cmd_addr(addr, &reply);
        } else {
            let beta = crypto::random_bytes::<10>().to_vec();
            let reply = Command::new("initivexpand")
                .arg("alpha", b64(&alpha))
                .arg("beta", b64(&beta))
                .arg("omega", self.identity.omega());
            let secret = SharedSecret::legacy(&self.identity.ecdh(&client_pub), &alpha, &beta);
            peer.stage = Stage::AwaitInit { omega };
            self.send_cmd_addr(addr, &reply);
            // Everything after initivexpand uses the new keys.
            self.peers.get_mut(&addr).unwrap().conn.secret = Some(secret);
        }
        Ok(())
    }

    fn on_clientek(&mut self, addr: SocketAddr, cmd: &Command) -> Result<()> {
        let peer = self.peers.get_mut(&addr).unwrap();
        let Stage::AwaitEk { alpha, beta, key, client_pub, omega } = &peer.stage else { unreachable!() };
        let ek = unb64(cmd.get("ek").ok_or_else(|| anyhow!("no ek"))?)?;
        let proof = unb64(cmd.get("proof").ok_or_else(|| anyhow!("no proof"))?)?;
        let mut signed = ek.clone();
        signed.extend_from_slice(beta);
        identity::verify(client_pub, &signed, &proof).map_err(|e| anyhow!("clientek proof: {e}"))?;
        let shared = key.shared_secret(&decode_point(&ek)?);
        peer.conn.secret = Some(SharedSecret::ed25519(&shared, alpha, beta));
        peer.stage = Stage::AwaitInit { omega: omega.clone() };
        Ok(())
    }

    fn on_clientinit(&mut self, addr: SocketAddr, cmd: &Command) -> Result<()> {
        let Stage::AwaitInit { omega } = &self.peers[&addr].stage else { unreachable!() };
        let omega = omega.clone();
        let uid = identity::uid_from_omega(&omega);
        let rc = cmd.get("return_code").map(String::from);
        let ip = addr.ip().to_string();
        let offset: u64 = cmd.num("client_key_offset").unwrap_or(0);
        if crypto::security_level(&omega, offset) < self.cfg.min_security_level {
            self.send_error(addr, err::IDENTITY_LEVEL, rc);
            return Err(anyhow!("security level too low"));
        }
        if let Some(ban) = self.st.active_ban(&uid, &ip) {
            let mut c = Command::new("error").arg("id", err::BANNED.0).arg("msg", err::BANNED.1).arg("extra_msg", &ban.reason);
            if let Some(rc) = &rc {
                c.push("return_code", rc);
            }
            self.send_cmd_addr(addr, &c);
            return Err(anyhow!("banned client {uid} ({ip})"));
        }
        if !self.st.password.is_empty() && cmd.get_or("client_server_password", "") != self.st.password {
            self.send_error(addr, err::SERVER_PASSWORD, rc);
            return Err(anyhow!("wrong server password"));
        }
        if self.clients().count() >= self.st.max_clients as usize {
            self.send_error(addr, err::SERVER_FULL, rc);
            return Err(anyhow!("server full"));
        }
        self.admit_client(addr, uid, ip, cmd, rc);
        Ok(())
    }

    /// Create the client, send it the initial server state and announce it to everybody.
    fn admit_client(&mut self, addr: SocketAddr, uid: String, ip: String, cmd: &Command, rc: Option<String>) -> u16 {
        // Unique nickname
        let base = cmd.get_or("client_nickname", "").trim().to_string();
        let base = if base.chars().count() < 3 { format!("TeamSpeakUser{base}") } else { base };
        let mut nickname = base.clone();
        let mut n = 1;
        while self.clients().any(|c| c.nickname == nickname) {
            nickname = format!("{base}{n}");
            n += 1;
        }

        let db = self.st.db_client(&uid, &nickname, &ip);
        let (dbid, groups) = (db.dbid, db.server_groups.clone());
        let _ = self.st.save();

        // Target channel: "/<cid>" or a "Parent/Child" path, if joinable
        let mut channel = self.st.default_channel();
        let want = cmd.get_or("client_default_channel", "");
        let found = if let Some(id) = want.strip_prefix('/').and_then(|s| s.parse::<u64>().ok()) {
            self.st.channel(id).map(|c| c.id)
        } else if !want.is_empty() {
            self.find_channel_path(want)
        } else {
            None
        };
        if let Some(cid) = found {
            let ch = self.st.channel(cid).unwrap();
            if ch.password.is_empty() || ch.password == cmd.get_or("client_default_channel_password", "") {
                channel = cid;
            }
        }

        let clid = (1..=u16::MAX).find(|i| !self.clid_addr.contains_key(i)).unwrap();
        let mut info = ClientInfo {
            clid,
            dbid,
            uid: uid.clone(),
            nickname: nickname.clone(),
            channel,
            channel_group: self.st.channel_group_of(dbid, channel),
            server_groups: groups,
            talk_power: 0,
            input_muted: cmd.get("client_input_muted") == Some("1"),
            output_muted: cmd.get("client_output_muted") == Some("1"),
            input_hw: cmd.get_or("client_input_hardware", "1") == "1",
            output_hw: cmd.get_or("client_output_hardware", "1") == "1",
            away: false,
            away_msg: String::new(),
            recording: false,
            description: String::new(),
            version: cmd.get_or("client_version", "").into(),
            platform: cmd.get_or("client_platform", "").into(),
            ip,
            connected_at: Instant::now(),
            last_active: Instant::now(),
            last_talked: None,
        };
        info.talk_power = self.perm_of(&info, channel, "i_client_talk_power");
        info!("client {clid} '{nickname}' ({uid}) connected from {addr} [{} {}]", info.version, info.platform);
        self.peers.get_mut(&addr).unwrap().stage = Stage::Connected(Box::new(info.clone()));
        self.clid_addr.insert(clid, addr);

        let initserver = Command::new("initserver")
            .arg("virtualserver_welcomemessage", &self.st.welcome_message)
            .arg("virtualserver_platform", std::env::consts::OS)
            .arg("virtualserver_version", "3.13.8 [Build: 0]")
            .arg("virtualserver_maxclients", self.st.max_clients)
            .arg("virtualserver_created", self.st.created)
            .arg("virtualserver_hostmessage", "")
            .arg("virtualserver_hostmessage_mode", 0)
            .arg("virtualserver_id", 1)
            .arg("virtualserver_ip", "")
            .arg("virtualserver_ask_for_privilegekey", 0)
            .arg("acn", &nickname)
            .arg("aclid", clid)
            .arg("pv", 6)
            .arg("lt", 0)
            .arg("client_talk_power", info.talk_power)
            .arg("client_needed_serverquery_view_power", 75)
            .arg("virtualserver_name", &self.st.name)
            .arg("virtualserver_codec_encryption_mode", 0)
            .arg("virtualserver_default_server_group", self.st.default_server_group)
            .arg("virtualserver_default_channel_group", self.st.default_channel_group)
            .arg("virtualserver_hostbanner_url", &self.st.hostbanner_url)
            .arg("virtualserver_hostbanner_gfx_url", &self.st.hostbanner_gfx_url)
            .arg("virtualserver_hostbanner_gfx_interval", self.st.hostbanner_gfx_interval)
            .arg("virtualserver_priority_speaker_dimm_modificator", "-18.0000")
            .arg("virtualserver_hostbutton_tooltip", "")
            .arg("virtualserver_hostbutton_url", "")
            .arg("virtualserver_hostbutton_gfx_url", "")
            .arg("virtualserver_name_phonetic", "")
            .arg("virtualserver_icon_id", 0)
            .arg("virtualserver_hostbanner_mode", self.st.hostbanner_mode)
            .arg("virtualserver_channel_temp_delete_delay_default", 0)
            .arg("virtualserver_unique_identifier", &self.st.unique_id);
        self.send_cmd_addr(addr, &initserver);
        let sgl = self.group_list_cmd(false);
        self.send_cmd_addr(addr, &sgl);
        let cgl = self.group_list_cmd(true);
        self.send_cmd_addr(addr, &cgl);

        let mut list = Command::new("channellist");
        for ch in self.st.ordered_channels() {
            list.add_item(channel_props(ch));
        }
        self.send_cmd_addr(addr, &list);
        self.send_cmd_addr(addr, &Command::new("channellistfinished"));

        let others: Vec<ClientInfo> = self.clients().filter(|c| c.clid != clid).cloned().collect();
        for c in others.iter().chain(std::iter::once(&info)) {
            let ev = self.enter_view(c, 0, 0);
            self.send_cmd_addr(addr, &ev);
        }
        let ev = self.enter_view(&info, 0, 0);
        self.broadcast(&ev, Some(clid));
        self.send_needed_permissions(clid);
        if rc.is_some() {
            self.send_error(addr, err::OK, rc);
        }
        clid
    }

    fn find_channel_path(&self, path: &str) -> Option<u64> {
        let mut parent = 0;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            parent = self.st.channels.iter().find(|c| c.parent == parent && c.name == part)?.id;
        }
        (parent != 0).then_some(parent)
    }

    fn enter_view(&self, c: &ClientInfo, from: u64, reason: u32) -> Command {
        let mut cmd = Command::new("notifycliententerview").arg("cfid", from).arg("ctid", c.channel).arg("reasonid", reason);
        for (k, v) in client_props(c) {
            cmd.push(&k, v);
        }
        cmd
    }

    // ------------------------------------------------------------------ permissions

    /// Effective permission of a client in a channel.
    pub fn perm_of(&self, c: &ClientInfo, cid: u64, perm: &str) -> i32 {
        let sgs: Vec<&Group> = c.server_groups.iter().filter_map(|g| self.st.server_group(*g)).collect();
        let cg = self.st.channel_group(self.st.channel_group_of(c.dbid, cid));
        perms::effective(&sgs, cg, perm)
    }

    /// Permission of an invoker in its current channel. Query/Server have every right.
    pub fn inv_perm(&self, by: &Invoker, perm: &str) -> i32 {
        match by {
            Invoker::Client(id) => self.client(*id).map(|c| self.perm_of(c, c.channel, perm)).unwrap_or(0),
            _ => i32::MAX,
        }
    }

    pub fn inv_perm_in(&self, by: &Invoker, cid: u64, perm: &str) -> i32 {
        match by {
            Invoker::Client(id) => self.client(*id).map(|c| self.perm_of(c, cid, perm)).unwrap_or(0),
            _ => i32::MAX,
        }
    }

    pub fn need(&self, by: &Invoker, perm: &str) -> Result<(), E> {
        if self.inv_perm(by, perm) > 0 { Ok(()) } else { Err(err::PERMISSIONS) }
    }

    pub fn need_in(&self, by: &Invoker, cid: u64, perm: &str) -> Result<(), E> {
        if self.inv_perm_in(by, cid, perm) > 0 { Ok(()) } else { Err(err::PERMISSIONS) }
    }

    /// `power` of the invoker must reach the target client's `needed` value.
    pub fn power_vs_client(&self, by: &Invoker, power: &str, target: u16, needed: &str) -> Result<(), E> {
        let t = self.client(target).ok_or(err::INVALID_CLIENT)?;
        let p = self.inv_perm(by, power);
        let n = self.perm_of(t, t.channel, needed);
        if p > 0 && p >= n { Ok(()) } else { Err(err::PERMISSIONS) }
    }

    /// Recompute channel group + talk power after a channel or group change and tell everyone.
    pub fn refresh_client(&mut self, clid: u16, by: &Invoker) {
        let Some(c) = self.client(clid) else { return };
        let cg = self.st.channel_group_of(c.dbid, c.channel);
        let tp = self.perm_of(c, c.channel, "i_client_talk_power");
        let (old_cg, old_tp, channel) = (c.channel_group, c.talk_power, c.channel);
        {
            let c = self.client_mut(clid).unwrap();
            c.channel_group = cg;
            c.talk_power = tp;
        }
        if cg != old_cg {
            let n = self
                .with_invoker(Command::new("notifyclientchannelgroupchanged"), by)
                .arg("cgid", cg)
                .arg("cgi", channel)
                .arg("cid", channel)
                .arg("clid", clid);
            self.broadcast(&n, None);
        }
        if tp != old_tp {
            let n = Command::new("notifyclientupdated").arg("clid", clid).arg("client_talk_power", tp);
            self.broadcast(&n, None);
        }
        self.send_needed_permissions(clid);
    }

    pub fn refresh_all_clients(&mut self) {
        for id in self.online_ids() {
            self.refresh_client(id, &Invoker::Server);
        }
    }

    /// Our effective permissions, so the client can show/hide actions.
    pub fn send_needed_permissions(&mut self, clid: u16) {
        let Some(c) = self.client(clid) else { return };
        let mut cmd = Command::new("notifyclientneededpermissions");
        for (i, p) in PERMS.iter().enumerate() {
            cmd.add_item(kv(&[
                ("permid", (i + 1).to_string()),
                ("permsid", p.name.into()),
                ("permvalue", self.perm_of(c, c.channel, p.name).to_string()),
            ]));
        }
        self.send_cmd(clid, &cmd);
    }

    /// Connection statistics of a client, from the client's point of view
    /// (what it sent = what we received).
    fn connection_info(&self, clid: u16, by: &Invoker) -> Result<Command, E> {
        let addr = *self.clid_addr.get(&clid).ok_or(err::INVALID_CLIENT)?;
        let peer = self.peers.get(&addr).ok_or(err::INVALID_CLIENT)?;
        let Stage::Connected(c) = &peer.stage else { return Err(err::INVALID_CLIENT) };
        let st = &peer.conn.stats;
        let show_ip = self.inv_perm(by, "b_client_remoteaddress_view") > 0 || matches!(by, Invoker::Client(i) if *i == clid);
        let mut n = Command::new("notifyconnectioninfo")
            .arg("clid", clid)
            .arg("connection_ping", format!("{:.4}", peer.conn.rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0)))
            .arg("connection_ping_deviation", "0")
            .arg("connection_connected_time", c.connected_at.elapsed().as_millis())
            .arg("connection_idle_time", c.last_active.elapsed().as_millis())
            .arg("connection_last_talked", c.last_talked.map(|t| t.elapsed().as_millis() as i64).unwrap_or(-1))
            .arg("connection_client_ip", if show_ip { addr.ip().to_string() } else { String::new() })
            .arg("connection_client_port", if show_ip { addr.port().to_string() } else { String::new() });
        let names = ["speech", "keepalive", "control"];
        let (ls_out, ls_in) = st.last_second();
        let (lm_out, lm_in) = st.last_minute();
        let mut put = |key: &str, vals: [u64; 3]| {
            for (i, name) in names.iter().enumerate() {
                n.push(&format!("{key}_{name}"), vals[i]);
            }
            n.push(&format!("{key}_total"), vals.iter().sum::<u64>());
        };
        put("connection_packets_sent", st.packets_recv);
        put("connection_bytes_sent", st.bytes_recv);
        put("connection_packets_received", st.packets_sent);
        put("connection_bytes_received", st.bytes_sent);
        put("connection_bandwidth_sent_last_second", ls_in);
        put("connection_bandwidth_sent_last_minute", lm_in);
        put("connection_bandwidth_received_last_second", ls_out);
        put("connection_bandwidth_received_last_minute", lm_out);
        n.push("connection_filetransfer_bandwidth_sent", 0);
        n.push("connection_filetransfer_bandwidth_received", 0);
        for (i, name) in names.iter().enumerate() {
            n.push(&format!("connection_client2server_packetloss_{name}"), format!("{:.4}", st.loss_in(i)));
        }
        n.push("connection_client2server_packetloss_total", format!("{:.4}", st.loss_in_total()));
        let out = st.loss_out();
        for name in names {
            n.push(&format!("connection_server2client_packetloss_{name}"), format!("{:.4}", if name == "control" { out } else { 0.0 }));
        }
        n.push("connection_server2client_packetloss_total", format!("{:.4}", out));
        Ok(n)
    }

    // ------------------------------------------------------------------ timers / disconnect

    fn on_tick(&mut self) {
        self.sync_video();
        let now = Instant::now();
        let mut dead = Vec::new();
        let mut out = Vec::new();
        for (addr, peer) in self.peers.iter_mut() {
            if peer.bot.is_some() {
                continue;
            }
            let connected = matches!(peer.stage, Stage::Connected(_));
            if !connected && now.duration_since(peer.created) > Duration::from_secs(20) {
                dead.push((*addr, 3, "handshake timeout"));
                continue;
            }
            match peer.conn.poll_resend(now) {
                Ok(p) => out.push((*addr, p)),
                Err(_) => {
                    dead.push((*addr, 3, "connection lost"));
                    continue;
                }
            }
            if connected && peer.conn.timed_out() {
                dead.push((*addr, 3, "connection lost"));
                continue;
            }
            if peer.conn.secret.is_some() && now.duration_since(peer.last_ping) >= Duration::from_secs(1) {
                peer.last_ping = now;
                out.push((*addr, vec![peer.conn.ping()]));
            }
        }
        for (addr, p) in out {
            self.send_raw(addr, p);
        }
        for (addr, reason, msg) in dead {
            debug!("{addr}: {msg}");
            self.disconnect(addr, reason, msg, Invoker::Server);
        }
    }

    /// Tell the video relay where everybody is and what they may do.
    fn sync_video(&self) {
        let Some((hub, _)) = &self.video else { return };
        let members = self
            .clients()
            .map(|c| {
                let m = crate::video::Member {
                    channel: c.channel,
                    nickname: c.nickname.clone(),
                    can_stream: self.perm_of(c, c.channel, "b_client_video_stream") > 0,
                    can_watch: self.perm_of(c, c.channel, "b_client_video_watch") > 0,
                };
                (c.clid, m)
            })
            .collect();
        hub.lock().unwrap().set_members(members);
    }

    /// Remove a peer. reasonid: 3 = timeout, 4 = channel kick, 5 = server kick, 6 = ban, 8 = leaving.
    pub fn disconnect(&mut self, addr: SocketAddr, reasonid: u32, msg: &str, by: Invoker) {
        self.disconnect_ex(addr, reasonid, msg, by, None);
    }

    pub fn disconnect_ex(&mut self, addr: SocketAddr, reasonid: u32, msg: &str, by: Invoker, bantime: Option<u64>) {
        let Some(peer) = self.peers.get(&addr) else { return };
        if let Stage::Connected(c) = &peer.stage {
            let (clid, channel) = (c.clid, c.channel);
            info!("client {clid} '{}' left ({msg})", c.nickname);
            let mut cmd = Command::new("notifyclientleftview")
                .arg("cfid", channel)
                .arg("ctid", 0)
                .arg("reasonid", reasonid)
                .arg("reasonmsg", msg)
                .arg("clid", clid);
            if let Some(t) = bantime {
                cmd.push("bantime", t);
            }
            if reasonid == 4 || reasonid == 5 || reasonid == 6 {
                for (k, v) in self.invoker(&by) {
                    cmd.push(k, v);
                }
            }
            // Tell the client itself too (it waits for this before closing).
            self.broadcast(&cmd, None);
            self.clid_addr.remove(&clid);
            self.peers.remove(&addr);
            self.cleanup_temp_channel(channel);
        } else {
            self.peers.remove(&addr);
        }
    }

    pub fn addr_of(&self, clid: u16) -> Option<SocketAddr> {
        self.clid_addr.get(&clid).copied()
    }

    fn cleanup_temp_channel(&mut self, cid: u64) {
        let Some(ch) = self.st.channel(cid) else { return };
        if !ch.temporary() || self.clients().any(|c| c.channel == cid) {
            return;
        }
        if self.st.channels.iter().any(|c| c.parent == cid) {
            return;
        }
        let _ = self.delete_channel(cid, true, Invoker::Server);
    }

    pub fn invoker(&self, i: &Invoker) -> Vec<(&'static str, String)> {
        match i {
            Invoker::Client(id) => {
                let c = self.client(*id);
                vec![
                    ("invokerid", id.to_string()),
                    ("invokername", c.map(|c| c.nickname.clone()).unwrap_or_default()),
                    ("invokeruid", c.map(|c| c.uid.clone()).unwrap_or_default()),
                ]
            }
            Invoker::Query(name) => vec![
                ("invokerid", "0".into()),
                ("invokername", name.clone()),
                ("invokeruid", "serveradmin".into()),
            ],
            Invoker::Server => vec![("invokerid", "0".into()), ("invokername", "Server".into()), ("invokeruid", String::new())],
        }
    }

    pub fn invoker_name(&self, i: &Invoker) -> String {
        self.invoker(i).into_iter().find(|(k, _)| *k == "invokername").map(|(_, v)| v).unwrap_or_default()
    }

    pub fn with_invoker(&self, mut cmd: Command, i: &Invoker) -> Command {
        for (k, v) in self.invoker(i) {
            cmd.push(k, v);
        }
        cmd
    }

    // ------------------------------------------------------------------ voice

    fn on_voice(&mut self, addr: SocketAddr, whisper: bool, p: &[u8]) {
        let Some(Stage::Connected(c)) = self.peers.get(&addr).map(|p| &p.stage) else { return };
        if c.input_muted || p.len() < 3 {
            return;
        }
        let (from, channel, talk_power) = (c.clid, c.channel, c.talk_power);
        if !whisper && self.st.channel(channel).map(|ch| talk_power < ch.needed_talk_power).unwrap_or(false) {
            return;
        }
        let codec = p[2];
        let talking = if whisper { p.len() > 5 } else { p.len() > 3 };
        if talking {
            if let Some(Stage::Connected(c)) = self.peers.get_mut(&addr).map(|p| &mut p.stage) {
                c.last_talked = Some(Instant::now());
            }
        }
        let (targets, data): (Vec<u16>, &[u8]) = if !whisper {
            (self.clients().filter(|o| o.channel == channel && o.clid != from).map(|o| o.clid).collect(), &p[3..])
        } else {
            // vid u16 | codec u8 | n_channels u8 | n_clients u8 | channel ids u64* | client ids u16* | data
            if p.len() < 5 {
                return;
            }
            let (nc, ncl) = (p[3] as usize, p[4] as usize);
            let data_at = 5 + nc * 8 + ncl * 2;
            if p.len() < data_at {
                return;
            }
            let chans: Vec<u64> = (0..nc).map(|i| u64::from_be_bytes(p[5 + i * 8..13 + i * 8].try_into().unwrap())).collect();
            let at = 5 + nc * 8;
            let mut t: Vec<u16> = (0..ncl).map(|i| u16::from_be_bytes([p[at + i * 2], p[at + i * 2 + 1]])).collect();
            t.extend(self.clients().filter(|o| chans.contains(&o.channel)).map(|o| o.clid));
            t.retain(|&x| x != from);
            t.sort();
            t.dedup();
            (t, &p[data_at..])
        };
        for t in targets {
            let Some(&taddr) = self.clid_addr.get(&t) else { continue };
            let Some(peer) = self.peers.get_mut(&taddr) else { continue };
            if peer.bot.is_some() {
                continue;
            }
            if let Stage::Connected(o) = &peer.stage {
                if o.output_muted {
                    continue;
                }
            }
            let pkt = peer.conn.send_voice_s2c(from, codec, data, whisper);
            self.send_raw(taddr, vec![pkt]);
        }
    }

    // ------------------------------------------------------------------ client commands

    fn client_command(&mut self, clid: u16, cmd: &Command) -> Result<(), E> {
        if let Some(c) = self.client_mut(clid) {
            c.last_active = Instant::now();
        }
        let me = Invoker::Client(clid);
        let reply = |s: &mut Self, c: Command| {
            s.send_cmd(clid, &c);
            Ok(())
        };
        match cmd.name.as_str() {
            "clientdisconnect" => {
                let addr = self.clid_addr[&clid];
                let msg = cmd.get_or("reasonmsg", "").to_string();
                // Ack/error first, then the leave notification
                self.send_error(addr, err::OK, cmd.get("return_code").map(String::from));
                self.disconnect(addr, 8, &msg, me);
                Ok(())
            }
            // RustSpeak extension: token for the WebSocket video relay.
            "videotoken" => {
                let Some((hub, port)) = &self.video else { return Err(err::CMD_NOT_FOUND) };
                let port = *port;
                self.sync_video();
                let token = hub.lock().unwrap().add_token(clid);
                let n = Command::new("notifyvideotoken").arg("token", token).arg("port", port).arg("clid", clid);
                reply(self, n)
            }
            "clientmove" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                for i in 0..cmd.items.len() {
                    let target: u16 = cmd.num_in(i, "clid").unwrap_or(clid);
                    let pw = if target == clid { cmd.get("cpw") } else { None };
                    self.move_client(target, cid, pw, me.clone())?;
                }
                Ok(())
            }
            "sendtextmessage" => {
                let mode: u32 = cmd.num("targetmode").ok_or(err::PARAM_MISSING)?;
                let target: u64 = cmd.num("target").unwrap_or(0);
                self.send_text(mode, target, cmd.get_or("msg", ""), me)
            }
            "clientpoke" => {
                let target = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                self.poke(target, cmd.get_or("msg", ""), me)
            }
            "clientkick" => {
                let reason: u32 = cmd.num("reasonid").unwrap_or(5);
                for i in 0..cmd.items.len() {
                    let t = cmd.num_in(i, "clid").ok_or(err::PARAM_MISSING)?;
                    self.kick(t, reason, cmd.get_or("reasonmsg", ""), me.clone())?;
                }
                Ok(())
            }
            "banclient" => {
                let t = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                self.ban_client(t, cmd.num("time").unwrap_or(0), cmd.get_or("banreason", ""), me).map(|_| ())
            }
            "banadd" => {
                self.ban_add(cmd.get_or("uid", ""), cmd.get_or("ip", ""), cmd.get_or("name", ""), cmd.num("time").unwrap_or(0), cmd.get_or("banreason", ""), me)
                    .map(|_| ())
            }
            "banlist" => {
                let items = self.ban_list(&me)?;
                let mut c = Command::new("notifybanlist");
                for it in items {
                    c.add_item(it);
                }
                reply(self, c)
            }
            "bandel" => self.ban_del(cmd.num("banid").ok_or(err::PARAM_MISSING)?, me),
            "clientupdate" => self.client_update(clid, cmd),
            "channelcreate" => {
                let cid = self.create_channel(cmd, me.clone())?;
                // The creator becomes channel admin and joins, as on the original server.
                let dbid = self.client(clid).map(|c| c.dbid).unwrap_or(0);
                self.st.set_channel_group(dbid, cid, CG_ADMIN);
                let _ = self.st.save();
                let _ = self.move_client(clid, cid, None, Invoker::Server);
                self.refresh_client(clid, &Invoker::Server);
                Ok(())
            }
            "channeldelete" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                self.delete_channel(cid, cmd.get("force") == Some("1"), me)
            }
            "channeledit" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                self.edit_channel(cid, cmd, me)
            }
            "channelgetdescription" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                let ch = self.st.channel(cid).ok_or(err::INVALID_CHANNEL)?;
                let c = Command::new("notifychanneledited").arg("cid", cid).arg("reasonid", 10).arg("channel_description", &ch.description);
                reply(self, c)
            }
            "channelsubscribe" | "channelsubscribeall" => {
                let mut n = Command::new("notifychannelsubscribed");
                let ids: Vec<u64> = if cmd.name == "channelsubscribeall" {
                    self.st.channels.iter().map(|c| c.id).collect()
                } else {
                    (0..cmd.items.len()).filter_map(|i| cmd.num_in(i, "cid")).collect()
                };
                for id in ids {
                    n.add_item(kv(&[("cid", id.to_string()), ("es", "0".into())]));
                }
                reply(self, n)
            }
            "channelunsubscribe" | "channelunsubscribeall" => Ok(()),
            "clientgetuidfromclid" => {
                let t: u16 = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                let c = self.client(t).ok_or(err::INVALID_CLIENT)?;
                let n = Command::new("notifyclientuidfromclid").arg("clid", t).arg("cluid", &c.uid).arg("nickname", &c.nickname).arg("cldbid", c.dbid);
                reply(self, n)
            }
            "clientgetvariables" => {
                let t: u16 = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                let c = self.client(t).ok_or(err::INVALID_CLIENT)?.clone();
                let created = self.st.clients.iter().find(|d| d.dbid == c.dbid).map(|d| (d.created, d.total_connections)).unwrap_or((0, 0));
                let mut n = Command::new("notifyclientupdated").arg("clid", t);
                for (k, v) in client_props(&c) {
                    if k != "clid" {
                        n.push(&k, v);
                    }
                }
                n.push("client_version", &c.version);
                n.push("client_platform", &c.platform);
                n.push("client_created", created.0);
                n.push("client_totalconnections", created.1);
                n.push("connection_connected_time", c.connected_at.elapsed().as_millis());
                n.push("client_idle_time", c.last_active.elapsed().as_millis());
                reply(self, n)
            }
            "servergetvariables" => {
                let n = Command::new("notifyserverupdated")
                    .arg("virtualserver_name", &self.st.name)
                    .arg("virtualserver_welcomemessage", &self.st.welcome_message)
                    .arg("virtualserver_maxclients", self.st.max_clients)
                    .arg("virtualserver_clientsonline", self.clients().count())
                    .arg("virtualserver_channelsonline", self.st.channels.len())
                    .arg("virtualserver_uptime", self.started.elapsed().as_secs())
                    .arg("virtualserver_created", self.st.created)
                    .arg("virtualserver_platform", std::env::consts::OS)
                    .arg("virtualserver_version", "3.13.8 [Build: 0] (RustSpeak server)")
                    .arg("virtualserver_flag_password", b(!self.st.password.is_empty()))
                    .arg("virtualserver_hostbanner_url", &self.st.hostbanner_url)
                    .arg("virtualserver_hostbanner_gfx_url", &self.st.hostbanner_gfx_url)
                    .arg("virtualserver_hostbanner_gfx_interval", self.st.hostbanner_gfx_interval)
                    .arg("virtualserver_hostbanner_mode", self.st.hostbanner_mode)
                    .arg("virtualserver_unique_identifier", &self.st.unique_id);
                reply(self, n)
            }
            "serveredit" => self.edit_server(cmd, me),
            "servergrouplist" => {
                self.need(&me, "b_virtualserver_servergroup_list")?;
                let c = self.group_list_cmd(false);
                reply(self, c)
            }
            "channelgrouplist" => {
                let c = self.group_list_cmd(true);
                reply(self, c)
            }
            "permissionlist" => {
                let c = permission_list_cmd();
                reply(self, c)
            }
            "servergroupadd" | "channelgroupadd" => {
                let channel = cmd.name.starts_with("channel");
                self.group_add(channel, cmd.get("name").ok_or(err::PARAM_MISSING)?, None, &me).map(|_| ())
            }
            "servergroupcopy" | "channelgroupcopy" => {
                let channel = cmd.name.starts_with("channel");
                let src = cmd.num(if channel { "scgid" } else { "ssgid" }).ok_or(err::PARAM_MISSING)?;
                self.group_add(channel, cmd.get("name").ok_or(err::PARAM_MISSING)?, Some(src), &me).map(|_| ())
            }
            "servergroupdel" | "channelgroupdel" => {
                let channel = cmd.name.starts_with("channel");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                self.group_del(channel, id, &me)
            }
            "servergrouprename" | "channelgrouprename" => {
                let channel = cmd.name.starts_with("channel");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                self.group_rename(channel, id, cmd.get("name").ok_or(err::PARAM_MISSING)?, &me)
            }
            "servergrouppermlist" | "channelgrouppermlist" => {
                let channel = cmd.name.starts_with("channel");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                let items = self.group_perm_list(channel, id, &me)?;
                let mut c = Command::new(if channel { "notifychannelgrouppermlist" } else { "notifyservergrouppermlist" }).arg(if channel { "cgid" } else { "sgid" }, id);
                for it in items {
                    c.add_item(it);
                }
                reply(self, c)
            }
            "servergroupaddperm" | "channelgroupaddperm" | "servergroupdelperm" | "channelgroupdelperm" => {
                let channel = cmd.name.starts_with("channel");
                let add = cmd.name.ends_with("addperm");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                let mut changes = Vec::new();
                for i in 0..cmd.items.len() {
                    let name = match cmd.get_in(i, "permsid") {
                        Some(n) => n.to_string(),
                        None => cmd.num_in::<usize>(i, "permid").and_then(perms::perm_by_id).map(|p| p.name.to_string()).ok_or(err::PARAM_MISSING)?,
                    };
                    let value = if add { Some(cmd.num_in(i, "permvalue").ok_or(err::PARAM_MISSING)?) } else { None };
                    changes.push((name, value));
                }
                self.group_set_perms(channel, id, changes, &me)
            }
            "servergroupaddclient" | "servergroupdelclient" => {
                let sgid = cmd.num("sgid").ok_or(err::PARAM_MISSING)?;
                let dbid = cmd.num("cldbid").ok_or(err::PARAM_MISSING)?;
                self.server_group_member(sgid, dbid, cmd.name == "servergroupaddclient", &me)
            }
            "servergroupclientlist" => {
                let sgid: u64 = cmd.num("sgid").ok_or(err::PARAM_MISSING)?;
                let mut c = Command::new("notifyservergroupclientlist").arg("sgid", sgid);
                for d in self.st.clients.iter().filter(|d| d.server_groups.contains(&sgid)) {
                    c.add_item(kv(&[("cldbid", d.dbid.to_string()), ("client_nickname", d.nickname.clone()), ("client_unique_identifier", d.uid.clone())]));
                }
                reply(self, c)
            }
            "setclientchannelgroup" => {
                let cgid = cmd.num("cgid").ok_or(err::PARAM_MISSING)?;
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                let dbid = cmd.num("cldbid").ok_or(err::PARAM_MISSING)?;
                self.set_client_channel_group(cgid, cid, dbid, &me)
            }
            "privilegekeyadd" | "tokenadd" => {
                let kind: u8 = cmd.num("tokentype").unwrap_or(0);
                let group = cmd.num("tokenid1").ok_or(err::PARAM_MISSING)?;
                let channel = cmd.num("tokenid2").unwrap_or(0);
                let token = self.token_add(kind, group, channel, cmd.get_or("tokendescription", ""), &me)?;
                reply(self, Command::new("notifytokenadd").arg("token", token))
            }
            "privilegekeylist" | "tokenlist" => {
                let items = self.token_list(&me)?;
                let mut c = Command::new("notifytokenlist");
                for it in items {
                    c.add_item(it);
                }
                reply(self, c)
            }
            "privilegekeydelete" | "tokendelete" => self.token_del(cmd.get("token").ok_or(err::PARAM_MISSING)?, &me),
            "privilegekeyuse" | "tokenuse" => self.token_use(clid, cmd.get("token").ok_or(err::PARAM_MISSING)?),
            "botkeyadd" => {
                let k = self.bot_key_add(cmd.get_or("name", ""), &me)?;
                let n = Command::new("notifybotkeyadd").arg("botid", k.id).arg("name", &k.name).arg("key", &k.key);
                reply(self, n)
            }
            "botkeylist" => {
                let mut c = Command::new("notifybotkeylist");
                for it in self.bot_key_list(&me)? {
                    c.add_item(it);
                }
                reply(self, c)
            }
            "botkeydel" => self.bot_key_del(cmd.num("botid").ok_or(err::PARAM_MISSING)?, &me),
            "getconnectioninfo" => {
                let t: u16 = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                let n = self.connection_info(t, &me)?;
                reply(self, n)
            }
            "iconupload" => {
                self.need(&me, "b_icon_manage")?;
                let data = cmd.get("data").ok_or(err::PARAM_MISSING)?;
                let raw = tsproto::unb64(data).map_err(|_| err::INVALID_PARAM)?;
                if raw.len() > 256 * 1024 || !raw.starts_with(&[0x89, 0x50, 0x4e, 0x47]) {
                    return Err(err::INVALID_PARAM);
                }
                let id = crc32(&raw);
                self.st.icons.insert(id, data.to_string());
                let _ = self.st.save();
                reply(self, Command::new("notifyiconupload").arg("iconid", id))
            }
            "iconlist" => {
                let mut c = Command::new("notifyiconlist");
                for (id, d) in &self.st.icons {
                    c.add_item(kv(&[("iconid", id.to_string()), ("size", d.len().to_string())]));
                }
                reply(self, c)
            }
            "icondownload" => {
                let id: u32 = cmd.get("iconid").and_then(|v| v.parse::<i64>().ok()).map(|v| v as u32).ok_or(err::PARAM_MISSING)?;
                let data = self.st.icons.get(&id).ok_or(err::EMPTY_RESULT)?.clone();
                reply(self, Command::new("notifyicondownload").arg("iconid", id).arg("data", data))
            }
            "icondelete" => {
                self.need(&me, "b_icon_manage")?;
                let id: u32 = cmd.get("iconid").and_then(|v| v.parse::<i64>().ok()).map(|v| v as u32).ok_or(err::PARAM_MISSING)?;
                self.st.icons.remove(&id).ok_or(err::EMPTY_RESULT)?;
                let _ = self.st.save();
                Ok(())
            }
            "clientchatcomposing" => {
                let t: u16 = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                let uid = self.client(clid).map(|c| c.uid.clone()).unwrap_or_default();
                let n = Command::new("notifyclientchatcomposing").arg("clid", clid).arg("cluid", uid);
                self.send_cmd(t, &n);
                Ok(())
            }
            "plugincmd" => {
                let n = Command::new("notifyplugincmd").arg("name", cmd.get_or("name", "")).arg("data", cmd.get_or("data", "")).arg("invokerid", clid);
                let target: u32 = cmd.num("targetmode").unwrap_or(0);
                match target {
                    2 => {
                        let t: u16 = cmd.num("target").unwrap_or(0);
                        self.send_cmd(t, &n)
                    }
                    _ => {
                        let ch = self.client(clid).map(|c| c.channel).unwrap_or(0);
                        let ids: Vec<u16> = self.clients().filter(|c| target == 1 || c.channel == ch).map(|c| c.clid).collect();
                        for id in ids {
                            self.send_cmd(id, &n);
                        }
                    }
                }
                Ok(())
            }
            "clientchatclosed" | "setconnectioninfo" | "clientupdatepermissions" | "connectioninfoautoupdate" => Ok(()),
            "channelclientpermlist" | "channelpermlist" | "clientpermlist" | "permoverview" | "complainlist" | "ftgetfilelist" => Err(err::EMPTY_RESULT),
            _ => Err(err::CMD_NOT_FOUND),
        }
    }

    fn client_update(&mut self, clid: u16, cmd: &Command) -> Result<(), E> {
        let mut changed = Vec::new();
        if let Some(nick) = cmd.get("client_nickname") {
            let nick = nick.trim();
            if nick.chars().count() < 3 || nick.chars().count() > 30 {
                return Err(err::INVALID_PARAM);
            }
            if self.clients().any(|c| c.nickname == nick && c.clid != clid) {
                return Err(err::NICK_IN_USE);
            }
        }
        let c = self.client_mut(clid).ok_or(err::INVALID_CLIENT)?;
        for (k, v) in &cmd.items[0] {
            let flag = v == "1";
            match k.as_str() {
                "client_nickname" => c.nickname = v.trim().into(),
                "client_input_muted" => c.input_muted = flag,
                "client_output_muted" => c.output_muted = flag,
                "client_input_hardware" => c.input_hw = flag,
                "client_output_hardware" => c.output_hw = flag,
                "client_away" => c.away = flag,
                "client_away_message" => c.away_msg = v.clone(),
                "client_is_recording" => c.recording = flag,
                "client_description" => c.description = v.clone(),
                "client_talk_request" | "client_talk_request_msg" | "client_meta_data" | "client_nickname_phonetic" | "client_flag_avatar" | "client_badges"
                | "client_outputonly_muted" | "client_is_channel_commander" => {}
                _ => continue,
            }
            changed.push((k.clone(), v.clone()));
        }
        if changed.is_empty() {
            return Ok(());
        }
        let mut n = Command::new("notifyclientupdated").arg("clid", clid);
        for (k, v) in changed {
            n.push(&k, v);
        }
        self.broadcast(&n, None);
        Ok(())
    }

    // ------------------------------------------------------------------ shared operations (voice + query)

    pub fn move_client(&mut self, clid: u16, cid: u64, pw: Option<&str>, by: Invoker) -> Result<(), E> {
        let ch = self.st.channel(cid).ok_or(err::INVALID_CHANNEL)?.clone();
        let c = self.client(clid).ok_or(err::INVALID_CLIENT)?;
        if c.channel == cid {
            return Err(err::ALREADY_IN_CHANNEL);
        }
        let self_move = matches!(by, Invoker::Client(i) if i == clid);
        if self_move {
            if ch.needed_join_power > 0 && self.inv_perm_in(&by, cid, "i_channel_join_power") < ch.needed_join_power {
                return Err(err::PERMISSIONS);
            }
            if !ch.password.is_empty() && pw.unwrap_or("") != ch.password && self.inv_perm_in(&by, cid, "b_channel_join_ignore_password") <= 0 {
                return Err(err::CHANNEL_PASSWORD);
            }
        } else {
            self.power_vs_client(&by, "i_client_move_power", clid, "i_client_needed_move_power")?;
        }
        let full = ch.max_clients >= 0 && self.clients().filter(|o| o.channel == cid).count() >= ch.max_clients as usize;
        if full && self.inv_perm_in(&by, cid, "b_channel_join_ignore_maxclients") <= 0 {
            return Err(err::CHANNEL_FULL);
        }
        let old = c.channel;
        self.client_mut(clid).unwrap().channel = cid;
        // Moves done by the server itself (e.g. into a freshly created channel) look like own moves.
        let own = self_move || matches!(by, Invoker::Server);
        let mut n = Command::new("notifyclientmoved").arg("ctid", cid).arg("reasonid", if own { 0 } else { 1 }).arg("clid", clid);
        if !own {
            n = self.with_invoker(n, &by);
        }
        self.broadcast(&n, None);
        self.refresh_client(clid, &Invoker::Server);
        self.cleanup_temp_channel(old);
        Ok(())
    }

    pub fn send_text(&mut self, mode: u32, target: u64, msg: &str, by: Invoker) -> Result<(), E> {
        let n = self.with_invoker(Command::new("notifytextmessage").arg("targetmode", mode).arg("msg", msg), &by);
        match mode {
            1 => {
                let t = target as u16;
                self.client(t).ok_or(err::INVALID_CLIENT)?;
                self.power_vs_client(&by, "i_client_private_textmessage_power", t, "i_client_needed_private_textmessage_power")?;
                let n = n.arg("target", t);
                self.send_cmd(t, &n);
                if let Invoker::Client(me) = by {
                    if me != t {
                        self.send_cmd(me, &n);
                    }
                }
            }
            2 => {
                self.need(&by, "b_client_channel_textmessage_send")?;
                let ch = match by {
                    Invoker::Client(me) => self.client(me).map(|c| c.channel).unwrap_or(0),
                    _ => {
                        if target != 0 {
                            target
                        } else {
                            self.st.default_channel()
                        }
                    }
                };
                let ids: Vec<u16> = self.clients().filter(|c| c.channel == ch).map(|c| c.clid).collect();
                for id in ids {
                    self.send_cmd(id, &n);
                }
            }
            3 => {
                self.need(&by, "b_client_server_textmessage_send")?;
                self.broadcast(&n, None)
            }
            _ => return Err(err::INVALID_PARAM),
        }
        Ok(())
    }

    pub fn poke(&mut self, target: u16, msg: &str, by: Invoker) -> Result<(), E> {
        self.power_vs_client(&by, "i_client_poke_power", target, "i_client_needed_poke_power")?;
        let n = self.with_invoker(Command::new("notifyclientpoke"), &by).arg("msg", msg);
        self.send_cmd(target, &n);
        Ok(())
    }

    pub fn kick(&mut self, target: u16, reason: u32, msg: &str, by: Invoker) -> Result<(), E> {
        let c = self.client(target).ok_or(err::INVALID_CLIENT)?;
        match reason {
            4 => {
                self.power_vs_client(&by, "i_client_kick_from_channel_power", target, "i_client_needed_kick_from_channel_power")?;
                let def = self.st.default_channel();
                if c.channel == def {
                    return Ok(());
                }
                let from = c.channel;
                self.client_mut(target).unwrap().channel = def;
                let n = self
                    .with_invoker(Command::new("notifyclientmoved").arg("ctid", def).arg("reasonid", 4).arg("clid", target), &by)
                    .arg("reasonmsg", msg);
                self.broadcast(&n, None);
                self.refresh_client(target, &Invoker::Server);
                self.cleanup_temp_channel(from);
            }
            5 => {
                self.power_vs_client(&by, "i_client_kick_from_server_power", target, "i_client_needed_kick_from_server_power")?;
                let addr = self.clid_addr[&target];
                self.disconnect(addr, 5, msg, by);
            }
            _ => return Err(err::INVALID_PARAM),
        }
        Ok(())
    }

    pub fn create_channel(&mut self, cmd: &Command, by: Invoker) -> Result<u64, E> {
        let name = cmd.get("channel_name").ok_or(err::PARAM_MISSING)?.trim().to_string();
        let parent: u64 = cmd.num("cpid").unwrap_or(0);
        if parent != 0 && self.st.channel(parent).is_none() {
            return Err(err::INVALID_CHANNEL);
        }
        if name.is_empty() || name.chars().count() > 40 {
            return Err(err::INVALID_PARAM);
        }
        if self.st.channels.iter().any(|c| c.parent == parent && c.name == name) {
            return Err(err::CHANNEL_NAME_IN_USE);
        }
        let permanent = cmd.get("channel_flag_permanent") == Some("1");
        let semi = cmd.get("channel_flag_semi_permanent") == Some("1");
        // Query-created channels are permanent by default.
        let (permanent, semi) = if matches!(by, Invoker::Query(_)) && !semi { (true, false) } else { (permanent, semi) };
        self.need(
            &by,
            if permanent {
                "b_channel_create_permanent"
            } else if semi {
                "b_channel_create_semi_permanent"
            } else {
                "b_channel_create_temporary"
            },
        )?;
        if parent != 0 {
            self.need(&by, "b_channel_create_child")?;
        }
        if cmd.get("channel_password").map(|p| !p.is_empty()).unwrap_or(false) {
            self.need(&by, "b_channel_create_with_password")?;
        }
        if cmd.get("channel_flag_default") == Some("1") {
            self.need(&by, "b_channel_modify_make_default")?;
        }
        let id = self.st.next_channel_id;
        self.st.next_channel_id += 1;
        let order = cmd.num("channel_order").unwrap_or_else(|| self.st.last_sibling(parent));
        // Insert after `order`: whoever followed `order` now follows us.
        for c in self.st.channels.iter_mut() {
            if c.parent == parent && c.order == order {
                c.order = id;
            }
        }
        let mut ch = Channel::new(id, parent, order, &name);
        ch.permanent = permanent;
        ch.semi_permanent = semi;
        apply_channel_props(&mut ch, cmd);
        if ch.is_default {
            for c in self.st.channels.iter_mut() {
                c.is_default = false;
            }
        }
        self.st.channels.push(ch.clone());
        let _ = self.st.save();
        let mut n = Command::new("notifychannelcreated").arg("cid", id).arg("cpid", parent);
        for (k, v) in channel_props(&ch) {
            if k != "cid" && k != "pid" && k != "cpid" {
                n.push(&k, v);
            }
        }
        let n = self.with_invoker(n, &by);
        self.broadcast(&n, None);
        Ok(id)
    }

    pub fn delete_channel(&mut self, cid: u64, force: bool, by: Invoker) -> Result<(), E> {
        let ch = self.st.channel(cid).ok_or(err::INVALID_CHANNEL)?.clone();
        if ch.is_default {
            return Err(err::PERMISSIONS);
        }
        self.need_in(
            &by,
            cid,
            if ch.permanent {
                "b_channel_delete_permanent"
            } else if ch.semi_permanent {
                "b_channel_delete_semi_permanent"
            } else {
                "b_channel_delete_temporary"
            },
        )?;
        let mut ids = vec![cid];
        let mut i = 0;
        while i < ids.len() {
            let p = ids[i];
            ids.extend(self.st.channels.iter().filter(|c| c.parent == p).map(|c| c.id));
            i += 1;
        }
        let inside: Vec<u16> = self.clients().filter(|c| ids.contains(&c.channel)).map(|c| c.clid).collect();
        if !inside.is_empty() {
            if !force {
                return Err(err::CHANNEL_NOT_EMPTY);
            }
            self.need_in(&by, cid, "b_channel_delete_flag_force")?;
        }
        let def = self.st.default_channel();
        for clid in inside.iter().copied() {
            self.client_mut(clid).unwrap().channel = def;
            let n = self.with_invoker(Command::new("notifyclientmoved").arg("ctid", def).arg("reasonid", 5).arg("clid", clid), &by);
            self.broadcast(&n, None);
        }
        self.st.remove_channel(cid);
        let _ = self.st.save();
        let n = self.with_invoker(Command::new("notifychanneldeleted").arg("cid", cid), &by);
        self.broadcast(&n, None);
        for clid in inside {
            self.refresh_client(clid, &Invoker::Server);
        }
        Ok(())
    }

    pub fn edit_channel(&mut self, cid: u64, cmd: &Command, by: Invoker) -> Result<(), E> {
        let ch = self.st.channel(cid).ok_or(err::INVALID_CHANNEL)?.clone();
        for (k, v) in &cmd.items[0] {
            let perm = match k.as_str() {
                "channel_name" => "b_channel_modify_name",
                "channel_topic" => "b_channel_modify_topic",
                "channel_description" => "b_channel_modify_description",
                "channel_password" => "b_channel_modify_password",
                "channel_maxclients" | "channel_flag_maxclients_unlimited" => "b_channel_modify_maxclients",
                "channel_codec_quality" | "channel_codec" => "b_channel_modify_codec_quality",
                "channel_needed_talk_power" => "b_channel_modify_needed_talk_power",
                "channel_needed_join_power" => "b_channel_modify_needed_join_power",
                "channel_flag_permanent" | "channel_flag_semi_permanent" => "b_channel_modify_make_permanent",
                "channel_flag_default" => "b_channel_modify_make_default",
                "channel_icon_id" => "b_channel_modify_icon",
                _ => continue,
            };
            self.need_in(&by, cid, perm)?;
            if k == "channel_name" {
                let name = v.trim();
                if name.is_empty() {
                    return Err(err::INVALID_PARAM);
                }
                if self.st.channels.iter().any(|c| c.parent == ch.parent && c.name == name && c.id != cid) {
                    return Err(err::CHANNEL_NAME_IN_USE);
                }
            }
        }
        let make_default = cmd.get("channel_flag_default") == Some("1");
        if make_default {
            for c in self.st.channels.iter_mut() {
                c.is_default = false;
            }
        }
        let ch = self.st.channel_mut(cid).unwrap();
        apply_channel_props(ch, cmd);
        if ch.is_default {
            ch.permanent = true;
            ch.semi_permanent = false;
        }
        let mut n = Command::new("notifychanneledited").arg("cid", cid).arg("reasonid", 10);
        for (k, v) in &cmd.items[0] {
            if k.starts_with("channel_") && k != "channel_password" {
                n.push(k, v.clone());
            }
        }
        if cmd.get("channel_password").is_some() {
            n.push("channel_flag_password", b(!ch.password.is_empty()));
        }
        let _ = self.st.save();
        let n = self.with_invoker(n, &by);
        self.broadcast(&n, None);
        // Talk power requirements may have changed for the people inside.
        let inside: Vec<u16> = self.clients().filter(|c| c.channel == cid).map(|c| c.clid).collect();
        for clid in inside {
            self.refresh_client(clid, &Invoker::Server);
        }
        Ok(())
    }

    pub fn edit_server(&mut self, cmd: &Command, by: Invoker) -> Result<(), E> {
        for (k, v) in &cmd.items[0] {
            // Banner image and click target must be external http(s) links.
            if matches!(k.as_str(), "virtualserver_hostbanner_url" | "virtualserver_hostbanner_gfx_url")
                && !v.is_empty()
                && (!crate::state::is_web_url(v) || v.len() > 2048)
            {
                return Err(err::INVALID_PARAM);
            }
            let perm = match k.as_str() {
                "virtualserver_name" => "b_virtualserver_modify_name",
                "virtualserver_welcomemessage" => "b_virtualserver_modify_welcomemessage",
                "virtualserver_maxclients" => "b_virtualserver_modify_maxclients",
                "virtualserver_password" => "b_virtualserver_modify_password",
                "virtualserver_hostbanner_url" | "virtualserver_hostbanner_gfx_url" | "virtualserver_hostbanner_gfx_interval" | "virtualserver_hostbanner_mode" => {
                    "b_virtualserver_modify_hostbanner"
                }
                _ => continue,
            };
            self.need(&by, perm)?;
        }
        let mut n = Command::new("notifyserveredited").arg("reasonid", 10);
        for (k, v) in &cmd.items[0] {
            match k.as_str() {
                "virtualserver_name" => self.st.name = v.clone(),
                "virtualserver_welcomemessage" => self.st.welcome_message = v.clone(),
                "virtualserver_maxclients" => self.st.max_clients = v.parse().map_err(|_| err::INVALID_PARAM)?,
                "virtualserver_hostbanner_url" => self.st.hostbanner_url = v.clone(),
                "virtualserver_hostbanner_gfx_url" => self.st.hostbanner_gfx_url = v.clone(),
                "virtualserver_hostbanner_gfx_interval" => self.st.hostbanner_gfx_interval = v.parse().unwrap_or(0),
                "virtualserver_hostbanner_mode" => self.st.hostbanner_mode = v.parse().unwrap_or(2),
                // Voice clients send the hash already, ServerQuery the plain text.
                "virtualserver_password" => {
                    self.st.password = if matches!(by, Invoker::Query(_)) { tsproto::hash_password(v) } else { v.clone() }
                }
                _ => continue,
            }
            if k != "virtualserver_password" {
                n.push(k, v);
            }
        }
        let _ = self.st.save();
        let n = self.with_invoker(n, &by);
        self.broadcast(&n, None);
        Ok(())
    }

    // ------------------------------------------------------------------ bots (RustSpeak extension)

    pub fn on_bot(&mut self, req: crate::bot::BotRequest) {
        use crate::bot::BotRequest;
        match req {
            BotRequest::Login { cmd, tx, reply } => {
                let r = self.bot_login(&cmd, tx).map_err(|e| Command::new("error").arg("id", e.0).arg("msg", e.1).to_string());
                let _ = reply.send(r);
            }
            BotRequest::Command { addr, cmd } => {
                let Some(Stage::Connected(c)) = self.peers.get(&addr).map(|p| &p.stage) else { return };
                let clid = c.clid;
                debug!("<- bot {clid}: {}", truncate(&cmd.to_string()));
                let r = self.client_command(clid, &cmd);
                if self.peers.contains_key(&addr) {
                    let rc = cmd.get("return_code").map(|s| s.to_string());
                    self.send_error(addr, r.err().unwrap_or(err::OK), rc);
                }
            }
            BotRequest::Logout { addr } => self.disconnect(addr, 8, "Bot getrennt", Invoker::Server),
        }
    }

    /// Log a bot in: it becomes a normal client with the stable identity `bot:<key id>`.
    fn bot_login(&mut self, cmd: &Command, tx: mpsc::UnboundedSender<String>) -> Result<SocketAddr, E> {
        let key = cmd.get("key").ok_or(err::PARAM_MISSING)?;
        let bk = self.st.bot_keys.iter().find(|k| k.key == key).cloned().ok_or(err::INVALID_LOGIN)?;
        let uid = format!("bot:{}", bk.id);
        if let Some(ban) = self.st.active_ban(&uid, "") {
            info!("banned bot '{}' tried to log in ({})", bk.name, ban.reason);
            return Err(err::BANNED);
        }
        if self.clients().count() >= self.st.max_clients as usize {
            return Err(err::SERVER_FULL);
        }
        // One session per key
        let old = self.clients().find(|c| c.uid == uid).map(|c| c.clid).and_then(|id| self.addr_of(id));
        if let Some(old) = old {
            self.disconnect(old, 8, "Bot hat sich neu angemeldet", Invoker::Server);
        }
        // Bots live on addresses of the IPv6 discard prefix (100::/64), never used for UDP.
        let n = (1..=u16::MAX).find(|n| !self.peers.contains_key(&bot_addr(*n))).ok_or(err::SERVER_FULL)?;
        let addr = bot_addr(n);
        let mut peer = self.new_peer();
        peer.bot = Some(tx);
        self.peers.insert(addr, peer);
        let mut c = cmd.clone();
        c.name = "clientinit".into();
        let it = &mut c.items[0];
        it.retain(|(k, _)| k != "key" && k != "client_version" && k != "client_platform");
        if !it.iter().any(|(k, _)| k == "client_nickname") {
            it.push(("client_nickname".into(), bk.name.clone()));
        }
        it.push(("client_version".into(), "RustSpeak Bot".into()));
        it.push(("client_platform".into(), "Bot".into()));
        let rc = c.get("return_code").map(String::from);
        let clid = self.admit_client(addr, uid, "bot".into(), &c, None);
        info!("bot '{}' (key {}) logged in as client {clid}", bk.name, bk.id);
        self.send_error(addr, err::OK, rc);
        Ok(addr)
    }

    pub fn bot_key_add(&mut self, name: &str, by: &Invoker) -> Result<BotKey, E> {
        self.need(by, "b_virtualserver_bot_manage")?;
        let name = name.trim();
        if name.chars().count() < 3 {
            return Err(err::INVALID_PARAM);
        }
        let id = self.st.bot_keys.iter().map(|k| k.id).max().unwrap_or(0) + 1;
        let k = BotKey { id, key: random_token(40), name: name.into(), created: tsproto::unix_now() };
        self.st.bot_keys.push(k.clone());
        let _ = self.st.save();
        Ok(k)
    }

    pub fn bot_key_list(&self, by: &Invoker) -> Result<Vec<Vec<(String, String)>>, E> {
        self.need(by, "b_virtualserver_bot_manage")?;
        Ok(self
            .st
            .bot_keys
            .iter()
            .map(|k| {
                let online = self.clients().any(|c| c.uid == format!("bot:{}", k.id));
                kv(&[
                    ("botid", k.id.to_string()),
                    ("name", k.name.clone()),
                    ("key", k.key.clone()),
                    ("created", k.created.to_string()),
                    ("online", b(online).into()),
                ])
            })
            .collect())
    }

    pub fn bot_key_del(&mut self, id: u32, by: &Invoker) -> Result<(), E> {
        self.need(by, "b_virtualserver_bot_manage")?;
        let before = self.st.bot_keys.len();
        self.st.bot_keys.retain(|k| k.id != id);
        if self.st.bot_keys.len() == before {
            return Err(err::EMPTY_RESULT);
        }
        let _ = self.st.save();
        let online = self.clients().find(|c| c.uid == format!("bot:{id}")).map(|c| c.clid).and_then(|c| self.addr_of(c));
        if let Some(addr) = online {
            self.disconnect(addr, 5, "Bot-Schlüssel gelöscht", by.clone());
        }
        Ok(())
    }

    pub fn identity_uid(&self) -> String {
        self.identity.uid()
    }
}

// ---------------------------------------------------------------------- property helpers

/// CRC32 (IEEE), used as icon id like TeamSpeak does.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

pub fn join(v: &[u64]) -> String {
    v.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(",")
}

fn truncate(s: &str) -> String {
    if s.len() > 300 {
        format!("{}...", &s[..s.char_indices().nth(300).map(|x| x.0).unwrap_or(s.len())])
    } else {
        s.into()
    }
}

pub fn permission_list_cmd() -> Command {
    let mut c = Command::new("notifypermissionlist");
    for (i, p) in PERMS.iter().enumerate() {
        c.add_item(kv(&[
            ("permid", (i + 1).to_string()),
            ("permname", p.name.into()),
            ("permdesc", p.desc.into()),
            ("permcat", p.cat.into()),
        ]));
    }
    c
}

pub fn channel_props(c: &Channel) -> Vec<(String, String)> {
    kv(&[
        ("cid", c.id.to_string()),
        ("cpid", c.parent.to_string()),
        ("channel_name", c.name.clone()),
        ("channel_topic", c.topic.clone()),
        ("channel_codec", c.codec.to_string()),
        ("channel_codec_quality", c.codec_quality.to_string()),
        ("channel_maxclients", c.max_clients.to_string()),
        ("channel_maxfamilyclients", "-1".into()),
        ("channel_order", c.order.to_string()),
        ("channel_flag_permanent", b(c.permanent).into()),
        ("channel_flag_semi_permanent", b(c.semi_permanent).into()),
        ("channel_flag_default", b(c.is_default).into()),
        ("channel_flag_password", b(!c.password.is_empty()).into()),
        ("channel_codec_latency_factor", "1".into()),
        ("channel_codec_is_unencrypted", "1".into()),
        ("channel_delete_delay", "0".into()),
        ("channel_flag_maxclients_unlimited", b(c.max_clients < 0).into()),
        ("channel_flag_maxfamilyclients_unlimited", "1".into()),
        ("channel_flag_maxfamilyclients_inherited", "0".into()),
        ("channel_needed_talk_power", c.needed_talk_power.to_string()),
        ("channel_needed_join_power", c.needed_join_power.to_string()),
        ("channel_forced_silence", "0".into()),
        ("channel_name_phonetic", String::new()),
        ("channel_icon_id", c.icon_id.to_string()),
        ("channel_flag_private", "0".into()),
    ])
}

fn apply_channel_props(ch: &mut Channel, cmd: &Command) {
    for (k, v) in &cmd.items[0] {
        match k.as_str() {
            "channel_name" => ch.name = v.trim().into(),
            "channel_topic" => ch.topic = v.clone(),
            "channel_description" => ch.description = v.clone(),
            "channel_password" => ch.password = v.clone(),
            "channel_maxclients" => ch.max_clients = v.parse().unwrap_or(-1),
            "channel_flag_maxclients_unlimited" if v == "1" => ch.max_clients = -1,
            "channel_codec" => ch.codec = v.parse().unwrap_or(4),
            "channel_codec_quality" => ch.codec_quality = v.parse::<u8>().unwrap_or(6).min(10),
            "channel_needed_talk_power" => ch.needed_talk_power = v.parse().unwrap_or(0),
            "channel_needed_join_power" => ch.needed_join_power = v.parse().unwrap_or(0),
            "channel_flag_permanent" => {
                ch.permanent = v == "1";
                if ch.permanent {
                    ch.semi_permanent = false;
                }
            }
            "channel_flag_semi_permanent" => {
                ch.semi_permanent = v == "1";
                if ch.semi_permanent {
                    ch.permanent = false;
                }
            }
            "channel_flag_default" => ch.is_default = v == "1",
            "channel_icon_id" => ch.icon_id = v.parse::<i64>().map(|x| x as u32).unwrap_or(0),
            _ => {}
        }
    }
}

pub fn client_props(c: &ClientInfo) -> Vec<(String, String)> {
    kv(&[
        ("clid", c.clid.to_string()),
        ("client_unique_identifier", c.uid.clone()),
        ("client_nickname", c.nickname.clone()),
        ("client_input_muted", b(c.input_muted).into()),
        ("client_output_muted", b(c.output_muted).into()),
        ("client_outputonly_muted", "0".into()),
        ("client_input_hardware", b(c.input_hw).into()),
        ("client_output_hardware", b(c.output_hw).into()),
        ("client_meta_data", String::new()),
        ("client_is_recording", b(c.recording).into()),
        ("client_database_id", c.dbid.to_string()),
        ("client_channel_group_id", c.channel_group.to_string()),
        ("client_servergroups", join(&c.server_groups)),
        ("client_away", b(c.away).into()),
        ("client_away_message", c.away_msg.clone()),
        ("client_type", "0".into()),
        ("client_flag_avatar", String::new()),
        ("client_talk_power", c.talk_power.to_string()),
        ("client_talk_request", "0".into()),
        ("client_talk_request_msg", String::new()),
        ("client_description", c.description.clone()),
        ("client_is_talker", "0".into()),
        ("client_is_priority_speaker", "0".into()),
        ("client_unread_messages", "0".into()),
        ("client_nickname_phonetic", String::new()),
        ("client_needed_serverquery_view_power", "75".into()),
        ("client_icon_id", "0".into()),
        ("client_is_channel_commander", "0".into()),
        ("client_country", String::new()),
        ("client_channel_group_inherited_channel_id", c.channel.to_string()),
        ("client_badges", String::new()),
        ("client_version", c.version.clone()),
        ("client_platform", c.platform.clone()),
    ])
}

pub fn uptime_secs(s: &Server) -> u64 {
    s.started.elapsed().as_secs()
}

/// Pseudo address of a bot client (IPv6 discard prefix 100::/64).
fn bot_addr(n: u16) -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, n)), 0)
}
