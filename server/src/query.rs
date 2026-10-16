//! ServerQuery: line based TCP admin interface (default port 10011).
//! Output format and banner as documented in `serverquerydocs/` of the original server.

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use tsproto::Command;

use crate::server::{channel_props, client_props, err, join, uptime_secs, Invoker, QueryRequest, Server};


const BANNER: &str = "TS3\n\rWelcome to the TeamSpeak 3 ServerQuery interface, type \"help\" for a list of commands and \"help <command>\" for information on a specific command.\n\r";

#[derive(Clone, Default)]
pub struct Session {
    pub login: Option<String>,
    pub selected: bool,
    pub nickname: String,
}

pub async fn listen(port: u16, tx: mpsc::Sender<QueryRequest>) -> Result<()> {
    let l = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("ServerQuery listening on tcp/{port}");
    loop {
        let (s, addr) = l.accept().await?;
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(s, tx).await {
                warn!("query {addr}: {e}");
            }
        });
    }
}

async fn handle(stream: TcpStream, tx: mpsc::Sender<QueryRequest>) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    w.write_all(BANNER.as_bytes()).await?;
    let mut session = Session { nickname: "serveradmin".into(), ..Default::default() };
    while let Ok(Some(line)) = tokio::time::timeout(std::time::Duration::from_secs(600), lines.next_line()).await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cmd = Command::parse(line, true);
        if cmd.name == "quit" {
            w.write_all(b"error id=0 msg=ok\n\r").await?;
            break;
        }
        let (reply, rx) = oneshot::channel();
        tx.send(QueryRequest { cmd, session: session.clone(), reply }).await?;
        let (out, s) = rx.await?;
        session = s;
        w.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

fn error_line(e: err::E) -> String {
    format!("error id={} msg={}\n\r", e.0, tsproto::command::escape(e.1))
}

fn data(items: Vec<Vec<(String, String)>>) -> String {
    let mut c = Command { name: String::new(), items };
    if c.items.is_empty() {
        c.items.push(vec![]);
    }
    format!("{c}\n\r")
}

fn has(cmd: &Command, flag: &str) -> bool {
    cmd.has_flag(flag)
}

/// Positional argument (`login name pw`, `use 1`).
fn positional(cmd: &Command, idx: usize) -> Option<&str> {
    cmd.items.first()?.iter().filter(|(_, v)| v.is_empty()).nth(idx).map(|(k, _)| k.as_str())
}

const COMMANDS: &[(&str, &str)] = &[
    ("help", "read help files"),
    ("login", "authenticate with the server"),
    ("logout", "deselect virtual server and log out"),
    ("quit", "close connection"),
    ("use", "select virtual server"),
    ("version", "display version information"),
    ("whoami", "display current session info"),
    ("serverinfo", "display virtual server properties"),
    ("serverlist", "list virtual servers"),
    ("serveredit", "change virtual server properties"),
    ("servernotifyregister", "register for event notifications (accepted, no events are sent)"),
    ("gm", "send global text message"),
    ("sendtextmessage", "send text message"),
    ("clientlist", "list clients online"),
    ("clientinfo", "display client properties"),
    ("clientdblist", "list known client identities"),
    ("clientkick", "kick a client"),
    ("clientmove", "move a client"),
    ("clientpoke", "poke a client"),
    ("channellist", "list channels"),
    ("channelinfo", "display channel properties"),
    ("channelcreate", "create a channel"),
    ("channeldelete", "delete a channel"),
    ("channeledit", "change channel properties"),
    ("servergrouplist", "list server groups"),
    ("servergroupaddclient", "add client (by cldbid) to server group"),
    ("servergroupdelclient", "remove client (by cldbid) from server group"),
    ("servergroupsbyclientid", "list server groups of a client (by cldbid)"),
    ("servergroupadd", "create a server group"),
    ("servergroupdel", "delete a server group"),
    ("servergrouprename", "rename a server group"),
    ("servergrouppermlist", "list permissions of a server group"),
    ("servergroupaddperm", "set permissions of a server group"),
    ("servergroupdelperm", "remove permissions from a server group"),
    ("servergroupclientlist", "list members of a server group"),
    ("channelgrouplist", "list channel groups (also add/del/rename/permlist/addperm/delperm)"),
    ("setclientchannelgroup", "set the channel group of a client in a channel"),
    ("permissionlist", "list all permissions"),
    ("privilegekeyadd", "create a privilege key (tokentype=0 tokenid1=sgid)"),
    ("privilegekeylist", "list privilege keys"),
    ("privilegekeydelete", "delete a privilege key"),
    ("botkeyadd", "create a bot key (name=…), see bot interface"),
    ("botkeylist", "list bot keys"),
    ("botkeydel", "delete a bot key (botid=…)"),
    ("banlist", "list active bans"),
    ("banadd", "ban by uid/ip"),
    ("banclient", "ban a connected client"),
    ("bandel", "remove a ban"),
];

impl Server {
    pub fn exec_query(&mut self, cmd: &Command, s: &mut Session) -> String {
        match self.query_inner(cmd, s) {
            Ok(out) => out + &error_line(err::OK),
            Err(e) => error_line(e),
        }
    }

    fn query_inner(&mut self, cmd: &Command, s: &mut Session) -> Result<String, err::E> {
        let name = cmd.name.as_str();
        // Commands usable without login
        match name {
            "help" => {
                let mut out = String::from("TeamSpeak 3 Server (Rust reimplementation) :: ServerQuery commands\n\r\n\r");
                for (c, d) in COMMANDS {
                    out += &format!("{c:<24}| {d}\n\r");
                }
                return Ok(out);
            }
            "version" => {
                return Ok(data(vec![vec![
                    ("version".into(), "3.13.8".into()),
                    ("build".into(), "0".into()),
                    ("platform".into(), std::env::consts::OS.into()),
                ]]))
            }
            "login" => {
                let user = cmd.get("client_login_name").or_else(|| positional(cmd, 0)).unwrap_or("");
                let pw = cmd.get("client_login_password").or_else(|| positional(cmd, 1)).unwrap_or("");
                if user == "serveradmin" && pw == self.st.query_password {
                    s.login = Some(user.into());
                    return Ok(String::new());
                }
                return Err(err::INVALID_LOGIN);
            }
            "logout" => {
                s.login = None;
                s.selected = false;
                return Ok(String::new());
            }
            _ => {}
        }
        if s.login.is_none() {
            return Err(err::NOT_LOGGED_IN);
        }
        let me = Invoker::Query(s.nickname.clone());
        match name {
            "use" => {
                let sid = cmd.get("sid").or_else(|| positional(cmd, 0)).unwrap_or("");
                let port = cmd.num::<u16>("port");
                if sid == "1" || port == Some(self.cfg.port) {
                    s.selected = true;
                    if let Some(n) = cmd.get("client_nickname") {
                        s.nickname = n.into();
                    }
                    return Ok(String::new());
                }
                return Err((1024, "invalid serverID"));
            }
            "whoami" => {
                return Ok(data(vec![vec![
                    ("virtualserver_status".into(), if s.selected { "online" } else { "unknown" }.into()),
                    ("virtualserver_id".into(), if s.selected { "1" } else { "0" }.into()),
                    ("virtualserver_unique_identifier".into(), if s.selected { self.st.unique_id.clone() } else { String::new() }),
                    ("virtualserver_port".into(), if s.selected { self.cfg.port.to_string() } else { "0".into() }),
                    ("client_id".into(), "0".into()),
                    ("client_channel_id".into(), "0".into()),
                    ("client_nickname".into(), s.nickname.clone()),
                    ("client_database_id".into(), "1".into()),
                    ("client_login_name".into(), s.login.clone().unwrap_or_default()),
                    ("client_unique_identifier".into(), "serveradmin".into()),
                    ("client_origin_server_id".into(), "0".into()),
                ]]))
            }
            "serverlist" => {
                return Ok(data(vec![vec![
                    ("virtualserver_id".into(), "1".into()),
                    ("virtualserver_port".into(), self.cfg.port.to_string()),
                    ("virtualserver_status".into(), "online".into()),
                    ("virtualserver_clientsonline".into(), self.clients().count().to_string()),
                    ("virtualserver_queryclientsonline".into(), "1".into()),
                    ("virtualserver_maxclients".into(), self.st.max_clients.to_string()),
                    ("virtualserver_uptime".into(), uptime_secs(self).to_string()),
                    ("virtualserver_name".into(), self.st.name.clone()),
                    ("virtualserver_autostart".into(), "1".into()),
                    ("virtualserver_unique_identifier".into(), self.st.unique_id.clone()),
                ]]))
            }
            _ => {}
        }
        if !s.selected {
            return Err((1024, "invalid serverID"));
        }
        match name {
            "serverinfo" => Ok(data(vec![vec![
                ("virtualserver_unique_identifier".into(), self.st.unique_id.clone()),
                ("virtualserver_name".into(), self.st.name.clone()),
                ("virtualserver_welcomemessage".into(), self.st.welcome_message.clone()),
                ("virtualserver_platform".into(), std::env::consts::OS.into()),
                ("virtualserver_version".into(), "3.13.8 [Build: 0]".into()),
                ("virtualserver_maxclients".into(), self.st.max_clients.to_string()),
                ("virtualserver_password".into(), String::new()),
                ("virtualserver_flag_password".into(), if self.st.password.is_empty() { "0" } else { "1" }.into()),
                ("virtualserver_clientsonline".into(), self.clients().count().to_string()),
                ("virtualserver_channelsonline".into(), self.st.channels.len().to_string()),
                ("virtualserver_created".into(), self.st.created.to_string()),
                ("virtualserver_uptime".into(), uptime_secs(self).to_string()),
                ("virtualserver_port".into(), self.cfg.port.to_string()),
                ("virtualserver_id".into(), "1".into()),
                ("virtualserver_status".into(), "online".into()),
                ("virtualserver_default_server_group".into(), self.st.default_server_group.to_string()),
                ("virtualserver_default_channel_group".into(), self.st.default_channel_group.to_string()),
                ("virtualserver_needed_identity_security_level".into(), self.cfg.min_security_level.to_string()),
                ("virtualserver_codec_encryption_mode".into(), "0".into()),
                ("virtualserver_queryclientsonline".into(), "1".into()),
            ]])),
            "serveredit" => self.edit_server(cmd, me).map(|_| String::new()),
            "servernotifyregister" | "servernotifyunregister" => Ok(String::new()),
            "gm" => self.send_text(3, 0, cmd.get_or("msg", ""), me).map(|_| String::new()),
            "sendtextmessage" => {
                let mode = cmd.num("targetmode").ok_or(err::PARAM_MISSING)?;
                self.send_text(mode, cmd.num("target").unwrap_or(0), cmd.get_or("msg", ""), me).map(|_| String::new())
            }
            "clientlist" => {
                let mut items = Vec::new();
                for c in self.clients() {
                    let mut it = vec![
                        ("clid".into(), c.clid.to_string()),
                        ("cid".into(), c.channel.to_string()),
                        ("client_database_id".into(), c.dbid.to_string()),
                        ("client_nickname".into(), c.nickname.clone()),
                        ("client_type".into(), "0".into()),
                    ];
                    if has(cmd, "-uid") {
                        it.push(("client_unique_identifier".into(), c.uid.clone()));
                    }
                    if has(cmd, "-away") {
                        it.push(("client_away".into(), (c.away as u8).to_string()));
                        it.push(("client_away_message".into(), c.away_msg.clone()));
                    }
                    if has(cmd, "-voice") {
                        it.push(("client_flag_talking".into(), "0".into()));
                        it.push(("client_input_muted".into(), (c.input_muted as u8).to_string()));
                        it.push(("client_output_muted".into(), (c.output_muted as u8).to_string()));
                        it.push(("client_input_hardware".into(), (c.input_hw as u8).to_string()));
                        it.push(("client_output_hardware".into(), (c.output_hw as u8).to_string()));
                        it.push(("client_is_recording".into(), (c.recording as u8).to_string()));
                    }
                    if has(cmd, "-times") {
                        it.push(("client_idle_time".into(), c.last_active.elapsed().as_millis().to_string()));
                    }
                    if has(cmd, "-groups") {
                        it.push(("client_servergroups".into(), join(&c.server_groups)));
                        it.push(("client_channel_group_id".into(), c.channel_group.to_string()));
                    }
                    if has(cmd, "-info") {
                        it.push(("client_version".into(), c.version.clone()));
                        it.push(("client_platform".into(), c.platform.clone()));
                    }
                    if has(cmd, "-ip") {
                        it.push(("connection_client_ip".into(), c.ip.clone()));
                    }
                    items.push(it);
                }
                if items.is_empty() {
                    return Err(err::EMPTY_RESULT);
                }
                Ok(data(items))
            }
            "clientinfo" => {
                let clid: u16 = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                let c = self.client(clid).ok_or(err::INVALID_CLIENT)?;
                let mut it: Vec<(String, String)> = vec![("cid".into(), c.channel.to_string())];
                it.extend(client_props(c).into_iter().filter(|(k, _)| k != "clid"));
                it.push(("client_version".into(), c.version.clone()));
                it.push(("client_platform".into(), c.platform.clone()));
                it.push(("client_idle_time".into(), c.last_active.elapsed().as_millis().to_string()));
                it.push(("connection_connected_time".into(), c.connected_at.elapsed().as_millis().to_string()));
                it.push(("connection_client_ip".into(), c.ip.clone()));
                Ok(data(vec![it]))
            }
            "clientdblist" => {
                let items: Vec<_> = self
                    .st
                    .clients
                    .iter()
                    .map(|c| {
                        vec![
                            ("cldbid".into(), c.dbid.to_string()),
                            ("client_unique_identifier".into(), c.uid.clone()),
                            ("client_nickname".into(), c.nickname.clone()),
                            ("client_created".into(), c.created.to_string()),
                            ("client_lastconnected".into(), c.last_connected.to_string()),
                            ("client_totalconnections".into(), c.total_connections.to_string()),
                        ]
                    })
                    .collect();
                if items.is_empty() {
                    return Err(err::EMPTY_RESULT);
                }
                Ok(data(items))
            }
            "clientkick" => {
                let reason = cmd.num("reasonid").unwrap_or(5);
                for i in 0..cmd.items.len() {
                    let t = cmd.num_in(i, "clid").ok_or(err::PARAM_MISSING)?;
                    self.kick(t, reason, cmd.get_or("reasonmsg", ""), me.clone())?;
                }
                Ok(String::new())
            }
            "clientmove" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                for i in 0..cmd.items.len() {
                    let t = cmd.num_in(i, "clid").ok_or(err::PARAM_MISSING)?;
                    self.move_client(t, cid, None, me.clone())?;
                }
                Ok(String::new())
            }
            "clientpoke" => {
                let t = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                self.poke(t, cmd.get_or("msg", ""), me).map(|_| String::new())
            }
            "channellist" => {
                let mut items = Vec::new();
                for ch in self.st.ordered_channels() {
                    let total = self.clients().filter(|c| c.channel == ch.id).count();
                    let mut it = vec![
                        ("cid".into(), ch.id.to_string()),
                        ("pid".into(), ch.parent.to_string()),
                        ("channel_order".into(), ch.order.to_string()),
                        ("channel_name".into(), ch.name.clone()),
                        ("total_clients".into(), total.to_string()),
                        ("channel_needed_subscribe_power".into(), "0".into()),
                    ];
                    if has(cmd, "-topic") {
                        it.push(("channel_topic".into(), ch.topic.clone()));
                    }
                    if has(cmd, "-flags") {
                        it.push(("channel_flag_default".into(), (ch.is_default as u8).to_string()));
                        it.push(("channel_flag_password".into(), (!ch.password.is_empty() as u8).to_string()));
                        it.push(("channel_flag_permanent".into(), (ch.permanent as u8).to_string()));
                        it.push(("channel_flag_semi_permanent".into(), "0".into()));
                    }
                    if has(cmd, "-voice") {
                        it.push(("channel_codec".into(), ch.codec.to_string()));
                        it.push(("channel_codec_quality".into(), ch.codec_quality.to_string()));
                        it.push(("channel_needed_talk_power".into(), ch.needed_talk_power.to_string()));
                    }
                    if has(cmd, "-limits") {
                        it.push(("total_clients_family".into(), total.to_string()));
                        it.push(("channel_maxclients".into(), ch.max_clients.to_string()));
                        it.push(("channel_maxfamilyclients".into(), "-1".into()));
                    }
                    items.push(it);
                }
                Ok(data(items))
            }
            "channelinfo" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                let ch = self.st.channel(cid).ok_or(err::INVALID_CHANNEL)?;
                let mut it: Vec<(String, String)> = vec![("pid".into(), ch.parent.to_string())];
                it.extend(channel_props(ch).into_iter().filter(|(k, _)| k != "cid" && k != "cpid"));
                it.push(("channel_description".into(), ch.description.clone()));
                Ok(data(vec![it]))
            }
            "channelcreate" => {
                let cid = self.create_channel(cmd, me)?;
                Ok(data(vec![vec![("cid".into(), cid.to_string())]]))
            }
            "channeldelete" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                self.delete_channel(cid, cmd.get("force") == Some("1"), me).map(|_| String::new())
            }
            "channeledit" => {
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                let mut c = cmd.clone();
                if let Some(pw) = c.get("channel_password").map(String::from) {
                    // Query sends plain text passwords; voice clients send the hash.
                    for (k, v) in c.items[0].iter_mut() {
                        if k == "channel_password" {
                            *v = tsproto::hash_password(&pw);
                        }
                    }
                }
                self.edit_channel(cid, &c, me).map(|_| String::new())
            }
            "servergrouplist" => Ok(data(self.group_list_items(false))),
            "channelgrouplist" => Ok(data(self.group_list_items(true))),
            "servergroupadd" | "channelgroupadd" => {
                let channel = name.starts_with("channel");
                let id = self.group_add(channel, cmd.get("name").ok_or(err::PARAM_MISSING)?, None, &me)?;
                Ok(data(vec![vec![((if channel { "cgid" } else { "sgid" }).into(), id.to_string())]]))
            }
            "servergroupdel" | "channelgroupdel" => {
                let channel = name.starts_with("channel");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                self.group_del(channel, id, &me).map(|_| String::new())
            }
            "servergrouprename" | "channelgrouprename" => {
                let channel = name.starts_with("channel");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                self.group_rename(channel, id, cmd.get("name").ok_or(err::PARAM_MISSING)?, &me).map(|_| String::new())
            }
            "servergrouppermlist" | "channelgrouppermlist" => {
                let channel = name.starts_with("channel");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                let items = self.group_perm_list(channel, id, &me)?;
                if items.is_empty() {
                    return Err(err::EMPTY_RESULT);
                }
                Ok(data(items))
            }
            "servergroupaddperm" | "channelgroupaddperm" | "servergroupdelperm" | "channelgroupdelperm" => {
                let channel = name.starts_with("channel");
                let add = name.ends_with("addperm");
                let id = cmd.num(if channel { "cgid" } else { "sgid" }).ok_or(err::PARAM_MISSING)?;
                let mut changes = Vec::new();
                for i in 0..cmd.items.len() {
                    let perm = match cmd.get_in(i, "permsid") {
                        Some(n) => n.to_string(),
                        None => cmd
                            .num_in::<usize>(i, "permid")
                            .and_then(crate::perms::perm_by_id)
                            .map(|p| p.name.to_string())
                            .ok_or(err::PARAM_MISSING)?,
                    };
                    let value = if add { Some(cmd.num_in(i, "permvalue").ok_or(err::PARAM_MISSING)?) } else { None };
                    changes.push((perm, value));
                }
                self.group_set_perms(channel, id, changes, &me).map(|_| String::new())
            }
            "servergroupaddclient" | "servergroupdelclient" => {
                let sgid = cmd.num("sgid").ok_or(err::PARAM_MISSING)?;
                let dbid = cmd.num("cldbid").ok_or(err::PARAM_MISSING)?;
                self.server_group_member(sgid, dbid, name == "servergroupaddclient", &me).map(|_| String::new())
            }
            "servergroupclientlist" => {
                let sgid: u64 = cmd.num("sgid").ok_or(err::PARAM_MISSING)?;
                let items: Vec<_> = self
                    .st
                    .clients
                    .iter()
                    .filter(|d| d.server_groups.contains(&sgid))
                    .map(|d| vec![("cldbid".into(), d.dbid.to_string()), ("client_nickname".into(), d.nickname.clone()), ("client_unique_identifier".into(), d.uid.clone())])
                    .collect();
                if items.is_empty() {
                    return Err(err::EMPTY_RESULT);
                }
                Ok(data(items))
            }
            "servergroupsbyclientid" => {
                let dbid: u64 = cmd.num("cldbid").ok_or(err::PARAM_MISSING)?;
                let c = self.st.clients.iter().find(|c| c.dbid == dbid).ok_or(err::EMPTY_RESULT)?;
                Ok(data(
                    c.server_groups
                        .iter()
                        .map(|g| {
                            vec![
                                ("name".into(), self.st.server_group(*g).map(|g| g.name.clone()).unwrap_or_default()),
                                ("sgid".into(), g.to_string()),
                                ("cldbid".into(), dbid.to_string()),
                            ]
                        })
                        .collect(),
                ))
            }
            "setclientchannelgroup" => {
                let cgid = cmd.num("cgid").ok_or(err::PARAM_MISSING)?;
                let cid = cmd.num("cid").ok_or(err::PARAM_MISSING)?;
                let dbid = cmd.num("cldbid").ok_or(err::PARAM_MISSING)?;
                self.set_client_channel_group(cgid, cid, dbid, &me).map(|_| String::new())
            }
            "permissionlist" => {
                let c = crate::server::permission_list_cmd();
                Ok(data(c.items))
            }
            "privilegekeyadd" | "tokenadd" => {
                let kind: u8 = cmd.num("tokentype").unwrap_or(0);
                let group = cmd.num("tokenid1").ok_or(err::PARAM_MISSING)?;
                let token = self.token_add(kind, group, cmd.num("tokenid2").unwrap_or(0), cmd.get_or("tokendescription", ""), &me)?;
                Ok(data(vec![vec![("token".into(), token)]]))
            }
            "botkeyadd" => {
                let k = self.bot_key_add(cmd.get_or("name", ""), &me)?;
                Ok(data(vec![vec![("botid".into(), k.id.to_string()), ("name".into(), k.name), ("key".into(), k.key)]]))
            }
            "botkeylist" => {
                let items = self.bot_key_list(&me)?;
                if items.is_empty() {
                    return Err(err::EMPTY_RESULT);
                }
                Ok(data(items))
            }
            "botkeydel" => self.bot_key_del(cmd.num("botid").ok_or(err::PARAM_MISSING)?, &me).map(|_| String::new()),
            "privilegekeylist" | "tokenlist" => {
                let items = self.token_list(&me)?;
                if items.is_empty() {
                    return Err(err::EMPTY_RESULT);
                }
                Ok(data(items))
            }
            "privilegekeydelete" | "tokendelete" => self.token_del(cmd.get("token").ok_or(err::PARAM_MISSING)?, &me).map(|_| String::new()),
            "banlist" => Ok(data(self.ban_list(&me)?)),
            "banadd" => {
                let id = self.ban_add(
                    cmd.get_or("uid", ""),
                    cmd.get_or("ip", ""),
                    cmd.get_or("name", ""),
                    cmd.num("time").unwrap_or(0),
                    cmd.get_or("banreason", ""),
                    me,
                )?;
                Ok(data(vec![vec![("banid".into(), id.to_string())]]))
            }
            "banclient" => {
                let t = cmd.num("clid").ok_or(err::PARAM_MISSING)?;
                let id = self.ban_client(t, cmd.num("time").unwrap_or(0), cmd.get_or("banreason", ""), me)?;
                Ok(data(vec![vec![("banid".into(), id.to_string())]]))
            }
            "bandel" => self.ban_del(cmd.num("banid").ok_or(err::PARAM_MISSING)?, me).map(|_| String::new()),
            _ => Err(err::CMD_NOT_FOUND),
        }
    }
}
