//! Server administration: server/channel groups and their permissions,
//! group memberships, privilege keys and bans. Shared by voice clients and ServerQuery.

use std::collections::BTreeMap;

use tsproto::Command;

use crate::perms::{self, Group};
use crate::server::{err, join, kv, Invoker, Server, E};
use crate::state::{Ban, State};

type Items = Vec<Vec<(String, String)>>;

fn groups(st: &State, channel: bool) -> &Vec<Group> {
    if channel { &st.channel_groups } else { &st.server_groups }
}

fn groups_mut(st: &mut State, channel: bool) -> &mut Vec<Group> {
    if channel { &mut st.channel_groups } else { &mut st.server_groups }
}

impl Server {
    pub fn group_list_items(&self, channel: bool) -> Items {
        let mut gs: Vec<&Group> = groups(&self.st, channel).iter().collect();
        gs.sort_by_key(|g| (g.sort_id, g.id));
        gs.into_iter()
            .map(|g| {
                kv(&[
                    (if channel { "cgid" } else { "sgid" }, g.id.to_string()),
                    ("name", g.name.clone()),
                    ("type", g.kind.to_string()),
                    ("iconid", (g.get("i_icon_id").unwrap_or(0) as u32).to_string()),
                    ("savedb", "1".into()),
                    ("sortid", g.sort_id.to_string()),
                    ("namemode", g.get("i_group_show_name_in_tree").unwrap_or(0).to_string()),
                    ("n_modifyp", g.get("i_group_needed_modify_power").unwrap_or(0).to_string()),
                    ("n_member_addp", g.get("i_group_needed_member_add_power").unwrap_or(0).to_string()),
                    ("n_member_removep", g.get("i_group_needed_member_remove_power").unwrap_or(0).to_string()),
                ])
            })
            .collect()
    }

    pub fn group_list_cmd(&self, channel: bool) -> Command {
        let mut c = Command::new(if channel { "notifychannelgrouplist" } else { "notifyservergrouplist" });
        for it in self.group_list_items(channel) {
            c.add_item(it);
        }
        c
    }

    fn broadcast_groups(&mut self, channel: bool) {
        let c = self.group_list_cmd(channel);
        self.broadcast(&c, None);
    }

    /// Invoker's `i_group_modify_power` must reach the group's needed modify power.
    fn can_modify_group(&self, by: &Invoker, g: &Group) -> Result<(), E> {
        let p = self.inv_perm(by, "i_group_modify_power");
        if p > 0 && p >= g.get("i_group_needed_modify_power").unwrap_or(0) { Ok(()) } else { Err(err::PERMISSIONS) }
    }

    pub fn group_add(&mut self, channel: bool, name: &str, copy_from: Option<u64>, by: &Invoker) -> Result<u64, E> {
        self.need(by, if channel { "b_virtualserver_channelgroup_create" } else { "b_virtualserver_servergroup_create" })?;
        let name = name.trim();
        if name.is_empty() {
            return Err(err::INVALID_PARAM);
        }
        if groups(&self.st, channel).iter().any(|g| g.name == name) {
            return Err(err::DUPLICATE);
        }
        let perms: BTreeMap<String, i32> = match copy_from {
            Some(src) => groups(&self.st, channel).iter().find(|g| g.id == src).ok_or(err::INVALID_GROUP)?.perms.clone(),
            None => [("i_group_needed_modify_power", 75), ("i_group_needed_member_add_power", 75), ("i_group_needed_member_remove_power", 75)]
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
        };
        let id = self.st.next_group_id;
        self.st.next_group_id += 1;
        let sort_id = groups(&self.st, channel).iter().map(|g| g.sort_id).max().unwrap_or(0) + 10;
        groups_mut(&mut self.st, channel).push(Group { id, name: name.into(), kind: 1, sort_id, perms });
        let _ = self.st.save();
        self.broadcast_groups(channel);
        Ok(id)
    }

    pub fn group_del(&mut self, channel: bool, id: u64, by: &Invoker) -> Result<(), E> {
        self.need(by, if channel { "b_virtualserver_channelgroup_delete" } else { "b_virtualserver_servergroup_delete" })?;
        let g = groups(&self.st, channel).iter().find(|g| g.id == id).ok_or(err::INVALID_GROUP)?.clone();
        self.can_modify_group(by, &g)?;
        let default = if channel { self.st.default_channel_group } else { self.st.default_server_group };
        if id == default {
            return Err(err::PERMISSIONS);
        }
        groups_mut(&mut self.st, channel).retain(|g| g.id != id);
        if channel {
            self.st.channel_group_members.retain(|m| m.cgid != id);
        } else {
            let def = self.st.default_server_group;
            for c in self.st.clients.iter_mut() {
                c.server_groups.retain(|&s| s != id);
                if c.server_groups.is_empty() {
                    c.server_groups.push(def);
                }
            }
            let online: Vec<(u16, u64)> = self.clients().map(|c| (c.clid, c.dbid)).collect();
            for (clid, dbid) in online {
                let groups = self.st.clients.iter().find(|d| d.dbid == dbid).map(|d| d.server_groups.clone()).unwrap_or_default();
                if let Some(c) = self.client_mut(clid) {
                    if c.server_groups != groups {
                        c.server_groups = groups.clone();
                        let n = Command::new("notifyclientupdated").arg("clid", clid).arg("client_servergroups", join(&groups));
                        self.broadcast(&n, None);
                    }
                }
            }
        }
        let _ = self.st.save();
        self.broadcast_groups(channel);
        self.refresh_all_clients();
        Ok(())
    }

    pub fn group_rename(&mut self, channel: bool, id: u64, name: &str, by: &Invoker) -> Result<(), E> {
        let g = groups(&self.st, channel).iter().find(|g| g.id == id).ok_or(err::INVALID_GROUP)?.clone();
        self.can_modify_group(by, &g)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(err::INVALID_PARAM);
        }
        if groups(&self.st, channel).iter().any(|g| g.name == name && g.id != id) {
            return Err(err::DUPLICATE);
        }
        groups_mut(&mut self.st, channel).iter_mut().find(|g| g.id == id).unwrap().name = name.into();
        let _ = self.st.save();
        self.broadcast_groups(channel);
        Ok(())
    }

    pub fn group_perm_list(&self, channel: bool, id: u64, by: &Invoker) -> Result<Items, E> {
        self.need(by, "b_virtualserver_servergroup_permission_list")?;
        let g = groups(&self.st, channel).iter().find(|g| g.id == id).ok_or(err::INVALID_GROUP)?;
        Ok(g.perms
            .iter()
            .map(|(name, v)| {
                kv(&[
                    ("permid", perms::perm_id(name).unwrap_or(0).to_string()),
                    ("permsid", name.clone()),
                    ("permvalue", v.to_string()),
                    ("permnegated", "0".into()),
                    ("permskip", "0".into()),
                ])
            })
            .collect())
    }

    /// Set (`Some`) or remove (`None`) permissions of a group.
    pub fn group_set_perms(&mut self, channel: bool, id: u64, changes: Vec<(String, Option<i32>)>, by: &Invoker) -> Result<(), E> {
        let g = groups(&self.st, channel).iter().find(|g| g.id == id).ok_or(err::INVALID_GROUP)?.clone();
        self.can_modify_group(by, &g)?;
        for (name, value) in &changes {
            if perms::perm_id(name).is_none() {
                return Err(err::INVALID_PARAM);
            }
            // Nobody can grant more power than they have themselves.
            if let Some(v) = value {
                if name.starts_with("i_") && !name.contains("_needed_") && name != "i_icon_id" && name != "i_group_show_name_in_tree" && *v > self.inv_perm(by, name) {
                    return Err(err::PERMISSIONS);
                }
            }
        }
        let g = groups_mut(&mut self.st, channel).iter_mut().find(|g| g.id == id).unwrap();
        for (name, value) in changes {
            match value {
                Some(v) => {
                    g.perms.insert(name, v);
                }
                None => {
                    g.perms.remove(&name);
                }
            }
        }
        let _ = self.st.save();
        self.broadcast_groups(channel);
        self.refresh_all_clients();
        Ok(())
    }

    pub fn server_group_member(&mut self, sgid: u64, dbid: u64, add: bool, by: &Invoker) -> Result<(), E> {
        let g = self.st.server_group(sgid).ok_or(err::INVALID_GROUP)?.clone();
        let (power, needed) = if add {
            ("i_group_member_add_power", "i_group_needed_member_add_power")
        } else {
            ("i_group_member_remove_power", "i_group_needed_member_remove_power")
        };
        let p = self.inv_perm(by, power);
        if !(p > 0 && p >= g.get(needed).unwrap_or(0)) {
            return Err(err::PERMISSIONS);
        }
        let def = self.st.default_server_group;
        let db = self.st.clients.iter_mut().find(|c| c.dbid == dbid).ok_or(err::EMPTY_RESULT)?;
        if add {
            if db.server_groups.contains(&sgid) {
                return Err(err::DUPLICATE);
            }
            db.server_groups.push(sgid);
            // Guests that get a real group are no longer guests.
            if sgid != def {
                db.server_groups.retain(|&s| s != def);
            }
        } else {
            db.server_groups.retain(|&s| s != sgid);
            if db.server_groups.is_empty() {
                db.server_groups.push(def);
            }
        }
        db.server_groups.sort();
        let groups = db.server_groups.clone();
        let _ = self.st.save();
        let online: Vec<u16> = self.clients().filter(|c| c.dbid == dbid).map(|c| c.clid).collect();
        for clid in online {
            let (name, uid) = {
                let c = self.client_mut(clid).unwrap();
                c.server_groups = groups.clone();
                (c.nickname.clone(), c.uid.clone())
            };
            let n = self
                .with_invoker(Command::new(if add { "notifyservergroupclientadded" } else { "notifyservergroupclientdeleted" }), by)
                .arg("sgid", sgid)
                .arg("clid", clid)
                .arg("name", name)
                .arg("cluid", uid);
            self.broadcast(&n, None);
            let n = Command::new("notifyclientupdated").arg("clid", clid).arg("client_servergroups", join(&groups));
            self.broadcast(&n, None);
            self.refresh_client(clid, by);
        }
        Ok(())
    }

    pub fn set_client_channel_group(&mut self, cgid: u64, cid: u64, dbid: u64, by: &Invoker) -> Result<(), E> {
        let g = self.st.channel_group(cgid).ok_or(err::INVALID_GROUP)?.clone();
        self.st.channel(cid).ok_or(err::INVALID_CHANNEL)?;
        let p = self.inv_perm_in(by, cid, "i_group_member_add_power");
        if !(p > 0 && p >= g.get("i_group_needed_member_add_power").unwrap_or(0)) {
            return Err(err::PERMISSIONS);
        }
        if !self.st.clients.iter().any(|c| c.dbid == dbid) {
            return Err(err::EMPTY_RESULT);
        }
        self.st.set_channel_group(dbid, cid, cgid);
        let _ = self.st.save();
        let online: Vec<u16> = self.clients().filter(|c| c.dbid == dbid && c.channel == cid).map(|c| c.clid).collect();
        for clid in online {
            self.refresh_client(clid, by);
        }
        Ok(())
    }

    // ------------------------------------------------------------------ privilege keys

    pub fn token_add(&mut self, kind: u8, group: u64, channel: u64, desc: &str, by: &Invoker) -> Result<String, E> {
        self.need(by, "b_virtualserver_token_add")?;
        let g = match kind {
            0 => self.st.server_group(group),
            1 => {
                self.st.channel(channel).ok_or(err::INVALID_CHANNEL)?;
                self.st.channel_group(group)
            }
            _ => return Err(err::INVALID_PARAM),
        }
        .ok_or(err::INVALID_GROUP)?
        .clone();
        let p = self.inv_perm(by, "i_group_member_add_power");
        if !(p > 0 && p >= g.get("i_group_needed_member_add_power").unwrap_or(0)) {
            return Err(err::PERMISSIONS);
        }
        let t = self.st.add_token(kind, group, channel, desc);
        let _ = self.st.save();
        Ok(t)
    }

    pub fn token_list(&self, by: &Invoker) -> Result<Items, E> {
        self.need(by, "b_virtualserver_token_list")?;
        Ok(self
            .st
            .tokens
            .iter()
            .map(|t| {
                kv(&[
                    ("token", t.token.clone()),
                    ("token_type", t.kind.to_string()),
                    ("token_id1", t.group.to_string()),
                    ("token_id2", t.channel.to_string()),
                    ("token_created", t.created.to_string()),
                    ("token_description", t.description.clone()),
                ])
            })
            .collect())
    }

    pub fn token_del(&mut self, token: &str, by: &Invoker) -> Result<(), E> {
        self.need(by, "b_virtualserver_token_delete")?;
        let before = self.st.tokens.len();
        self.st.tokens.retain(|t| t.token != token);
        if self.st.tokens.len() == before {
            return Err(err::INVALID_TOKEN);
        }
        let _ = self.st.save();
        Ok(())
    }

    pub fn token_use(&mut self, clid: u16, token: &str) -> Result<(), E> {
        let me = Invoker::Client(clid);
        self.need(&me, "b_virtualserver_token_use")?;
        let pos = self.st.tokens.iter().position(|t| t.token == token.trim()).ok_or(err::INVALID_TOKEN)?;
        let t = self.st.tokens.remove(pos);
        let dbid = self.client(clid).ok_or(err::INVALID_CLIENT)?.dbid;
        // The key itself is the authorization: apply as the server.
        let r = if t.kind == 0 {
            self.server_group_member(t.group, dbid, true, &Invoker::Server)
        } else {
            self.set_client_channel_group(t.group, t.channel, dbid, &Invoker::Server)
        };
        let _ = self.st.save();
        match r {
            Err(e) if e == err::DUPLICATE => Ok(()),
            r => r,
        }
    }

    // ------------------------------------------------------------------ bans

    pub fn ban_client(&mut self, target: u16, duration: u64, reason: &str, by: Invoker) -> Result<u64, E> {
        self.power_vs_client(&by, "i_client_ban_power", target, "i_client_needed_ban_power")?;
        let c = self.client(target).ok_or(err::INVALID_CLIENT)?.clone();
        let id = self.insert_ban(Ban {
            id: 0,
            uid: c.uid.clone(),
            ip: c.ip.clone(),
            name: c.nickname.clone(),
            reason: reason.into(),
            created: tsproto::unix_now(),
            duration,
            invoker: self.invoker_name(&by),
        });
        if let Some(addr) = self.addr_of(target) {
            self.disconnect_ex(addr, 6, reason, by, Some(duration));
        }
        Ok(id)
    }

    pub fn ban_add(&mut self, uid: &str, ip: &str, name: &str, duration: u64, reason: &str, by: Invoker) -> Result<u64, E> {
        if self.inv_perm(&by, "i_client_ban_power") <= 0 {
            return Err(err::PERMISSIONS);
        }
        if uid.is_empty() && ip.is_empty() {
            return Err(err::PARAM_MISSING);
        }
        let id = self.insert_ban(Ban {
            id: 0,
            uid: uid.into(),
            ip: ip.into(),
            name: name.into(),
            reason: reason.into(),
            created: tsproto::unix_now(),
            duration,
            invoker: self.invoker_name(&by),
        });
        // Kick matching clients that are online right now.
        let hits: Vec<u16> = self.clients().filter(|c| (!uid.is_empty() && c.uid == uid) || (!ip.is_empty() && c.ip == ip)).map(|c| c.clid).collect();
        for clid in hits {
            if let Some(addr) = self.addr_of(clid) {
                self.disconnect_ex(addr, 6, reason, by.clone(), Some(duration));
            }
        }
        Ok(id)
    }

    fn insert_ban(&mut self, mut ban: Ban) -> u64 {
        ban.id = self.st.next_ban_id;
        self.st.next_ban_id += 1;
        let id = ban.id;
        self.st.bans.push(ban);
        let _ = self.st.save();
        id
    }

    pub fn ban_list(&self, by: &Invoker) -> Result<Items, E> {
        self.need(by, "b_client_ban_list")?;
        let now = tsproto::unix_now();
        let items: Items = self
            .st
            .bans
            .iter()
            .filter(|b| b.active(now))
            .map(|b| {
                kv(&[
                    ("banid", b.id.to_string()),
                    ("ip", b.ip.clone()),
                    ("name", b.name.clone()),
                    ("uid", b.uid.clone()),
                    ("created", b.created.to_string()),
                    ("duration", b.duration.to_string()),
                    ("invokername", b.invoker.clone()),
                    ("reason", b.reason.clone()),
                    ("enforcements", "0".into()),
                    ("lastnickname", b.name.clone()),
                ])
            })
            .collect();
        if items.is_empty() {
            return Err(err::EMPTY_RESULT);
        }
        Ok(items)
    }

    pub fn ban_del(&mut self, id: u64, by: Invoker) -> Result<(), E> {
        self.need(&by, "b_client_ban_delete")?;
        let before = self.st.bans.len();
        self.st.bans.retain(|b| b.id != id);
        if self.st.bans.len() == before {
            return Err(err::EMPTY_RESULT);
        }
        let _ = self.st.save();
        Ok(())
    }
}
