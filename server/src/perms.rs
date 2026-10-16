//! Permission system modelled on TeamSpeak 3: named permissions with integer
//! values, attached to server groups and channel groups.
//!
//! Effective value of a permission for a client in a channel: the channel
//! group's value if it sets the permission, otherwise the maximum over the
//! client's server groups. `b_*` permissions are granted when the value is > 0.
//! "Power" checks compare an invoker's `*_power` with the target's `*_needed_*_power`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub struct PermDef {
    pub name: &'static str,
    pub desc: &'static str,
    pub cat: &'static str,
}

macro_rules! perms {
    ($($cat:literal => { $($name:literal : $desc:literal),* $(,)? })*) => {
        pub const PERMS: &[PermDef] = &[ $($( PermDef { name: $name, desc: $desc, cat: $cat }, )*)* ];
    };
}

perms! {
    "Virtueller Server" => {
        "b_virtualserver_modify_name": "Servername ändern",
        "b_virtualserver_modify_welcomemessage": "Willkommensnachricht ändern",
        "b_virtualserver_modify_maxclients": "Maximale Clientanzahl ändern",
        "b_virtualserver_modify_password": "Serverpasswort ändern",
        "b_virtualserver_modify_hostbanner": "Server-Banner ändern",
        "b_icon_manage": "Icons hochladen und löschen",
        "b_virtualserver_servergroup_list": "Servergruppen anzeigen",
        "b_virtualserver_servergroup_permission_list": "Rechte von Servergruppen anzeigen",
        "b_virtualserver_servergroup_create": "Servergruppen erstellen",
        "b_virtualserver_servergroup_delete": "Servergruppen löschen",
        "b_virtualserver_channelgroup_create": "Channelgruppen erstellen",
        "b_virtualserver_channelgroup_delete": "Channelgruppen löschen",
        "b_virtualserver_token_add": "Berechtigungsschlüssel erstellen",
        "b_virtualserver_token_list": "Berechtigungsschlüssel anzeigen",
        "b_virtualserver_token_delete": "Berechtigungsschlüssel löschen",
        "b_virtualserver_token_use": "Berechtigungsschlüssel verwenden",
        "b_virtualserver_bot_manage": "Bot-Schlüssel verwalten",
    }
    "Channels" => {
        "b_channel_create_temporary": "Temporäre Channels erstellen",
        "b_channel_create_semi_permanent": "Semi-permanente Channels erstellen",
        "b_channel_create_permanent": "Permanente Channels erstellen",
        "b_channel_create_child": "Unterchannels erstellen",
        "b_channel_create_with_password": "Channels mit Passwort erstellen",
        "b_channel_modify_name": "Channelnamen ändern",
        "b_channel_modify_topic": "Channelthema ändern",
        "b_channel_modify_description": "Channelbeschreibung ändern",
        "b_channel_modify_password": "Channelpasswort ändern",
        "b_channel_modify_maxclients": "Channel-Clientlimit ändern",
        "b_channel_modify_codec_quality": "Codec-Qualität ändern",
        "b_channel_modify_needed_talk_power": "Benötigte Sprechkraft ändern",
        "b_channel_modify_needed_join_power": "Benötigte Beitrittskraft ändern",
        "b_channel_modify_make_permanent": "Channeltyp ändern",
        "b_channel_modify_make_default": "Standardchannel festlegen",
        "b_channel_modify_icon": "Channel-Icon ändern",
        "b_channel_delete_temporary": "Temporäre Channels löschen",
        "b_channel_delete_semi_permanent": "Semi-permanente Channels löschen",
        "b_channel_delete_permanent": "Permanente Channels löschen",
        "b_channel_delete_flag_force": "Nicht leere Channels löschen",
        "i_channel_join_power": "Channel-Beitrittskraft",
        "b_channel_join_ignore_password": "Channelpasswort ignorieren",
        "b_channel_join_ignore_maxclients": "Channel-Clientlimit ignorieren",
    }
    "Clients" => {
        "i_client_talk_power": "Sprechkraft",
        "i_client_move_power": "Clients verschieben (Kraft)",
        "i_client_needed_move_power": "Benötigte Kraft zum Verschieben",
        "i_client_kick_from_channel_power": "Aus Channel werfen (Kraft)",
        "i_client_needed_kick_from_channel_power": "Benötigte Kraft zum Channel-Kick",
        "i_client_kick_from_server_power": "Vom Server werfen (Kraft)",
        "i_client_needed_kick_from_server_power": "Benötigte Kraft zum Server-Kick",
        "i_client_ban_power": "Bannen (Kraft)",
        "i_client_needed_ban_power": "Benötigte Kraft zum Bannen",
        "i_client_poke_power": "Anstupsen (Kraft)",
        "i_client_needed_poke_power": "Benötigte Kraft zum Anstupsen",
        "i_client_private_textmessage_power": "Private Nachrichten (Kraft)",
        "i_client_needed_private_textmessage_power": "Benötigte Kraft für private Nachrichten",
        "b_client_server_textmessage_send": "Servernachrichten senden",
        "b_client_channel_textmessage_send": "Channelnachrichten senden",
        "b_client_ban_list": "Bannliste anzeigen",
        "b_client_ban_delete": "Banns aufheben",
        "b_client_remoteaddress_view": "IP-Adressen anderer Clients sehen",
        "b_client_video_stream": "Bildschirm oder Webcam im Channel übertragen",
        "b_client_video_watch": "Video-Übertragungen im Channel ansehen",
    }
    "Gruppen" => {
        "i_group_modify_power": "Gruppen bearbeiten (Kraft)",
        "i_group_needed_modify_power": "Benötigte Kraft zum Bearbeiten dieser Gruppe",
        "i_group_member_add_power": "Mitglieder hinzufügen (Kraft)",
        "i_group_needed_member_add_power": "Benötigte Kraft zum Hinzufügen zu dieser Gruppe",
        "i_group_member_remove_power": "Mitglieder entfernen (Kraft)",
        "i_group_needed_member_remove_power": "Benötigte Kraft zum Entfernen aus dieser Gruppe",
        "i_icon_id": "Gruppen-Icon (Icon-ID)",
        "i_group_show_name_in_tree": "Gruppenname im Baum anzeigen (0 = nein, 1 = davor, 2 = dahinter)",
    }
}

pub fn perm_id(name: &str) -> Option<usize> {
    PERMS.iter().position(|p| p.name == name).map(|i| i + 1)
}

pub fn perm_by_id(id: usize) -> Option<&'static PermDef> {
    PERMS.get(id.checked_sub(1)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: u64,
    pub name: String,
    /// 0 = template, 1 = regular, 2 = query (like TeamSpeak's `type`)
    #[serde(default = "one")]
    pub kind: u8,
    #[serde(default)]
    pub sort_id: u32,
    pub perms: BTreeMap<String, i32>,
}

fn one() -> u8 {
    1
}

impl Group {
    pub fn get(&self, p: &str) -> Option<i32> {
        self.perms.get(p).copied()
    }
}

fn group(id: u64, name: &str, sort_id: u32, perms: &[(&str, i32)]) -> Group {
    Group {
        id,
        name: name.into(),
        kind: 1,
        sort_id,
        perms: perms.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
    }
}

/// Built-in icon ids (rendered by the client, no upload needed).
pub const ICON_CROWN: i32 = 100;
pub const ICON_SHIELD: i32 = 200;
pub const ICON_FLAG: i32 = 707;

pub const SG_ADMIN: u64 = 6;
pub const SG_NORMAL: u64 = 7;
pub const SG_GUEST: u64 = 8;
pub const CG_ADMIN: u64 = 5;
pub const CG_OPERATOR: u64 = 6;
pub const CG_GUEST: u64 = 8;

/// Permissions everybody needs; also the base of the Guest group.
const GUEST: &[(&str, i32)] = &[
    ("b_virtualserver_servergroup_list", 1),
    ("b_virtualserver_token_use", 1),
    ("b_channel_create_temporary", 1),
    ("b_channel_create_child", 1),
    ("b_channel_create_with_password", 1),
    ("i_channel_join_power", 25),
    ("i_client_talk_power", 25),
    ("i_client_needed_move_power", 25),
    ("i_client_needed_kick_from_channel_power", 25),
    ("i_client_needed_kick_from_server_power", 25),
    ("i_client_needed_ban_power", 25),
    ("i_client_poke_power", 25),
    ("i_client_needed_poke_power", 25),
    ("i_client_private_textmessage_power", 25),
    ("i_client_needed_private_textmessage_power", 25),
    ("b_client_server_textmessage_send", 1),
    ("b_client_channel_textmessage_send", 1),
    ("b_client_video_stream", 1),
    ("b_client_video_watch", 1),
    ("i_group_needed_modify_power", 75),
    ("i_group_needed_member_add_power", 75),
    ("i_group_needed_member_remove_power", 75),
];

pub fn default_server_groups() -> Vec<Group> {
    let mut admin: Vec<(&str, i32)> = PERMS
        .iter()
        .map(|p| (p.name, if p.name.starts_with("b_") { 1 } else { 75 }))
        .collect();
    for (k, v) in admin.iter_mut() {
        match *k {
            "i_client_talk_power" | "i_channel_join_power" => *v = 75,
            "i_client_needed_move_power" | "i_client_needed_kick_from_channel_power" | "i_client_needed_kick_from_server_power"
            | "i_client_needed_ban_power" | "i_client_needed_poke_power" | "i_client_needed_private_textmessage_power" => *v = 75,
            "i_group_modify_power" | "i_group_member_add_power" | "i_group_member_remove_power" => *v = 75,
            "i_group_needed_modify_power" | "i_group_needed_member_add_power" | "i_group_needed_member_remove_power" => *v = 75,
            "i_icon_id" => *v = ICON_CROWN,
            "i_group_show_name_in_tree" => *v = 0,
            _ => {}
        }
    }
    let mut normal: Vec<(&str, i32)> = GUEST.to_vec();
    normal.extend_from_slice(&[("b_channel_create_semi_permanent", 1), ("b_channel_create_permanent", 1), ("i_group_needed_modify_power", 75)]);
    vec![group(SG_ADMIN, "Server Admin", 100, &admin), group(SG_NORMAL, "Normal", 200, &normal), group(SG_GUEST, "Guest", 300, GUEST)]
}

pub fn default_channel_groups() -> Vec<Group> {
    let admin = [
        ("b_channel_modify_name", 1),
        ("b_channel_modify_topic", 1),
        ("b_channel_modify_description", 1),
        ("b_channel_modify_password", 1),
        ("b_channel_modify_maxclients", 1),
        ("b_channel_modify_codec_quality", 1),
        ("b_channel_modify_needed_talk_power", 1),
        ("b_channel_modify_needed_join_power", 1),
        ("b_channel_modify_icon", 1),
        ("i_icon_id", ICON_SHIELD),
        ("b_channel_delete_temporary", 1),
        ("b_channel_delete_semi_permanent", 1),
        ("b_channel_delete_flag_force", 1),
        ("b_channel_create_child", 1),
        ("i_client_move_power", 50),
        ("i_client_kick_from_channel_power", 50),
        ("i_client_talk_power", 50),
        ("i_group_member_add_power", 50),
        ("i_group_member_remove_power", 50),
        ("i_group_needed_modify_power", 75),
        ("i_group_needed_member_add_power", 50),
        ("i_group_needed_member_remove_power", 50),
    ];
    let operator = [
        ("i_icon_id", ICON_FLAG),
        ("b_channel_modify_topic", 1),
        ("b_channel_modify_description", 1),
        ("i_client_move_power", 35),
        ("i_client_kick_from_channel_power", 35),
        ("i_client_talk_power", 35),
        ("i_group_needed_modify_power", 75),
        ("i_group_needed_member_add_power", 50),
        ("i_group_needed_member_remove_power", 50),
    ];
    let guest = [("i_group_needed_modify_power", 75), ("i_group_needed_member_add_power", 50), ("i_group_needed_member_remove_power", 50)];
    vec![group(CG_ADMIN, "Channel Admin", 100, &admin), group(CG_OPERATOR, "Operator", 200, &operator), group(CG_GUEST, "Guest", 300, &guest)]
}

/// Effective permission value from the client's server groups and channel group.
pub fn effective(server_groups: &[&Group], channel_group: Option<&Group>, perm: &str) -> i32 {
    if let Some(v) = channel_group.and_then(|g| g.get(perm)) {
        // Channel group values add rights on top of the server groups (never reduce them).
        return v.max(server_groups.iter().filter_map(|g| g.get(perm)).max().unwrap_or(0));
    }
    server_groups.iter().filter_map(|g| g.get(perm)).max().unwrap_or(0)
}
