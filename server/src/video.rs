//! Video relay for screen sharing and webcams (RustSpeak extension, not part of TS3).
//!
//! A client asks for a one-time token over its voice connection (`videotoken`) and
//! opens a WebSocket to the TCP port announced with it (by default the same number as
//! the UDP voice port). Text frames are JSON control messages; binary frames carry
//! encoded video chunks (WebCodecs, H.264 Annex B or VP8). Streams are only visible to
//! clients in the publisher's channel; leaving the channel ends the stream.
//!
//! Publisher -> server: `kind u8 | flags u8 (bit0 = keyframe) | timestamp u64 LE (µs) | data`
//! Server -> viewer:    `clid u16 LE | kind u8 | flags u8 | timestamp u64 LE | data`

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

/// What the relay needs to know about a connected voice client.
#[derive(Clone, PartialEq, Debug)]
pub struct Member {
    pub channel: u64,
    pub nickname: String,
    pub can_stream: bool,
    pub can_watch: bool,
}

/// (publisher clid, kind: 0 = screen, 1 = camera)
type StreamKey = (u16, u8);

struct Stream {
    channel: u64,
    codec: String,
    width: u32,
    height: u32,
    fps: u32,
    started: u64,
}

struct Conn {
    id: u64,
    tx: mpsc::Sender<Message>,
    watching: HashSet<StreamKey>,
    /// Streams this viewer waits for a keyframe on (after joining or dropping frames).
    need_key: HashSet<StreamKey>,
    last_list: String,
}

#[derive(Default)]
pub struct Hub {
    tokens: HashMap<String, (u16, Instant)>,
    members: HashMap<u16, Member>,
    conns: HashMap<u16, Conn>,
    streams: HashMap<StreamKey, Stream>,
    key_req: HashMap<StreamKey, Instant>,
}

pub type SharedHub = Arc<Mutex<Hub>>;

const TOKEN_TTL: Duration = Duration::from_secs(60);
const QUEUE: usize = 120;
const MAX_FRAME: usize = 4 << 20;

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

fn send_json(tx: &mpsc::Sender<Message>, v: Value) {
    let _ = tx.try_send(Message::Text(v.to_string().into()));
}

impl Hub {
    pub fn new_shared() -> SharedHub {
        Arc::new(Mutex::new(Hub::default()))
    }

    /// One-time token for `clid` to open the video WebSocket.
    pub fn add_token(&mut self, clid: u16) -> String {
        let now = Instant::now();
        self.tokens.retain(|_, (_, t)| now.duration_since(*t) < TOKEN_TTL);
        let token: String = (0..32).map(|_| format!("{:x}", rand::random::<u8>() & 15)).collect();
        self.tokens.insert(token.clone(), (clid, now));
        token
    }

    /// Update the voice-side view of the clients (channels, rights); called every tick.
    pub fn set_members(&mut self, members: HashMap<u16, Member>) {
        if members != self.members {
            self.members = members;
            self.reconcile();
        }
    }

    /// Drop everything that is no longer allowed and push changed stream lists.
    fn reconcile(&mut self) {
        // Streams end when the owner leaves, changes channel or loses the right.
        let dead: Vec<StreamKey> = self
            .streams
            .iter()
            .filter(|(k, s)| match self.members.get(&k.0) {
                Some(m) => m.channel != s.channel || !m.can_stream || !self.conns.contains_key(&k.0),
                None => true,
            })
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.streams.remove(&k);
            if let Some(c) = self.conns.get(&k.0) {
                send_json(&c.tx, json!({"t": "stopped", "kind": k.1}));
            }
        }
        // Connections of clients that left the server are closed.
        let gone: Vec<u16> = self.conns.keys().filter(|id| !self.members.contains_key(id)).copied().collect();
        for id in gone {
            if let Some(c) = self.conns.remove(&id) {
                let _ = c.tx.try_send(Message::Close(None));
            }
        }
        let lists: HashMap<u64, String> = {
            let mut chans: HashSet<u64> = HashSet::new();
            for id in self.conns.keys() {
                if let Some(m) = self.members.get(id) {
                    chans.insert(m.channel);
                }
            }
            chans.into_iter().map(|ch| (ch, self.list_for(ch).to_string())).collect()
        };
        for (id, c) in self.conns.iter_mut() {
            let Some(m) = self.members.get(id) else { continue };
            let streams = &self.streams;
            c.watching.retain(|k| m.can_watch && streams.get(k).is_some_and(|s| s.channel == m.channel));
            c.need_key.retain(|k| c.watching.contains(k));
            let list = &lists[&m.channel];
            if *list != c.last_list {
                c.last_list = list.clone();
                let msg = format!(
                    r#"{{"t":"streams","can_stream":{},"can_watch":{},"list":{}}}"#,
                    m.can_stream, m.can_watch, list
                );
                let _ = c.tx.try_send(Message::Text(msg.into()));
            }
        }
    }

    fn list_for(&self, channel: u64) -> Value {
        let mut v: Vec<(&StreamKey, &Stream)> = self.streams.iter().filter(|(_, s)| s.channel == channel).collect();
        v.sort_by_key(|(k, s)| (s.started, **k));
        Value::Array(
            v.into_iter()
                .map(|(k, s)| {
                    json!({
                        "clid": k.0,
                        "kind": k.1,
                        "name": self.members.get(&k.0).map(|m| m.nickname.as_str()).unwrap_or(""),
                        "codec": s.codec,
                        "width": s.width,
                        "height": s.height,
                        "fps": s.fps,
                        "started": s.started,
                    })
                })
                .collect(),
        )
    }

    /// Ask a publisher for a keyframe (rate limited).
    fn request_key(&mut self, key: StreamKey) {
        let now = Instant::now();
        if self.key_req.get(&key).is_some_and(|t| now.duration_since(*t) < Duration::from_millis(400)) {
            return;
        }
        self.key_req.insert(key, now);
        if let Some(c) = self.conns.get(&key.0) {
            send_json(&c.tx, json!({"t": "keyframe", "kind": key.1}));
        }
    }

    fn on_text(&mut self, clid: u16, v: &Value) {
        let Some(m) = self.members.get(&clid).cloned() else { return };
        let Some(tx) = self.conns.get(&clid).map(|c| c.tx.clone()) else { return };
        let kind = v["kind"].as_u64().unwrap_or(0).min(1) as u8;
        match v["t"].as_str().unwrap_or("") {
            "start" => {
                if !m.can_stream {
                    return send_json(&tx, json!({"t": "error", "kind": kind, "msg": "no_permission"}));
                }
                let codec: String = v["codec"].as_str().unwrap_or("").chars().take(64).collect();
                if codec.is_empty() {
                    return send_json(&tx, json!({"t": "error", "kind": kind, "msg": "invalid_codec"}));
                }
                let started = self.streams.get(&(clid, kind)).map(|s| s.started).unwrap_or_else(tsproto::unix_now);
                self.streams.insert(
                    (clid, kind),
                    Stream {
                        channel: m.channel,
                        codec,
                        width: v["width"].as_u64().unwrap_or(0).min(8192) as u32,
                        height: v["height"].as_u64().unwrap_or(0).min(8192) as u32,
                        fps: v["fps"].as_u64().unwrap_or(30).min(240) as u32,
                        started,
                    },
                );
                // Viewers need a fresh keyframe when the format changes.
                for c in self.conns.values_mut() {
                    if c.watching.contains(&(clid, kind)) {
                        c.need_key.insert((clid, kind));
                    }
                }
                info!("client {clid} started video stream kind {kind}");
                send_json(&tx, json!({"t": "started", "kind": kind}));
                self.reconcile();
            }
            "stop" => {
                if self.streams.remove(&(clid, kind)).is_some() {
                    info!("client {clid} stopped video stream kind {kind}");
                }
                send_json(&tx, json!({"t": "stopped", "kind": kind}));
                self.reconcile();
            }
            "watch" | "keyframe" => {
                let key = (v["clid"].as_u64().unwrap_or(0) as u16, kind);
                let ok = m.can_watch && self.streams.get(&key).is_some_and(|s| s.channel == m.channel);
                if !ok {
                    return send_json(&tx, json!({"t": "error", "clid": key.0, "kind": kind, "msg": "not_available"}));
                }
                let c = self.conns.get_mut(&clid).unwrap();
                c.watching.insert(key);
                c.need_key.insert(key);
                self.request_key(key);
            }
            "unwatch" => {
                let key = (v["clid"].as_u64().unwrap_or(0) as u16, kind);
                if let Some(c) = self.conns.get_mut(&clid) {
                    c.watching.remove(&key);
                    c.need_key.remove(&key);
                }
            }
            _ => {}
        }
    }

    fn on_frame(&mut self, clid: u16, data: &[u8]) {
        if data.len() < 10 {
            return;
        }
        let key = (clid, data[0].min(1));
        if !self.streams.contains_key(&key) {
            return;
        }
        let keyframe = data[1] & 1 != 0;
        let mut out = Vec::with_capacity(data.len() + 2);
        out.extend_from_slice(&clid.to_le_bytes());
        out.push(key.1);
        out.extend_from_slice(&data[1..]);
        let mut want_key = false;
        for c in self.conns.values_mut() {
            if !c.watching.contains(&key) {
                continue;
            }
            if c.need_key.contains(&key) {
                if !keyframe {
                    want_key = true;
                    continue;
                }
                c.need_key.remove(&key);
            }
            if c.tx.try_send(Message::Binary(out.clone().into())).is_err() {
                // Viewer is too slow: skip until the next keyframe.
                c.need_key.insert(key);
                want_key = true;
            }
        }
        if want_key {
            self.request_key(key);
        }
    }
}

pub async fn listen(port: u16, hub: SharedHub) -> Result<()> {
    let l = TcpListener::bind(("0.0.0.0", port)).await.context("binding video port")?;
    info!("video relay listening on tcp/0.0.0.0:{port} (WebSocket)");
    loop {
        let (sock, addr) = l.accept().await?;
        let hub = hub.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, hub).await {
                debug!("video {addr}: {e:#}");
            }
        });
    }
}

async fn handle(sock: TcpStream, hub: SharedHub) -> Result<()> {
    sock.set_nodelay(true)?;
    let cfg = WebSocketConfig { max_message_size: Some(MAX_FRAME), max_frame_size: Some(MAX_FRAME), ..Default::default() };
    let ws = tokio_tungstenite::accept_async_with_config(sock, Some(cfg)).await?;
    let (mut sink, mut stream) = ws.split();

    // First message: {"t":"auth","token":"…"}
    let first = tokio::time::timeout(Duration::from_secs(10), stream.next()).await.context("auth timeout")?;
    let Some(Ok(Message::Text(t))) = first else { anyhow::bail!("expected auth") };
    let v: Value = serde_json::from_str(&t)?;
    let token = v["token"].as_str().unwrap_or("");
    let (tx, mut rx) = mpsc::channel::<Message>(QUEUE);
    let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
    let clid = {
        let mut h = hub.lock().unwrap();
        let entry = h.tokens.remove(token).filter(|(_, t)| t.elapsed() < TOKEN_TTL);
        match entry.filter(|(c, _)| h.members.contains_key(c)) {
            Some((clid, _)) => {
                if let Some(old) = h.conns.remove(&clid) {
                    let _ = old.tx.try_send(Message::Close(None));
                }
                h.conns.insert(clid, Conn { id, tx: tx.clone(), watching: HashSet::new(), need_key: HashSet::new(), last_list: String::new() });
                send_json(&tx, json!({"t": "hello", "clid": clid}));
                h.reconcile();
                Some(clid)
            }
            None => None,
        }
    };
    let Some(clid) = clid else {
        sink.send(Message::Text(json!({"t": "error", "msg": "invalid_token"}).to_string().into())).await?;
        anyhow::bail!("invalid token");
    };
    info!("client {clid} opened the video relay");

    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let close = matches!(m, Message::Close(_));
            if sink.send(m).await.is_err() || close {
                break;
            }
        }
    });

    let mut alive = true;
    while alive {
        let msg = tokio::select! {
            m = stream.next() => m,
            _ = tx.closed() => None,
        };
        let Some(Ok(msg)) = msg else { break };
        let mut h = hub.lock().unwrap();
        if h.conns.get(&clid).map(|c| c.id) != Some(id) {
            break; // replaced by a newer connection
        }
        match msg {
            Message::Text(t) => {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    h.on_text(clid, &v);
                }
            }
            Message::Binary(b) => h.on_frame(clid, &b),
            Message::Close(_) => alive = false,
            _ => {}
        }
    }

    {
        let mut h = hub.lock().unwrap();
        if h.conns.get(&clid).map(|c| c.id) == Some(id) {
            h.conns.remove(&clid);
            h.streams.retain(|k, _| k.0 != clid);
            h.reconcile();
        }
    }
    drop(tx);
    writer.abort();
    info!("client {clid} closed the video relay");
    Ok(())
}
