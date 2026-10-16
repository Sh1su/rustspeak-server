//! Bot interface (RustSpeak extension): programs log in over TCP with a bot key and
//! appear on the server as normal clients. Other users see them in the channel tree,
//! can write them private or channel messages and poke them.
//!
//! The protocol is line based and uses the TS3 command syntax (same escaping as
//! ServerQuery). After `login` the bot receives exactly what a voice client gets
//! (`initserver`, `channellist`, `notifycliententerview`, `notifytextmessage`, …), one
//! command per line, and may send any client command (`sendtextmessage`, `clientmove`,
//! `clientupdate`, `clientpoke`, …). Every command is answered with an `error` line.
//!
//! ```text
//! <- RSBOT 1
//! -> login key=… client_nickname=EchoBot client_default_channel=/1
//! <- initserver … / channellist … / … / error id=0 msg=ok
//! <- notifytextmessage targetmode=1 msg=hallo invokerid=2 invokername=Alice …
//! -> sendtextmessage targetmode=1 target=2 msg=hallo\szurück
//! <- error id=0 msg=ok
//! ```

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};
use tsproto::Command;

pub enum BotRequest {
    Login { cmd: Command, tx: mpsc::UnboundedSender<String>, reply: oneshot::Sender<Result<SocketAddr, String>> },
    Command { addr: SocketAddr, cmd: Command },
    Logout { addr: SocketAddr },
}

const MAX_LINE: usize = 64 * 1024;

pub async fn listen(port: u16, server: mpsc::Sender<BotRequest>) -> Result<()> {
    let l = TcpListener::bind(("0.0.0.0", port)).await.context("binding bot port")?;
    info!("bot interface listening on tcp/0.0.0.0:{port}");
    loop {
        let (sock, peer) = l.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, server).await {
                debug!("bot {peer}: {e:#}");
            }
        });
    }
}

async fn handle(sock: TcpStream, server: mpsc::Sender<BotRequest>) -> Result<()> {
    sock.set_nodelay(true)?;
    let (rd, mut wr) = sock.into_split();
    let mut lines = BufReader::new(rd);
    wr.write_all(b"RSBOT 1\n").await?;

    // Login first
    let mut line = String::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let addr = loop {
        line.clear();
        let n = tokio::time::timeout(std::time::Duration::from_secs(30), lines.read_line(&mut line)).await.context("login timeout")??;
        if n == 0 {
            return Ok(());
        }
        let cmd = Command::parse(line.trim_end(), true);
        if cmd.name.is_empty() {
            continue;
        }
        if cmd.name != "login" {
            wr.write_all(b"error id=2568 msg=please\\slogin\\sfirst\n").await?;
            continue;
        }
        let (reply, wait) = oneshot::channel();
        server.send(BotRequest::Login { cmd, tx: tx.clone(), reply }).await?;
        match wait.await? {
            Ok(addr) => break addr,
            Err(e) => wr.write_all(format!("{e}\n").as_bytes()).await?,
        }
    };
    drop(tx);

    // Server -> bot: everything queued for this client
    let writer = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if wr.write_all(text.as_bytes()).await.is_err() || wr.write_all(b"\n").await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    // Bot -> server: commands
    loop {
        line.clear();
        let n = tokio::select! {
            r = lines.read_line(&mut line) => r.unwrap_or(0),
            _ = async { while !writer.is_finished() { tokio::time::sleep(std::time::Duration::from_millis(200)).await } } => 0,
        };
        if n == 0 || line.len() > MAX_LINE {
            break;
        }
        let cmd = Command::parse(line.trim_end(), true);
        if cmd.name.is_empty() {
            continue;
        }
        if cmd.name == "quit" || cmd.name == "logout" {
            break;
        }
        if server.send(BotRequest::Command { addr, cmd }).await.is_err() {
            break;
        }
    }
    let _ = server.send(BotRequest::Logout { addr }).await;
    writer.abort();
    Ok(())
}
