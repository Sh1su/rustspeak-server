//! TeamSpeak 3 compatible server, reimplemented in Rust.

mod admin;
mod bot;
mod perms;
mod query;
mod server;
mod state;
mod video;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::UdpSocket;
use tracing::info;

use server::{Config, Handshake, Server};

#[derive(Parser)]
#[command(version, about = "TeamSpeak 3 compatible voice server")]
struct Args {
    /// UDP voice port
    #[arg(long, default_value_t = 9987)]
    port: u16,
    /// TCP ServerQuery port (0 = disabled)
    #[arg(long, default_value_t = 10011)]
    query_port: u16,
    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
    /// Data file (channels, client database, keys)
    #[arg(long, default_value = "ts3server_state.json")]
    data: PathBuf,
    /// Minimum identity security level of connecting clients
    #[arg(long, default_value_t = 8)]
    security_level: u32,
    /// Difficulty of the init puzzle (number of modular squarings)
    #[arg(long, default_value_t = 1000)]
    puzzle_level: u32,
    /// Key exchange used for clients announcing the new protocol
    #[arg(long, value_enum, default_value_t = Handshake::Legacy)]
    handshake: Handshake,
    /// TCP port of the WebSocket video relay for screen sharing / webcams
    /// (default: same number as the voice port, 0 = disabled)
    #[arg(long)]
    video_port: Option<u16>,
    /// TCP port of the bot interface (0 = disabled)
    #[arg(long, default_value_t = 10013)]
    bot_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();

    let (mut st, created) = state::State::load_or_create(&args.data).context("loading server state")?;
    let has_admin = st.clients.iter().any(|c| c.server_groups.contains(&state::SG_ADMIN));
    let admin_token = st.tokens.iter().find(|t| t.kind == 0 && t.group == state::SG_ADMIN).map(|t| t.token.clone());
    let admin_token = match (has_admin, admin_token) {
        (true, _) => None,
        (false, Some(t)) => Some(t),
        (false, None) => {
            let t = st.add_token(0, state::SG_ADMIN, 0, "Initial Server Admin key");
            st.save()?;
            Some(t)
        }
    };
    if created {
        info!("------------------------------------------------------------------");
        info!("                      I M P O R T A N T");
        info!("Server Query Admin Account created");
        info!("     loginname= \"serveradmin\", password= \"{}\"", st.query_password);
        info!("------------------------------------------------------------------");
    }

    if let Some(token) = admin_token {
        info!("------------------------------------------------------------------");
        info!("      ServerAdmin privilege key created, please use it to gain");
        info!("      serveradmin rights for your virtualserver.");
        info!("      token={token}");
        info!("------------------------------------------------------------------");
    }

    let sock = UdpSocket::bind((args.bind.as_str(), args.port)).await.context("binding voice port")?;
    info!("voice server listening on udp/{}:{}", args.bind, args.port);
    let cfg = Config {
        port: args.port,
        min_security_level: args.security_level,
        puzzle_level: args.puzzle_level,
        handshake: args.handshake,
    };
    let mut srv = Server::new(sock, cfg, st)?;
    let video_port = args.video_port.unwrap_or(args.port);
    if video_port != 0 {
        let hub = video::Hub::new_shared();
        srv.video = Some((hub.clone(), video_port));
        tokio::spawn(async move {
            if let Err(e) = video::listen(video_port, hub).await {
                tracing::error!("video relay: {e:#}");
            }
        });
    }
    info!("server identity {}", srv.identity_uid());

    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let (bot_tx, bot_rx) = tokio::sync::mpsc::channel(256);
    if args.bot_port != 0 {
        let port = args.bot_port;
        tokio::spawn(async move {
            if let Err(e) = bot::listen(port, bot_tx).await {
                tracing::error!("bot interface: {e:#}");
            }
        });
    }
    if args.query_port != 0 {
        let port = args.query_port;
        tokio::spawn(async move {
            if let Err(e) = query::listen(port, tx).await {
                tracing::error!("ServerQuery: {e:#}");
            }
        });
    }
    tokio::select! {
        r = srv.run(rx, bot_rx) => r,
        _ = tokio::signal::ctrl_c() => { info!("shutting down"); Ok(()) }
    }
}
