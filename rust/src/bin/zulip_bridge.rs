//! Bridges one katzenqt1 group with one Zulip stream. katzenqt and hushphone users join the group
//! by routing the join code their app shows to it, with `pigeonhole-voucher send`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use pigeonhole_protocols::protocols::katzenqt1::client::{self, Client};
use pigeonhole_protocols::services::zulip::{Bridge, Zulip, open_group};
use pigeonhole_protocols::pigeonservice::{Config, Keypair, Service};
use pigeonhole_protocols::transport::thinclient::ThinClientBackend;

#[derive(Parser)]
struct Args {
    /// The client daemon: `@name` for an abstract unix socket, a socket path, or `host:port`.
    #[arg(long, default_value = "@katzenpost")]
    daemon: String,
    /// Holds the bot's key, its state and its group.
    #[arg(long)]
    data_dir: PathBuf,
    /// A zuliprc file with the bot's `email`, `key` and `site`.
    #[arg(long)]
    zuliprc: PathBuf,
    /// The Zulip stream bridged.
    #[arg(long)]
    stream: String,
    /// The topic in the stream.
    #[arg(long, default_value = "pigeonhole")]
    topic: String,
    /// The group's name; the stream's by default.
    #[arg(long)]
    group: Option<String>,
    /// The bot's name in the group and to those who contact it.
    #[arg(long, default_value = "zulip")]
    name: String,
    /// Stop reading a member who writes nothing for this many days; they rejoin through the bot.
    #[arg(long, default_value_t = 14.0)]
    idle_days: f64,
    /// How often a pending read is retried, in seconds.
    #[arg(long, default_value_t = 5.0)]
    poll_interval: f64,
    /// Don't advertise in the service directory.
    #[arg(long)]
    no_advertise: bool,
    /// The katzenqt1 wire version written and minted: 3 for clients that read only maps, 4 for
    /// those that read only version 4, 5 packs messages.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(3..=5))]
    wire_version: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let zulip = Zulip::from_zuliprc(&args.zuliprc)?;
    zulip.subscribe(&args.stream).await?;
    let backend = Arc::new(ThinClientBackend::dial(&args.daemon).await?);

    let client = Arc::new(
        Client::open(
            client::Config {
                state_dir: args.data_dir.join("group"),
                name: args.name.clone(),
                epoch_poll: Duration::from_secs(60),
                no_sync: false,
                key: None,
                wire_version: args.wire_version,
            },
            backend.clone(),
        )
        .await?,
    );
    let chat = open_group(&client, args.group.as_deref().unwrap_or(&args.stream)).await?;

    let mut cfg = Config::new(Keypair::load_or_generate(&*backend, &args.data_dir, "zulip").await?, args.data_dir.join("state"));
    cfg.display_name = args.name;
    cfg.advertise = !args.no_advertise;
    cfg.poll_interval = Duration::try_from_secs_f64(args.poll_interval).map_err(|e| format!("--poll_interval: {e}"))?;
    let svc = Service::new(cfg, backend.clone())?;
    log::info!("service id {}", svc.id());

    let bridge = Arc::new(Bridge {
        client: client.clone(),
        chat,
        zulip,
        stream: args.stream,
        topic: args.topic,
        data_dir: args.data_dir.clone(),
        idle: Duration::try_from_secs_f64(args.idle_days * 86400.0).map_err(|e| format!("--idle-days: {e}"))?,
    });
    let run = {
        let (svc, b) = (svc.clone(), bridge.clone());
        tokio::spawn(async move { b.admit(&svc).await })
    };
    let to = { let b = bridge.clone(); tokio::spawn(async move { b.to_zulip().await }) };
    let from = { let b = bridge.clone(); tokio::spawn(async move { b.from_zulip().await }) };
    let expire = { let b = bridge.clone(); tokio::spawn(async move { b.expire().await }) };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => log::info!("shutting down"),
        r = to => log::error!("the group side stopped: {r:?}"),
        r = from => log::error!("the zulip side stopped: {r:?}"),
        r = expire => log::error!("the idle sweep stopped: {r:?}"),
    }
    svc.close().await;
    run.abort();
    client.close().await;
    backend.close().await;
    Ok(())
}
