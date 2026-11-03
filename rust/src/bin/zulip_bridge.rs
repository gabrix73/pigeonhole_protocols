//! Bridges one katzenqt1 group with one Zulip stream. katzenqt and hushphone users join the group
//! by contacting the bot through the service directory and sending it their join code.

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
    /// How often a pending read is retried, in seconds.
    #[arg(long, default_value_t = 5.0)]
    poll_interval: f64,
    /// Bounds the conversations served at once.
    #[arg(long, default_value_t = 64)]
    max_sessions: usize,
    /// Don't advertise in the service directory.
    #[arg(long)]
    no_advertise: bool,
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
    cfg.max_concurrent_sessions = args.max_sessions;
    let svc = Service::new(cfg, backend.clone())?;
    log::info!("service id {}", svc.id());

    let bridge = Arc::new(Bridge {
        client: client.clone(),
        chat,
        zulip,
        stream: args.stream,
        topic: args.topic,
        data_dir: args.data_dir.clone(),
    });
    let run = {
        let (svc, b) = (svc.clone(), bridge.clone());
        tokio::spawn(async move { svc.run(move |s| { let b = b.clone(); async move { b.join(s).await } }).await })
    };
    let to = { let b = bridge.clone(); tokio::spawn(async move { b.to_zulip().await }) };
    let from = { let b = bridge.clone(); tokio::spawn(async move { b.from_zulip().await }) };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => log::info!("shutting down"),
        r = to => log::error!("the group side stopped: {r:?}"),
        r = from => log::error!("the zulip side stopped: {r:?}"),
    }
    svc.close().await;
    run.abort();
    client.close().await;
    backend.close().await;
    Ok(())
}
