//! A status bot for the mixnet its client daemon is on: each epoch it tells every conversation
//! it is in what changed in the PKI document, which pigeonhole services the directory lists and
//! whether each answers, and how many routers it is linked with. It is reached only through
//! the service directory and a voucher router. Anything that is not `status` gets an ELIZA
//! answer, for the fun of it. With `--group` and `--bridge` it also joins a katzenqt1 group
//! through the bot that invites into it, and says each report there.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use pigeonhole_protocols::pigeonservice::wire::ServiceId;
use pigeonhole_protocols::pigeonservice::{Config, Keypair, Service};
use pigeonhole_protocols::protocols::katzenqt1::client::{self, Client};
use pigeonhole_protocols::services::status::{Bot, PROBE_LIMIT, join_group};
use pigeonhole_protocols::transport::thinclient::ThinClientBackend;

#[derive(Parser)]
struct Args {
    /// The client daemon: `@name` for an abstract unix socket, a socket path, or `host:port`.
    #[arg(long, default_value = "@katzenpost")]
    daemon: String,
    /// Holds the bot's key and its state.
    #[arg(long)]
    data_dir: PathBuf,
    /// How often a pending read is retried, in seconds.
    #[arg(long, default_value_t = 5.0)]
    poll_interval: f64,
    /// Bounds the conversations served at once.
    #[arg(long, default_value_t = 64)]
    max_sessions: usize,
    /// How often the PKI document is looked at for a new epoch, in seconds.
    #[arg(long, default_value_t = 60.0)]
    check_interval: f64,
    /// Probe the directory's services each epoch only when there are at most this many.
    #[arg(long, default_value_t = PROBE_LIMIT)]
    probe_limit: usize,
    /// Don't advertise in the service directory.
    #[arg(long)]
    no_advertise: bool,
    /// The katzenqt1 wire version written and minted: 3 for clients that read only maps, 4 for
    /// those that read only version 4, 5 packs messages.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(3..=5))]
    wire_version: u64,
    /// A katzenqt1 group to join and say each report in.
    #[arg(long, requires = "bridge")]
    group: Option<String>,
    /// The service id of the bot that invites into `--group`, such as a zulip-bridge.
    #[arg(long, requires = "group")]
    bridge: Option<ServiceId>,
    /// The bot's name in the group.
    #[arg(long, default_value = "status")]
    name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let backend = Arc::new(ThinClientBackend::dial(&args.daemon).await?);

    let mut cfg = Config::new(
        Keypair::load_or_generate(&*backend, &args.data_dir, "status").await?,
        args.data_dir.join("state"),
    );
    cfg.display_name = "Status".into();
    cfg.advertise = !args.no_advertise;
    cfg.poll_interval = Duration::try_from_secs_f64(args.poll_interval)
        .map_err(|e| format!("--poll_interval: {e}"))?;
    cfg.max_concurrent_sessions = args.max_sessions;
    let svc = Service::new(cfg, backend.clone())?;
    log::info!("service id {}", svc.id());
    let bot = Bot::new(svc.clone(), args.probe_limit, args.wire_version);
    let group = match (args.group, args.bridge) {
        (Some(name), Some(bridge)) => {
            let client = Arc::new(
                Client::open(
                    client::Config {
                        state_dir: args.data_dir.join("group"),
                        name: args.name,
                        epoch_poll: Duration::from_secs(60),
                        no_sync: false,
                        key: None,
                        wire_version: args.wire_version,
                    },
                    backend.clone(),
                )
                .await?,
            );
            let mut reports = bot.listen();
            let (c, ph, poll) = (
                client.clone(),
                backend.clone(),
                Duration::from_secs_f64(args.poll_interval),
            );
            tokio::spawn(async move {
                let chat = match join_group(&c, ph, &name, bridge, poll).await {
                    Ok(chat) => chat,
                    Err(e) => return log::error!("joining {name}: {e}"),
                };
                log::info!("in the group {name}");
                while let Some(r) = reports.recv().await {
                    if let Err(e) = c.send(&chat, &r).await {
                        log::warn!("saying the report in {name}: {e}");
                    }
                }
            });
            Some(client)
        }
        _ => None,
    };

    let run = {
        let bot = bot.clone();
        let svc = svc.clone();
        tokio::spawn(async move { svc.run(move |s| bot.clone().chat(s)).await })
    };
    let client = backend.client.clone();
    let every = Duration::try_from_secs_f64(args.check_interval)
        .map_err(|e| format!("--check_interval: {e}"))?;
    let watch = tokio::spawn(bot.clone().watch(
        move || {
            let client = client.clone();
            async move { client.pki_document().await.ok() }
        },
        every,
    ));

    tokio::signal::ctrl_c().await?;
    log::info!("shutting down");
    watch.abort();
    svc.close().await;
    run.await??;
    if let Some(c) = group {
        c.close().await;
    }
    backend.close().await;
    Ok(())
}
