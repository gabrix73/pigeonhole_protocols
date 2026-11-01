//! An ELIZA chatbot on the Katzenpost mixnet. katzenqt users talk to it by pasting one of its
//! vouchers into a new conversation.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use pigeonhole_protocols::services::{Config, Keypair, Service, eliza};
use pigeonhole_protocols::transport::thinclient::ThinClientBackend;

#[derive(Parser)]
struct Args {
    /// The client daemon: `@name` for an abstract unix socket, a socket path, or `host:port`.
    #[arg(long, default_value = "@katzenpost")]
    daemon: String,
    /// Holds the bot's key, its state and its vouchers.
    #[arg(long)]
    data_dir: PathBuf,
    /// How many unused vouchers to keep in data_dir/vouchers.
    #[arg(long, default_value_t = 3)]
    vouchers: usize,
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
    let backend = Arc::new(ThinClientBackend::dial(&args.daemon).await?);

    let mut cfg = Config::new(Keypair::load_or_generate(&*backend, &args.data_dir, "eliza").await?, args.data_dir.join("state"));
    cfg.display_name = "Eliza".into();
    cfg.advertise = !args.no_advertise;
    cfg.poll_interval = Duration::try_from_secs_f64(args.poll_interval).map_err(|e| format!("--poll_interval: {e}"))?;
    cfg.max_concurrent_sessions = args.max_sessions;
    let svc = Service::new(cfg, backend.clone())?;
    log::info!("service id {}", svc.id());

    let run = {
        let svc = svc.clone();
        tokio::spawn(async move { svc.run(eliza::chat).await })
    };
    let pool = tokio::spawn(eliza::keep_vouchers(svc.clone(), args.data_dir.join("vouchers"), args.vouchers));

    tokio::signal::ctrl_c().await?;
    log::info!("shutting down");
    pool.abort();
    svc.close().await;
    run.await??;
    backend.close().await;
    Ok(())
}
