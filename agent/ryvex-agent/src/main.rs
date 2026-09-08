//! ryvex-agent — the Ryvex data-plane node agent.
//!
//! Enrolls its node resource with the control plane on start, then
//! heartbeats on a fixed interval with CAS-safe upserts. Self-heals
//! (re-creates the node when it vanishes), backs off exponentially on
//! transient failures, and marks itself "draining" on SIGINT/SIGTERM.

use ryvex_agent::config::Config;
use ryvex_agent::{backoff, client};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run());
    std::process::exit(code);
}

async fn run() -> i32 {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ryvex-agent: {e}");
            return 2;
        }
    };
    // Effective node name (issue #43): logged so operators can see
    // exactly which resource identity the agent will manage.
    tracing::info!(
        node = cfg.node_name(),
        api = %cfg.api,
        interval_secs = cfg.interval,
        spec_refresh_secs = cfg.spec_refresh_secs,
        "agent starting"
    );

    let agent = match client::ApiClient::new(cfg.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ryvex-agent: {e}");
            return 1;
        }
    };

    // ---- enrollment ----
    match agent.health().await {
        Ok((version, resources)) => {
            tracing::info!(%version, resources, "connected to control plane");
        }
        Err(e) => {
            tracing::warn!(%e, "control plane not reachable yet; will keep trying");
        }
    }

    let mut bo = backoff::Backoff::new();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM stream");
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).expect("SIGINT stream");

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(cfg.interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // First sync immediately (enrollment), then on every tick.
    loop {
        match agent.sync_node(AGENT_VERSION, None).await {
            client::Outcome::Upserted { generation } => {
                if bo.attempts() > 0 || generation <= 1 {
                    tracing::info!(generation, node = cfg.node_name(), "node synced with control plane");
                } else {
                    tracing::debug!(generation, "heartbeat ok");
                }
                bo.reset();
            }
            client::Outcome::Missing => {
                tracing::warn!("node resource vanished; re-creating on next tick");
            }
            client::Outcome::Rejected(reason) => {
                tracing::error!(%reason, "control plane rejected the node document");
            }
            client::Outcome::Transient(reason) => {
                let wait = bo.advance();
                tracing::warn!(%reason, wait_secs = wait.as_secs(), "transient failure; backing off");
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = sigterm.recv() => break,
                    _ = sigint.recv() => break,
                }
            }
            client::Outcome::Conflict { fresh_generation } => {
                // Defensive: sync_node resolves CAS conflicts internally
                // and must never leak this variant. Issue #43: this arm
                // used to be a reachable `unreachable!()` — under
                // sustained contention the final retry returned Conflict
                // and the agent panic-restart-looped. If a future
                // refactor leaks one anyway, degrade to the transient
                // path instead of crashing the node.
                tracing::error!(
                    fresh_generation,
                    "sync_node leaked a Conflict outcome (bug); treating as transient"
                );
                let wait = bo.advance();
                tracing::warn!(wait_secs = wait.as_secs(), "backing off after unexpected conflict");
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = sigterm.recv() => break,
                    _ = sigint.recv() => break,
                }
            }
        }

        tokio::select! {
            _ = ticker.tick() => {}
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }

    tracing::info!("signal received; draining");
    agent.mark_draining(AGENT_VERSION).await;
    tracing::info!("bye");
    0
}
