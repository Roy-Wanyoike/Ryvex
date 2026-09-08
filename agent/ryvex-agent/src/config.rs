//! Agent configuration: CLI flags with env fallbacks (clap) and
//! validation. Pure logic — fully unit-tested.

use clap::Parser;

/// Ryvex data-plane node agent.
#[derive(Parser, Debug, Clone)]
#[command(name = "ryvex-agent", version, about = "Ryvex node agent — enrollment, heartbeats, self-healing")]
pub struct Config {
    /// Control plane base URL.
    #[arg(long, env = "RYVEX_AGENT_API", default_value = "http://127.0.0.1:8080")]
    pub api: String,

    /// Bearer API key (ryk_...). Required.
    #[arg(long, env = "RYVEX_AGENT_TOKEN")]
    pub token: String,

    /// Heartbeat interval in seconds (clamped to >= 5).
    #[arg(long, env = "RYVEX_AGENT_INTERVAL", default_value_t = 10)]
    pub interval: u64,

    /// Node name (defaults to the machine hostname at parse time).
    #[arg(long, env = "RYVEX_AGENT_NAME")]
    pub name: Option<String>,

    /// Cluster the node belongs to.
    #[arg(long, env = "RYVEX_AGENT_CLUSTER", default_value = "unassigned")]
    pub cluster: String,

    /// Org scope for the node resource.
    #[arg(long, env = "RYVEX_AGENT_ORG", default_value = "acme")]
    pub org: String,

    /// Project scope for the node resource.
    #[arg(long, env = "RYVEX_AGENT_PROJECT", default_value = "core")]
    pub project: String,

    /// Env scope for the node resource.
    #[arg(long, env = "RYVEX_AGENT_ENV", default_value = "prod")]
    pub env: String,
}

impl Config {
    /// Parse from CLI + env, applying defaults and validation.
    pub fn load() -> Result<Self, String> {
        let mut cfg = Self::try_parse().map_err(|e| e.to_string())?;
        if cfg.name.is_none() || cfg.name.as_deref() == Some("") {
            cfg.name = Some(
                hostname().unwrap_or_else(|| "localhost".to_string()),
            );
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Enforce invariants; shared by load() and tests.
    pub fn validate(&mut self) -> Result<(), String> {
        if self.token.is_empty() {
            return Err("missing --token (env RYVEX_AGENT_TOKEN)".into());
        }
        if !self.token.starts_with("ryk_") {
            return Err("token must be a ryk_ API key".into());
        }
        if self.interval < 5 {
            tracing::warn!(
                requested = self.interval,
                "heartbeat interval below 5s, clamping to 5"
            );
            self.interval = 5;
        }
        while self.api.ends_with('/') {
            self.api.pop();
        }
        if self.api.is_empty() {
            return Err("--api must not be empty".into());
        }
        Ok(())
    }

    /// Effective node name.
    pub fn node_name(&self) -> &str {
        self.name.as_deref().unwrap_or("localhost")
    }

    /// Scope path segment: /v1/{org}/{project}/{env}/nodes/{name}.
    pub fn node_path(&self) -> String {
        format!(
            "/v1/{}/{}/{}/nodes/{}",
            self.org,
            self.project,
            self.env,
            self.node_name()
        )
    }
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}
