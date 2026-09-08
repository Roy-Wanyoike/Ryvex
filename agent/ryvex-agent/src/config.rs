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

    /// Minimum seconds between spec.last_seen refreshes — the heartbeat
    /// spec-throttle. Between refreshes the agent re-sends the previous
    /// timestamp so the document stays identical and the control plane
    /// does not bump the generation or emit an "updated" event.
    #[arg(long, env = "RYVEX_AGENT_SPEC_REFRESH_SECS", default_value_t = 300)]
    pub spec_refresh_secs: u64,
}

impl Config {
    /// Parse from CLI + env, applying defaults and validation.
    pub fn load() -> Result<Self, String> {
        let mut cfg = Self::try_parse().map_err(|e| e.to_string())?;
        // Explicit --name / RYVEX_AGENT_NAME wins; otherwise detect the
        // machine hostname. A "localhost" fallback is refused instead of
        // colliding fleet-wide and CAS ping-ponging (issue #43).
        let explicit = cfg.name.as_deref().is_some_and(|n| !n.is_empty());
        if !explicit {
            cfg.name = Some(resolve_hostname()?);
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
    ///
    /// Every segment is percent-encoded (RFC 3986 unreserved set kept
    /// literal), so spaces, slashes and non-ASCII names cannot corrupt
    /// the path or smuggle extra segments.
    pub fn node_path(&self) -> String {
        format!(
            "/v1/{}/{}/{}/nodes/{}",
            encode_segment(&self.org),
            encode_segment(&self.project),
            encode_segment(&self.env),
            encode_segment(self.node_name()),
        )
    }
}

/// Detect a unique node name, refusing a useless fallback (issue #43).
///
/// Order: `HOSTNAME` env override (set by most shells/containers), then
/// the kernel hostname via /proc/sys/kernel/hostname — kept
/// dependency-free (no libc); every Linux the agent targets has it.
/// A literal "localhost" result is rejected: fleet-wide localhost names
/// collided and CAS ping-ponged. Non-Linux hosts without HOSTNAME must
/// pass `--name`.
fn resolve_hostname() -> Result<String, String> {
    let candidate = std::env::var("HOSTNAME")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(detect_kernel_hostname);
    match candidate {
        Some(h) if h != "localhost" => Ok(h),
        _ => Err(
            "could not determine a unique node name; pass --name (or env RYVEX_AGENT_NAME). \
             Refusing to fall back to \"localhost\": fleet-wide name collisions cause CAS ping-pong"
                .into(),
        ),
    }
}

/// Kernel hostname without a libc dependency.
fn detect_kernel_hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|h| !h.is_empty())
}

/// Percent-encode one path segment: keep RFC 3986 unreserved bytes
/// (ALPHA / DIGIT / "-" / "." / "_" / "~"), escape everything else,
/// including UTF-8 multibyte sequences. Manual encoder — zero deps.
fn encode_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for byte in seg.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}
