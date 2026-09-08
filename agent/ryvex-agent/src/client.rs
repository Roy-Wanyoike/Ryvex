//! Control-plane API client: enrollment, heartbeats, self-healing.
//! All control flow returns an [`Outcome`] so the state machine is
//! testable against a mock server.

use crate::config::Config;
use crate::spec;
use serde_json::Value;
use std::time::Duration;

/// What a control-plane exchange decided.
#[derive(Debug, PartialEq, Clone)]
pub enum Outcome {
    /// Resource stored (created or updated).
    Upserted { generation: i64 },
    /// Stale CAS generation: retry with the fresh generation.
    Conflict { fresh_generation: i64 },
    /// Node vanished: re-create it.
    Missing,
    /// Transient failure: back off and retry.
    Transient(String),
    /// Permanent rejection: log loudly and skip this cycle.
    Rejected(String),
}

/// Throttle state for the heartbeat spec-refresh window. See
/// [`next_last_seen`] for the decision and the rationale.
#[derive(Default)]
struct SyncState {
    /// `spec.last_seen` value carried by the most recent document.
    last_seen: Option<String>,
    /// When that value was refreshed (drives the throttle window).
    last_refresh: Option<std::time::Instant>,
}

impl SyncState {
    /// Apply the throttle decision for this cycle and persist it.
    /// Sync-only: callers must drop the guard before awaiting.
    fn refresh(&mut self, now: &str, refresh_secs: u64) -> String {
        let since = self.last_refresh.map(|t| t.elapsed());
        let (last_seen, refreshed) =
            next_last_seen(self.last_seen.as_deref(), since, refresh_secs, now);
        if refreshed {
            self.last_refresh = Some(std::time::Instant::now());
        }
        self.last_seen = Some(last_seen.clone());
        last_seen
    }
}

/// Heartbeat spec-throttle decision (pure, unit-tested).
///
/// Returns the `spec.last_seen` the next document should carry, plus
/// whether the value changed (and the throttle window reset). Refreshes
/// when there is no previous value or when `since_refresh` has reached
/// `refresh_secs`; otherwise the previous timestamp is re-sent.
///
/// Rationale (issue #43): `last_seen` used to change on every tick, so
/// every heartbeat was a spec change that bumped the resource
/// generation — an "updated" event storm flooding the replay ring and
/// audit log, and a permanent CAS race against human edits. The
/// control plane treats an upsert whose spec equals the stored one as
/// a no-op (`internal/api/handlers.go` handleScopePut →
/// `internal/state/store.go` UpdateResource: `specLabelsEqual` →
/// generation NOT advanced, no event), so re-sending an identical
/// spec between refreshes is free.
pub fn next_last_seen(
    prev: Option<&str>,
    since_refresh: Option<Duration>,
    refresh_secs: u64,
    now: &str,
) -> (String, bool) {
    let refresh = prev.is_none()
        || match since_refresh {
            Some(elapsed) => elapsed >= Duration::from_secs(refresh_secs),
            None => true,
        };
    if refresh {
        (now.to_string(), true)
    } else {
        (prev.unwrap_or(now).to_string(), false)
    }
}

pub struct ApiClient {
    http: reqwest::Client,
    cfg: Config,
    /// Heartbeat throttle state; guard never held across an await.
    sync: std::sync::Mutex<SyncState>,
}

impl ApiClient {
    pub fn new(cfg: Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            http,
            cfg,
            sync: std::sync::Mutex::new(SyncState::default()),
        })
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{path}", self.cfg.api))
            .bearer_auth(&self.cfg.token)
    }

    fn put(&self, path: &str, body: &Value) -> reqwest::RequestBuilder {
        self.http
            .put(format!("{}{path}", self.cfg.api))
            .bearer_auth(&self.cfg.token)
            .json(body)
    }

    /// GET /healthz — returns (version, resources) on success.
    pub async fn health(&self) -> Result<(String, i64), String> {
        let v: Value = self
            .get("/healthz")
            .send()
            .await
            .map_err(|e| format!("health: {e}"))?
            .error_for_status()
            .map_err(|e| format!("health: {e}"))?
            .json()
            .await
            .map_err(|e| format!("health: {e}"))?;
        Ok((
            v["version"].as_str().unwrap_or("unknown").to_string(),
            v["resources"].as_i64().unwrap_or(0),
        ))
    }

    /// GET the agent's own node resource; None when absent.
    async fn fetch_node(&self) -> Result<Option<Value>, String> {
        let resp = self
            .get(&self.cfg.node_path())
            .send()
            .await
            .map_err(|e| format!("get node: {e}"))?;
        match resp.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => {
                Ok(Some(resp.json().await.map_err(|e| format!("node json: {e}"))?))
            }
            s => Err(format!("get node: http {s}")),
        }
    }

    /// PUT the node document; classifies the response. Public so the
    /// mock-server integration suite can drive single transitions.
    pub async fn put_node(&self, doc: &Value) -> Outcome {
        let resp = match self.put(&self.cfg.node_path(), doc).send().await {
            Ok(r) => r,
            Err(e) => return Outcome::Transient(format!("put node: {e}")),
        };
        match resp.status() {
            s if s.is_success() => match resp.json::<Value>().await {
                Ok(v) => Outcome::Upserted {
                    generation: v["generation"].as_i64().unwrap_or(0),
                },
                Err(e) => Outcome::Transient(format!("put response: {e}")),
            },
            reqwest::StatusCode::CONFLICT => {
                // Stale generation: fetch the fresh one and signal retry.
                match self.fetch_node().await {
                    Ok(Some(v)) => Outcome::Conflict {
                        fresh_generation: v["generation"].as_i64().unwrap_or(0),
                    },
                    Ok(None) => Outcome::Missing,
                    Err(e) => Outcome::Transient(e),
                }
            }
            reqwest::StatusCode::NOT_FOUND => Outcome::Missing,
            s => Outcome::Rejected(format!("http {s}")),
        }
    }

    /// Enroll or heartbeat the node (same upsert, different messaging).
    /// CAS-aware with a bounded 3-attempt retry; self-heals on 404.
    /// Never leaks [`Outcome::Conflict`] to the caller: a conflict on
    /// the final attempt degrades to `Transient("gave up after CAS
    /// retries")` (issue #43 — run() used to panic on that arm).
    pub async fn sync_node(&self, agent_version: &str, status_message: Option<&str>) -> Outcome {
        let now = spec::rfc3339(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        // Heartbeat spec-throttle (issue #43): pick the spec.last_seen
        // this cycle carries. The guard is dropped at the end of this
        // block — never held across an await below.
        let last_seen = {
            let mut state = self
                .sync
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.refresh(&now, self.cfg.spec_refresh_secs)
        };
        for attempt in 0..3 {
            let generation = match self.fetch_node().await {
                Ok(Some(v)) => Some(v["generation"].as_i64().unwrap_or(0)),
                Ok(None) => None,
                Err(e) => return Outcome::Transient(e),
            };
            let doc = spec::node_document(&self.cfg, agent_version, &last_seen, generation, status_message);
            match self.put_node(&doc).await {
                Outcome::Conflict { fresh_generation } if attempt < 2 => {
                    tracing::debug!(fresh_generation, "CAS conflict, retrying with fresh generation");
                    let doc = spec::node_document(
                        &self.cfg,
                        agent_version,
                        &last_seen,
                        Some(fresh_generation),
                        status_message,
                    );
                    if let upserted @ Outcome::Upserted { .. } = self.put_node(&doc).await {
                        return upserted;
                    }
                    continue;
                }
                // Final attempt: surface as Transient instead of leaking
                // Conflict to run() (used to be a reachable
                // unreachable!() panic there — issue #43).
                Outcome::Conflict { fresh_generation } => {
                    tracing::error!(
                        fresh_generation,
                        "CAS conflict on final retry; giving up until next tick"
                    );
                    return Outcome::Transient("gave up after CAS retries".into());
                }
                outcome => return outcome,
            }
        }
        Outcome::Transient("gave up after CAS retries".into())
    }

    /// Best-effort draining marker; single attempt, result ignored.
    pub async fn mark_draining(&self, agent_version: &str) {
        let _ = self.sync_node(agent_version, Some("draining")).await;
    }
}
