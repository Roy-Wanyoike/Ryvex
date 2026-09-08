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

pub struct ApiClient {
    http: reqwest::Client,
    cfg: Config,
}

impl ApiClient {
    pub fn new(cfg: Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self { http, cfg })
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

    /// PUT the node document; classifies the response.
    async fn put_node(&self, doc: &Value) -> Outcome {
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
    /// CAS-aware with one bounded retry; self-heals on 404.
    pub async fn sync_node(&self, agent_version: &str, status_message: Option<&str>) -> Outcome {
        let now = spec::rfc3339(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        for attempt in 0..3 {
            let generation = match self.fetch_node().await {
                Ok(Some(v)) => Some(v["generation"].as_i64().unwrap_or(0)),
                Ok(None) => None,
                Err(e) => return Outcome::Transient(e),
            };
            let doc = spec::node_document(&self.cfg, agent_version, &now, generation, status_message);
            match self.put_node(&doc).await {
                Outcome::Conflict { fresh_generation } if attempt < 2 => {
                    tracing::debug!(fresh_generation, "CAS conflict, retrying once with fresh generation");
                    let doc = spec::node_document(
                        &self.cfg,
                        agent_version,
                        &now,
                        Some(fresh_generation),
                        status_message,
                    );
                    if let upserted @ Outcome::Upserted { .. } = self.put_node(&doc).await {
                        return upserted;
                    }
                    continue;
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
