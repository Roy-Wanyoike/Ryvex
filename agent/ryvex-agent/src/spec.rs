//! Node resource spec building for the control plane. Pure JSON
//! shapes — golden-tested against the frozen API contract.

use serde_json::{json, Value};

/// Build the resource document the agent upserts for itself.
pub fn node_document(cfg: &crate::config::Config, agent_version: &str, last_seen: &str, generation: Option<i64>, status_message: Option<&str>) -> Value {
    let mut doc = json!({
        "kind": "Node",
        "org": cfg.org,
        "project": cfg.project,
        "env": cfg.env,
        "name": cfg.node_name(),
        "labels": {
            "managed-by": "ryvex-agent",
            "cluster": cfg.cluster,
        },
        "spec": {
            "cluster": cfg.cluster,
            "agent_version": agent_version,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "last_seen": last_seen,
        },
    });
    if let Some(g) = generation {
        doc["generation"] = json!(g);
    }
    if let Some(msg) = status_message {
        doc["spec"]["status_message"] = json!(msg);
    }
    doc
}

/// RFC3339 UTC timestamp for `last_seen`, from a unix epoch.
pub fn rfc3339(epoch_secs: u64) -> String {
    // Minimal RFC3339 UTC formatter (no chrono dependency).
    let days = epoch_secs / 86_400;
    let rem = epoch_secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's civil_from_days: days since 1970-01-01 -> y/m/d.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
