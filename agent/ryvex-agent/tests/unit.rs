use ryvex_agent::backoff::Backoff;
use ryvex_agent::config::Config;
use ryvex_agent::spec;

use clap::Parser as _;
use serde_json::json;

// ---- config ----

fn cfg(args: &[&str]) -> Result<Config, String> {
    Config::try_parse_from(std::iter::once("ryvex-agent").chain(args.iter().copied()))
        .map_err(|e| e.to_string())
}

#[test]
fn token_required() {
    let err = cfg(&["--api", "http://x"]).unwrap_err();
    assert!(err.contains("token"), "err: {err}");
}

#[test]
fn token_namespace_enforced() {
    // validate() (not clap) enforces the ryk_ namespace.
    let mut c = cfg(&["--token", "sk_bad", "--api", "http://x"]).unwrap();
    let err = c.validate().unwrap_err();
    assert!(err.contains("ryk_"), "err: {err}");
}

#[test]
fn interval_clamped_to_minimum() {
    let mut c = cfg(&["--token", "ryk_x", "--interval", "1"]).unwrap();
    c.validate().unwrap();
    assert_eq!(c.interval, 5);
    let mut c2 = cfg(&["--token", "ryk_x", "--interval", "30"]).unwrap();
    c2.validate().unwrap();
    assert_eq!(c2.interval, 30);
}

#[test]
fn api_trailing_slash_trimmed() {
    let mut c = cfg(&["--token", "ryk_x", "--api", "http://x.test/"]).unwrap();
    c.validate().unwrap();
    assert_eq!(c.api, "http://x.test");
}

#[test]
fn node_path_scope_addressing() {
    let mut c = cfg(&["--token", "ryk_x", "--org", "acme", "--project", "core", "--env", "prod", "--name", "n1"])
        .unwrap();
    c.validate().unwrap();
    assert_eq!(c.node_path(), "/v1/acme/core/prod/nodes/n1");
}

#[test]
fn node_path_percent_encodes_space_in_name() {
    let mut c = cfg(&["--token", "ryk_x", "--name", "node 01 eu"]).unwrap();
    c.validate().unwrap();
    // space (0x20) is outside the RFC 3986 unreserved set -> %20
    assert_eq!(c.node_path(), "/v1/acme/core/prod/nodes/node%2001%20eu");
}

#[test]
fn node_path_escapes_slashes_to_single_segment() {
    let mut c = cfg(&["--token", "ryk_x", "--org", "ac/me", "--name", "../admin"]).unwrap();
    c.validate().unwrap();
    // '/' -> %2F: a hostile name cannot add or traverse path segments
    assert_eq!(c.node_path(), "/v1/ac%2Fme/core/prod/nodes/..%2Fadmin");
}

// ---- backoff ----

#[test]
fn backoff_doubles_then_caps_with_symmetric_jitter() {
    let mut b = Backoff::new();
    let mut waits = Vec::new();
    for _ in 0..8 {
        waits.push(b.advance().as_secs());
    }
    // Symmetric ±20% jitter (issue #43) on the doubling sequence
    // 1,2,4,8,16,30(cap),30,30, floored at 1s and truncated to whole
    // seconds: expected ranges [1,1] [1,2] [3,4] [6,9] [12,19] [24,35].
    assert_eq!(waits[0], 1, "w0={}", waits[0]);
    assert!(waits[1] >= 1 && waits[1] <= 2, "w1={}", waits[1]);
    assert!(waits[2] >= 3 && waits[2] <= 4, "w2={}", waits[2]);
    assert!(waits[3] >= 6 && waits[3] <= 9, "w3={}", waits[3]);
    assert!(waits[4] >= 12 && waits[4] <= 19, "w4={}", waits[4]);
    assert!(waits[5] >= 24 && waits[5] <= 35, "w5={}", waits[5]);
    // at the cap the jitter is symmetric around 30s: [24, 36)
    assert!(waits[6] >= 24 && waits[6] <= 35, "w6={}", waits[6]);
    assert!(waits[7] >= 24 && waits[7] <= 35, "w7={}", waits[7]);
    b.reset();
    assert_eq!(b.attempts(), 0);
}

// ---- spec ----

#[test]
fn node_document_matches_golden_contract() {
    let mut c = cfg(&[
        "--token", "ryk_x",
        "--org", "acme",
        "--project", "core",
        "--env", "prod",
        "--name", "smoke-node",
        "--cluster", "prod-eu1",
    ])
    .unwrap();
    c.validate().unwrap();
    let doc = spec::node_document(&c, "1.0.0", "2026-09-08T10:00:00Z", Some(3), Some("draining"));
    assert_eq!(
        doc,
        json!({
            "kind": "Node",
            "org": "acme",
            "project": "core",
            "env": "prod",
            "name": "smoke-node",
            "labels": {"managed-by": "ryvex-agent", "cluster": "prod-eu1"},
            "generation": 3,
            "spec": {
                "cluster": "prod-eu1",
                "agent_version": "1.0.0",
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "last_seen": "2026-09-08T10:00:00Z",
                "status_message": "draining",
            },
        })
    );
    // no generation when absent (fresh create)
    let fresh = spec::node_document(&c, "1.0.0", "2026-09-08T10:00:00Z", None, None);
    assert!(fresh.get("generation").is_none());
}

#[test]
fn rfc3339_known_epochs() {
    assert_eq!(spec::rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(spec::rfc3339(951_782_400), "2000-02-29T00:00:00Z"); // leap day
    assert_eq!(spec::rfc3339(1_788_800_000), "2026-09-07T16:53:20Z");
}
