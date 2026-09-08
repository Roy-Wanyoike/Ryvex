//! Client state-machine tests against a hand-rolled stdlib HTTP/1.1
//! mock (issue #43). No new dependencies: `std::net::TcpListener` +
//! manual request parsing, same style as the rest of the suite; the
//! async client runs under `#[tokio::test]`.
//!
//! The mock answers with `Connection: close`, so every request the
//! agent sends gets its own accepted connection — strict sequencing,
//! no keep-alive handling needed.
//!
//! Server-semantics grounding (`internal/api/handlers.go`
//! handleScopePut and `internal/state/store.go` UpdateResource):
//! - PUT onto a fresh address → `201 Created` (upsert semantics);
//! - PUT with a matching generation and an identical spec → `200 OK`,
//!   generation NOT advanced, no "updated" event (`specLabelsEqual`);
//! - PUT with a stale generation → `409 Conflict`;
//! - GET/PUT on an absent address → `404 Not Found`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ryvex_agent::client::{next_last_seen, ApiClient, Outcome};
use ryvex_agent::config::Config;

const NODE_PATH: &str = "/v1/acme/core/prod/nodes/mock-node";

// ---- mock server ----

#[derive(Clone, Debug)]
struct Record {
    method: String,
    path: String,
    body: String,
}

#[derive(Clone)]
enum Action {
    /// Answer with an HTTP response (status + body).
    Respond(u16, String),
    /// Accept the request, then close without responding.
    Close,
}

struct Mock {
    addr: std::net::SocketAddr,
    records: Arc<Mutex<Vec<Record>>>,
}

impl Mock {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<Record> {
        self.records.lock().expect("mock records mutex").clone()
    }
}

/// Bind an ephemeral port and serve scripted responses: `gets` for GET
/// requests, `puts` for everything else. The last action repeats when
/// the script is exhausted; an empty script closes connections.
fn spawn_mock(gets: Vec<Action>, puts: Vec<Action>) -> Mock {
    let records: Arc<Mutex<Vec<Record>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener bind");
    let addr = listener.local_addr().expect("mock local addr");
    let shared = records.clone();
    let get_hits = Arc::new(AtomicUsize::new(0));
    let put_hits = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let req = match read_request(&mut stream) {
                Ok(r) => r,
                Err(_) => break,
            };
            let action = match req.method.as_str() {
                "GET" => {
                    let i = get_hits.fetch_add(1, Ordering::SeqCst);
                    pick(&gets, i)
                }
                _ => {
                    let i = put_hits.fetch_add(1, Ordering::SeqCst);
                    pick(&puts, i)
                }
            };
            shared.lock().expect("mock records mutex").push(req);
            match action {
                Action::Respond(status, body) => {
                    let _ = write_response(&mut stream, status, &body);
                }
                Action::Close => drop(stream),
            }
        }
    });
    Mock { addr, records }
}

fn pick(script: &[Action], i: usize) -> Action {
    if script.is_empty() {
        return Action::Close;
    }
    script[i.min(script.len() - 1)].clone()
}

/// Read one HTTP/1.1 request (headers + Content-Length body).
fn read_request(stream: &mut TcpStream) -> std::io::Result<Record> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "mock: client closed before full request",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut content_length = 0usize;
    for line in head.split("\r\n").skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let body_start = head_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "mock: client closed mid-body",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body =
        String::from_utf8_lossy(&buf[body_start..body_start + content_length]).into_owned();
    let request_line = head.lines().next().unwrap_or_default().to_owned();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    Ok(Record { method, path, body })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

// ---- helpers ----

fn test_cfg(api: &str) -> Config {
    Config::try_parse_from([
        "ryvex-agent",
        "--token",
        "ryk_test_key",
        "--api",
        api,
        "--name",
        "mock-node",
    ])
    .expect("valid config")
}

fn node_json(generation: i64) -> String {
    format!(
        r#"{{"kind":"Node","org":"acme","project":"core","env":"prod","name":"mock-node","generation":{generation},"spec":{{"cluster":"unassigned"}}}}"#
    )
}

fn error_json(code: &str) -> String {
    format!(r#"{{"error":{{"code":"{code}","message":"mock rejection","details":[]}}}}"#)
}

fn put_bodies(mock: &Mock) -> Vec<serde_json::Value> {
    mock.requests()
        .iter()
        .filter(|r| r.method == "PUT")
        .map(|r| serde_json::from_str(&r.body).expect("put body is json"))
        .collect()
}

// ---- state machine: enrollment / heartbeat / self-heal ----

/// Fresh address: GET 404 → PUT → created. The real server answers
/// `201 Created` on create (handleScopePut); any 2xx classifies as
/// Upserted. This is also the self-heal path after a node vanishes.
#[tokio::test]
async fn sync_creates_node_when_get_is_404() {
    let mock = spawn_mock(
        vec![Action::Respond(404, error_json("not_found"))],
        vec![Action::Respond(201, r#"{"generation":1}"#.into())],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert_eq!(outcome, Outcome::Upserted { generation: 1 });
    let recs = mock.requests();
    assert_eq!(recs.len(), 2, "GET then PUT");
    assert_eq!(recs[0].method, "GET");
    assert_eq!(recs[0].path, NODE_PATH);
    assert_eq!(recs[1].method, "PUT");
    let body: serde_json::Value = serde_json::from_str(&recs[1].body).expect("put body json");
    assert!(
        body.get("generation").is_none(),
        "fresh create must not pin a generation"
    );
}

/// Existing node: GET 200 (gen 1) → PUT echoes the observed generation
/// → 200 with the updated resource.
#[tokio::test]
async fn sync_updates_with_observed_generation() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(1))],
        vec![Action::Respond(200, r#"{"generation":2}"#.into())],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert_eq!(outcome, Outcome::Upserted { generation: 2 });
    let bodies = put_bodies(&mock);
    assert_eq!(bodies.len(), 1);
    assert_eq!(
        bodies[0]["generation"], 1,
        "PUT echoes the observed generation"
    );
}

/// One 409 is absorbed inside sync_node: the fresh generation is
/// fetched and the retry PUT wins. run() must never see Conflict here.
#[tokio::test]
async fn single_conflict_is_resolved_internally() {
    let mock = spawn_mock(
        vec![
            Action::Respond(200, node_json(1)),  // initial fetch
            Action::Respond(200, node_json(2)), // conflict re-fetch
        ],
        vec![
            Action::Respond(409, error_json("conflict")),         // stale CAS
            Action::Respond(200, r#"{"generation":3}"#.into()), // retry wins
        ],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert_eq!(outcome, Outcome::Upserted { generation: 3 });
    let recs = mock.requests();
    assert_eq!(recs.len(), 4, "GET, PUT(409), GET(fresh), PUT(retry)");
    let retry: serde_json::Value = serde_json::from_str(&recs[3].body).expect("retry body json");
    assert_eq!(
        retry["generation"], 2,
        "retry must carry the fresh generation"
    );
}

/// put_node classifies a bare 409 as Conflict carrying the fresh
/// generation it just fetched from the server.
#[tokio::test]
async fn put_conflict_returns_fresh_generation() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(2))],
        vec![Action::Respond(409, error_json("conflict"))],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let doc = serde_json::json!({"kind": "Node", "name": "mock-node"});
    let outcome = client.put_node(&doc).await;
    assert_eq!(outcome, Outcome::Conflict { fresh_generation: 2 });
}

/// Issue #43 regression: sustained CAS contention (every PUT 409) must
/// end in Transient — it used to reach the `unreachable!()` in run()
/// and panic-restart-loop the agent under exactly this load.
#[tokio::test]
async fn sustained_conflicts_yield_transient_not_panic() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(1))], // every fetch
        vec![Action::Respond(409, error_json("conflict"))], // every PUT
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert_eq!(outcome, Outcome::Transient("gave up after CAS retries".into()));
    let puts = mock.requests().iter().filter(|r| r.method == "PUT").count();
    assert!(puts >= 3, "expected at least 3 CAS attempts, got {puts}");
}

/// PUT answering 404 → Missing: the caller knows the node vanished and
/// the next cycle self-heals (see sync_creates_node_when_get_is_404).
#[tokio::test]
async fn put_404_reports_missing() {
    let mock = spawn_mock(
        vec![Action::Respond(404, error_json("not_found"))],
        vec![Action::Respond(404, error_json("not_found"))],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert_eq!(outcome, Outcome::Missing);
}

/// Success status with a non-JSON body: the fetch decode fails and
/// surfaces as Transient — handled, no panic.
#[tokio::test]
async fn non_json_success_body_is_transient() {
    let mock = spawn_mock(
        vec![Action::Respond(200, "<html>proxy error</html>".into())],
        vec![Action::Respond(200, r#"{"generation":9}"#.into())],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    match outcome {
        Outcome::Transient(msg) => assert!(
            msg.contains("node json"),
            "decode failure should surface as a node json error, got: {msg}"
        ),
        other => panic!("expected Transient, got {other:?}"),
    }
}

/// GET 500 → Transient (server trouble backs off). Note the pre-existing
/// asymmetry: PUT 500 currently maps to Rejected — see the PR's
/// out-of-scope notes.
#[tokio::test]
async fn get_500_is_transient() {
    let mock = spawn_mock(
        vec![Action::Respond(500, error_json("internal_error"))],
        vec![Action::Respond(200, r#"{"generation":1}"#.into())],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert!(matches!(outcome, Outcome::Transient(_)), "got {outcome:?}");
}

/// Non-JSON 500 on PUT → Rejected (error body never parsed, no panic).
#[tokio::test]
async fn put_500_with_non_json_body_is_rejected() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(1))],
        vec![Action::Respond(500, "<html>boom</html>".into())],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    assert!(matches!(outcome, Outcome::Rejected(_)), "got {outcome:?}");
}

/// Connection dropped mid-PUT (accepted, read, closed without a
/// response) → Transient with the transport error.
#[tokio::test]
async fn connection_drop_mid_put_is_transient() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(1))],
        vec![Action::Close],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let outcome = client.sync_node("test-1.0", None).await;
    match outcome {
        Outcome::Transient(msg) => assert!(
            msg.contains("put node"),
            "drop should surface as a put transport error, got: {msg}"
        ),
        other => panic!("expected Transient, got {other:?}"),
    }
}

// ---- heartbeat spec-throttle (issue #43) ----

/// Within the refresh window the agent re-sends the PREVIOUS
/// spec.last_seen, so both PUTs carry byte-identical documents.
/// Grounded in server behavior: handleScopePut → UpdateResource with a
/// matching generation and an identical spec does NOT advance the
/// generation and does NOT publish an "updated" event (specLabelsEqual
/// path) — the per-tick event storm that used to flood the replay ring
/// and audit log is gone.
#[tokio::test]
async fn heartbeat_within_refresh_window_resends_identical_spec() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(1))],
        vec![Action::Respond(200, r#"{"generation":1}"#.into())],
    );
    let client = ApiClient::new(test_cfg(&mock.url())).expect("client");
    let _ = client.sync_node("test-1.0", None).await;
    let _ = client.sync_node("test-1.0", None).await;
    let bodies = put_bodies(&mock);
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        bodies[0], bodies[1],
        "throttled heartbeat must resend an identical document (same last_seen, same generation)"
    );
}

/// spec-refresh-secs = 0 refreshes last_seen on every cycle; a >1s gap
/// guarantees a different RFC3339 (second-granularity) timestamp.
#[tokio::test]
async fn spec_refreshes_every_cycle_when_window_is_zero() {
    let mock = spawn_mock(
        vec![Action::Respond(200, node_json(1))],
        vec![Action::Respond(200, r#"{"generation":1}"#.into())],
    );
    let api = mock.url();
    let cfg = Config::try_parse_from([
        "ryvex-agent",
        "--token",
        "ryk_test_key",
        "--api",
        api.as_str(),
        "--name",
        "mock-node",
        "--spec-refresh-secs",
        "0",
    ])
    .expect("valid config");
    let client = ApiClient::new(cfg).expect("client");
    let _ = client.sync_node("test-1.0", None).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let _ = client.sync_node("test-1.0", None).await;
    let bodies = put_bodies(&mock);
    assert_eq!(bodies.len(), 2);
    assert_ne!(
        bodies[0]["spec"]["last_seen"], bodies[1]["spec"]["last_seen"],
        "window 0 must force a fresh last_seen each cycle"
    );
}

// ---- throttle decision (pure) ----

#[test]
fn throttle_decision_refreshes_without_previous_value() {
    let (ls, refreshed) =
        next_last_seen(None, Some(std::time::Duration::from_secs(0)), 300, "t2");
    assert_eq!(ls, "t2");
    assert!(refreshed);
}

#[test]
fn throttle_decision_holds_within_window() {
    let (ls, refreshed) = next_last_seen(
        Some("t1"),
        Some(std::time::Duration::from_secs(299)),
        300,
        "t2",
    );
    assert_eq!(ls, "t1", "299s < 300s window: keep previous last_seen");
    assert!(!refreshed);
}

#[test]
fn throttle_decision_refreshes_at_window_boundary() {
    let (ls, refreshed) = next_last_seen(
        Some("t1"),
        Some(std::time::Duration::from_secs(300)),
        300,
        "t2",
    );
    assert_eq!(ls, "t2", "elapsed == refresh window: refresh");
    assert!(refreshed);
}

#[test]
fn throttle_decision_zero_window_always_refreshes() {
    let (ls, refreshed) =
        next_last_seen(Some("t1"), Some(std::time::Duration::from_secs(0)), 0, "t2");
    assert_eq!(ls, "t2");
    assert!(refreshed);
}
