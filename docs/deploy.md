# Deploying Ryvex

The full self-hosting story: container images, docker compose, and the
Kubernetes manifests in [`deploy/k8s/`](../deploy/k8s). Read once top to
bottom — each section states what the defaults assume and how to change
them.

## Images

Two images are published to GHCR by the release workflow (triggered on
every `v*` tag):

| Image | Source | Runs as |
|-------|--------|---------|
| `ghcr.io/roy-wanyoike/ryvexd` | [`Dockerfile`](../Dockerfile) | static Go binaries (ryvexd + ryvex CLI), UID 10001, alpine |
| `ghcr.io/roy-wanyoike/ryvex-agent` | [`Dockerfile.agent`](../Dockerfile.agent) | static musl Rust binary, UID 10002, alpine |

Both are built from the repository root:

```bash
docker build -t ryvexd .                      # control plane (+ ryvex CLI)
docker build -f Dockerfile.agent -t ryvex-agent .   # node agent
```

The agent build context is trimmed by `Dockerfile.agent.dockerignore`
(BuildKit per-Dockerfile ignore): only `agent/` sources reach the
builder; the root `.dockerignore` keeps the control-plane context
Go-only.

The agent build pins `rust:1.98-alpine` — the toolchain the crate is
verified with — and builds `--locked` against `Cargo.lock` for
reproducible releases.

## docker compose

```bash
cp .env.example .env                     # then fill in what you need
docker compose up -d                     # postgres + ryvexd (memory bus)
docker compose --profile nats up -d      # + NATS JetStream bus
docker compose --profile agent up -d     # + node agent (needs RYVEX_AGENT_TOKEN)
```

### Event bus choice (memory vs NATS)

`ryvexd` boots with the **memory bus** by default: events live in a
replay ring and are **lost on restart**. The durable choice is NATS
JetStream, and it is deliberate that there is no `RYVEX_BUS` env var:
`--bus` is a command-line flag only (`cmd/ryvexd/serve.go`), so the
switch is a visible edit, and `--bus=nats` fails at boot when NATS is
unreachable (never a silent fallback to memory).

Compose (edit the `command` of the `ryvexd` service):

```yaml
command: ["serve", "--store", "postgres", "--bus", "nats"]
```

Kubernetes (edit the `args` in `deploy/k8s/04-ryvexd.yaml`) the same
way, after deploying NATS reachable at `RYVEX_NATS_URL`. Pairing the
postgres store with the memory bus — the shipped default — trades
event durability for a dependency-free first boot; the compose comment
block documents exactly this.

### Node agent on compose

The `agent` profile builds `Dockerfile.agent` and enrolls the host with
the control plane (GET/PUT only — it opens no listen port). It needs a
real `ryk_` token: empty or malformed tokens make the binary exit(2).

```bash
RYVEX_AGENT_TOKEN=ryk_... docker compose --profile agent up -d
```

All 9 agent variables (verbatim from
`agent/ryvex-agent/src/config.rs`) are listed in
[`.env.example`](../.env.example).

## Kubernetes

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
kubectl apply -f deploy/k8s/          # or: kubectl apply -k deploy/k8s
```

Manifest order and purpose:

| File | Contents |
|------|----------|
| `00-namespace.yaml` | `ryvex` namespace (labeled, network policy matches on it) |
| `01-postgres.yaml` | headless Service + StatefulSet, non-root UID 999, fsGroup, caps dropped |
| `02-ryvexd-configmap.yaml` | plain ryvexd config incl. `RYVEX_PG_SSLMODE` |
| `03-ryvexd-secret.yaml` | secret key contract (see below — fail closed) |
| `04-ryvexd.yaml` | Deployment + Service; startupProbe on `/readyz`, liveness `/healthz`, readiness `/readyz` |
| `05-ryvexd-networkpolicy.yaml` | default-deny ingress/egress around ryvexd |
| `06-ryvexd-pdb.yaml` | PDB `minAvailable: 1` |
| `07-ryvex-agent.yaml` | ConfigMap + DaemonSet, one agent per node |
| `kustomization.yaml` | tag parameterization (below) |

### Secrets — fail closed

`03-ryvexd-secret.yaml` defines the key contract but ships **commented
out**: applying it as-is creates an empty Secret and the pods refuse to
start (`CreateContainerConfigError`) rather than booting with
publicly-known `CHANGE_ME` credentials. Create the secret out-of-band:

```bash
kubectl -n ryvex create secret generic ryvexd-secret \
  --from-literal=api-keys="ops=ryk_$(openssl rand -hex 24)" \
  --from-literal=webhook-secret="$(openssl rand -hex 32)" \
  --from-literal=postgres-password="$(openssl rand -hex 16)" \
  --from-literal=agent-token="ryk_$(openssl rand -hex 24)"
```

`agent-token` is the key the DaemonSet heartbeats with; scope it to the
agent's org/project/env via `POST /v1/keys`.

### Pinning image tags

`kustomization.yaml` carries the current release tags for both images.
To roll a different version without editing YAML:

```bash
cd deploy/k8s
kustomize edit set image \
  ghcr.io/roy-wanyoike/ryvexd=v1.2.0 \
  ghcr.io/roy-wanyoike/ryvex-agent=v1.2.0
kubectl apply -k .
```

### Postgres TLS (sslmode)

The DSN is assembled in `04-ryvexd.yaml` from `RYVEX_PG_SSLMODE`
(configmap). The shipped default is `disable` — plaintext, defensible
only while traffic provably stays inside the cluster network. For TLS:

```yaml
# 02-ryvexd-configmap.yaml
RYVEX_PG_SSLMODE: "verify-full"
```

`verify-full` encrypts **and** verifies the server certificate against
the CA bundle inside the ryvexd image — pair it with a certificate on
`ryvex-postgres` (e.g. cert-manager) whose DNS SAN matches the DSN host.

### Liveness, readiness, startup

- **startupProbe** on `/readyz`: the first boot runs the embedded
  Postgres migrations under a 30s context; a cold PVC adds disk latency.
  `30 × 5s = 150s` of grace before liveness/readiness even start, so a
  healthy pod is never killed mid-migration.
- **readiness** on `/readyz` (dependency-aware, issue #71): a dead-DB
  pod leaves the Service rotation instead of serving errors.
- **liveness** on `/healthz`: keeps 200 semantics — a dependency
  failure a restart cannot fix does not restart the pod.

### Network policy — assumptions

`05-ryvexd-networkpolicy.yaml` default-denies both directions around
ryvexd:

- **Ingress**: same-namespace pods (ports 8080 + 9090 for metrics) and
  any namespace labeled `app.kubernetes.io/part-of: ryvex` (port 8080
  only) — that label is the documented home for the console. Everything
  else is denied.
- **Egress**: DNS to `kube-system:53`, Postgres/NATS inside `ryvex`
  (5432/4222), and HTTP/HTTPS to the public internet for **webhook
  deliveries** — with RFC1918/CGNAT/link-local excluded at the network
  layer, mirroring the application-layer SSRF egress guard.

Assumptions to re-check if you deviate: Postgres and NATS live in the
`ryvex` namespace; your CNI enforces NetworkPolicy (many default
installs do not); the cluster resolver lives in `kube-system`.

### Disruption budget

`06-ryvexd-pdb.yaml` sets `minAvailable: 1`. With `replicas: 1` this
**blocks voluntary drains** of the only control-plane replica — scale
up first or accept the disruption consciously. Involuntary failures
are unaffected.

### Node agent DaemonSet

`07-ryvex-agent.yaml` runs one agent per node (control-plane taints
tolerated). Design notes:

- `RYVEX_AGENT_NAME` comes from `spec.nodeName`, so each Kubernetes
  node is exactly one stable `Node` resource — surviving pod restarts
  (a pod name would enroll a fresh node on every reschedule).
- No probes and no Service: the agent is a pure client (GET/PUT to
  ryvexd); crash recovery is `restartPolicy: Always` plus the binary's
  internal jittered exponential backoff.
- Runs non-root, all caps dropped, read-only root filesystem.
