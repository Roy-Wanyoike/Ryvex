import type { AuditEntry, Resource, RyvexEvent } from "./types";

/**
 * Demo snapshot mirroring the `ryvexd --seed` dataset. Used ONLY when the
 * console runs without a configured control plane (no NEXT_PUBLIC_RYVEX_API
 * and no API base in Settings) so recruiters and reviewers always see a
 * living, read-only UI.
 *
 * Hydration safety: timestamps used to be computed at module load, so the
 * server render and the client render disagreed (SSR/CSR mismatch). Now the
 * snapshot is built lazily on first access and its clock is anchored once per
 * browser session:
 *   - on the client, the anchor is the moment the snapshot is first needed
 *     (i.e. after mount, when a fetch resolves in demo mode);
 *   - on the server (if a demo value is ever rendered during SSR) the anchor
 *     is a fixed epoch, keeping server output deterministic.
 * All times are fixed offsets from that anchor, so the demo story ("checkout
 * deployed 12 minutes ago") stays intact.
 */

const SERVER_ANCHOR_ISO = "2025-01-15T12:00:00.000Z";

let clientAnchorMs: number | null = null;
let snapshot: { resources: Resource[]; events: RyvexEvent[]; audit: AuditEntry[] } | null = null;

function anchor(): number {
  if (typeof window === "undefined") return Date.parse(SERVER_ANCHOR_ISO);
  if (clientAnchorMs === null) clientAnchorMs = Date.now();
  return clientAnchorMs;
}

function buildSnapshot(): { resources: Resource[]; events: RyvexEvent[]; audit: AuditEntry[] } {
  const t = (minsAgo: number) => new Date(anchor() - minsAgo * 60_000).toISOString();

  const resources: Resource[] = [
    {
      id: "r-demo-001", kind: "Project", org: "acme", project: "core", env: "prod", name: "core",
      generation: 3, labels: { "managed-by": "ryvex", tier: "platform" },
      spec: { description: "Acme core commerce platform", owner: "platform-team" },
      status: { phase: "Ready", observed_generation: 3, updated_at: t(48) },
      created_at: t(1440), updated_at: t(48),
    },
    {
      id: "r-demo-002", kind: "Environment", org: "acme", project: "core", env: "prod", name: "prod",
      generation: 2, labels: { "managed-by": "ryvex", tier: "production" },
      spec: { region: "eu-west-1", protection: "full" },
      status: { phase: "Ready", observed_generation: 2, updated_at: t(120) },
      created_at: t(1440), updated_at: t(120),
    },
    {
      id: "r-demo-003", kind: "Environment", org: "acme", project: "core", env: "staging", name: "staging",
      generation: 1, labels: { "managed-by": "ryvex", tier: "staging" },
      spec: { region: "eu-west-1", protection: "none" },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(600) },
      created_at: t(1440), updated_at: t(600),
    },
    {
      id: "r-demo-004", kind: "Application", org: "acme", project: "core", env: "prod", name: "checkout",
      generation: 7, labels: { "managed-by": "ryvex", team: "payments" },
      spec: { image: "registry.acme.io/checkout:1.42.0", replicas: 4, port: 8080 },
      status: { phase: "Ready", observed_generation: 7, updated_at: t(12) },
      created_at: t(1400), updated_at: t(12),
    },
    {
      id: "r-demo-005", kind: "Application", org: "acme", project: "core", env: "prod", name: "web",
      generation: 5, labels: { "managed-by": "ryvex", team: "storefront" },
      spec: { image: "registry.acme.io/web:2.7.3", replicas: 6, port: 3000 },
      status: { phase: "Ready", observed_generation: 5, updated_at: t(30) },
      created_at: t(1400), updated_at: t(30),
    },
    {
      id: "r-demo-006", kind: "Deployment", org: "acme", project: "core", env: "prod", name: "checkout-1-42-0",
      generation: 1, labels: { "managed-by": "ryvex", team: "payments" },
      spec: { application: "checkout", image: "registry.acme.io/checkout:1.42.0", strategy: "rolling", commit: "9f3e2a1" },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(14) },
      created_at: t(16), updated_at: t(14),
    },
    {
      id: "r-demo-007", kind: "Cluster", org: "acme", project: "core", env: "prod", name: "prod-eu1",
      generation: 2, labels: { "managed-by": "ryvex", region: "eu-west-1" },
      spec: { provider: "aws", version: "1.30", nodes: 2, cpus: 32 },
      status: { phase: "Ready", observed_generation: 2, updated_at: t(200) },
      created_at: t(1440), updated_at: t(200),
    },
    {
      id: "r-demo-008", kind: "Node", org: "acme", project: "core", env: "prod", name: "prod-eu1-a",
      generation: 1, labels: { "managed-by": "ryvex", instance: "m6i.2xlarge" },
      spec: { cluster: "prod-eu1", capacity_gb: 512, status: "joined" },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(180) },
      created_at: t(1440), updated_at: t(180),
    },
    {
      id: "r-demo-009", kind: "Node", org: "acme", project: "core", env: "prod", name: "prod-eu1-b",
      generation: 1, labels: { "managed-by": "ryvex", instance: "m6i.2xlarge" },
      spec: { cluster: "prod-eu1", capacity_gb: 512, status: "joined" },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(175) },
      created_at: t(1440), updated_at: t(175),
    },
    {
      id: "r-demo-010", kind: "Database", org: "acme", project: "core", env: "prod", name: "orders-postgres",
      generation: 2, labels: { "managed-by": "ryvex", team: "payments" },
      spec: { engine: "postgres", version: "16", size: "db.m6g.large", ha: true },
      status: { phase: "Ready", observed_generation: 2, updated_at: t(90) },
      created_at: t(1440), updated_at: t(90),
    },
    {
      id: "r-demo-011", kind: "Cache", org: "acme", project: "core", env: "prod", name: "sessions-redis",
      generation: 1, labels: { "managed-by": "ryvex", team: "storefront" },
      spec: { engine: "redis", version: "7.2", size: "cache.m6g.large", eviction: "allkeys-lru" },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(95) },
      created_at: t(1440), updated_at: t(95),
    },
    {
      id: "r-demo-012", kind: "Bucket", org: "acme", project: "core", env: "prod", name: "invoice-archive",
      generation: 1, labels: { "managed-by": "ryvex", team: "billing" },
      spec: { provider: "aws", versioning: true, encryption: "aws:kms" },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(500) },
      created_at: t(1400), updated_at: t(500),
    },
    {
      id: "r-demo-013", kind: "Policy", org: "acme", project: "core", env: "prod", name: "require-approval-prod",
      generation: 4, labels: { "managed-by": "ryvex", governance: "change-control" },
      spec: { applies_to: ["Deployment", "Database"], min_approvers: 2, window: "business-hours" },
      status: { phase: "Ready", observed_generation: 4, updated_at: t(320) },
      created_at: t(1440), updated_at: t(320),
    },
    {
      id: "r-demo-014", kind: "Policy", org: "acme", project: "core", env: "prod", name: "deny-public-buckets",
      generation: 1, labels: { "managed-by": "ryvex", governance: "security" },
      spec: { applies_to: ["Bucket"], deny: ["public_read"] },
      status: { phase: "Ready", observed_generation: 1, updated_at: t(310) },
      created_at: t(1440), updated_at: t(310),
    },
    {
      id: "r-demo-015", kind: "Secret", org: "acme", project: "core", env: "prod", name: "stripe-api-key",
      generation: 8, labels: { "managed-by": "ryvex", rotation: "30d" },
      spec: { provider: "vault", keys: ["secret_key", "webhook_secret"] },
      status: { phase: "Ready", observed_generation: 8, updated_at: t(60) },
      created_at: t(1440), updated_at: t(60),
    },
  ];

  const events: RyvexEvent[] = [
    { id: "evt-120", time: t(2), type: "status_changed", subject: "ryvex.resource.acme.deployment.status_changed", org: "acme", kind: "Deployment", name: "checkout-1-42-0", phase: "Ready", actor: "reconciler" },
    { id: "evt-119", time: t(3), type: "created", subject: "ryvex.resource.acme.deployment.created", org: "acme", kind: "Deployment", name: "checkout-1-42-0", actor: "ci-bot" },
    { id: "evt-118", time: t(12), type: "status_changed", subject: "ryvex.resource.acme.application.status_changed", org: "acme", kind: "Application", name: "checkout", phase: "Ready", actor: "reconciler" },
    { id: "evt-117", time: t(13), type: "updated", subject: "ryvex.resource.acme.application.updated", org: "acme", kind: "Application", name: "checkout", generation: 7, actor: "ci-bot" },
    { id: "evt-116", time: t(30), type: "status_changed", subject: "ryvex.resource.acme.application.status_changed", org: "acme", kind: "Application", name: "web", phase: "Ready", actor: "reconciler" },
    { id: "evt-115", time: t(60), type: "status_changed", subject: "ryvex.resource.acme.secret.status_changed", org: "acme", kind: "Secret", name: "stripe-api-key", phase: "Ready", actor: "reconciler" },
    { id: "evt-114", time: t(61), type: "updated", subject: "ryvex.resource.acme.secret.updated", org: "acme", kind: "Secret", name: "stripe-api-key", generation: 8, actor: "alice" },
    { id: "evt-113", time: t(90), type: "status_changed", subject: "ryvex.resource.acme.database.status_changed", org: "acme", kind: "Database", name: "orders-postgres", phase: "Ready", actor: "reconciler" },
  ];

  const audit: AuditEntry[] = [
    { id: "a-90", time: t(3), actor: "ci-bot", action: "created", resource_id: "r-demo-006", kind: "Deployment", logical_key: "acme/core/prod/Deployment/checkout-1-42-0", generation: 1, reason: "release 1.42.0" },
    { id: "a-89", time: t(13), actor: "ci-bot", action: "updated", resource_id: "r-demo-004", kind: "Application", logical_key: "acme/core/prod/Application/checkout", generation: 7 },
    { id: "a-88", time: t(61), actor: "alice", action: "updated", resource_id: "r-demo-015", kind: "Secret", logical_key: "acme/core/prod/Secret/stripe-api-key", generation: 8, reason: "rotation" },
    { id: "a-87", time: t(90), actor: "reconciler", action: "status_changed", resource_id: "r-demo-010", kind: "Database", logical_key: "acme/core/prod/Database/orders-postgres", generation: 2 },
    { id: "a-86", time: t(320), actor: "bob", action: "updated", resource_id: "r-demo-013", kind: "Policy", logical_key: "acme/core/prod/Policy/require-approval-prod", generation: 4, reason: "raise approvers to 2" },
  ];

  return { resources, events, audit };
}

/** Demo resources (lazy — built once, anchored at first client access). */
export function demoResources(): Resource[] {
  if (!snapshot) snapshot = buildSnapshot();
  return snapshot.resources;
}

/** Demo event stream (lazy — built once, anchored at first client access). */
export function demoEvents(): RyvexEvent[] {
  if (!snapshot) snapshot = buildSnapshot();
  return snapshot.events;
}

/** Demo audit trail (lazy — built once, anchored at first client access). */
export function demoAudit(): AuditEntry[] {
  if (!snapshot) snapshot = buildSnapshot();
  return snapshot.audit;
}
