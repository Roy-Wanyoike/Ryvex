/**
 * Wire types for the Ryvex control plane REST API (`/v1` face).
 *
 * These mirror the Go types in `internal/state` and `internal/bus` one
 * to one (JSON tags are the source of truth). Timestamps stay ISO-8601
 * strings so clients can decide their own parsing strategy; the server
 * always emits UTC RFC3339.
 *
 * Per the frozen contract (docs/api-contracts.md): new fields may be
 * added to responses at any time — treat these shapes as minimums, not
 * exhaustive.
 */

/** The closed set of resource kinds registered in the control plane. */
export type ResourceKind =
  | "Project"
  | "Environment"
  | "Application"
  | "Deployment"
  | "Cluster"
  | "Node"
  | "Database"
  | "Cache"
  | "Bucket"
  | "Policy"
  | "Secret";

/** Reconciliation lifecycle phases (server-owned). */
export type ResourcePhase =
  | "Pending"
  | "Provisioning"
  | "Ready"
  | "Degraded"
  | "Failed"
  | "Terminating";

/** Free-form JSON object carried as the declarative desired state. */
export type ResourceSpec = Record<string, unknown>;

/** Observed state, owned exclusively by the reconciler. */
export interface ResourceStatus {
  phase: ResourcePhase | string;
  message?: string;
  observed_generation: number;
  updated_at: string;
}

/**
 * A stored resource document, exactly as the API returns it.
 * `status` and `generation` are server-owned: client writes to `status`
 * are ignored, and `generation` increments only when `spec`/`labels`
 * actually change.
 */
export interface Resource {
  id: string;
  kind: ResourceKind | string;
  org: string;
  project: string;
  env: string;
  name: string;
  generation: number;
  labels?: Record<string, string>;
  spec?: ResourceSpec;
  status: ResourceStatus;
  created_at: string;
  updated_at: string;
}

/** Body for POST /v1/resources (create at a fresh address). */
export interface CreateResourceInput {
  kind: ResourceKind | string;
  org: string;
  project: string;
  env: string;
  name: string;
  labels?: Record<string, string>;
  spec: ResourceSpec;
}

/**
 * Body for PUT /v1/{org}/{project}/{env}/{kind}/{name} (upsert).
 * Identity comes from the path; the server only consumes `spec`,
 * `labels` and `generation` from this document.
 *
 * Include `generation: N` for optimistic concurrency (CAS): the write
 * fails with a 409 `conflict` error if the stored generation is no
 * longer N. Omit it for last-writer-wins.
 */
export interface UpsertResourceInput {
  kind?: ResourceKind | string;
  org?: string;
  project?: string;
  env?: string;
  name?: string;
  /** Optimistic CAS token: the generation previously read. */
  generation?: number;
  labels?: Record<string, string>;
  spec: ResourceSpec;
}

/** Filters + pagination for GET /v1/resources. */
export interface ListOptions {
  org?: string;
  project?: string;
  env?: string;
  /** Case-insensitive; simple plurals ("applications") accepted. */
  kind?: string;
  /** Page size, default 50, max 200. */
  limit?: number;
  /** Continuation token from a previous page's `next_cursor`. */
  cursor?: string;
}

/** One cursor-paginated page. `next_cursor` is "" on the last page. */
export interface Page<T> {
  items: T[];
  next_cursor: string;
}

/**
 * A bus event (ryvex.resource.{org}.{kind}.{event}).
 * `type` ∈ created | updated | deleted | status_changed.
 */
export interface RyvexEvent {
  id: string;
  time: string;
  type: string;
  subject: string;
  org: string;
  project: string;
  env: string;
  kind: string;
  name: string;
  resource_id: string;
  generation: number;
  phase?: string;
  actor?: string;
  data?: Record<string, unknown>;
}

/** Response of GET /v1/{org}/events. */
export interface EventsPage {
  events: RyvexEvent[];
  count: number;
}

/** Options for {@link Ryvex.events}. */
export interface EventsOptions {
  limit?: number;
}

/**
 * A single state-mutation record from the audit trail.
 * `action` ∈ created | updated | deleted | status_changed.
 */
export interface AuditEntry {
  id: string;
  time: string;
  actor: string;
  action: string;
  resource_id: string;
  kind: string;
  logical_key: string;
  generation: number;
  reason?: string;
}

/** Response of GET /v1/{org}/audit. */
export interface AuditPage {
  entries: AuditEntry[];
  count: number;
}

/** Options for {@link Ryvex.audit}. */
export interface AuditOptions {
  /** Filter by resource kind (case-insensitive). */
  kind?: string;
  /** Page size, default 100, max 500. */
  limit?: number;
}

/** Response of POST /v1/{org}/reconcile/{id} (202). */
export interface ReconcileAck {
  status: string;
  resource_id: string;
  reason: string;
}

/** Response of GET /healthz (unauthenticated). */
export interface HealthInfo {
  status: string;
  service: string;
  version: string;
  resources: number;
  time: string;
}

/** Machine-readable endpoint list served at GET /v1. */
export interface ApiIndex {
  name: string;
  version: string;
  endpoints: string[];
  docs: string;
}
