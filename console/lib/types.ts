export type Phase =
  | "Pending"
  | "Provisioning"
  | "Ready"
  | "Degraded"
  | "Failed"
  | "Terminating";

/**
 * Server-owned status block.
 *
 * Typed loosely on purpose: the console renders untrusted wire data, and a
 * malformed or truncated document must degrade the UI ("Unknown" phase) —
 * never crash it. Views access these fields with `?.` + fallbacks.
 */
export interface ResourceStatus {
  phase?: Phase;
  message?: string;
  observed_generation?: number;
  updated_at?: string;
}

export interface Resource {
  id: string;
  kind: string;
  org: string;
  project: string;
  env: string;
  name: string;
  generation: number;
  labels?: Record<string, string>;
  spec?: Record<string, unknown>;
  /** Absent on malformed documents — render "Unknown" instead of crashing. */
  status?: ResourceStatus;
  created_at: string;
  updated_at: string;
}

export interface RyvexEvent {
  id: string;
  time: string;
  type: string;
  subject: string;
  org: string;
  kind: string;
  name: string;
  resource_id?: string;
  generation?: number;
  phase?: string;
  actor?: string;
}

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
