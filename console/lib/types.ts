export type Phase =
  | "Pending"
  | "Provisioning"
  | "Ready"
  | "Degraded"
  | "Failed"
  | "Terminating";

export interface ResourceStatus {
  phase: Phase;
  message?: string;
  observed_generation: number;
  updated_at: string;
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
  status: ResourceStatus;
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
