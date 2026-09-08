/**
 * ryvex — TypeScript client for the Ryvex control plane REST API.
 *
 * @example
 * ```ts
 * import { Ryvex, RyvexError } from "ryvex";
 *
 * const ryvex = new Ryvex({ baseUrl: "http://127.0.0.1:8080", token: "ryk_…" });
 * const app = await ryvex.putInScope("acme", "core", "prod", "Application", "checkout", {
 *   spec: { image: "checkout:1.42.0", replicas: 4 },
 * });
 * ```
 */
export { Ryvex, type RyvexClientOptions } from "./client.js";
export { RyvexError, DEFAULT_CODE_BY_STATUS, STATUS_BY_CODE, type ErrorCode, type ErrorDetail } from "./errors.js";
export type {
  ApiIndex,
  AuditEntry,
  AuditOptions,
  AuditPage,
  CreateResourceInput,
  EventsOptions,
  EventsPage,
  HealthInfo,
  ListOptions,
  Page,
  ReconcileAck,
  Resource,
  ResourceKind,
  ResourcePhase,
  ResourceSpec,
  ResourceStatus,
  RyvexEvent,
  UpsertResourceInput,
} from "./types.js";
