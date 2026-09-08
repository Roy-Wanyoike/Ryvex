import { DEMO_AUDIT, DEMO_EVENTS, DEMO_RESOURCES } from "./demo";
import type { AuditEntry, Resource, RyvexEvent } from "./types";

/**
 * The console talks to the Ryvex control plane API (ryvexd).
 *
 * Configuration resolution order (strongest first):
 *   1. localStorage  ryvex.apiBase / ryvex.token  (set from the Settings view)
 *   2. build-time env  NEXT_PUBLIC_RYVEX_API / NEXT_PUBLIC_RYVEX_TOKEN
 *   3. defaults        no base (demo mode) + "ryk_console_dev"
 *
 * When no API base resolves the console degrades gracefully to an embedded
 * demo snapshot so the UI is always reviewable. Mutations in demo mode throw
 * a DemoModeError which callers render as an info toast.
 */

const ENV_API_BASE = process.env.NEXT_PUBLIC_RYVEX_API ?? "";
const ENV_TOKEN = process.env.NEXT_PUBLIC_RYVEX_TOKEN ?? "ryk_console_dev";

export const LS_API_BASE = "ryvex.apiBase";
export const LS_TOKEN = "ryvex.token";
const DEFAULT_TOKEN = "ryk_console_dev";

// ---- module-level runtime config store ----

let runtimeApiBase = ENV_API_BASE;
let runtimeToken = ENV_TOKEN;

function normalizeBase(base: string): string {
  return base.trim().replace(/\/+$/, "");
}

/** Runtime override. Callers pass raw form values; bases are normalized. */
export function configureApi(opts: { apiBase?: string; token?: string }): void {
  if (opts.apiBase !== undefined) runtimeApiBase = normalizeBase(opts.apiBase);
  if (opts.token !== undefined) runtimeToken = opts.token.trim();
}

export function getApiBase(): string {
  return runtimeApiBase;
}

export function getApiToken(): string {
  return runtimeToken;
}

export function getApiMode(): "live" | "demo" {
  return runtimeApiBase ? "live" : "demo";
}

/**
 * Pull persisted settings out of localStorage (raw — "" means the key is
 * stored but empty, which is distinct from "not set"). Safe to call on the
 * server: returns blanks there.
 */
export function loadStoredConfig(): { apiBase: string; token: string; hasBase: boolean; hasToken: boolean } {
  if (typeof window === "undefined") return { apiBase: "", token: "", hasBase: false, hasToken: false };
  const apiBase = window.localStorage.getItem(LS_API_BASE) ?? "";
  const token = window.localStorage.getItem(LS_TOKEN) ?? "";
  return { apiBase, token, hasBase: window.localStorage.getItem(LS_API_BASE) !== null, hasToken: window.localStorage.getItem(LS_TOKEN) !== null };
}

/**
 * Apply persisted localStorage settings over the build-time env defaults.
 * Keys that were explicitly stored (even as "") win; unset keys defer to env.
 */
export function hydrateApiFromStorage(): void {
  const stored = loadStoredConfig();
  if (stored.hasBase) runtimeApiBase = normalizeBase(stored.apiBase);
  if (stored.hasToken) runtimeToken = stored.token.trim();
  else if (!runtimeToken) runtimeToken = DEFAULT_TOKEN;
}

/** Persist the given settings; also applies them to the runtime store. */
export function storeConfig(apiBase: string, token: string): void {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(LS_API_BASE, normalizeBase(apiBase));
    window.localStorage.setItem(LS_TOKEN, token.trim());
  }
  configureApi({ apiBase, token });
}

// ---- error envelope (frozen contract) ----

/** Wire shape: {"error":{"code","message","request_id","details"}} */
interface ErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    request_id?: string;
  };
}

/** Typed parser for the frozen error envelope; null when the body is not one. */
export function parseErrorEnvelope(body: unknown): { code: string; message: string; requestId: string } | null {
  if (typeof body !== "object" || body === null) return null;
  const err = (body as ErrorEnvelope).error;
  if (typeof err !== "object" || err === null) return null;
  if (typeof err.message !== "string" && typeof err.code !== "string") return null;
  return {
    code: typeof err.code === "string" ? err.code : "unknown",
    message: typeof err.message === "string" ? err.message : "request failed",
    requestId: typeof err.request_id === "string" ? err.request_id : "",
  };
}

/** API error carrying the parsed envelope plus the HTTP status. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;

  constructor(status: number, code: string, message: string, requestId = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }

  /** CAS generation mismatch (409 conflict). */
  get isConflict(): boolean {
    return this.status === 409 || this.code === "conflict";
  }
}

/** Thrown by mutations when the console runs without an API base. */
export class DemoModeError extends Error {
  constructor() {
    super("demo mode is read-only — set an API base URL in Settings to make changes");
    this.name = "DemoModeError";
  }
}

function describeFailure(err: unknown, base: string): string {
  if (err instanceof Error && err.name === "AbortError") {
    return `request to ${base} timed out`;
  }
  return `cannot reach control plane at ${base}`;
}

/** Single request primitive for mutations: JSON in, ApiError on failure. */
async function apiRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  const base = getApiBase();
  if (!base) throw new DemoModeError();

  let res: Response;
  try {
    res = await fetch(`${base}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${getApiToken()}`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
  } catch (err) {
    throw new ApiError(0, "network_error", describeFailure(err, base));
  }

  if (!res.ok) {
    let envelope: unknown = null;
    try {
      envelope = await res.json();
    } catch {
      // non-JSON error body — fall through to generic message
    }
    const parsed = parseErrorEnvelope(envelope);
    throw new ApiError(
      res.status,
      parsed?.code ?? `http_${res.status}`,
      parsed?.message ?? `request failed with HTTP ${res.status}`,
      parsed?.requestId ?? "",
    );
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function scopePath(org: string, project: string, env: string, kind: string, name?: string): string {
  const seg = [org, project, env, kind, name ?? ""].map(encodeURIComponent).filter(Boolean);
  return `/v1/${seg.join("/")}`;
}

// ---- document bodies for writes (status is server-owned) ----

export interface ResourcePutDoc {
  kind: string;
  org?: string;
  project?: string;
  env?: string;
  name?: string;
  /** CAS token: echo the generation you read; 409 conflict when stale. Omit for last-writer-wins. */
  generation?: number;
  labels?: Record<string, string>;
  spec: Record<string, unknown>;
}

/** PUT /v1/{org}/{project}/{env}/{kind}/{name} — upsert with optional CAS. */
export function putResource(
  org: string,
  project: string,
  env: string,
  kind: string,
  name: string,
  doc: ResourcePutDoc,
): Promise<Resource> {
  return apiRequest<Resource>("PUT", scopePath(org, project, env, kind, name), {
    kind,
    org,
    project,
    env,
    name,
    generation: doc.generation,
    labels: doc.labels,
    spec: doc.spec,
  });
}

/** DELETE /v1/{org}/{project}/{env}/{kind}/{name} — 204 on success. */
export async function deleteResource(
  org: string,
  project: string,
  env: string,
  kind: string,
  name: string,
): Promise<void> {
  await apiRequest<void>("DELETE", scopePath(org, project, env, kind, name));
}

/** GET /v1/{org}/{project}/{env}/{kind}/{name} — latest stored doc, or null. */
export async function fetchResource(
  org: string,
  project: string,
  env: string,
  kind: string,
  name: string,
): Promise<Resource | null> {
  if (!getApiBase()) {
    return (
      DEMO_RESOURCES.find(
        (r) => r.org === org && r.project === project && r.env === env && r.kind === kind && r.name === name,
      ) ?? null
    );
  }
  try {
    return await apiRequest<Resource>("GET", scopePath(org, project, env, kind, name));
  } catch {
    return null;
  }
}

// ---- health / connection test ----

export interface HealthInfo {
  status: string;
  service: string;
  version: string;
  resources: number;
  time?: string;
}

export type ConnectionResult = { ok: true; info: HealthInfo } | { ok: false; error: string };

/**
 * GET {base}/healthz with the given bearer attached. Unauthenticated on the
 * wire per contract, but sending the header verifies the token is at least
 * well-formed plumbing-wise. Never throws — returns a discriminated result.
 */
export async function testConnection(rawBase: string, token: string): Promise<ConnectionResult> {
  const base = normalizeBase(rawBase);
  if (!base) {
    return { ok: false, error: "No API base URL configured — the console is in demo mode." };
  }
  try {
    const res = await fetch(`${base}/healthz`, {
      headers: token.trim() ? { Authorization: `Bearer ${token.trim()}` } : {},
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      let envelope: unknown = null;
      try {
        envelope = await res.json();
      } catch {
        // non-JSON body
      }
      const parsed = parseErrorEnvelope(envelope);
      return { ok: false, error: parsed?.message ?? `HTTP ${res.status} from ${base}/healthz` };
    }
    const info = (await res.json()) as HealthInfo;
    return { ok: true, info };
  } catch (err) {
    return { ok: false, error: describeFailure(err, base) };
  }
}

// ---- read paths (demo-fallback as before) ----

async function get<T>(path: string, fallback: T): Promise<T> {
  const base = getApiBase();
  if (!base) return fallback;
  try {
    const res = await fetch(`${base}${path}`, {
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${getApiToken()}` },
      cache: "no-store",
    });
    if (!res.ok) return fallback;
    return (await res.json()) as T;
  } catch {
    return fallback;
  }
}

export function fetchResources(): Promise<{ items: Resource[] }> {
  return get<{ items: Resource[] }>(
    "/v1/resources?limit=200",
    { items: DEMO_RESOURCES },
  );
}

export function fetchEvents(): Promise<{ events: RyvexEvent[] }> {
  return get<{ events: RyvexEvent[] }>(
    "/v1/acme/events?limit=100",
    { events: DEMO_EVENTS },
  );
}

export function fetchAudit(): Promise<{ entries: AuditEntry[] }> {
  return get<{ entries: AuditEntry[] }>(
    "/v1/acme/audit?limit=100",
    { entries: DEMO_AUDIT },
  );
}
