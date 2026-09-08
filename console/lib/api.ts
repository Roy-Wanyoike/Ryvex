import { demoAudit, demoEvents, demoResources } from "./demo";
import type { AuditEntry, Resource, RyvexEvent } from "./types";

/**
 * The console talks to the Ryvex control plane API (ryvexd).
 *
 * Configuration resolution order (strongest first):
 *   1. localStorage  ryvex.apiBase / ryvex.org / ryvex.project / ryvex.env (Settings view)
 *      sessionStorage ryvex.token — only when the operator opts in with
 *      "remember in this browser"; otherwise the token lives in memory alone
 *   2. build-time env  NEXT_PUBLIC_RYVEX_API / NEXT_PUBLIC_RYVEX_TOKEN /
 *                      NEXT_PUBLIC_RYVEX_ORG / NEXT_PUBLIC_RYVEX_PROJECT / NEXT_PUBLIC_RYVEX_ENV
 *   3. defaults        no base (demo mode) + NO token (requests go out
 *                      unauthenticated and fail with an explicit 401 —
 *                      nothing is baked into the bundle, issue #42) + scope acme/core/prod
 *
 * TRUST RULE (issue #41): demo data is served ONLY when no API base is
 * configured. In live mode a failed read never masquerades as demo data —
 * every read returns a FetchResult carrying {data, status, at, reason} so the
 * UI can tell the truth:
 *   - "ok"        fresh data from the control plane
 *   - "degraded"  the fetch failed; `data` is the last good snapshot (or a
 *                 partial page) and `at` says when it was fetched
 *   - "error"     the fetch failed and there is no data to show at all
 *
 * Mutations in demo mode throw a DemoModeError which callers render as an
 * info toast.
 */

const ENV_API_BASE = process.env.NEXT_PUBLIC_RYVEX_API ?? "";
// No default token: an unconfigured console sends NO Authorization header so
// the control plane answers with an explicit 401 instead of silently riding
// a shared dev credential baked into the bundle (issue #42).
const ENV_TOKEN = process.env.NEXT_PUBLIC_RYVEX_TOKEN ?? "";
const ENV_ORG = process.env.NEXT_PUBLIC_RYVEX_ORG ?? "acme";
const ENV_PROJECT = process.env.NEXT_PUBLIC_RYVEX_PROJECT ?? "core";
const ENV_ENV = process.env.NEXT_PUBLIC_RYVEX_ENV ?? "prod";

export const LS_API_BASE = "ryvex.apiBase";
/**
 * Token storage key, now in sessionStorage (per-tab, gone when the tab
 * closes). The same key used to exist in localStorage — hydrateApiFromStorage
 * scrubs that legacy copy on load (issue #42).
 */
export const SS_TOKEN = "ryvex.token";
export const LS_ORG = "ryvex.org";
export const LS_PROJECT = "ryvex.project";
export const LS_ENV = "ryvex.env";

const DEFAULT_ORG = "acme";
const DEFAULT_PROJECT = "core";
const DEFAULT_ENV = "prod";

/** Every network read/write is bounded by this timeout. */
export const REQUEST_TIMEOUT_MS = 10_000;

/** Hard cap on resources accumulated by the pagination loop. */
const RESOURCE_PAGE_LIMIT = 200; // server max page size
const RESOURCE_TOTAL_CAP = 1000;

// ---- module-level runtime config store ----

let runtimeApiBase = ENV_API_BASE;
let runtimeToken = ENV_TOKEN;
let runtimeOrg = ENV_ORG;
let runtimeProject = ENV_PROJECT;
let runtimeEnv = ENV_ENV;

export interface ScopeConfig {
  org: string;
  project: string;
  env: string;
}

function normalizeBase(base: string): string {
  return base.trim().replace(/\/+$/, "");
}

/**
 * Runtime override. Callers pass raw form values; bases are normalized and
 * scope fields fall back to their defaults when blanked out.
 * Cached "last good" feeds are dropped: they belong to the previous
 * configuration and must never be shown as fresh fallback data afterwards.
 */
export function configureApi(opts: {
  apiBase?: string;
  token?: string;
  org?: string;
  project?: string;
  env?: string;
}): void {
  if (opts.apiBase !== undefined) runtimeApiBase = normalizeBase(opts.apiBase);
  if (opts.token !== undefined) runtimeToken = opts.token.trim();
  if (opts.org !== undefined) runtimeOrg = opts.org.trim() || DEFAULT_ORG;
  if (opts.project !== undefined) runtimeProject = opts.project.trim() || DEFAULT_PROJECT;
  if (opts.env !== undefined) runtimeEnv = opts.env.trim() || DEFAULT_ENV;
  lastGood.clear();
}

export function getApiBase(): string {
  return runtimeApiBase;
}

/** Current bearer token. Empty string = send no Authorization header. */
export function getApiToken(): string {
  return runtimeToken;
}

/**
 * Authorization header only when a token is actually configured. An
 * unconfigured console must fail loudly (401) rather than authenticate with
 * an implicit shared credential.
 */
function authHeader(token: string): Record<string, string> {
  const t = token.trim();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export function getOrg(): string {
  return runtimeOrg;
}

export function getProject(): string {
  return runtimeProject;
}

export function getEnv(): string {
  return runtimeEnv;
}

export function getScope(): ScopeConfig {
  return { org: runtimeOrg, project: runtimeProject, env: runtimeEnv };
}

/** Config-derived mode. Truthful *health* comes from FetchResult.status. */
export function getApiMode(): "live" | "demo" {
  return runtimeApiBase ? "live" : "demo";
}

/**
 * Pull persisted settings out of localStorage (raw — "" means the key is
 * stored but empty, which is distinct from "not set"). Safe to call on the
 * server: returns blanks there.
 */
export function loadStoredConfig(): {
  apiBase: string;
  token: string;
  org: string;
  project: string;
  env: string;
  hasBase: boolean;
  hasToken: boolean;
  hasOrg: boolean;
  hasProject: boolean;
  hasEnv: boolean;
} {
  if (typeof window === "undefined") {
    return { apiBase: "", token: "", org: "", project: "", env: "", hasBase: false, hasToken: false, hasOrg: false, hasProject: false, hasEnv: false };
  }
  const raw = (key: string) => window.localStorage.getItem(key);
  // The token is the one credential that never touches localStorage —
  // sessionStorage only (opt-in), so it dies with the tab.
  const rawSession = (key: string) => window.sessionStorage.getItem(key);
  return {
    apiBase: raw(LS_API_BASE) ?? "",
    token: rawSession(SS_TOKEN) ?? "",
    org: raw(LS_ORG) ?? "",
    project: raw(LS_PROJECT) ?? "",
    env: raw(LS_ENV) ?? "",
    hasBase: raw(LS_API_BASE) !== null,
    hasToken: rawSession(SS_TOKEN) !== null,
    hasOrg: raw(LS_ORG) !== null,
    hasProject: raw(LS_PROJECT) !== null,
    hasEnv: raw(LS_ENV) !== null,
  };
}

/**
 * Apply persisted settings over the build-time env defaults: base/scope from
 * localStorage, token from sessionStorage (opt-in "remember"). Keys that were
 * explicitly stored (even as "") win; unset keys defer to env.
 */
export function hydrateApiFromStorage(): void {
  const stored = loadStoredConfig();
  if (stored.hasBase) runtimeApiBase = normalizeBase(stored.apiBase);
  // Token: sessionStorage copy (when remembered) wins over the build-time env
  // value; with neither, the runtime token stays empty and requests go out
  // unauthenticated. The old "fall back to a dev token" behavior is gone.
  if (stored.hasToken) runtimeToken = stored.token.trim();
  // Scrub the legacy localStorage token written by earlier consoles (#42).
  if (typeof window !== "undefined") window.localStorage.removeItem(SS_TOKEN);
  if (stored.hasOrg) runtimeOrg = stored.org.trim() || DEFAULT_ORG;
  if (stored.hasProject) runtimeProject = stored.project.trim() || DEFAULT_PROJECT;
  if (stored.hasEnv) runtimeEnv = stored.env.trim() || DEFAULT_ENV;
}

export interface StoreConfigOptions {
  /**
   * Opt-in persistence for the bearer token: sessionStorage for this tab
   * only. When false the token is applied to the in-memory runtime store and
   * nothing is written to any storage.
   */
  rememberToken?: boolean;
}

/** Persist the given settings; also applies them to the runtime store. */
export function storeConfig(
  apiBase: string,
  token: string,
  scope?: Partial<ScopeConfig>,
  opts?: StoreConfigOptions,
): void {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(LS_API_BASE, normalizeBase(apiBase));
    if (opts?.rememberToken && token.trim()) {
      window.sessionStorage.setItem(SS_TOKEN, token.trim());
    } else {
      window.sessionStorage.removeItem(SS_TOKEN);
    }
    if (scope?.org !== undefined) window.localStorage.setItem(LS_ORG, scope.org.trim());
    if (scope?.project !== undefined) window.localStorage.setItem(LS_PROJECT, scope.project.trim());
    if (scope?.env !== undefined) window.localStorage.setItem(LS_ENV, scope.env.trim());
  }
  configureApi({ apiBase, token, ...scope });
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

// ---- failure reasons (operator-actionable, per issue #41) ----

/** Why a network-level fetch failed — timeout vs. unreachable vs. malformed. */
export function failureReason(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError")) {
    return `request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`;
  }
  if (err instanceof SyntaxError) return "control plane returned a malformed response";
  return "unreachable — check --cors-origins / base URL";
}

/** Why an HTTP-level failure happened — 401/403 are called out as token issues. */
export function httpReason(status: number): string {
  if (status === 401 || status === 403) return `invalid token (HTTP ${status})`;
  return `control plane returned HTTP ${status}`;
}

/** Human line for mutation failures and the connection test. */
function describeFailure(err: unknown, base: string): string {
  if (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError")) {
    return `request to ${base} timed out`;
  }
  return `cannot reach control plane at ${base} — ${failureReason(err)}`;
}

/**
 * Combine the caller's abort signal with a hard per-request deadline.
 * The combined signal fires when EITHER source trips, so a superseded poll is
 * cancelled immediately and no request can hang past REQUEST_TIMEOUT_MS.
 */
function requestSignal(external?: AbortSignal): AbortSignal {
  const deadline = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  if (!external) return deadline;
  // AbortSignal.any is available in all modern engines; on the off-chance an
  // older engine lacks it, the deadline still bounds the request.
  if (typeof AbortSignal.any === "function") return AbortSignal.any([external, deadline]);
  return deadline;
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
        ...authHeader(getApiToken()),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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
      demoResources().find(
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
      headers: authHeader(token),
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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

// ---- read paths with per-fetch health (issue #41) ----

export type FetchHealth = "ok" | "degraded" | "error";

/**
 * Result of a console read. `status` — not configuration — is what the UI
 * badges are computed from, so a dead control plane can never look "Live".
 */
export interface FetchResult<T> {
  data: T;
  status: FetchHealth;
  /** Epoch ms when `data` was fetched from the control plane ("last good" time when degraded). */
  at: number;
  /** Present when status !== "ok": operator-actionable failure reason. */
  reason?: string;
}

/**
 * Last good feed data, keyed by wire path. In live mode a failed read falls
 * back to this (status "degraded") instead of demo data. Cleared whenever the
 * runtime config changes so stale data from a previous control plane is never
 * presented as current.
 */
const lastGood = new Map<string, { data: unknown; at: number }>();

interface ResourcePage {
  items: Resource[];
  next_cursor?: string;
}

/**
 * GET /v1/resources following `next_cursor` until exhausted. Hard caps at
 * RESOURCE_TOTAL_CAP items and guards against control planes that keep
 * returning the same cursor (tracked in `seen`). Pages are pushed into `into`
 * as they arrive, so a mid-pagination failure still leaves the partial page
 * inspectable by the caller.
 */
async function listAllResources(into: Resource[], signal?: AbortSignal): Promise<Resource[]> {
  const base = getApiBase();
  const seenCursors = new Set<string>();
  let cursor = "";

  while (into.length < RESOURCE_TOTAL_CAP) {
    const qs = new URLSearchParams({ limit: String(RESOURCE_PAGE_LIMIT) });
    if (cursor) qs.set("cursor", cursor);
    const res = await fetch(`${base}/v1/resources?${qs.toString()}`, {
      headers: { "Content-Type": "application/json", ...authHeader(getApiToken()) },
      cache: "no-store",
      signal: requestSignal(signal),
    });
    if (!res.ok) throw new ApiError(res.status, `http_${res.status}`, httpReason(res.status));
    const page = (await res.json()) as ResourcePage;
    into.push(...(page.items ?? []));

    const next = typeof page.next_cursor === "string" ? page.next_cursor : "";
    if (!next || seenCursors.has(next) || into.length >= RESOURCE_TOTAL_CAP) break;
    seenCursors.add(next);
    cursor = next;
  }

  return into.slice(0, RESOURCE_TOTAL_CAP);
}

/** Single-request feed with last-good fallback. Never throws. */
async function fetchFeed<T>(
  path: string,
  demo: () => T,
  empty: () => T,
  opts?: { signal?: AbortSignal },
): Promise<FetchResult<T>> {
  // Demo data ONLY when no API base is configured — that is the mode.
  if (!getApiBase()) {
    return { data: demo(), status: "ok", at: Date.now() };
  }
  const base = getApiBase();
  try {
    const res = await fetch(`${base}${path}`, {
      headers: { "Content-Type": "application/json", ...authHeader(getApiToken()) },
      cache: "no-store",
      signal: requestSignal(opts?.signal),
    });
    if (!res.ok) throw new ApiError(res.status, `http_${res.status}`, httpReason(res.status));
    const data = (await res.json()) as T;
    const now = Date.now();
    lastGood.set(path, { data, at: now });
    return { data, status: "ok", at: now };
  } catch (err) {
    const reason = failureReason(err);
    const cached = lastGood.get(path) as { data: T; at: number } | undefined;
    if (cached) return { data: cached.data, status: "degraded", at: cached.at, reason };
    return { data: empty(), status: "error", at: Date.now(), reason };
  }
}

/**
 * Resources list: paginated (follows next_cursor up to the 1000-item cap).
 * In live mode, NEVER returns demo data — a total failure yields
 * status "error" with an empty list, a mid-pagination failure yields the
 * partial page as "degraded" (fresher than any cached snapshot).
 */
export async function fetchResources(opts?: { signal?: AbortSignal }): Promise<FetchResult<Resource[]>> {
  if (!getApiBase()) {
    return { data: demoResources(), status: "ok", at: Date.now() };
  }
  const key = "/v1/resources";
  const partial: Resource[] = [];
  try {
    const items = await listAllResources(partial, opts?.signal);
    const now = Date.now();
    lastGood.set(key, { data: items, at: now });
    return { data: items, status: "ok", at: now };
  } catch (err) {
    const reason = failureReason(err);
    // Partial page from this attempt? Show it (clearly degraded) rather than
    // silently replacing fresher data with an older full snapshot.
    if (partial.length > 0) {
      return { data: partial, status: "degraded", at: Date.now(), reason: `${reason} — partial list (${partial.length} items)` };
    }
    const cached = lastGood.get(key) as { data: Resource[]; at: number } | undefined;
    if (cached) return { data: cached.data, status: "degraded", at: cached.at, reason };
    return { data: [], status: "error", at: Date.now(), reason };
  }
}

/** Events for the configured org (newest first, limit 100). */
export function fetchEvents(opts?: { signal?: AbortSignal }): Promise<FetchResult<{ events: RyvexEvent[] }>> {
  const org = encodeURIComponent(getOrg());
  return fetchFeed<{ events: RyvexEvent[] }>(
    `/v1/${org}/events?limit=100`,
    () => ({ events: demoEvents() }),
    () => ({ events: [] }),
    opts,
  );
}

/** Audit entries for the configured org (newest first, limit 100). */
export function fetchAudit(opts?: { signal?: AbortSignal }): Promise<FetchResult<{ entries: AuditEntry[] }>> {
  const org = encodeURIComponent(getOrg());
  return fetchFeed<{ entries: AuditEntry[] }>(
    `/v1/${org}/audit?limit=100`,
    () => ({ entries: demoAudit() }),
    () => ({ entries: [] }),
    opts,
  );
}
