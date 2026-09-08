/**
 * Ryvex — TypeScript client for the Ryvex control plane REST API
 * (the `/v1` face, contract frozen in docs/api-contracts.md).
 *
 * Every request carries `Authorization: Bearer <token>` and
 * `Content-Type: application/json`. Non-2xx responses throw a
 * {@link RyvexError} parsed from the frozen error envelope. Requests
 * are bounded by `timeoutMs` (default 15 s) and an optional per-call
 * AbortSignal — cancellations reject with `code: "timeout"`.
 */
import { RyvexError, isAbortCause } from "./errors.js";
import type {
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
  RyvexEvent,
  UpsertResourceInput,
} from "./types.js";

/** Default per-request timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Per-call overrides, accepted as the trailing argument of every public
 * method.
 */
export interface CallOptions {
  /**
   * AbortSignal for this single request. Firing it cancels the
   * in-flight call, which rejects with a {@link RyvexError} of
   * `code: "timeout"`, `status: 0`. Combined with the client-level
   * `timeoutMs` — whichever fires first wins.
   */
  signal?: AbortSignal;
}

export interface RyvexClientOptions {
  /** Root of the daemon, e.g. "http://127.0.0.1:8080". The /v1 prefix is appended per call. */
  baseUrl: string;
  /** Bearer token (ryk_…). */
  token: string;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
  /**
   * Per-request timeout in milliseconds (default {@link DEFAULT_TIMEOUT_MS}).
   * Implemented with `AbortSignal.timeout` when the runtime provides it
   * and an `AbortController` + timer fallback elsewhere. `0` disables
   * the client-side timeout entirely.
   */
  timeoutMs?: number;
}

type QueryParams = Record<string, string | number | undefined>;

/** Internal shape threaded from the public methods into request(). */
interface RequestOptions {
  body?: unknown;
  query?: QueryParams;
  signal?: AbortSignal;
}

export class Ryvex {
  readonly baseUrl: string;
  /** Effective per-request timeout in milliseconds (0 = disabled). */
  readonly timeoutMs: number;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: RyvexClientOptions) {
    if (!opts || typeof opts.baseUrl !== "string" || opts.baseUrl.length === 0) {
      throw new TypeError("ryvex: opts.baseUrl is required");
    }
    if (!opts || typeof opts.token !== "string" || opts.token.length === 0) {
      throw new TypeError("ryvex: opts.token is required");
    }
    if (
      opts.timeoutMs !== undefined &&
      (typeof opts.timeoutMs !== "number" || !Number.isFinite(opts.timeoutMs) || opts.timeoutMs < 0)
    ) {
      throw new TypeError(
        "ryvex: opts.timeoutMs must be a non-negative finite number of milliseconds (0 disables the timeout)",
      );
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.token = opts.token;
    if (typeof opts.fetch === "function") {
      this.fetchImpl = opts.fetch;
    } else if (typeof globalThis.fetch === "function") {
      this.fetchImpl = globalThis.fetch.bind(globalThis);
    } else {
      throw new TypeError(
        "ryvex: no fetch implementation available; pass `fetch` in opts (required on Node < 18)",
      );
    }
  }

  // ---- service ----

  /** Liveness probe. GET /healthz (unauthenticated on the server). */
  async health(callOpts: CallOptions = {}): Promise<HealthInfo> {
    return await this.requestJson<HealthInfo>("GET", "/healthz", { signal: callOpts?.signal });
  }

  /** Machine-readable endpoint list. GET /v1. */
  async index(callOpts: CallOptions = {}): Promise<ApiIndex> {
    return await this.requestJson<ApiIndex>("GET", "/v1", { signal: callOpts?.signal });
  }

  // ---- resources (handle-addressed) ----

  /** Create a resource at a fresh address. POST /v1/resources → 201. */
  async createResource(doc: CreateResourceInput, callOpts: CallOptions = {}): Promise<Resource> {
    return await this.requestJson<Resource>("POST", "/v1/resources", { body: doc, signal: callOpts?.signal });
  }

  /** Fetch a resource by opaque ID. GET /v1/resources/{id}. */
  async getResource(id: string, callOpts: CallOptions = {}): Promise<Resource> {
    return await this.requestJson<Resource>("GET", `/v1/resources/${seg(id)}`, { signal: callOpts?.signal });
  }

  /** Delete a resource by opaque ID. DELETE /v1/resources/{id} → 204. */
  async deleteResource(id: string, callOpts: CallOptions = {}): Promise<void> {
    await this.request("DELETE", `/v1/resources/${seg(id)}`, { signal: callOpts?.signal });
  }

  /**
   * Fetch one filtered page. GET /v1/resources?org=&project=&env=&kind=&limit=&cursor=.
   * `next_cursor` is "" on the last page.
   */
  async listResources(opts: ListOptions = {}, callOpts: CallOptions = {}): Promise<Page<Resource>> {
    const body = await this.requestJson<{ items?: Resource[]; next_cursor?: string }>(
      "GET",
      "/v1/resources",
      {
        query: {
          org: opts.org,
          project: opts.project,
          env: opts.env,
          kind: opts.kind,
          limit: opts.limit,
          cursor: opts.cursor,
        },
        signal: callOpts?.signal,
      },
    );
    return { items: body.items ?? [], next_cursor: body.next_cursor ?? "" };
  }

  /**
   * Iterate every resource matching `opts` across all pages, following
   * the `next_cursor` chain until it is "". Lazily fetched: each `for
   * await` turn issues at most one HTTP request.
   */
  async *listAll(
    opts: ListOptions = {},
    callOpts: CallOptions = {},
  ): AsyncGenerator<Resource, void, undefined> {
    let cursor = opts.cursor ?? "";
    const seen = new Set<string>();
    do {
      seen.add(cursor);
      const page = await this.listResources({ ...opts, cursor }, callOpts);
      for (const item of page.items) {
        yield item;
      }
      cursor = page.next_cursor;
    } while (cursor !== "" && !seen.has(cursor));
  }

  // ---- resources (scope-addressed) ----

  /** Fetch by logical address. GET /v1/{org}/{project}/{env}/{kind}/{name}. */
  async getInScope(
    org: string,
    project: string,
    env: string,
    kind: string,
    name: string,
    callOpts: CallOptions = {},
  ): Promise<Resource> {
    return await this.requestJson<Resource>(
      "GET",
      `/v1/${seg(org)}/${seg(project)}/${seg(env)}/${seg(kind)}/${seg(name)}`,
      { signal: callOpts?.signal },
    );
  }

  /**
   * Upsert by logical address. PUT /v1/{org}/{project}/{env}/{kind}/{name}.
   *
   * Returns 201's stored doc when the address was fresh (created) and
   * 200's when it already existed (updated).
   *
   * Optimistic concurrency (CAS): pass `doc.generation` — the value you
   * previously read — to fail with a 409 `conflict` {@link RyvexError}
   * if the stored generation moved. Omit it for last-writer-wins.
   */
  async putInScope(
    org: string,
    project: string,
    env: string,
    kind: string,
    name: string,
    doc: UpsertResourceInput,
    callOpts: CallOptions = {},
  ): Promise<Resource> {
    return await this.requestJson<Resource>(
      "PUT",
      `/v1/${seg(org)}/${seg(project)}/${seg(env)}/${seg(kind)}/${seg(name)}`,
      { body: doc, signal: callOpts?.signal },
    );
  }

  /** Delete by logical address. DELETE /v1/{org}/{project}/{env}/{kind}/{name} → 204. */
  async deleteInScope(
    org: string,
    project: string,
    env: string,
    kind: string,
    name: string,
    callOpts: CallOptions = {},
  ): Promise<void> {
    await this.request("DELETE", `/v1/${seg(org)}/${seg(project)}/${seg(env)}/${seg(kind)}/${seg(name)}`, {
      signal: callOpts?.signal,
    });
  }

  // ---- observability & control ----

  /** Recent bus events for an org, newest first. GET /v1/{org}/events?limit=. */
  async events(org: string, opts: EventsOptions = {}, callOpts: CallOptions = {}): Promise<EventsPage> {
    const body = await this.requestJson<{ events?: RyvexEvent[]; count?: number }>(
      "GET",
      `/v1/${seg(org)}/events`,
      { query: { limit: opts.limit }, signal: callOpts?.signal },
    );
    return { events: body.events ?? [], count: body.count ?? body.events?.length ?? 0 };
  }

  /** Audit entries for an org, newest first. GET /v1/{org}/audit?kind=&limit=. */
  async audit(org: string, opts: AuditOptions = {}, callOpts: CallOptions = {}): Promise<AuditPage> {
    const body = await this.requestJson<{ entries?: AuditEntry[]; count?: number }>(
      "GET",
      `/v1/${seg(org)}/audit`,
      { query: { kind: opts.kind, limit: opts.limit }, signal: callOpts?.signal },
    );
    return { entries: body.entries ?? [], count: body.count ?? body.entries?.length ?? 0 };
  }

  /** Trigger an immediate reconcile. POST /v1/{org}/reconcile/{id} → 202. */
  async triggerReconcile(org: string, id: string, callOpts: CallOptions = {}): Promise<ReconcileAck> {
    return await this.requestJson<ReconcileAck>("POST", `/v1/${seg(org)}/reconcile/${seg(id)}`, {
      signal: callOpts?.signal,
    });
  }

  // ---- internals ----

  /**
   * Issue a request and return the raw Response (2xx guaranteed, else
   * throws). The abort signal handed to fetch combines the client-level
   * `timeoutMs` timer with the optional per-call signal; rejections are
   * mapped to `code: "timeout"` (abort/timeout) or
   * `code: "transport_error"` (connection failure), both status 0.
   */
  private async request(method: string, path: string, opts: RequestOptions = {}): Promise<Response> {
    const url = this.buildUrl(path, opts.query);
    const { signal, dispose } = this.wireSignal(opts.signal);
    const init: RequestInit = {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      signal,
    };
    if (opts.body !== undefined) {
      init.body = JSON.stringify(opts.body);
    }

    try {
      const res = await this.fetchImpl(url, init);
      if (!res.ok) {
        const text = await readBody(res, (cause) => this.mapFetchError(cause, url, opts.signal));
        throw RyvexError.fromResponse(res.status, text);
      }
      return res;
    } catch (err) {
      if (err instanceof RyvexError) throw err;
      throw this.mapFetchError(err, url, opts.signal);
    } finally {
      dispose();
    }
  }

  /** Like {@link Ryvex.request} but JSON-decodes a non-empty 2xx body. */
  private async requestJson<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const res = await this.request(method, path, opts);
    const url = this.buildUrl(path, opts.query);
    const text = await readBody(res, (cause) => this.mapFetchError(cause, url, opts.signal));
    if (text.length === 0) {
      // 204 / empty 2xx — hand back a permissive empty object.
      return {} as T;
    }
    try {
      return JSON.parse(text) as T;
    } catch (err) {
      throw new RyvexError(res.status, "internal_error", `invalid JSON in response from ${path}`, { cause: err });
    }
  }

  /**
   * Combine the client timeout with an optional per-call signal into the
   * single AbortSignal handed to fetch, plus a `dispose` callback that
   * detaches any relay listeners once the response headers arrived.
   *
   * - Timeout: `AbortSignal.timeout` when the runtime has it, else an
   *   `AbortController` fired by a timer (old browsers / Node < 17.3).
   * - Merging: `AbortSignal.any` when available, else listeners relay
   *   the caller's abort into a controller.
   */
  private wireSignal(external: AbortSignal | undefined): { signal: AbortSignal | undefined; dispose: () => void } {
    const noop = () => {};
    const timed = Number.isFinite(this.timeoutMs) && this.timeoutMs > 0;
    if (!timed || external?.aborted) {
      return { signal: external, dispose: noop };
    }
    const timeoutSignal = makeTimeoutSignal(this.timeoutMs);
    if (!external) {
      return { signal: timeoutSignal, dispose: noop };
    }
    const signalCtor = AbortSignal as AbortSignalCtor;
    if (typeof signalCtor.any === "function") {
      return { signal: signalCtor.any([timeoutSignal, external]), dispose: noop };
    }
    // Relay fallback: forward the caller's abort into one controller.
    const relay = new AbortController();
    const abortFromCaller = () => relay.abort(external.reason);
    const abortFromTimer = () => relay.abort();
    external.addEventListener("abort", abortFromCaller, { once: true });
    timeoutSignal.addEventListener("abort", abortFromTimer, { once: true });
    return {
      signal: relay.signal,
      dispose: () => {
        external.removeEventListener("abort", abortFromCaller);
        timeoutSignal.removeEventListener("abort", abortFromTimer);
      },
    };
  }

  /** Map a fetch/body rejection to timeout-vs-transport RyvexError. */
  private mapFetchError(cause: unknown, url: string, external: AbortSignal | undefined): RyvexError {
    if (isAbortCause(cause)) {
      return RyvexError.fromAbort(cause, url, external?.aborted === true, this.timeoutMs);
    }
    return RyvexError.fromTransport(cause, url);
  }

  private buildUrl(path: string, query?: QueryParams): string {
    let url = `${this.baseUrl}${path}`;
    const search = encodeQuery(query);
    if (search.length > 0) {
      url += `?${search}`;
    }
    return url;
  }
}

/** encodeURIComponent, but typed for path segments. */
function seg(value: string): string {
  return encodeURIComponent(value);
}

/** AbortSignal statics that may be missing on older runtimes. */
type AbortSignalCtor = typeof AbortSignal & {
  any?: (signals: AbortSignal[]) => AbortSignal;
  timeout?: (ms: number) => AbortSignal;
};

/**
 * An AbortSignal that fires after `ms` milliseconds: `AbortSignal.timeout`
 * where available, an `AbortController` + timer fallback elsewhere.
 */
function makeTimeoutSignal(ms: number): AbortSignal {
  const ctor = AbortSignal as AbortSignalCtor;
  if (typeof ctor.timeout === "function") {
    return ctor.timeout(ms);
  }
  const controller = new AbortController();
  const timer: ReturnType<typeof setTimeout> = setTimeout(() => controller.abort(), ms);
  unrefTimer(timer); // a pending fallback timer must not keep the process alive
  return controller.signal;
}

/** Node/Bun timers expose unref(); browser setTimeout returns a number. */
function unrefTimer(timer: unknown): void {
  if (typeof timer === "object" && timer !== null && "unref" in timer) {
    (timer as { unref: () => void }).unref();
  }
}

/**
 * Read a response body as text. Tolerates ordinary body failures
 * (returning ""), but re-raises aborts — mapped through `onAbort` — so
 * a timeout that fires mid-body still surfaces as `code: "timeout"`.
 */
async function readBody(res: Response, onAbort: (cause: unknown) => RyvexError): Promise<string> {
  try {
    return await res.text();
  } catch (err) {
    if (isAbortCause(err)) throw onAbort(err);
    return "";
  }
}

/** URLSearchParams builder that drops undefined/empty values. */
function encodeQuery(query?: QueryParams): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === "") continue;
    params.set(key, String(value));
  }
  return params.toString();
}

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
