/**
 * Ryvex — TypeScript client for the Ryvex control plane REST API
 * (the `/v1` face, contract frozen in docs/api-contracts.md).
 *
 * Every request carries `Authorization: Bearer <token>` and
 * `Content-Type: application/json`. Non-2xx responses throw a
 * {@link RyvexError} parsed from the frozen error envelope.
 */
import { RyvexError } from "./errors.js";
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

export interface RyvexClientOptions {
  /** Root of the daemon, e.g. "http://127.0.0.1:8080". The /v1 prefix is appended per call. */
  baseUrl: string;
  /** Bearer token (ryk_…). */
  token: string;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
}

type QueryParams = Record<string, string | number | undefined>;

export class Ryvex {
  readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: RyvexClientOptions) {
    if (!opts || typeof opts.baseUrl !== "string" || opts.baseUrl.length === 0) {
      throw new TypeError("ryvex: opts.baseUrl is required");
    }
    if (!opts || typeof opts.token !== "string" || opts.token.length === 0) {
      throw new TypeError("ryvex: opts.token is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
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
  async health(): Promise<HealthInfo> {
    return await this.requestJson<HealthInfo>("GET", "/healthz");
  }

  /** Machine-readable endpoint list. GET /v1. */
  async index(): Promise<ApiIndex> {
    return await this.requestJson<ApiIndex>("GET", "/v1");
  }

  // ---- resources (handle-addressed) ----

  /** Create a resource at a fresh address. POST /v1/resources → 201. */
  async createResource(doc: CreateResourceInput): Promise<Resource> {
    return await this.requestJson<Resource>("POST", "/v1/resources", { body: doc });
  }

  /** Fetch a resource by opaque ID. GET /v1/resources/{id}. */
  async getResource(id: string): Promise<Resource> {
    return await this.requestJson<Resource>("GET", `/v1/resources/${seg(id)}`);
  }

  /** Delete a resource by opaque ID. DELETE /v1/resources/{id} → 204. */
  async deleteResource(id: string): Promise<void> {
    await this.request("DELETE", `/v1/resources/${seg(id)}`);
  }

  /**
   * Fetch one filtered page. GET /v1/resources?org=&project=&env=&kind=&limit=&cursor=.
   * `next_cursor` is "" on the last page.
   */
  async listResources(opts: ListOptions = {}): Promise<Page<Resource>> {
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
      },
    );
    return { items: body.items ?? [], next_cursor: body.next_cursor ?? "" };
  }

  /**
   * Iterate every resource matching `opts` across all pages, following
   * the `next_cursor` chain until it is "". Lazily fetched: each `for
   * await` turn issues at most one HTTP request.
   */
  async *listAll(opts: ListOptions = {}): AsyncGenerator<Resource, void, undefined> {
    let cursor = opts.cursor ?? "";
    const seen = new Set<string>();
    do {
      seen.add(cursor);
      const page = await this.listResources({ ...opts, cursor });
      for (const item of page.items) {
        yield item;
      }
      cursor = page.next_cursor;
    } while (cursor !== "" && !seen.has(cursor));
  }

  // ---- resources (scope-addressed) ----

  /** Fetch by logical address. GET /v1/{org}/{project}/{env}/{kind}/{name}. */
  async getInScope(org: string, project: string, env: string, kind: string, name: string): Promise<Resource> {
    return await this.requestJson<Resource>(
      "GET",
      `/v1/${seg(org)}/${seg(project)}/${seg(env)}/${seg(kind)}/${seg(name)}`,
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
  ): Promise<Resource> {
    return await this.requestJson<Resource>(
      "PUT",
      `/v1/${seg(org)}/${seg(project)}/${seg(env)}/${seg(kind)}/${seg(name)}`,
      { body: doc },
    );
  }

  /** Delete by logical address. DELETE /v1/{org}/{project}/{env}/{kind}/{name} → 204. */
  async deleteInScope(org: string, project: string, env: string, kind: string, name: string): Promise<void> {
    await this.request("DELETE", `/v1/${seg(org)}/${seg(project)}/${seg(env)}/${seg(kind)}/${seg(name)}`);
  }

  // ---- observability & control ----

  /** Recent bus events for an org, newest first. GET /v1/{org}/events?limit=. */
  async events(org: string, opts: EventsOptions = {}): Promise<EventsPage> {
    const body = await this.requestJson<{ events?: RyvexEvent[]; count?: number }>(
      "GET",
      `/v1/${seg(org)}/events`,
      { query: { limit: opts.limit } },
    );
    return { events: body.events ?? [], count: body.count ?? body.events?.length ?? 0 };
  }

  /** Audit entries for an org, newest first. GET /v1/{org}/audit?kind=&limit=. */
  async audit(org: string, opts: AuditOptions = {}): Promise<AuditPage> {
    const body = await this.requestJson<{ entries?: AuditEntry[]; count?: number }>(
      "GET",
      `/v1/${seg(org)}/audit`,
      { query: { kind: opts.kind, limit: opts.limit } },
    );
    return { entries: body.entries ?? [], count: body.count ?? body.entries?.length ?? 0 };
  }

  /** Trigger an immediate reconcile. POST /v1/{org}/reconcile/{id} → 202. */
  async triggerReconcile(org: string, id: string): Promise<ReconcileAck> {
    return await this.requestJson<ReconcileAck>("POST", `/v1/${seg(org)}/reconcile/${seg(id)}`);
  }

  // ---- internals ----

  /** Issue a request and return the raw Response (2xx guaranteed, else throws). */
  private async request(
    method: string,
    path: string,
    opts: { body?: unknown; query?: QueryParams } = {},
  ): Promise<Response> {
    const url = this.buildUrl(path, opts.query);
    const init: RequestInit = {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    };
    if (opts.body !== undefined) {
      init.body = JSON.stringify(opts.body);
    }

    let res: Response;
    try {
      res = await this.fetchImpl(url, init);
    } catch (err) {
      throw RyvexError.fromTransport(err, url);
    }
    if (!res.ok) {
      const text = await safeText(res);
      throw RyvexError.fromResponse(res.status, text);
    }
    return res;
  }

  /** Like {@link Ryvex.request} but JSON-decodes a non-empty 2xx body. */
  private async requestJson<T>(
    method: string,
    path: string,
    opts: { body?: unknown; query?: QueryParams } = {},
  ): Promise<T> {
    const res = await this.request(method, path, opts);
    const text = await safeText(res);
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
