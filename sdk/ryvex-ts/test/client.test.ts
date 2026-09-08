/**
 * Unit tests for the Ryvex TypeScript client.
 *
 * All tests run against a mocked `fetch` — no network access, no live
 * daemon. They pin down: URL paths, HTTP methods, headers, JSON bodies
 * (including the CAS `generation` field), cursor pagination sequencing
 * and frozen error-envelope parsing.
 */
import { describe, expect, test } from "bun:test";
import { Ryvex, RyvexError } from "../src/index.js";
import type { CreateResourceInput, Resource } from "../src/index.js";

const BASE = "http://127.0.0.1:18201";
const TOKEN = "ryk_test_agent";

// ---- mock fetch harness ----

interface RecordedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
  signal?: AbortSignal;
}

type Handler = (req: RecordedRequest, init?: RequestInit) => Response | Promise<Response>;

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function emptyResponse(status: number, headers: Record<string, string> = {}): Response {
  return new Response(null, { status, headers });
}

function textResponse(status: number, body: string): Response {
  return new Response(body, { status, headers: { "content-type": "text/html" } });
}

function mockFetch(handler: Handler): { fetch: typeof fetch; requests: RecordedRequest[] } {
  const requests: RecordedRequest[] = [];
  const fn = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const headers = new Headers(init?.headers);
    const req: RecordedRequest = {
      url,
      method: init?.method ?? "GET",
      headers,
      body: typeof init?.body === "string" ? init.body : undefined,
      signal: init?.signal instanceof AbortSignal ? init.signal : undefined,
    };
    requests.push(req);
    return await handler(req, init);
  };
  return { fetch: fn as unknown as typeof fetch, requests };
}

function clientWith(handler: Handler): { client: Ryvex; requests: RecordedRequest[] } {
  const { fetch, requests } = mockFetch(handler);
  return { client: new Ryvex({ baseUrl: BASE, token: TOKEN, fetch }), requests };
}

function sampleResource(over: Partial<Resource> = {}): Resource {
  return {
    id: "r-00b52b6eb859f432",
    kind: "Application",
    org: "acme",
    project: "core",
    env: "prod",
    name: "checkout",
    generation: 1,
    labels: { "managed-by": "ryvex", team: "payments" },
    spec: { image: "registry.acme.io/checkout:1.42.0", replicas: 4 },
    status: { phase: "Pending", observed_generation: 0, updated_at: "2026-09-08T09:00:00Z" },
    created_at: "2026-09-08T08:59:59Z",
    updated_at: "2026-09-08T09:00:00Z",
    ...over,
  };
}

function errorEnvelope(
  status: number,
  code: string,
  message: string,
  requestId = "e3b0c44298fc",
  details: string[] = [],
): Response {
  return jsonResponse(status, { error: { code, message, request_id: requestId, details } });
}

// ---- constructor ----

describe("constructor", () => {
  test("rejects missing baseUrl", () => {
    // @ts-expect-error — probing runtime validation of required fields
    expect(() => new Ryvex({ token: TOKEN })).toThrow(TypeError);
  });

  test("rejects missing token", () => {
    // @ts-expect-error — probing runtime validation of required fields
    expect(() => new Ryvex({ baseUrl: BASE })).toThrow(TypeError);
  });

  test("strips trailing slashes from baseUrl", async () => {
    const { fetch, requests } = mockFetch(() => jsonResponse(200, { status: "ok" }));
    const loose = new Ryvex({ baseUrl: `${BASE}/`, token: TOKEN, fetch });
    expect(loose.baseUrl).toBe(BASE);
    await loose.health();
    expect(requests[0]?.url).toBe(`${BASE}/healthz`);
  });
});

// ---- service ----

describe("health + index", () => {
  test("health() GETs /healthz with bearer headers", async () => {
    const { client, requests } = clientWith(() =>
      jsonResponse(200, { status: "ok", service: "ryvexd", version: "v1.0.0", resources: 15, time: "2026-09-08T09:00:00Z" }),
    );
    const health = await client.health();
    const req = requests[0];
    expect(req?.url).toBe(`${BASE}/healthz`);
    expect(req?.method).toBe("GET");
    expect(req?.headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
    expect(req?.headers.get("Content-Type")).toBe("application/json");
    expect(health.status).toBe("ok");
    expect(health.version).toBe("v1.0.0");
  });

  test("index() GETs /v1", async () => {
    const { client, requests } = clientWith(() =>
      jsonResponse(200, { name: "Ryvex Control Plane API", version: "v1.0.0", endpoints: ["GET /healthz"], docs: "docs/api-contracts.md" }),
    );
    const index = await client.index();
    expect(requests[0]?.url).toBe(`${BASE}/v1`);
    expect(requests[0]?.method).toBe("GET");
    expect(index.name).toBe("Ryvex Control Plane API");
  });
});

// ---- handle-addressed resources ----

describe("handle-addressed resources", () => {
  test("createResource() POSTs the document to /v1/resources", async () => {
    const doc: CreateResourceInput = {
      kind: "Application",
      org: "acme",
      project: "core",
      env: "prod",
      name: "checkout",
      labels: { "managed-by": "ryvex", team: "payments" },
      spec: { image: "registry.acme.io/checkout:1.42.0", replicas: 4 },
    };
    const { client, requests } = clientWith((req) => {
      expect(JSON.parse(req.body ?? "{}")).toEqual(doc);
      return jsonResponse(201, sampleResource());
    });
    const created = await client.createResource(doc);
    const req = requests[0];
    expect(req?.url).toBe(`${BASE}/v1/resources`);
    expect(req?.method).toBe("POST");
    expect(created.id).toBe("r-00b52b6eb859f432");
    expect(created.generation).toBe(1);
  });

  test("getResource() GETs /v1/resources/{id}", async () => {
    const { client, requests } = clientWith(() => jsonResponse(200, sampleResource()));
    const res = await client.getResource("r-00b52b6eb859f432");
    expect(requests[0]?.url).toBe(`${BASE}/v1/resources/r-00b52b6eb859f432`);
    expect(requests[0]?.method).toBe("GET");
    expect(res.name).toBe("checkout");
  });

  test("deleteResource() DELETEs and tolerates an empty 204 body", async () => {
    const { client, requests } = clientWith(() => emptyResponse(204));
    await expect(client.deleteResource("r-00b52b6eb859f432")).resolves.toBeUndefined();
    const req = requests[0];
    expect(req?.url).toBe(`${BASE}/v1/resources/r-00b52b6eb859f432`);
    expect(req?.method).toBe("DELETE");
  });

  test("listResources() forwards filters as query params and normalizes the page", async () => {
    const { client, requests } = clientWith(() =>
      jsonResponse(200, { items: [sampleResource()], next_cursor: "c-next" }),
    );
    const page = await client.listResources({ org: "acme", kind: "applications", limit: 50, cursor: "c1" });
    expect(requests[0]?.url).toBe(`${BASE}/v1/resources?org=acme&kind=applications&limit=50&cursor=c1`);
    expect(page.items).toHaveLength(1);
    expect(page.next_cursor).toBe("c-next");
  });

  test("listResources() omits unset filters and tolerates a null items array", async () => {
    const { client, requests } = clientWith(() => jsonResponse(200, { items: null, next_cursor: "" }));
    const page = await client.listResources();
    expect(requests[0]?.url).toBe(`${BASE}/v1/resources`);
    expect(page.items).toEqual([]);
    expect(page.next_cursor).toBe("");
  });
});

// ---- pagination ----

describe("listAll() auto-pagination", () => {
  test("follows next_cursor across pages in order", async () => {
    const a = sampleResource({ id: "r-a", name: "alpha" });
    const b = sampleResource({ id: "r-b", name: "beta" });
    const c = sampleResource({ id: "r-c", name: "gamma" });
    const { client, requests } = clientWith((req) => {
      if (req.url === `${BASE}/v1/resources?org=acme&limit=2&cursor=c2`) {
        return jsonResponse(200, { items: [c], next_cursor: "" });
      }
      // first page (two items), continuation token set
      return jsonResponse(200, { items: [a, b], next_cursor: "c2" });
    });

    const seen: string[] = [];
    for await (const res of client.listAll({ org: "acme", limit: 2 })) {
      seen.push(res.id);
    }

    expect(seen).toEqual(["r-a", "r-b", "r-c"]);
    expect(requests).toHaveLength(2);
    expect(requests[0]?.url).toBe(`${BASE}/v1/resources?org=acme&limit=2`);
    expect(requests[1]?.url).toBe(`${BASE}/v1/resources?org=acme&limit=2&cursor=c2`);
  });

  test("yields nothing and makes exactly one request on an empty store", async () => {
    const { client, requests } = clientWith(() => jsonResponse(200, { items: [], next_cursor: "" }));
    const seen: string[] = [];
    for await (const res of client.listAll()) {
      seen.push(res.id);
    }
    expect(seen).toEqual([]);
    expect(requests).toHaveLength(1);
  });

  test("stops even if the server keeps returning the same cursor (loop guard)", async () => {
    const { client, requests } = clientWith(() =>
      jsonResponse(200, { items: [sampleResource()], next_cursor: "stuck" }),
    );
    const seen: string[] = [];
    for await (const res of client.listAll()) {
      seen.push(res.id);
    }
    expect(requests).toHaveLength(2); // initial + one repeat, then the guard kicks in
    expect(seen).toHaveLength(2);
  });
});

// ---- scope-addressed resources ----

describe("scope-addressed resources", () => {
  test("getInScope() GETs the logical address", async () => {
    const { client, requests } = clientWith(() => jsonResponse(200, sampleResource()));
    const res = await client.getInScope("acme", "core", "prod", "applications", "checkout");
    expect(requests[0]?.url).toBe(`${BASE}/v1/acme/core/prod/applications/checkout`);
    expect(res.id).toBe("r-00b52b6eb859f432");
  });

  test("getInScope() URL-encodes path segments", async () => {
    const { client, requests } = clientWith(() => errorEnvelope(404, "not_found", "resource not found"));
    await expect(client.getInScope("a b", "c/d", "e%2F", "x", "y z")).rejects.toThrow(RyvexError);
    expect(requests[0]?.url).toBe(`${BASE}/v1/a%20b/c%2Fd/e%252F/x/y%20z`);
  });

  test("putInScope() sends generation in the body for optimistic CAS", async () => {
    const updated = sampleResource({ generation: 2, spec: { image: "registry.acme.io/checkout:1.42.1", replicas: 5 } });
    const { client, requests } = clientWith((req) => {
      expect(req.method).toBe("PUT");
      const body = JSON.parse(req.body ?? "{}") as Record<string, unknown>;
      expect(body["generation"]).toBe(1); // CAS token: the generation we previously read
      expect(body["spec"]).toEqual({ image: "registry.acme.io/checkout:1.42.1", replicas: 5 });
      return jsonResponse(200, updated);
    });
    const res = await client.putInScope("acme", "core", "prod", "applications", "checkout", {
      generation: 1,
      spec: { image: "registry.acme.io/checkout:1.42.1", replicas: 5 },
    });
    expect(requests[0]?.url).toBe(`${BASE}/v1/acme/core/prod/applications/checkout`);
    expect(res.generation).toBe(2);
  });

  test("deleteInScope() DELETEs the logical address", async () => {
    const { client, requests } = clientWith(() => emptyResponse(204));
    await expect(client.deleteInScope("acme", "core", "prod", "applications", "checkout")).resolves.toBeUndefined();
    expect(requests[0]?.method).toBe("DELETE");
    expect(requests[0]?.url).toBe(`${BASE}/v1/acme/core/prod/applications/checkout`);
  });
});

// ---- observability & control ----

describe("observability & control", () => {
  test("events() GETs /v1/{org}/events?limit=", async () => {
    const ev = {
      id: "ev-1", time: "2026-09-08T09:00:00Z", type: "created", subject: "ryvex.resource.acme.application.created",
      org: "acme", project: "core", env: "prod", kind: "Application", name: "checkout",
      resource_id: "r-00b52b6eb859f432", generation: 1, phase: "Pending", actor: "dev:test",
    };
    const { client, requests } = clientWith(() => jsonResponse(200, { events: [ev], count: 1 }));
    const page = await client.events("acme", { limit: 10 });
    expect(requests[0]?.url).toBe(`${BASE}/v1/acme/events?limit=10`);
    expect(page.count).toBe(1);
    expect(page.events[0]?.subject).toBe("ryvex.resource.acme.application.created");
  });

  test("audit() GETs /v1/{org}/audit?kind=&limit=", async () => {
    const entry = {
      id: "a-1", time: "2026-09-08T09:00:00Z", actor: "dev:test", action: "created",
      resource_id: "r-1", kind: "Application", logical_key: "acme/core/prod/Application/checkout",
      generation: 1, reason: "api put",
    };
    const { client, requests } = clientWith(() => jsonResponse(200, { entries: [entry], count: 1 }));
    const page = await client.audit("acme", { kind: "Application", limit: 5 });
    expect(requests[0]?.url).toBe(`${BASE}/v1/acme/audit?kind=Application&limit=5`);
    expect(page.entries[0]?.logical_key).toBe("acme/core/prod/Application/checkout");
  });

  test("triggerReconcile() POSTs /v1/{org}/reconcile/{id}", async () => {
    const { client, requests } = clientWith(() =>
      jsonResponse(202, { status: "accepted", resource_id: "r-1", reason: "manual reconcile trigger" }),
    );
    const ack = await client.triggerReconcile("acme", "r-1");
    const req = requests[0];
    expect(req?.method).toBe("POST");
    expect(req?.url).toBe(`${BASE}/v1/acme/reconcile/r-1`);
    expect(ack.status).toBe("accepted");
  });
});

// ---- error handling ----

describe("error envelope parsing", () => {
  test("404 not_found parses code, message, request_id and details", async () => {
    const { client } = clientWith(() =>
      errorEnvelope(404, "not_found", "resource not found", "e3b0c44298fc", []),
    );
    const err = await client.getResource("r-missing").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RyvexError);
    if (!(err instanceof RyvexError)) return;
    expect(err.status).toBe(404);
    expect(err.code).toBe("not_found");
    expect(err.message).toBe("resource not found");
    expect(err.requestId).toBe("e3b0c44298fc");
    expect(err.details).toEqual([]);
    expect(RyvexError.is(err)).toBe(true);
  });

  test("409 conflict carries the CAS generation conflict", async () => {
    const { client } = clientWith(() =>
      errorEnvelope(409, "conflict", "generation conflict: resource was modified concurrently"),
    );
    const err = await client
      .putInScope("acme", "core", "prod", "applications", "checkout", { generation: 1, spec: { replicas: 9 } })
      .catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(409);
    expect(err.code).toBe("conflict");
  });

  test("400 validation_failed surfaces details", async () => {
    const { client } = clientWith(() =>
      errorEnvelope(400, "validation_failed", "spec: spec is required", "aaa111bbb222", ["spec"]),
    );
    const err = await client.createResource({
      kind: "Application", org: "acme", project: "core", env: "prod", name: "checkout", spec: {},
    }).catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(400);
    expect(err.code).toBe("validation_failed");
    expect(err.details).toEqual(["spec"]);
    expect(err.requestId).toBe("aaa111bbb222");
  });

  test("401 unauthorized", async () => {
    const { client } = clientWith(() =>
      errorEnvelope(401, "unauthorized", "missing or invalid bearer token (expected ryk_ API key)"),
    );
    const err = await client.listResources().catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(401);
    expect(err.code).toBe("unauthorized");
  });

  test("non-JSON error body falls back to a status-derived code", async () => {
    const { client } = clientWith(() => textResponse(500, "<html>upstream exploded</html>"));
    const err = await client.getResource("r-x").catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(500);
    expect(err.code).toBe("internal_error");
    expect(err.message).toContain("internal error");
  });

  test("empty error body falls back to the status-derived code", async () => {
    const { client } = clientWith(() => emptyResponse(401));
    const err = await client.getResource("r-x").catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(401);
    expect(err.code).toBe("unauthorized");
  });

  test("transport failures are wrapped in RyvexError with status 0 and code 'transport_error'", async () => {
    const { fetch } = mockFetch(() => {
      throw new Error("connection refused");
    });
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, fetch });
    const err = await client.health().catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(0);
    // Parity with the Python SDK (sdk/ryvex-py/src/ryvex/errors.py):
    // connection-level failures are "transport_error", not "internal_error".
    expect(err.code).toBe("transport_error");
    expect(err.message).toContain("connection refused");
  });

  test("abort-shaped fetch rejections map to code 'timeout'", async () => {
    const { fetch } = mockFetch(() => {
      throw new DOMException("The operation was aborted", "AbortError");
    });
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, fetch });
    const err = await client.health().catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(0);
    expect(err.code).toBe("timeout");
  });

  test("403 forbidden parses the envelope code", async () => {
    const { client } = clientWith(() =>
      errorEnvelope(403, "forbidden", "token lacks scope rbac:read", "f043b1dd3n", ["scope"]),
    );
    const err = await client.listResources({ org: "acme" }).catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(403);
    expect(err.code).toBe("forbidden");
    expect(err.requestId).toBe("f043b1dd3n");
    expect(err.details).toEqual(["scope"]);
  });

  test("non-envelope 403 (edge proxy HTML) falls back to code 'forbidden'", async () => {
    const { client } = clientWith(() => textResponse(403, "<html>denied by edge proxy</html>"));
    const err = await client.getResource("r-x").catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(403);
    expect(err.code).toBe("forbidden");
  });

  test("every request carries Authorization and Content-Type headers", async () => {
    const { client, requests } = clientWith(() => jsonResponse(200, { status: "ok" }));
    await client.health();
    await client.index();
    await client.listResources({ org: "acme" });
    expect(requests.length).toBe(3);
    for (const req of requests) {
      expect(req.headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
      expect(req.headers.get("Content-Type")).toBe("application/json");
      expect(req.headers.get("Accept")).toBe("application/json");
    }
  });
});

// ---- timeout & cancellation plumbing (mock fetch, no sockets) ----

describe("timeout & cancellation plumbing", () => {
  test("defaults timeoutMs to 15000 and validates overrides", () => {
    expect(new Ryvex({ baseUrl: BASE, token: TOKEN }).timeoutMs).toBe(15_000);
    expect(new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: 0 }).timeoutMs).toBe(0);
    expect(() => new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: -1 })).toThrow(TypeError);
    expect(() => new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: Number.NaN })).toThrow(TypeError);
    expect(() => new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: Number.POSITIVE_INFINITY })).toThrow(TypeError);
  });

  test("per-call signal reaches fetch init verbatim when the timeout is disabled", async () => {
    let seen: RequestInit | undefined;
    const capture = ((_input: string | URL | Request, init?: RequestInit) => {
      seen = init;
      return Promise.resolve(jsonResponse(200, { status: "ok" }));
    }) as unknown as typeof fetch;
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, fetch: capture, timeoutMs: 0 });
    const ac = new AbortController();
    await client.health({ signal: ac.signal });
    expect(seen?.signal).toBe(ac.signal);
  });

  test("client timeout aborts fetch through init.signal", async () => {
    const { fetch } = mockFetch(
      (_req, init) =>
        new Promise<Response>((_, reject) => {
          const signal = init?.signal;
          if (!(signal instanceof AbortSignal)) {
            reject(new Error("no AbortSignal passed to fetch"));
            return;
          }
          signal.addEventListener("abort", () => reject(new DOMException("The operation was aborted", "AbortError")));
        }),
    );
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, fetch, timeoutMs: 30 });
    const err = await client.health().catch((e: unknown) => e);
    if (!(err instanceof RyvexError)) throw new Error("expected RyvexError");
    expect(err.status).toBe(0);
    expect(err.code).toBe("timeout");
    expect(err.message).toContain("timed out after 30ms");
  });

  test("listAll forwards the per-call signal to every page request", async () => {
    const { fetch, requests } = mockFetch((req) =>
      req.url.endsWith("cursor=c2")
        ? jsonResponse(200, { items: [], next_cursor: "" })
        : jsonResponse(200, { items: [sampleResource()], next_cursor: "c2" }),
    );
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, fetch, timeoutMs: 0 });
    const ac = new AbortController();
    const seen: string[] = [];
    for await (const r of client.listAll({ org: "acme" }, { signal: ac.signal })) {
      seen.push(r.id);
    }
    expect(seen).toHaveLength(1);
    expect(requests).toHaveLength(2);
    for (const req of requests) {
      expect(req.signal).toBe(ac.signal);
    }
  });
});
