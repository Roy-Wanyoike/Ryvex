/**
 * Unit tests for console/lib/api.ts (issue #77).
 *
 * Guards the truth-in-UI contract: demo data is served ONLY when no API base
 * is configured; in live mode a failed read degrades to the last good
 * snapshot or an explicit error — never to demo data (issue #41), and no
 * implicit Authorization header is ever sent (issue #42).
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
  ApiError,
  DemoModeError,
  REQUEST_TIMEOUT_MS,
  configureApi,
  fetchAudit,
  fetchEvents,
  fetchResources,
  failureReason,
  getApiBase,
  getApiMode,
  getOrg,
  getProject,
  getEnv,
  getApiToken,
  httpReason,
  parseErrorEnvelope,
} from "@/lib/api";
import { demoAudit, demoEvents, demoResources } from "@/lib/demo";
import { installFetch, jsonReply, networkFailure, reqHeader } from "./helpers";

const BASE = "https://api.test";

beforeEach(() => {
  // Reset the module-level runtime store through the public API. configureApi
  // also drops the "last good" feed caches, so every test starts clean.
  configureApi({ apiBase: "", token: "", org: "acme", project: "core", env: "prod" });
  window.localStorage.clear();
  window.sessionStorage.clear();
});

// ---- parseErrorEnvelope: the frozen error-envelope wire contract ----

describe("parseErrorEnvelope", () => {
  test("returns null for non-object bodies", () => {
    expect(parseErrorEnvelope(null)).toBeNull();
    expect(parseErrorEnvelope(undefined)).toBeNull();
    expect(parseErrorEnvelope(42)).toBeNull();
    expect(parseErrorEnvelope("boom")).toBeNull();
    expect(parseErrorEnvelope(true)).toBeNull();
    expect(parseErrorEnvelope([])).toBeNull();
  });

  test("returns null when the error key is missing or not an object", () => {
    expect(parseErrorEnvelope({})).toBeNull();
    expect(parseErrorEnvelope({ error: null })).toBeNull();
    expect(parseErrorEnvelope({ error: "boom" })).toBeNull();
    expect(parseErrorEnvelope({ error: 7 })).toBeNull();
  });

  test("returns null when error carries neither code nor message", () => {
    expect(parseErrorEnvelope({ error: {} })).toBeNull();
    expect(parseErrorEnvelope({ error: { request_id: "req-1" } })).toBeNull();
    expect(parseErrorEnvelope({ error: { code: 7, message: 8 } })).toBeNull();
  });

  test("message-only envelope falls back to code 'unknown'", () => {
    expect(parseErrorEnvelope({ error: { message: "kaboom" } })).toEqual({
      code: "unknown",
      message: "kaboom",
      requestId: "",
    });
  });

  test("code-only envelope falls back to message 'request failed'", () => {
    expect(parseErrorEnvelope({ error: { code: "not_found" } })).toEqual({
      code: "not_found",
      message: "request failed",
      requestId: "",
    });
  });

  test("parses the full envelope, mapping request_id → requestId", () => {
    expect(
      parseErrorEnvelope({ error: { code: "conflict", message: "stale generation", request_id: "req-42" } }),
    ).toEqual({ code: "conflict", message: "stale generation", requestId: "req-42" });
  });

  test("non-string request_id maps to empty string", () => {
    expect(parseErrorEnvelope({ error: { code: "x", message: "y", request_id: 99 } })).toEqual({
      code: "x",
      message: "y",
      requestId: "",
    });
  });
});

// ---- ApiError / DemoModeError / failure reasons ----

describe("ApiError", () => {
  test("carries status, code, message and requestId", () => {
    const err = new ApiError(404, "not_found", "no such resource", "req-7");
    expect(err.name).toBe("ApiError");
    expect(err.status).toBe(404);
    expect(err.code).toBe("not_found");
    expect(err.message).toBe("no such resource");
    expect(err.requestId).toBe("req-7");
  });

  test("isConflict matches HTTP 409 or code 'conflict'", () => {
    expect(new ApiError(409, "http_409", "x").isConflict).toBe(true);
    expect(new ApiError(500, "conflict", "x").isConflict).toBe(true);
    expect(new ApiError(500, "http_500", "x").isConflict).toBe(false);
  });
});

describe("failureReason / httpReason", () => {
  test("ApiError keeps its own message", () => {
    expect(failureReason(new ApiError(500, "http_500", "control plane returned HTTP 500"))).toBe(
      "control plane returned HTTP 500",
    );
  });

  test("abort/timeout errors report the request timeout", () => {
    const abort = Object.assign(new Error("The operation was aborted"), { name: "AbortError" });
    expect(failureReason(abort)).toBe(`request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
  });

  test("SyntaxError means a malformed response body", () => {
    expect(failureReason(new SyntaxError("Unexpected token"))).toBe(
      "control plane returned a malformed response",
    );
  });

  test("anything else reads as unreachable", () => {
    expect(failureReason(new TypeError("fetch failed"))).toBe("unreachable — check --cors-origins / base URL");
  });

  test("401/403 are called out as token problems", () => {
    expect(httpReason(401)).toBe("invalid token (HTTP 401)");
    expect(httpReason(403)).toBe("invalid token (HTTP 403)");
    expect(httpReason(500)).toBe("control plane returned HTTP 500");
  });
});

// ---- runtime config: getApiBase / getApiMode / configureApi ----

describe("runtime config", () => {
  test("defaults to demo mode with no base", () => {
    expect(getApiBase()).toBe("");
    expect(getApiMode()).toBe("demo");
  });

  test("configureApi normalizes the base (trim + strip trailing slashes)", () => {
    configureApi({ apiBase: `  ${BASE}///  ` });
    expect(getApiBase()).toBe(BASE);
    expect(getApiMode()).toBe("live");
  });

  test("a slash-only base normalizes back to demo mode", () => {
    configureApi({ apiBase: "///" });
    expect(getApiBase()).toBe("");
    expect(getApiMode()).toBe("demo");
  });

  test("token is trimmed; scope falls back to defaults when blanked", () => {
    configureApi({ token: "  tok  ", org: "  ", project: "", env: undefined });
    expect(getApiToken()).toBe("tok");
    expect(getOrg()).toBe("acme");
    expect(getProject()).toBe("core");
    expect(getEnv()).toBe("prod");
  });
});

// ---- fetchEvents / fetchAudit: the fetchFeed contract ----

describe("fetchEvents (fetchFeed semantics)", () => {
  test("demo mode: no fetch at all, demo data is served as ok", async () => {
    const { calls } = installFetch(() => jsonReply({ events: [] }));
    const result = await fetchEvents();
    expect(calls).toHaveLength(0);
    expect(result.status).toBe("ok");
    expect(result.data.events.map((e) => e.id)).toEqual(demoEvents().map((e) => e.id));
    expect(result.reason).toBeUndefined();
  });

  test("live path: 200 returns the control-plane payload as ok", async () => {
    configureApi({ apiBase: BASE });
    const payload = { events: [{ id: "evt-live-1", time: "t", type: "created", subject: "s", org: "acme", kind: "Application", name: "web" }] };
    const { calls } = installFetch(() => jsonReply(payload));
    const result = await fetchEvents();
    expect(result.status).toBe("ok");
    expect(result.data).toEqual(payload);
    expect(result.reason).toBeUndefined();
    expect(calls).toHaveLength(1);
    expect(calls[0].input).toBe(`${BASE}/v1/acme/events?limit=100`);
  });

  test("live path: org is URL-encoded in the request path", async () => {
    configureApi({ apiBase: BASE, org: "ac me" });
    const { calls } = installFetch(() => jsonReply({ events: [] }));
    await fetchEvents();
    expect(calls[0].input).toBe(`${BASE}/v1/ac%20me/events?limit=100`);
  });

  test("live path: non-200 with no last-good snapshot is an explicit error, NOT demo data", async () => {
    configureApi({ apiBase: BASE });
    installFetch(() => jsonReply({ error: { code: "internal" } }, 500));
    const result = await fetchEvents();
    expect(result.status).toBe("error");
    expect(result.data.events).toEqual([]);
    expect(result.reason).toBe("control plane returned HTTP 500");
    expect(result.data.events.some((e) => e.id.startsWith("evt-"))).toBe(false);
  });

  test("live path: network failure with no snapshot is an error with the unreachable reason", async () => {
    configureApi({ apiBase: BASE });
    installFetch(networkFailure());
    const result = await fetchEvents();
    expect(result.status).toBe("error");
    expect(result.data.events).toEqual([]);
    expect(result.reason).toBe("unreachable — check --cors-origins / base URL");
  });

  test("live path: failure after a good read degrades to the last good snapshot", async () => {
    configureApi({ apiBase: BASE });
    const good = { events: [{ id: "evt-good" }] };
    let n = 0;
    const { calls } = installFetch(() => {
      n++;
      if (n === 1) return jsonReply(good);
      throw new TypeError("fetch failed");
    });
    const first = await fetchEvents();
    expect(first.status).toBe("ok");
    expect(first.data).toEqual(good);

    const second = await fetchEvents();
    expect(calls).toHaveLength(2);
    expect(second.status).toBe("degraded");
    expect(second.data).toEqual(good);
    expect(second.at).toBe(first.at);
    expect(second.reason).toBe("unreachable — check --cors-origins / base URL");
  });

  test("reconfiguring the API drops the last-good cache (stale data never resurfaces)", async () => {
    configureApi({ apiBase: BASE });
    let n = 0;
    installFetch(() => (n++ === 0 ? jsonReply({ events: [{ id: "evt-a" }] }) : jsonReply({}, 500)));
    expect((await fetchEvents()).status).toBe("ok");

    configureApi({ apiBase: "https://other.test" });
    const result = await fetchEvents();
    expect(result.status).toBe("error"); // not "degraded" — cache belongs to the old config
    expect(result.data.events).toEqual([]);
  });

  test("demo data never appears once a base is configured", async () => {
    configureApi({ apiBase: BASE });
    installFetch(networkFailure());
    const result = await fetchEvents();
    expect(result.status).toBe("error");
    expect(result.data.events).toHaveLength(0);
    expect(result.data.events).not.toEqual(demoEvents());
  });
});

describe("fetchAudit (fetchFeed semantics)", () => {
  test("demo mode serves the demo audit trail as ok", async () => {
    const { calls } = installFetch(() => jsonReply({ entries: [] }));
    const result = await fetchAudit();
    expect(calls).toHaveLength(0);
    expect(result.status).toBe("ok");
    expect(result.data.entries.map((a) => a.id)).toEqual(demoAudit().map((a) => a.id));
  });

  test("live path: 200 passthrough against /v1/{org}/audit", async () => {
    configureApi({ apiBase: BASE });
    const payload = { entries: [{ id: "a-1", time: "t", actor: "ci-bot", action: "created", resource_id: "r", kind: "Application", logical_key: "k", generation: 1 }] };
    const { calls } = installFetch(() => jsonReply(payload));
    const result = await fetchAudit();
    expect(calls[0].input).toBe(`${BASE}/v1/acme/audit?limit=100`);
    expect(result).toEqual({ data: payload, status: "ok", at: expect.any(Number) });
  });
});

// ---- fetchResources: pagination + last-good fallback ----

describe("fetchResources", () => {
  const res = (id: string) => ({ id, kind: "Application", org: "acme", project: "core", env: "prod", name: id, generation: 1, created_at: "t", updated_at: "t" });

  test("demo mode: no fetch, demo snapshot served as ok", async () => {
    const { calls } = installFetch(() => jsonReply({ items: [] }));
    const result = await fetchResources();
    expect(calls).toHaveLength(0);
    expect(result.status).toBe("ok");
    expect(result.data.map((r) => r.id)).toEqual(demoResources().map((r) => r.id));
  });

  test("live path: follows next_cursor until exhausted", async () => {
    configureApi({ apiBase: BASE });
    let n = 0;
    const { calls } = installFetch(() => {
      n++;
      return n === 1 ? jsonReply({ items: [res("r1"), res("r2")], next_cursor: "c2" }) : jsonReply({ items: [res("r3")] });
    });
    const result = await fetchResources();
    expect(result.status).toBe("ok");
    expect(result.data.map((r) => r.id)).toEqual(["r1", "r2", "r3"]);
    expect(calls.map((c) => c.input)).toEqual([
      `${BASE}/v1/resources?limit=200`,
      `${BASE}/v1/resources?limit=200&cursor=c2`,
    ]);
  });

  test("live path: mid-pagination failure degrades to the partial page", async () => {
    configureApi({ apiBase: BASE });
    let n = 0;
    installFetch(() => {
      n++;
      return n === 1 ? jsonReply({ items: [res("r1"), res("r2")], next_cursor: "c2" }) : jsonReply({}, 503);
    });
    const result = await fetchResources();
    expect(result.status).toBe("degraded");
    expect(result.data.map((r) => r.id)).toEqual(["r1", "r2"]);
    expect(result.reason).toContain("control plane returned HTTP 503");
    expect(result.reason).toContain("partial list (2 items)");
  });

  test("live path: total failure with no snapshot is an explicit error, never demo data", async () => {
    configureApi({ apiBase: BASE });
    installFetch(() => jsonReply({}, 500));
    const result = await fetchResources();
    expect(result.status).toBe("error");
    expect(result.data).toEqual([]);
    expect(result.reason).toBe("control plane returned HTTP 500");
    expect(result.data.some((r) => r.id.startsWith("r-demo-"))).toBe(false);
  });

  test("live path: failure after a good read degrades to the last good snapshot", async () => {
    configureApi({ apiBase: BASE });
    let n = 0;
    installFetch(() => {
      n++;
      return n === 1 ? jsonReply({ items: [res("r1")] }) : jsonReply({ items: [] }, 503);
    });
    const first = await fetchResources();
    expect(first.status).toBe("ok");

    const second = await fetchResources();
    expect(second.status).toBe("degraded");
    expect(second.data.map((r) => r.id)).toEqual(["r1"]);
    expect(second.at).toBe(first.at);
  });
});

// ---- Authorization header hygiene (issue #42) ----

describe("Authorization header hygiene", () => {
  test("no Authorization header is sent when no token is configured", async () => {
    configureApi({ apiBase: BASE, token: "" });
    const { calls } = installFetch(() => jsonReply({ events: [] }));
    await fetchEvents();
    expect(calls).toHaveLength(1);
    expect(reqHeader(calls[0], "Authorization")).toBeUndefined();
  });

  test("a configured token rides as a Bearer header", async () => {
    configureApi({ apiBase: BASE, token: "tok-1" });
    const { calls } = installFetch(() => jsonReply({ events: [] }));
    await fetchEvents();
    expect(reqHeader(calls[0], "Authorization")).toBe("Bearer tok-1");
  });
});

// ---- mutations in demo mode ----

describe("demo mode mutations", () => {
  test("unrelated guard: DemoModeError exists for read-only demo mode", () => {
    expect(new DemoModeError().name).toBe("DemoModeError");
    expect(new DemoModeError().message).toContain("demo mode is read-only");
  });
});
