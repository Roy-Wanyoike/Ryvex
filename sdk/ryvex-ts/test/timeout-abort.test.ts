/**
 * Timeout, cancellation and transport-failure tests.
 *
 * Everything here exercises the real transport on loopback sockets:
 * Bun.serve fixtures on 127.0.0.1 (a server that never answers, a slow
 * one, plus a dead port) — no external network access. Unit-level
 * plumbing tests live in client.test.ts; this file pins the observable
 * behaviour:
 *
 *   - `timeoutMs` (default 15000) fires against a never-responding
 *     handler → RyvexError `code: "timeout"`, `status: 0`
 *   - a caller-supplied AbortSignal cancels an in-flight request →
 *     same `timeout` code, "aborted by the caller" message
 *   - connection failures → `code: "transport_error"`, `status: 0`
 *     (parity with the Python SDK)
 */
import { afterAll, describe, expect, test } from "bun:test";
import { DEFAULT_TIMEOUT_MS, Ryvex, RyvexError } from "../src/index.js";

const TOKEN = "ryk_test_agent";

// ---- loopback fixtures ----

/** Accepts requests and never answers — the ~5-minute stall, fast-forwarded. */
const hangServer = Bun.serve({
  port: 0,
  fetch: () => new Promise<Response>(() => {}),
});

/**
 * Routes fixture: /healthz answers instantly, /v1/slow/* delays long
 * enough for an external abort to win the race.
 */
const routesServer = Bun.serve({
  port: 0,
  async fetch(req) {
    const { pathname } = new URL(req.url);
    if (pathname === "/healthz") {
      return Response.json({ status: "ok", service: "ryvexd", version: "v1.0.0", resources: 0, time: "now" });
    }
    if (pathname.startsWith("/v1/slow/")) {
      await Bun.sleep(300);
      return Response.json({ status: "accepted", resource_id: "r-1", reason: "manual reconcile trigger" });
    }
    return Response.json({ ok: true });
  },
});

const BASE = `http://127.0.0.1:${routesServer.port}`;
const HANG = `http://127.0.0.1:${hangServer.port}`;

afterAll(() => {
  hangServer.stop(true);
  routesServer.stop(true);
});

/** Resolve with the rejection (or null on success) instead of throwing. */
function errorOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => null,
    (err) => err,
  );
}

// ---- client-side timeout (timeoutMs) ----

describe("timeoutMs", () => {
  test("exported default is 15000 and clients use it", () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(15_000);
    expect(new Ryvex({ baseUrl: HANG, token: TOKEN }).timeoutMs).toBe(15_000);
  });

  test("fires against a never-responding server → code 'timeout', status 0", async () => {
    const client = new Ryvex({ baseUrl: HANG, token: TOKEN, timeoutMs: 60 });
    const err = await errorOf(client.health());
    expect(err).toBeInstanceOf(RyvexError);
    if (!(err instanceof RyvexError)) return;
    expect(err.status).toBe(0);
    expect(err.code).toBe("timeout");
    expect(err.message).toContain("timed out after 60ms");
    expect(err.cause).toBeDefined();
  });

  test("0 disables the client-side timeout (slow handler still completes)", async () => {
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: 0 });
    const ack = await client.triggerReconcile("slow", "r-1");
    expect(ack.status).toBe("accepted");
  });

  test("rejects invalid timeoutMs values", () => {
    expect(() => new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: -1 })).toThrow(TypeError);
    expect(() => new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: Number.NaN })).toThrow(TypeError);
    expect(() => new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: Number.POSITIVE_INFINITY })).toThrow(TypeError);
  });
});

// ---- per-call AbortSignal ----

describe("per-call AbortSignal", () => {
  test("aborts an in-flight request → code 'timeout', 'aborted by the caller'", async () => {
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: 5_000 });
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 20);
    const err = await errorOf(client.triggerReconcile("slow", "r-1", { signal: ac.signal }));
    expect(err).toBeInstanceOf(RyvexError);
    if (!(err instanceof RyvexError)) return;
    expect(err.status).toBe(0);
    expect(err.code).toBe("timeout");
    expect(err.message).toContain("aborted by the caller");
  });

  test("an already-aborted signal rejects immediately", async () => {
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN, timeoutMs: 5_000 });
    const ac = new AbortController();
    ac.abort();
    const err = await errorOf(client.health({ signal: ac.signal }));
    expect(err).toBeInstanceOf(RyvexError);
    if (!(err instanceof RyvexError)) return;
    expect(err.status).toBe(0);
    expect(err.code).toBe("timeout");
    expect(err.message).toContain("aborted by the caller");
  });

  test("a signal that never fires leaves the call untouched", async () => {
    const client = new Ryvex({ baseUrl: BASE, token: TOKEN });
    const ac = new AbortController();
    const health = await client.health({ signal: ac.signal });
    expect(health.status).toBe("ok");
  });
});

// ---- transport failures ----

describe("transport failures", () => {
  test("connection refused → code 'transport_error', status 0", async () => {
    // Grab a free port, then close the listener so connections refuse.
    const probe = Bun.serve({ port: 0, fetch: () => new Response() });
    const deadPort = probe.port;
    probe.stop(true);

    const client = new Ryvex({ baseUrl: `http://127.0.0.1:${deadPort}`, token: TOKEN, timeoutMs: 2_000 });
    const err = await errorOf(client.health());
    expect(err).toBeInstanceOf(RyvexError);
    if (!(err instanceof RyvexError)) return;
    expect(err.status).toBe(0);
    expect(err.code).toBe("transport_error");
    expect(err.message).toContain("failed");
    expect(err.cause).toBeDefined();
  });
});
