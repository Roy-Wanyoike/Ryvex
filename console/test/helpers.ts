/**
 * Shared helpers for the console test suite (issue #77).
 *
 * The suite tests the real exported functions from console/lib/api.ts and
 * console/app/page.tsx. fetch is mocked per test by replacing globalThis.fetch
 * (happy-dom/Bun supply a real Response implementation for reply bodies).
 */
import { afterEach, expect } from "bun:test";

/** One captured fetch invocation. */
export interface FetchCall {
  input: string;
  init: RequestInit | undefined;
}

type FetchHandler = (input: string, init: RequestInit | undefined) => Response;

let restore: (() => void) | null = null;

afterEach(() => {
  restore?.();
  restore = null;
});

/**
 * Replace globalThis.fetch with a handler. Every invocation is recorded so
 * tests can assert request URLs and headers. Restored automatically in
 * afterEach (and idempotently on manual restore()).
 */
export function installFetch(handler: FetchHandler): { calls: FetchCall[]; restore: () => void } {
  const calls: FetchCall[] = [];
  const impl = ((input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ input: String(input), init });
    return handler(String(input), init);
  }) as unknown as typeof fetch;
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  const uninstall = () => {
    if (globalThis.fetch === impl) globalThis.fetch = original;
  };
  restore = uninstall;
  return { calls, restore: uninstall };
}

/** A fetch handler that always rejects (network-level failure). */
export function networkFailure(err = new TypeError("fetch failed")): FetchHandler {
  return () => {
    throw err;
  };
}

/** JSON reply with the given status (default 200). */
export function jsonReply(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Read a header off a captured call's plain-object headers. */
export function reqHeader(call: FetchCall, name: string): string | undefined {
  const headers = (call.init?.headers ?? {}) as Record<string, string>;
  return headers[name];
}

/** Guard: fail loudly if a captured call ever carried an Authorization header. */
export function expectNoAuthHeader(call: FetchCall): void {
  expect(reqHeader(call, "Authorization")).toBeUndefined();
}
