import { DEMO_AUDIT, DEMO_EVENTS, DEMO_RESOURCES } from "./demo";
import type { AuditEntry, Resource, RyvexEvent } from "./types";

/**
 * The console talks to the Ryvex control plane API (ryvexd).
 * NEXT_PUBLIC_RYVEX_API points at the daemon, e.g. http://localhost:8080.
 * When the API is unreachable the console degrades gracefully to an
 * embedded demo snapshot so the UI is always reviewable.
 */
export const API_BASE = process.env.NEXT_PUBLIC_RYVEX_API ?? "";

/**
 * Bearer token used by the console. In development ryvexd --dev-auth
 * accepts any well-formed ryk_ token; in production bake a real
 * read-scoped key at build time via NEXT_PUBLIC_RYVEX_TOKEN.
 */
const TOKEN = process.env.NEXT_PUBLIC_RYVEX_TOKEN ?? "ryk_console_dev";

export const apiMode: "live" | "demo" = API_BASE ? "live" : "demo";

async function get<T>(path: string, fallback: T): Promise<T> {
  if (!API_BASE) return fallback;
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
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
