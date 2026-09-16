import type { FetchHealth, FetchResult } from "./api";
import type { AuditEntry, Resource, RyvexEvent } from "./types";

/**
 * Feed-health aggregation for the truth-in-UI contract (issue #41).
 *
 * Extracted verbatim from app/page.tsx for issue #77: Next.js page files may
 * only export known Page fields, so these pure helpers live in a lib module
 * where they can be unit-tested without rendering the page. No behavior change.
 */

export interface FeedResults {
  resources: FetchResult<Resource[]>;
  events: FetchResult<{ events: RyvexEvent[] }>;
  audit: FetchResult<{ entries: AuditEntry[] }>;
}

const HEALTH_RANK: Record<FetchHealth, number> = { ok: 0, degraded: 1, error: 2 };

/** Worst of the three feed statuses — what the badge and banner render. */
export function worstHealth(results: FeedResults | null): FetchHealth | null {
  if (!results) return null;
  const all: FetchHealth[] = [results.resources.status, results.events.status, results.audit.status];
  return all.reduce<FetchHealth>((worst, s) => (HEALTH_RANK[s] > HEALTH_RANK[worst] ? s : worst), "ok");
}

/** The failing feed with the highest rank, for banner reason/time display. Ties keep the earliest feed. */
export function worstResult(results: FeedResults): FetchResult<unknown> {
  const all: FetchResult<unknown>[] = [results.resources, results.events, results.audit];
  return all.reduce<FetchResult<unknown>>(
    (worst, r) => (HEALTH_RANK[r.status] > HEALTH_RANK[worst.status] ? r : worst),
    all[0],
  );
}
