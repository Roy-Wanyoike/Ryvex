/**
 * Feed-health aggregation tests for console/lib/health.ts (issue #77).
 *
 * worstHealth is the single function that turns the three feed FetchResults
 * into the health the badge and banner render. Its ordering (ok < degraded
 * < error) is the truth-in-UI contract: a failing control plane must surface
 * as Degraded/Unreachable — never as Live — and demo mode (all feeds "ok")
 * must never masquerade as a failure either. worstResult picks which feed's
 * reason/timestamp the banner shows.
 */
import { describe, expect, test } from "bun:test";
import { worstHealth, worstResult, type FeedResults } from "@/lib/health";
import type { FetchHealth, FetchResult } from "@/lib/api";
import type { AuditEntry, Resource, RyvexEvent } from "@/lib/types";

/** Minimal FetchResult carrying just the fields the aggregators read. */
function feed(status: FetchHealth): FetchResult<unknown> {
  return { data: [], status, at: 0, reason: status === "ok" ? undefined : `reason-${status}` };
}

function results(resources: FetchHealth, events: FetchHealth, audit: FetchHealth): FeedResults {
  return {
    resources: feed(resources) as FetchResult<Resource[]>,
    events: feed(events) as FetchResult<{ events: RyvexEvent[] }>,
    audit: feed(audit) as FetchResult<{ entries: AuditEntry[] }>,
  };
}

const RANK: Record<FetchHealth, number> = { ok: 0, degraded: 1, error: 2 };

describe("worstHealth", () => {
  test("null results (first load) → null — the badge defers to the mode chip", () => {
    expect(worstHealth(null)).toBeNull();
  });

  test("all feeds ok → ok (demo mode and a healthy live plane both land here)", () => {
    expect(worstHealth(results("ok", "ok", "ok"))).toBe("ok");
  });

  test("every status pair resolves to the strictly worse one, regardless of feed slot", () => {
    const statuses: FetchHealth[] = ["ok", "degraded", "error"];
    for (const a of statuses) {
      for (const b of statuses) {
        const expected = RANK[a] >= RANK[b] ? a : b;
        expect(worstHealth(results(a, b, "ok"))).toBe(expected);
        expect(worstHealth(results("ok", a, b))).toBe(expected);
        expect(worstHealth(results(b, "ok", a))).toBe(expected);
      }
    }
  });

  test("a single failing feed poisons the whole console health", () => {
    expect(worstHealth(results("ok", "ok", "error"))).toBe("error");
    expect(worstHealth(results("ok", "degraded", "ok"))).toBe("degraded");
  });

  test("degraded beats ok, error beats degraded (transitive ordering)", () => {
    expect(worstHealth(results("degraded", "degraded", "ok"))).toBe("degraded");
    expect(worstHealth(results("degraded", "error", "degraded"))).toBe("error");
    expect(worstHealth(results("error", "error", "error"))).toBe("error");
  });

  test("error is never downgraded by ok feeds — a dead plane can never look Live", () => {
    const health = worstHealth(results("ok", "ok", "error"));
    expect(health).not.toBe("ok");
    expect(health).not.toBe("degraded");
    expect(health).toBe("error");
  });
});

describe("worstResult", () => {
  test("picks the worst-ranked feed for the banner's reason/time display", () => {
    const mixed = results("ok", "error", "degraded");
    expect(worstResult(mixed)).toBe(mixed.events);

    const degradedOnly = results("degraded", "ok", "ok");
    expect(worstResult(degradedOnly)).toBe(degradedOnly.resources);

    const errorOnly = results("ok", "ok", "error");
    expect(worstResult(errorOnly)).toBe(errorOnly.audit);
    expect(worstResult(errorOnly).status).toBe("error");
  });

  test("ties keep the earliest feed (resources → events → audit)", () => {
    const tied = results("degraded", "degraded", "ok");
    expect(worstResult(tied)).toBe(tied.resources);
  });

  test("all-ok results still resolve to a feed (never undefined)", () => {
    const allOk = results("ok", "ok", "ok");
    expect(worstResult(allOk)).toBe(allOk.resources);
  });
});
