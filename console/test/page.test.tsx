/**
 * Client-render tests for app/page.tsx (issue #86).
 *
 * Renders the real console page with react-dom/client inside happy-dom and
 * guards the two UI contracts introduced with the feed-pagination work:
 *
 *  1. aria-live scope (#86): the whole-view `aria-live="polite"` wrapper is
 *     gone — tables no longer re-announce on every 15s poll. The only live
 *     regions are the connection status chip and the toast stack.
 *  2. Load-more (#86): a feed whose plane emitted `next_cursor` shows a
 *     "Load more" button; clicking appends the next page; a feed whose
 *     cursor is exhausted (or never emitted) shows no button. Refresh
 *     replaces accumulated pages with a fresh page one (documented
 *     semantics: live window resets, pause to read a long tail).
 */
import { beforeEach, afterEach, describe, expect, test } from "bun:test";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import Home from "@/app/page";
import { configureApi } from "@/lib/api";
import type { AuditEntry, Resource, RyvexEvent } from "@/lib/types";
import { installFetch, jsonReply } from "./helpers";

const BASE = "https://api.test";

// React 19 needs this flag to allow act() outside @testing-library.
(globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;

const evt = (id: string): RyvexEvent => ({
  id,
  time: "2025-01-15T12:00:00.000Z",
  type: "created",
  subject: "ryvex.resource.acme.application.created",
  org: "acme",
  kind: "Application",
  name: `app-${id}`,
});

const entry = (id: string): AuditEntry => ({
  id,
  time: "2025-01-15T12:00:00.000Z",
  actor: "ci-bot",
  action: "created",
  resource_id: `r-${id}`,
  kind: "Application",
  logical_key: `acme/core/prod/Application/app-${id}`,
  generation: 1,
});

const resource = (id: string): Resource => ({
  id,
  kind: "Application",
  org: "acme",
  project: "core",
  env: "prod",
  name: id,
  generation: 1,
  created_at: "2025-01-15T12:00:00.000Z",
  updated_at: "2025-01-15T12:00:00.000Z",
});

/** URL-routed fetch mock: events pages by call count, everything else static. */
function routeFeeds(opts?: {
  eventsPages?: { events: RyvexEvent[]; next_cursor?: string }[];
  auditPages?: { entries: AuditEntry[]; next_cursor?: string }[];
}) {
  const eventsPages = opts?.eventsPages ?? [{ events: [] }];
  const auditPages = opts?.auditPages ?? [{ entries: [] }];
  let eventsPageNo = 0;
  let auditPageNo = 0;
  return installFetch((input) => {
    const url = String(input);
    if (url.includes("/events?")) {
      const page = eventsPages[Math.min(eventsPageNo, eventsPages.length - 1)];
      eventsPageNo++;
      return jsonReply(page);
    }
    if (url.includes("/audit?")) {
      const page = auditPages[Math.min(auditPageNo, auditPages.length - 1)];
      auditPageNo++;
      return jsonReply(page);
    }
    return jsonReply({ items: [resource("r1")], next_cursor: "" });
  });
}

/** Flush the mock fetch promise chain inside act. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

describe("console page (issue #86)", () => {
  let container: HTMLElement | null = null;
  let root: Root | null = null;

  beforeEach(() => {
    configureApi({ apiBase: BASE, token: "", org: "acme", project: "core", env: "prod" });
    window.localStorage.clear();
    window.sessionStorage.clear();
    document.body.innerHTML = "";
  });

  afterEach(async () => {
    if (root && container) {
      await act(async () => {
        root?.unmount();
      });
    }
    container?.remove();
    container = null;
    root = null;
  });

  async function renderPage() {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container!);
    await act(async () => {
      root!.render(<Home />);
      await settle();
    });
    return container!;
  }

  /** Click a sidebar nav button to switch views (button text = glyph + label). */
  async function showView(el: HTMLElement, label: string) {
    const button = [...el.querySelectorAll("nav button")].find((b) => b.textContent?.trim().endsWith(label));
    expect(button).toBeDefined();
    await act(async () => {
      button!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await settle();
    });
  }

  test("aria-live is scoped to the status chip and toasts — never wraps the views", async () => {
    routeFeeds({
      eventsPages: [{ events: [evt("e1"), evt("e2"), evt("e3")], next_cursor: "c2" }],
      auditPages: [{ entries: [entry("a1")] }],
    });
    const el = await renderPage();

    // The events view is on screen with its table rows.
    expect(el.querySelectorAll("li").length).toBeGreaterThan(0);

    const liveRegions = [...el.querySelectorAll('[aria-live="polite"]')];
    // Exactly two: the connection status chip + the toast stack. The old
    // whole-view wrapper would have made this three (or more).
    expect(liveRegions).toHaveLength(2);
    for (const region of liveRegions) {
      // A live region must never contain a data table or feed list —
      // otherwise every poll re-announces the whole view.
      expect(region.querySelector("table, li")).toBeNull();
    }
  });

  test("load more appends the next page, then disappears when the cursor is exhausted", async () => {
    routeFeeds({
      eventsPages: [
        { events: [evt("e1"), evt("e2")], next_cursor: "c2" },
        { events: [evt("e3"), evt("e4")] }, // no next_cursor → exhausted
      ],
      auditPages: [{ entries: [entry("a1")] }],
    });
    const el = await renderPage();
    await showView(el, "Events");

    const moreButton = () => el.querySelector('button[aria-label="Load more events"]');
    expect(moreButton()).not.toBeNull();
    expect(el.querySelectorAll("li")).toHaveLength(2);

    await act(async () => {
      moreButton()!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await settle();
    });

    // Pages appended: 2 + 2 rows, button gone (cursor exhausted).
    expect(el.querySelectorAll("li")).toHaveLength(4);
    expect(moreButton()).toBeNull();
  });

  test("no Load more button when the plane does not paginate the feed", async () => {
    routeFeeds(); // pages carry no next_cursor at all (today's ryvexd feeds)
    const el = await renderPage();
    await showView(el, "Events");
    expect(el.querySelector('button[aria-label="Load more events"]')).toBeNull();
    await showView(el, "Audit");
    expect(el.querySelector('button[aria-label="Load more audit entries"]')).toBeNull();
  });

  test("refresh re-fetches page one and truncates appended pages (live window resets)", async () => {
    routeFeeds({
      eventsPages: [
        { events: [evt("e1"), evt("e2")], next_cursor: "c2" },
        { events: [evt("e3"), evt("e4")] },
        { events: [evt("fresh-1"), evt("fresh-2")], next_cursor: "c2" }, // next poll's page one
      ],
      auditPages: [{ entries: [entry("a1")] }],
    });
    const el = await renderPage();
    await showView(el, "Events");

    await act(async () => {
      el.querySelector('button[aria-label="Load more events"]')!.dispatchEvent(
        new MouseEvent("click", { bubbles: true }),
      );
      await settle();
    });
    expect(el.querySelectorAll("li")).toHaveLength(4);

    // Manual refresh: page one replaces the accumulated list.
    await act(async () => {
      el.querySelector('button[title="Reload all feeds now"]')!.dispatchEvent(
        new MouseEvent("click", { bubbles: true }),
      );
      await settle();
    });

    expect(el.querySelectorAll("li")).toHaveLength(2); // truncated back to page one
    expect(el.querySelector('button[aria-label="Load more events"]')).not.toBeNull();
  });
});
