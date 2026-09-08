"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchAudit,
  fetchEvents,
  fetchResources,
  getApiBase,
  getApiMode,
  getScope,
  hydrateApiFromStorage,
} from "@/lib/api";
import type { FetchHealth, FetchResult, ScopeConfig } from "@/lib/api";
import type { AuditEntry, Resource, RyvexEvent } from "@/lib/types";
import { ResourceDrawer } from "@/components/drawer";
import { SettingsView } from "@/components/settings";
import { Toasts } from "@/components/toasts";
import { toast } from "@/lib/toast";
import { AuditView, EventsView, OverviewView, ResourcesView, TopologyView } from "@/components/views";

type ViewKey = "overview" | "resources" | "topology" | "events" | "audit" | "settings";

const NAV: { key: ViewKey; label: string; glyph: string }[] = [
  { key: "overview", label: "Overview", glyph: "◱" },
  { key: "resources", label: "Resources", glyph: "▤" },
  { key: "topology", label: "Topology", glyph: "◈" },
  { key: "events", label: "Events", glyph: "⚡" },
  { key: "audit", label: "Audit", glyph: "☰" },
  { key: "settings", label: "Settings", glyph: "⚙" },
];

const POLL_INTERVAL_MS = 15_000;

type FeedResults = {
  resources: FetchResult<Resource[]>;
  events: FetchResult<{ events: RyvexEvent[] }>;
  audit: FetchResult<{ entries: AuditEntry[] }>;
};

const HEALTH_RANK: Record<FetchHealth, number> = { ok: 0, degraded: 1, error: 2 };

/** Worst of the three feed statuses — what the badge and banner render. */
function worstHealth(results: FeedResults | null): FetchHealth | null {
  if (!results) return null;
  const all: FetchHealth[] = [results.resources.status, results.events.status, results.audit.status];
  return all.reduce<FetchHealth>((worst, s) => (HEALTH_RANK[s] > HEALTH_RANK[worst] ? s : worst), "ok");
}

/** The failing feed with the highest rank, for banner reason/time display. */
function worstResult(results: FeedResults): FetchResult<unknown> {
  const all: FetchResult<unknown>[] = [results.resources, results.events, results.audit];
  return all.reduce<FetchResult<unknown>>(
    (worst, r) => (HEALTH_RANK[r.status] > HEALTH_RANK[worst.status] ? r : worst),
    all[0],
  );
}

export default function Home() {
  const [view, setView] = useState<ViewKey>("overview");
  const [resources, setResources] = useState<Resource[]>([]);
  const [events, setEvents] = useState<RyvexEvent[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<Resource | null>(null);
  const [conn, setConn] = useState<{ mode: "live" | "demo"; base: string }>({ mode: "demo", base: "" });
  const [scope, setScope] = useState<ScopeConfig>({ org: "acme", project: "core", env: "prod" });
  const [results, setResults] = useState<FeedResults | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [paused, setPaused] = useState(false);
  // Bumping this re-hydrates runtime config from localStorage and reloads data.
  const [reloadKey, setReloadKey] = useState(0);

  // The in-flight poll; a new loadAll cancels it so fetches never overlap.
  const inflight = useRef<AbortController | null>(null);

  const loadAll = useCallback(async () => {
    inflight.current?.abort();
    const controller = new AbortController();
    inflight.current = controller;
    try {
      const [res, evs, aud] = await Promise.all([
        fetchResources({ signal: controller.signal }),
        fetchEvents({ signal: controller.signal }),
        fetchAudit({ signal: controller.signal }),
      ]);
      if (controller.signal.aborted) return; // superseded by a newer load
      setResources(res.data);
      setEvents(evs.data.events ?? []);
      setAudit(aud.data.entries ?? []);
      setResults({ resources: res, events: evs, audit: aud });
      setLastUpdated(Date.now());
      setLoaded(true);
    } catch (err) {
      // Reads never throw by design; a cancelled poll lands here via abort.
      if (controller.signal.aborted) return;
      toast.error(err instanceof Error ? err.message : "Unexpected failure while refreshing");
      setLoaded(true); // never wedge the console on the connecting screen
    } finally {
      if (inflight.current === controller) inflight.current = null;
    }
  }, []);

  useEffect(() => {
    hydrateApiFromStorage();
    setConn({ mode: getApiMode(), base: getApiBase() });
    setScope(getScope());
    void loadAll();
  }, [reloadKey, loadAll]);

  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => void loadAll(), POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, [paused, reloadKey, loadAll]);

  const handleConfigChange = () => setReloadKey((k) => k + 1);

  const handleMutated = () => {
    void loadAll();
  };

  const health = worstHealth(results);
  const badge = !conn.mode || conn.mode === "demo"
    ? { dot: "bg-amber-400", chip: "border-amber-400/40 text-amber-300", label: "Demo mode", title: "Demo mode — configure an API base in Settings" }
    : health === "error"
      ? { dot: "bg-red-400", chip: "border-red-400/40 text-red-300", label: "Unreachable", title: `Cannot reach ${conn.base} — open Settings to fix the connection` }
      : health === "degraded"
        ? { dot: "bg-amber-400", chip: "border-amber-400/40 text-amber-300", label: "Degraded", title: `Showing last good data — ${conn.base} is failing` }
        : { dot: "bg-emerald-400", chip: "border-emerald-400/40 text-emerald-300", label: `Live · ${conn.base}`, title: conn.base };

  return (
    <div className="grid-bg min-h-screen lg:grid lg:grid-cols-[240px_1fr]">
      {/* Sidebar */}
      <aside className="flex flex-col border-b border-[var(--line)] bg-[var(--panel)]/80 p-5 backdrop-blur lg:min-h-screen lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-2.5">
          <Logo />
          <div>
            <div className="text-lg font-black tracking-tight">Ryvex</div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-[var(--muted)]">Control Console</div>
          </div>
        </div>

        <nav className="mt-6 flex flex-row gap-1 overflow-x-auto lg:flex-col lg:overflow-visible">
          {NAV.map((n) => (
            <button
              key={n.key}
              onClick={() => setView(n.key)}
              className={`flex items-center gap-2.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-medium transition ${
                view === n.key
                  ? "bg-[var(--violet)]/15 text-[var(--violet)]"
                  : "text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--text)]"
              }`}
            >
              <span className="w-4 text-center opacity-80">{n.glyph}</span>
              {n.label}
            </button>
          ))}
        </nav>

        <div className="mt-auto hidden pt-6 lg:block">
          <div className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)] p-3 text-xs text-[var(--muted)]">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${badge.dot}`} />
              <span className="font-semibold text-[var(--text)]">
                {conn.mode === "live"
                  ? health === "ok"
                    ? "Live control plane"
                    : health === "degraded"
                      ? "Degraded — last good data"
                      : "Control plane unreachable"
                  : "Demo snapshot"}
              </span>
            </div>
            <p className="mt-1.5 leading-relaxed">
              {conn.mode === "live"
                ? health === "ok"
                  ? `Connected to ${conn.base}`
                  : "Retrying automatically — see the banner for details."
                : "Connect a control plane in Settings."}
            </p>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="p-6 lg:p-8">
        <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold tracking-tight capitalize">{view}</h1>
            <p className="mt-0.5 text-sm text-[var(--muted)]">
              {scope.org} / {scope.project} · {scope.env} · {resources.length} resources under management
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Freshness lastUpdated={lastUpdated} />
            <button
              type="button"
              onClick={() => void loadAll()}
              className="rounded-lg border border-[var(--line)] px-2.5 py-1 text-xs font-semibold text-[var(--muted)] transition hover:text-[var(--text)]"
              title="Reload all feeds now"
            >
              ⟳ Refresh
            </button>
            <button
              type="button"
              onClick={() => setPaused((p) => !p)}
              aria-pressed={paused}
              className={`rounded-lg border px-2.5 py-1 text-xs font-semibold transition ${
                paused
                  ? "border-amber-400/40 text-amber-300 hover:bg-amber-400/10"
                  : "border-[var(--line)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
              title={paused ? "Resume 15s auto-refresh" : "Pause 15s auto-refresh"}
            >
              {paused ? "▶ Resume" : "⏸ Pause"}
            </button>
            <span className={`chip ${badge.chip}`} title={badge.title}>
              <span className="h-1.5 w-1.5 rounded-full bg-current" />
              {badge.label}
            </span>
            <span className="chip">v1.0.0</span>
            <span className="chip border-[var(--violet)]/40 text-[var(--violet)]">ryvexd</span>
          </div>
        </header>

        {/* Truthful connection banner — live mode only, shown when a feed is not ok */}
        {conn.mode === "live" && results && (health === "degraded" || health === "error") ? (
          <ConnectionBanner
            variant={health}
            base={conn.base}
            result={worstResult(results)}
            onRetry={() => void loadAll()}
            onOpenSettings={() => setView("settings")}
          />
        ) : null}

        {!loaded ? (
          <div className="panel grid h-64 place-items-center text-sm text-[var(--muted)]">
            Connecting to control plane…
          </div>
        ) : (
          <>
            {view === "overview" && <OverviewView resources={resources} events={events} />}
            {view === "resources" && <ResourcesView resources={resources} onOpen={setSelected} />}
            {view === "topology" && <TopologyView resources={resources} />}
            {view === "events" && <EventsView events={events} />}
            {view === "audit" && <AuditView entries={audit} />}
            {view === "settings" && <SettingsView onConfigChange={handleConfigChange} />}
          </>
        )}
      </main>

      {/* resource detail drawer */}
      {selected ? (
        <ResourceDrawer
          key={selected.id}
          resource={selected}
          onClose={() => setSelected(null)}
          onMutated={handleMutated}
        />
      ) : null}

      <Toasts />
    </div>
  );
}

/**
 * Amber/red banner shown in live mode when reads are failing. Never renders
 * demo data — explains what broke, when the shown data was last good, and how
 * to fix it (retry or Settings).
 */
function ConnectionBanner({
  variant,
  base,
  result,
  onRetry,
  onOpenSettings,
}: {
  variant: "degraded" | "error";
  base: string;
  result: FetchResult<unknown>;
  onRetry: () => void;
  onOpenSettings: () => void;
}) {
  const degraded = variant === "degraded";
  const tone = degraded
    ? "border-amber-400/40 bg-amber-400/10 text-amber-200"
    : "border-red-400/40 bg-red-400/10 text-red-200";
  const subTone = degraded ? "text-amber-200/80" : "text-red-200/80";
  const time = new Date(result.at).toLocaleTimeString();

  return (
    <div role="status" className={`mb-6 rounded-xl border p-4 text-sm ${tone}`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="font-semibold">
          {degraded ? "⚠ Control plane degraded" : "✕ Cannot reach control plane"} — {base}
        </span>
        <span className={subTone}>{result.reason ?? "unknown failure"}.</span>
        {degraded ? <span className={subTone}>Showing last good data from {time}.</span> : null}
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={onRetry}
            className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition hover:bg-white/5 ${tone}`}
          >
            ⟳ Retry
          </button>
          <button
            type="button"
            onClick={onOpenSettings}
            className={`rounded-lg border px-3 py-1.5 text-xs font-semibold underline-offset-2 transition hover:bg-white/5 hover:underline ${tone}`}
          >
            Open Settings
          </button>
        </div>
      </div>
    </div>
  );
}

/** "Updated Xs ago" label that ticks on a private 1s clock (self-contained). */
function Freshness({ lastUpdated }: { lastUpdated: number | null }) {
  const [now, setNow] = useState<number | null>(null);

  useEffect(() => {
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  if (!lastUpdated || now === null) {
    return <span className="text-xs text-[var(--muted)]">…</span>;
  }
  const s = Math.max(0, Math.floor((now - lastUpdated) / 1000));
  const label = s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ${s % 60}s ago`;
  return (
    <span className="text-xs text-[var(--muted)]" title={new Date(lastUpdated).toLocaleTimeString()}>
      Updated {label}
    </span>
  );
}

function Logo() {
  return (
    <svg width="34" height="34" viewBox="0 0 40 40" fill="none" aria-hidden>
      <rect x="2" y="2" width="36" height="36" rx="10" fill="#12122a" stroke="#7c5cff" strokeWidth="2" />
      <path d="M13 28V12h8.5a5 5 0 0 1 0 10H17l8 6" stroke="url(#g1)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />
      <defs>
        <linearGradient id="g1" x1="13" y1="12" x2="27" y2="28">
          <stop stopColor="#7c5cff" />
          <stop offset="1" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
    </svg>
  );
}
