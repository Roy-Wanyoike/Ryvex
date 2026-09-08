"use client";

import { useEffect, useState } from "react";
import { apiMode, fetchAudit, fetchEvents, fetchResources } from "@/lib/api";
import type { AuditEntry, Resource, RyvexEvent } from "@/lib/types";
import { AuditView, EventsView, OverviewView, ResourcesView, TopologyView } from "@/components/views";

type ViewKey = "overview" | "resources" | "topology" | "events" | "audit";

const NAV: { key: ViewKey; label: string; glyph: string }[] = [
  { key: "overview", label: "Overview", glyph: "◱" },
  { key: "resources", label: "Resources", glyph: "▤" },
  { key: "topology", label: "Topology", glyph: "◈" },
  { key: "events", label: "Events", glyph: "⚡" },
  { key: "audit", label: "Audit", glyph: "☰" },
];

export default function Home() {
  const [view, setView] = useState<ViewKey>("overview");
  const [resources, setResources] = useState<Resource[]>([]);
  const [events, setEvents] = useState<RyvexEvent[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const [res, evs, aud] = await Promise.all([fetchResources(), fetchEvents(), fetchAudit()]);
      if (!alive) return;
      setResources(res.items ?? []);
      setEvents(evs.events ?? []);
      setAudit(aud.entries ?? []);
      setLoaded(true);
    };
    load();
    const t = setInterval(load, 15_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

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
              <span className={`h-2 w-2 rounded-full ${apiMode === "live" ? "bg-emerald-400" : "bg-amber-400"}`} />
              <span className="font-semibold text-[var(--text)]">
                {apiMode === "live" ? "Live control plane" : "Demo snapshot"}
              </span>
            </div>
            <p className="mt-1.5 leading-relaxed">
              {apiMode === "live"
                ? `Connected to ${process.env.NEXT_PUBLIC_RYVEX_API}`
                : "Set NEXT_PUBLIC_RYVEX_API to connect a running ryvexd."}
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
              acme / core · eu-west-1 · {resources.length} resources under management
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="chip">v1.0.0</span>
            <span className="chip border-[var(--violet)]/40 text-[var(--violet)]">ryvexd</span>
          </div>
        </header>

        {!loaded ? (
          <div className="panel grid h-64 place-items-center text-sm text-[var(--muted)]">
            Connecting to control plane…
          </div>
        ) : (
          <>
            {view === "overview" && <OverviewView resources={resources} events={events} />}
            {view === "resources" && <ResourcesView resources={resources} />}
            {view === "topology" && <TopologyView resources={resources} />}
            {view === "events" && <EventsView events={events} />}
            {view === "audit" && <AuditView entries={audit} />}
          </>
        )}
      </main>
    </div>
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
