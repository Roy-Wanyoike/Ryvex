"use client";

import { useMemo, useState } from "react";
import type { AuditEntry, Resource, RyvexEvent } from "@/lib/types";
import { KindChip, PhaseBadge, SectionTitle, StatCard, TimeAgo } from "./ui";

/* ---------------- Overview ---------------- */

export function OverviewView({
  resources,
  events,
}: {
  resources: Resource[];
  events: RyvexEvent[];
}) {
  const ready = resources.filter((r) => r.status.phase === "Ready").length;
  const clusters = resources.filter((r) => r.kind === "Cluster").length;
  const apps = resources.filter((r) => r.kind === "Application").length;
  const byPhase = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of resources) m.set(r.status.phase, (m.get(r.status.phase) ?? 0) + 1);
    return [...m.entries()];
  }, [resources]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Resources" value={resources.length} sub="under management" />
        <StatCard label="Ready" value={`${ready}/${resources.length}`} sub="converged to spec" accent="text-[var(--green)]" />
        <StatCard label="Applications" value={apps} sub="running workloads" accent="text-[var(--cyan)]" />
        <StatCard label="Clusters" value={clusters} sub="in prod-eu1" accent="text-[var(--amber)]" />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="panel p-5 lg:col-span-2">
          <SectionTitle>Phase distribution</SectionTitle>
          <PhaseDonut data={byPhase} total={resources.length} />
        </div>
        <div className="panel p-5 lg:col-span-3">
          <SectionTitle>Recent events</SectionTitle>
          <EventStream events={events.slice(0, 6)} compact />
        </div>
      </div>
    </div>
  );
}

const DONUT_COLORS: Record<string, string> = {
  Ready: "#34d399",
  Provisioning: "#22d3ee",
  Pending: "#fbbf24",
  Degraded: "#fb923c",
  Failed: "#f87171",
  Terminating: "#a1a1aa",
};

function PhaseDonut({ data, total }: { data: [string, number][]; total: number }) {
  const size = 170;
  const stroke = 22;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;

  return (
    <div className="mt-4 flex items-center gap-6">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1c1c30" strokeWidth={stroke} />
        {data.map(([phase, count]) => {
          const frac = total ? count / total : 0;
          const dash = frac * c;
          const el = (
            <circle
              key={phase}
              cx={size / 2} cy={size / 2} r={r} fill="none"
              stroke={DONUT_COLORS[phase] ?? "#7c5cff"}
              strokeWidth={stroke}
              strokeDasharray={`${dash} ${c - dash}`}
              strokeDashoffset={-offset}
            />
          );
          offset += dash;
          return el;
        })}
      </svg>
      <ul className="space-y-2 text-sm">
        {data.map(([phase, count]) => (
          <li key={phase} className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: DONUT_COLORS[phase] ?? "#7c5cff" }} />
            <span className="text-[var(--text)]">{phase}</span>
            <span className="text-[var(--muted)]">{count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ---------------- Resources ---------------- */

const KIND_FILTERS = ["All", "Application", "Deployment", "Database", "Cluster", "Node", "Policy", "Secret"];

export function ResourcesView({
  resources,
  onOpen,
}: {
  resources: Resource[];
  onOpen: (r: Resource) => void;
}) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("All");

  const rows = resources.filter((r) => {
    if (kind !== "All" && r.kind !== kind) return false;
    if (!q) return true;
    const hay = `${r.name} ${r.env} ${r.project} ${r.org}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  });

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] p-4">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter resources…"
          className="w-64 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-sm outline-none placeholder:text-[var(--muted)] focus:border-[var(--violet)]"
        />
        <div className="flex flex-wrap gap-1.5">
          {KIND_FILTERS.map((k) => (
            <button
              key={k}
              onClick={() => setKind(k)}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
                kind === k
                  ? "border-[var(--violet)] bg-[var(--violet)]/15 text-[var(--violet)]"
                  : "border-[var(--line)] text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              {k}
            </button>
          ))}
        </div>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
            <th className="px-4 py-3 font-semibold">Kind</th>
            <th className="px-4 py-3 font-semibold">Name</th>
            <th className="px-4 py-3 font-semibold">Scope</th>
            <th className="px-4 py-3 font-semibold">Phase</th>
            <th className="px-4 py-3 font-semibold">Gen</th>
            <th className="px-4 py-3 font-semibold">Updated</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.id}
              tabIndex={0}
              aria-label={`Inspect ${r.kind} ${r.name}`}
              onClick={() => onOpen(r)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onOpen(r);
                }
              }}
              className="cursor-pointer border-b border-[var(--line)]/50 transition hover:bg-[var(--panel-2)] focus:bg-[var(--panel-2)] focus:outline-none"
            >
              <td className="px-4 py-3"><KindChip kind={r.kind} /></td>
              <td className="px-4 py-3 font-medium">{r.name}</td>
              <td className="px-4 py-3 text-[var(--muted)]">{r.org}/{r.project}/{r.env}</td>
              <td className="px-4 py-3"><PhaseBadge phase={r.status.phase} /></td>
              <td className="px-4 py-3 text-[var(--muted)]">{r.generation}</td>
              <td className="px-4 py-3 text-[var(--muted)]"><TimeAgo iso={r.updated_at} /></td>
            </tr>
          ))}
          {rows.length === 0 ? (
            <tr><td colSpan={6} className="px-4 py-10 text-center text-[var(--muted)]">No resources match this filter.</td></tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------- Events ---------------- */

export function EventStream({ events, compact = false }: { events: RyvexEvent[]; compact?: boolean }) {
  return (
    <ul className={`mt-3 space-y-2 ${compact ? "" : ""}`}>
      {events.map((e) => (
        <li key={e.id} className="flex items-start gap-3 rounded-lg border border-[var(--line)]/60 bg-[var(--panel-2)]/60 p-3">
          <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-[var(--violet)]" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold uppercase text-[var(--cyan)]">{e.type}</span>
              <span className="truncate text-sm font-medium">{e.kind}/{e.name}</span>
              {e.phase ? <PhaseBadge phase={e.phase as never} /> : null}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-[var(--muted)]">
              <code className="truncate">{e.subject}</code>
              <span>·</span>
              <TimeAgo iso={e.time} />
              {e.actor ? <><span>·</span><span>{e.actor}</span></> : null}
            </div>
          </div>
        </li>
      ))}
      {events.length === 0 ? (
        <li className="py-6 text-center text-sm text-[var(--muted)]">No events yet.</li>
      ) : null}
    </ul>
  );
}

export function EventsView({ events }: { events: RyvexEvent[] }) {
  return (
    <div className="panel p-5">
      <SectionTitle>Event stream — subject ryvex.resource.*</SectionTitle>
      <EventStream events={events} />
    </div>
  );
}

/* ---------------- Audit ---------------- */

export function AuditView({ entries }: { entries: AuditEntry[] }) {
  return (
    <div className="panel overflow-hidden">
      <div className="border-b border-[var(--line)] p-4">
        <SectionTitle>Audit trail — every mutation, attributed</SectionTitle>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
            <th className="px-4 py-3 font-semibold">Actor</th>
            <th className="px-4 py-3 font-semibold">Action</th>
            <th className="px-4 py-3 font-semibold">Resource</th>
            <th className="px-4 py-3 font-semibold">Gen</th>
            <th className="px-4 py-3 font-semibold">When</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((a) => (
            <tr key={a.id} className="border-b border-[var(--line)]/50 hover:bg-[var(--panel-2)]">
              <td className="px-4 py-3 font-medium">{a.actor}</td>
              <td className="px-4 py-3">
                <span className={`chip ${
                  a.action === "created" ? "text-emerald-300" :
                  a.action === "deleted" ? "text-red-300" : "text-cyan-300"}`}>
                  {a.action}
                </span>
              </td>
              <td className="px-4 py-3 font-mono text-xs text-[var(--muted)]">{a.logical_key}</td>
              <td className="px-4 py-3 text-[var(--muted)]">{a.generation}</td>
              <td className="px-4 py-3 text-[var(--muted)]"><TimeAgo iso={a.time} /></td>
            </tr>
          ))}
          {entries.length === 0 ? (
            <tr><td colSpan={5} className="px-4 py-10 text-center text-[var(--muted)]">Audit log is empty.</td></tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------- Topology ---------------- */

export function TopologyView({ resources }: { resources: Resource[] }) {
  const clusters = resources.filter((r) => r.kind === "Cluster");
  const nodes = resources.filter((r) => r.kind === "Node");
  const apps = resources.filter((r) => r.kind === "Application");
  const data = resources.filter((r) => ["Database", "Cache", "Bucket"].includes(r.kind));

  return (
    <div className="space-y-6">
      {clusters.map((c) => (
        <div key={c.id} className="panel p-5">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-base font-bold">{c.name}</span>
            <PhaseBadge phase={c.status.phase} />
            <span className="chip">{String(c.spec?.provider ?? "provider")}</span>
            <span className="chip">v{String(c.spec?.version ?? "?")}</span>
            <span className="ml-auto text-xs text-[var(--muted)]">{c.org}/{c.project}/{c.env}</span>
          </div>

          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <TopologyGroup title="Nodes" items={nodes.filter((n) => n.spec?.cluster === c.name)} />
            <TopologyGroup title="Applications" items={apps} />
            <TopologyGroup title="Data services" items={data} />
          </div>
        </div>
      ))}
      {clusters.length === 0 ? (
        <div className="panel p-10 text-center text-[var(--muted)]">No clusters registered yet.</div>
      ) : null}
    </div>
  );
}

function TopologyGroup({ title, items }: { title: string; items: Resource[] }) {
  return (
    <div className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)]/50 p-4">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">{title}</div>
      <ul className="mt-2 space-y-2">
        {items.map((i) => (
          <li key={i.id} className="flex items-center justify-between gap-2 text-sm">
            <span className="truncate">{i.name}</span>
            <PhaseBadge phase={i.status.phase} />
          </li>
        ))}
        {items.length === 0 ? <li className="text-xs text-[var(--muted)]">none</li> : null}
      </ul>
    </div>
  );
}
