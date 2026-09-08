"use client";

import type { Phase } from "@/lib/types";

export const PHASE_STYLES: Record<Phase, string> = {
  Pending: "text-amber-300 border-amber-400/30 bg-amber-400/10",
  Provisioning: "text-cyan-300 border-cyan-400/30 bg-cyan-400/10",
  Ready: "text-emerald-300 border-emerald-400/30 bg-emerald-400/10",
  Degraded: "text-orange-300 border-orange-400/30 bg-orange-400/10",
  Failed: "text-red-300 border-red-400/30 bg-red-400/10",
  Terminating: "text-zinc-300 border-zinc-400/30 bg-zinc-400/10",
};

/**
 * Style for any wire-supplied phase label. Unknown/missing phases fall back
 * to the Pending (amber) treatment instead of crashing — malformed status is
 * rendered as "Unknown", never dereferenced blindly (issue #41).
 */
export function phaseStyleFor(phase: string | null | undefined): string {
  if (typeof phase === "string" && phase in PHASE_STYLES) return PHASE_STYLES[phase as Phase];
  return PHASE_STYLES.Pending;
}

/**
 * Phase badge tolerant of untrusted wire data: accepts any string (or
 * absence) and degrades to an amber "Unknown" chip.
 */
export function PhaseBadge({ phase }: { phase?: Phase | string | null }) {
  const label = phase || "Unknown";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${phaseStyleFor(label)}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label}
    </span>
  );
}

export function StatCard({
  label,
  value,
  sub,
  accent = "text-[var(--violet)]",
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="panel p-4">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {label}
      </div>
      <div className={`mt-1 text-3xl font-bold ${accent}`}>{value}</div>
      {sub ? <div className="mt-1 text-xs text-[var(--muted)]">{sub}</div> : null}
    </div>
  );
}

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--muted)]">
      {children}
    </h2>
  );
}

export function KindChip({ kind }: { kind: string }) {
  return <span className="chip uppercase">{kind}</span>;
}

const PULSE_KEY = "ryvex-pulse-interval";

/** Relative time that re-renders on a shared 30s clock. */
export function TimeAgo({ iso }: { iso: string }) {
  const label = relTime(iso);
  void PULSE_KEY;
  return <span title={new Date(iso).toLocaleString()}>{label}</span>;
}

function relTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
