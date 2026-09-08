"use client";

import { useEffect, useState } from "react";
import type { Phase } from "@/lib/types";
import { toast } from "@/lib/toast";

export const PHASE_STYLES: Record<Phase, string> = {
  Pending: "text-amber-300 border-amber-400/30 bg-amber-400/10",
  Provisioning: "text-cyan-300 border-cyan-400/30 bg-cyan-400/10",
  Ready: "text-emerald-300 border-emerald-400/30 bg-emerald-400/10",
  Degraded: "text-orange-300 border-orange-400/30 bg-orange-400/10",
  Failed: "text-red-300 border-red-400/30 bg-red-400/10",
  Terminating: "text-zinc-300 border-zinc-400/30 bg-zinc-400/10",
};

/** Neutral zinc treatment for unknown/missing phase labels (#42). */
const UNKNOWN_PHASE_STYLE = "text-zinc-300 border-zinc-400/30 bg-zinc-400/10";

/**
 * Style for any wire-supplied phase label. Known phases get their own color;
 * unknown/missing phases render neutral zinc — never amber Pending, which
 * would misreport malformed status as a real state (issue #41, tuned in #42).
 */
export function phaseStyleFor(phase: string | null | undefined): string {
  if (typeof phase === "string" && phase in PHASE_STYLES) return PHASE_STYLES[phase as Phase];
  return UNKNOWN_PHASE_STYLE;
}

/**
 * Phase badge tolerant of untrusted wire data: accepts any string (or
 * absence) and degrades to a neutral zinc "Unknown" chip.
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

/** Relative time that re-renders on a shared 30s clock. */
export function TimeAgo({ iso }: { iso: string }) {
  const label = relTime(iso);
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

/**
 * Copy text to the clipboard, falling back to a hidden-textarea execCommand
 * on engines/pl origins where the async Clipboard API is unavailable.
 * Returns false only when every path failed, so callers can toast the error.
 */
async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to the legacy path (permission denied, insecure origin, …)
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

/**
 * Small inline copy affordance for machine values (resource IDs, logical
 * keys, event subjects). Uses the shared toast store for feedback (#42).
 */
export function CopyButton({ value, label = "value" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  const handleCopy = () => {
    void copyToClipboard(value).then((ok) => {
      if (ok) {
        setCopied(true);
        toast.success(`${label} copied to clipboard`);
      } else {
        toast.error(`Could not copy ${label} — clipboard access was blocked`);
      }
    });
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
      className={`shrink-0 rounded p-0.5 text-xs leading-none transition hover:text-[var(--text)] ${
        copied ? "text-emerald-300" : "text-[var(--muted)]"
      }`}
    >
      {copied ? "✓" : "⧉"}
    </button>
  );
}
