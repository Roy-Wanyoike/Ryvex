"use client";

import { useEffect, useState } from "react";
import { TOAST_AUTO_DISMISS_MS, subscribeToasts, toast } from "@/lib/toast";
import type { ToastItem, ToastVariant } from "@/lib/toast";

const VARIANT_STYLES: Record<ToastVariant, { border: string; glyph: string; glyphColor: string }> = {
  success: { border: "border-l-emerald-400", glyph: "✓", glyphColor: "text-emerald-300" },
  error: { border: "border-l-red-400", glyph: "✕", glyphColor: "text-red-300" },
  info: { border: "border-l-[var(--violet)]", glyph: "ℹ", glyphColor: "text-[var(--violet)]" },
};

/**
 * Fixed bottom-right toast stack. Mounted once in app/page.tsx.
 * aria-live="polite" so screen readers announce toasts without interrupting.
 */
export function Toasts() {
  const [items, setItems] = useState<readonly ToastItem[]>([]);

  useEffect(() => subscribeToasts(setItems), []);

  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      className="pointer-events-none fixed bottom-5 right-5 z-[100] flex w-80 max-w-[calc(100vw-2.5rem)] flex-col gap-2"
    >
      {items.map((t) => (
        <ToastRow key={t.id} item={t} />
      ))}
    </div>
  );
}

function ToastRow({ item }: { item: ToastItem }) {
  useEffect(() => {
    const timer = setTimeout(() => toast.dismiss(item.id), TOAST_AUTO_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [item.id]);

  const style = VARIANT_STYLES[item.variant];

  return (
    <div
      className={`pointer-events-auto flex items-start gap-2.5 rounded-xl border border-[var(--line)] border-l-4 ${style.border} bg-[var(--panel)] p-3 shadow-lg shadow-black/40`}
    >
      <span className={`text-sm font-bold ${style.glyphColor}`}>{style.glyph}</span>
      <p className="min-w-0 flex-1 break-words text-sm leading-snug">{item.message}</p>
      <button
        type="button"
        onClick={() => toast.dismiss(item.id)}
        aria-label="Dismiss notification"
        className="shrink-0 rounded px-1 text-[var(--muted)] transition hover:text-[var(--text)]"
      >
        ✕
      </button>
    </div>
  );
}
