"use client";

import Link from "next/link";

/**
 * Route-level error boundary (issue #41, finding 3).
 *
 * A render crash must never brick the operator: offer a retry (reset), a way
 * back to Overview, and a request id (Next.js digest) to quote when reporting.
 */
export default function ConsoleError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="grid-bg flex min-h-screen items-center justify-center p-6">
      <div className="panel max-w-lg p-8 text-center" role="alert">
        <p className="text-4xl" aria-hidden>
          ⚠
        </p>
        <h1 className="mt-3 text-xl font-bold tracking-tight">The console hit an unexpected error</h1>
        <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">
          This view crashed while rendering — your data is safe. Retry the view below. If it keeps
          happening, check the control plane connection in Settings.
        </p>

        {error.digest ? (
          <p className="mt-4 font-mono text-xs text-[var(--muted)]">
            request id: <code className="text-[var(--text)]">{error.digest}</code>
          </p>
        ) : null}
        {error.message ? (
          <p className="mt-2 break-words font-mono text-xs text-[var(--muted)]">{error.message}</p>
        ) : null}

        <div className="mt-6 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={reset}
            className="rounded-lg bg-[var(--violet)] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[var(--violet)]/85"
          >
            ⟳ Retry
          </button>
          <Link
            href="/"
            className="rounded-lg border border-[var(--line)] px-4 py-2 text-sm font-semibold text-[var(--muted)] transition hover:text-[var(--text)]"
          >
            Back to Overview
          </Link>
        </div>
      </div>
    </main>
  );
}
