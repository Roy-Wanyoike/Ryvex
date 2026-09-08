import Link from "next/link";

export default function NotFound() {
  return (
    <main className="grid-bg flex min-h-screen items-center justify-center p-6">
      <div className="panel max-w-md p-8 text-center">
        <p className="text-5xl font-black text-[var(--violet)]">404</p>
        <h1 className="mt-3 text-xl font-bold tracking-tight">Page not found</h1>
        <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">
          This console route does not exist. Everything under <code className="font-mono text-xs">/</code> is
          the control console — data views live there.
        </p>
        <Link
          href="/"
          className="mt-6 inline-block rounded-lg bg-[var(--violet)] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[var(--violet)]/85"
        >
          Back to console
        </Link>
      </div>
    </main>
  );
}
