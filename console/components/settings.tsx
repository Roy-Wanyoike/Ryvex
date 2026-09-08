"use client";

import { useEffect, useState } from "react";
import {
  LS_API_BASE,
  LS_ENV,
  LS_ORG,
  LS_PROJECT,
  LS_TOKEN,
  getApiBase,
  getApiMode,
  getApiToken,
  getEnv,
  getOrg,
  getProject,
  hydrateApiFromStorage,
  storeConfig,
  testConnection,
} from "@/lib/api";
import { toast } from "@/lib/toast";
import { SectionTitle } from "./ui";

/**
 * Settings view — runtime connection config for the console.
 * Values persist to localStorage (ryvex.apiBase / ryvex.token) and override
 * the build-time NEXT_PUBLIC_RYVEX_* env via the lib/api runtime store.
 */

type TestState =
  | { phase: "idle" }
  | { phase: "testing" }
  | { phase: "ok"; version: string; resources: number }
  | { phase: "failed"; error: string };

export function SettingsView({ onConfigChange }: { onConfigChange: () => void }) {
  const [apiBase, setApiBase] = useState("");
  const [token, setToken] = useState("");
  const [org, setOrg] = useState("");
  const [project, setProject] = useState("");
  const [env, setEnv] = useState("");
  const [savedMode, setSavedMode] = useState<"live" | "demo">("demo");
  const [savedBase, setSavedBase] = useState("");
  const [savedOrg, setSavedOrg] = useState("");
  const [savedProject, setSavedProject] = useState("");
  const [savedEnv, setSavedEnv] = useState("");
  const [test, setTest] = useState<TestState>({ phase: "idle" });

  useEffect(() => {
    hydrateApiFromStorage();
    setApiBase(getApiBase());
    setToken(getApiToken());
    setOrg(getOrg());
    setProject(getProject());
    setEnv(getEnv());
    setSavedMode(getApiMode());
    setSavedBase(getApiBase());
    setSavedOrg(getOrg());
    setSavedProject(getProject());
    setSavedEnv(getEnv());
  }, []);

  const handleSave = () => {
    storeConfig(apiBase, token, { org, project, env });
    setSavedMode(getApiMode());
    setSavedBase(getApiBase());
    setSavedOrg(getOrg());
    setSavedProject(getProject());
    setSavedEnv(getEnv());
    onConfigChange();
    toast.success(
      getApiMode() === "live"
        ? `Settings saved — console set to live mode (${getApiBase()}).`
        : "Settings saved — console set to read-only demo mode.",
    );
  };

  const handleTest = async () => {
    setTest({ phase: "testing" });
    const result = await testConnection(apiBase, token);
    if (result.ok) {
      setTest({ phase: "ok", version: result.info.version, resources: result.info.resources });
    } else {
      setTest({ phase: "failed", error: result.error });
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-5">
      {/* connection form */}
      <div className="panel p-5 lg:col-span-3">
        <SectionTitle>Control plane connection</SectionTitle>
        <p className="mt-2 text-sm text-[var(--muted)]">
          Point the console at a running ryvexd. Settings are stored in this browser
          (localStorage keys <code className="font-mono text-xs">{LS_API_BASE}</code>,{" "}
          <code className="font-mono text-xs">{LS_TOKEN}</code>,{" "}
          <code className="font-mono text-xs">{LS_ORG}</code>,{" "}
          <code className="font-mono text-xs">{LS_PROJECT}</code> and{" "}
          <code className="font-mono text-xs">{LS_ENV}</code>) and override the build-time
          NEXT_PUBLIC_RYVEX_API value.
        </p>

        <div className="mt-5 space-y-4">
          <Field label="API base URL" hint="e.g. http://127.0.0.1:8080 — leave empty for demo mode">
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="http://localhost:8080"
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 font-mono text-sm outline-none placeholder:text-[var(--muted)] focus:border-[var(--violet)]"
            />
          </Field>
          <Field label="Bearer token" hint="a ryk_ key; accepted as-is by ryvexd --dev-auth">
            <input
              value={token}
              onChange={(e) => setToken(e.target.value)}
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder="ryk_…"
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 font-mono text-sm outline-none placeholder:text-[var(--muted)] focus:border-[var(--violet)]"
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Org" hint="scope for events + audit (default: acme)">
              <input
                value={org}
                onChange={(e) => setOrg(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="acme"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 font-mono text-sm outline-none placeholder:text-[var(--muted)] focus:border-[var(--violet)]"
              />
            </Field>
            <Field label="Project" hint="header scope label (default: core)">
              <input
                value={project}
                onChange={(e) => setProject(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="core"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 font-mono text-sm outline-none placeholder:text-[var(--muted)] focus:border-[var(--violet)]"
              />
            </Field>
            <Field label="Environment" hint="header scope label (default: prod)">
              <input
                value={env}
                onChange={(e) => setEnv(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="prod"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 font-mono text-sm outline-none placeholder:text-[var(--muted)] focus:border-[var(--violet)]"
              />
            </Field>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleSave}
            className="rounded-lg bg-[var(--violet)] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[var(--violet)]/85"
          >
            Save settings
          </button>
          <button
            type="button"
            onClick={() => void handleTest()}
            disabled={test.phase === "testing"}
            className="rounded-lg border border-[var(--violet)]/50 px-4 py-2 text-sm font-semibold text-[var(--violet)] transition hover:bg-[var(--violet)]/10 disabled:opacity-50"
          >
            {test.phase === "testing" ? "Testing…" : "Test connection"}
          </button>
          {test.phase === "ok" ? (
            <span className="chip border-emerald-400/40 text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-current" />
              ok — ryvexd v{test.version} · {test.resources} resources
            </span>
          ) : null}
          {test.phase === "failed" ? (
            <span
              className="chip max-w-full border-red-400/40 text-red-300"
              title={test.error}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-current" />
              failed — {test.error}
            </span>
          ) : null}
        </div>

        {test.phase === "failed" ? (
          <p role="alert" className="mt-3 rounded-xl border border-red-400/40 bg-red-400/10 p-3 text-sm text-red-200">
            {test.error}
          </p>
        ) : null}
      </div>

      {/* status + reference */}
      <div className="space-y-6 lg:col-span-2">
        <div className="panel p-5">
          <SectionTitle>Saved configuration</SectionTitle>
          <div className="mt-3 space-y-3 text-sm">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[var(--muted)]">Mode</span>
              <span
                className={`chip ${
                  savedMode === "live"
                    ? "border-emerald-400/40 text-emerald-300"
                    : "border-amber-400/40 text-amber-300"
                }`}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                {savedMode === "live" ? "Live control plane" : "Demo snapshot"}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[var(--muted)]">API base</span>
              <code className="truncate font-mono text-xs">{savedBase || "— not set —"}</code>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[var(--muted)]">Scope</span>
              <code className="truncate font-mono text-xs">{savedOrg}/{savedProject}/{savedEnv}</code>
            </div>
          </div>
          {savedMode === "demo" ? (
            <p className="mt-4 rounded-xl border border-amber-400/30 bg-amber-400/10 p-3 text-xs leading-relaxed text-amber-200">
              Demo mode serves an embedded snapshot and is read-only — saves and deletes will show an
              info toast instead of hitting the API.
            </p>
          ) : null}
        </div>

        <div className="panel p-5 text-sm leading-relaxed text-[var(--muted)]">
          <SectionTitle>Notes</SectionTitle>
          <ul className="mt-3 list-disc space-y-2 pl-4">
            <li>
              Writes use optimistic concurrency: the console PUTs the generation it read and a stale
              write is rejected with <code className="font-mono text-xs">409 conflict</code>.
            </li>
            <li>
              The connection test calls <code className="font-mono text-xs">GET /healthz</code>, which
              reports version and resource count without auth.
            </li>
            <li>
              Build-time env (NEXT_PUBLIC_RYVEX_API / NEXT_PUBLIC_RYVEX_TOKEN) is the fallback when no
              localStorage keys exist.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {label}
      </span>
      {children}
      {hint ? <span className="mt-1 block text-xs text-[var(--muted)]">{hint}</span> : null}
    </label>
  );
}
