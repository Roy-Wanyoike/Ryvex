"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  DemoModeError,
  deleteResource,
  fetchResource,
  putResource,
} from "@/lib/api";
import type { Resource } from "@/lib/types";
import { toast } from "@/lib/toast";
import { CopyButton, KindChip, PhaseBadge, TimeAgo } from "./ui";

/**
 * Right-side detail drawer for a single resource.
 *
 * - metadata header (identity, scope, generation, phase, labels, timestamps)
 * - spec JSON editor with live client-side validation and CAS-aware save
 *   (PUT echoes the generation it read → 409 offers an inline reload)
 * - guarded delete (type the resource name to confirm)
 */

interface ResourceDrawerProps {
  resource: Resource;
  onClose: () => void;
  /** Called after a successful save or delete so parents refresh their lists. */
  onMutated: () => void;
}

type ParsedSpec = { ok: true; value: Record<string, unknown> } | { ok: false; error: string };

/** Query for elements that can take focus inside the dialog. */
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

function serializeSpec(spec: Record<string, unknown> | undefined): string {
  return JSON.stringify(spec ?? {}, null, 2);
}

/** Turn a JSON.parse failure into a human line/column message. */
function jsonErrorDetail(raw: string, err: unknown): string {
  const msg = err instanceof Error ? err.message : "invalid JSON";
  if (/line \d+ column \d+/i.test(msg)) return msg;
  const m = /position (\d+)/i.exec(msg);
  if (!m) return msg;
  const pos = Math.min(Number(m[1]), raw.length);
  const upto = raw.slice(0, pos);
  const line = upto.split("\n").length;
  const col = pos - upto.lastIndexOf("\n");
  return `Line ${line}, column ${col}: ${msg}`;
}

export function ResourceDrawer({ resource, onClose, onMutated }: ResourceDrawerProps) {
  const [doc, setDoc] = useState<Resource>(resource);
  const [text, setText] = useState(() => serializeSpec(resource.spec));
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [confirmName, setConfirmName] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  // Pull the latest stored doc so CAS uses a fresh generation (best effort —
  // if the fetch fails we keep the row we were opened with).
  useEffect(() => {
    let alive = true;
    fetchResource(resource.org, resource.project, resource.env, resource.kind, resource.name)
      .then((fresh) => {
        if (alive && fresh) setDoc(fresh);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [resource]);

  // Reset the editor whenever the underlying doc advances (save, reload).
  const docKey = `${doc.id}:${doc.generation}`;
  const appliedKey = useRef(docKey);
  useEffect(() => {
    if (appliedKey.current === docKey) return;
    appliedKey.current = docKey;
    setText(serializeSpec(doc.spec));
  }, [docKey, doc.spec]);

  // ESC closes the drawer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // A11y (#42): move focus into the dialog on open, trap Tab inside it while
  // it is up, restore focus to the invoking element on close, and lock body
  // scroll so the page behind cannot scroll.
  const panelRef = useRef<HTMLElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    returnFocusRef.current = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
      returnFocusRef.current?.focus();
    };
  }, []);

  const handleTabTrap = (e: React.KeyboardEvent) => {
    if (e.key !== "Tab") return;
    const panel = panelRef.current;
    if (!panel) return;
    const focusables = Array.from(
      panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
    );
    if (focusables.length === 0) {
      e.preventDefault();
      panel.focus();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      // Backwards from the first focusable (or the panel itself) wraps to last.
      if (active === first || active === panel) {
        e.preventDefault();
        last.focus();
      }
    } else if (active === last || !panel.contains(active)) {
      // Forward from the last focusable (or anything outside) wraps to first.
      e.preventDefault();
      first.focus();
    }
  };

  const parsed: ParsedSpec = useMemo(() => {
    const trimmed = text.trim();
    if (!trimmed) return { ok: false, error: "Spec is empty — enter a JSON object." };
    try {
      const value: unknown = JSON.parse(trimmed);
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return { ok: false, error: "Spec must be a JSON object." };
      }
      return { ok: true, value: value as Record<string, unknown> };
    } catch (err) {
      return { ok: false, error: jsonErrorDetail(text, err) };
    }
  }, [text]);

  const dirty = useMemo(() => {
    if (!parsed.ok) return false;
    return JSON.stringify(parsed.value) !== JSON.stringify(doc.spec ?? {});
  }, [parsed, doc.spec]);

  const labels = Object.entries(doc.labels ?? {});

  const applyMutationError = (err: unknown): boolean => {
    if (err instanceof DemoModeError) {
      toast.info(err.message);
      return true;
    }
    if (err instanceof ApiError && err.isConflict) {
      setConflict(true);
      return true;
    }
    return false;
  };

  const handleSave = async () => {
    if (!parsed.ok || saving) return;
    setSaving(true);
    setSaveError(null);
    setConflict(false);
    try {
      const updated = await putResource(doc.org, doc.project, doc.env, doc.kind, doc.name, {
        kind: doc.kind,
        org: doc.org,
        project: doc.project,
        env: doc.env,
        name: doc.name,
        generation: doc.generation,
        labels: doc.labels,
        spec: parsed.value,
      });
      setDoc(updated);
      toast.success(`${doc.kind} ${doc.name} saved — generation ${doc.generation} → ${updated.generation}`);
      onMutated();
    } catch (err) {
      if (applyMutationError(err)) return;
      if (err instanceof ApiError) {
        setSaveError(err.message);
      } else {
        setSaveError(err instanceof Error ? err.message : "Save failed");
        toast.error("Save failed — check the console connection in Settings.");
      }
    } finally {
      setSaving(false);
    }
  };

  const handleReload = async () => {
    setSaveError(null);
    setConflict(false);
    const fresh = await fetchResource(doc.org, doc.project, doc.env, doc.kind, doc.name);
    if (fresh) {
      setDoc(fresh);
      toast.info("Reloaded the latest stored version.");
    } else {
      toast.error("Could not reload the resource — is the control plane reachable?");
    }
  };

  const handleDelete = async () => {
    if (deleting) return;
    setDeleting(true);
    try {
      await deleteResource(doc.org, doc.project, doc.env, doc.kind, doc.name);
      toast.success(`Deleted ${doc.kind} ${doc.name}.`);
      onMutated();
      onClose();
    } catch (err) {
      if (applyMutationError(err)) return;
      toast.error(err instanceof ApiError ? `${err.code}: ${err.message}` : "Delete failed");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      {/* backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[2px]"
        onClick={onClose}
        aria-hidden
      />

      {/* panel */}
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Resource ${doc.kind} ${doc.name}`}
        tabIndex={-1}
        onKeyDown={handleTabTrap}
        className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col border-l border-[var(--line)] bg-[var(--panel)] shadow-2xl shadow-black/60"
      >
        {/* header */}
        <header className="flex items-center gap-3 border-b border-[var(--line)] p-5">
          <KindChip kind={doc.kind} />
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-lg font-bold tracking-tight">{doc.name}</h2>
            <p className="truncate font-mono text-xs text-[var(--muted)]">
              {doc.org}/{doc.project}/{doc.env}
            </p>
          </div>
          <PhaseBadge phase={doc.status?.phase} />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close drawer"
            className="rounded-lg border border-[var(--line)] px-2.5 py-1 text-sm text-[var(--muted)] transition hover:text-[var(--text)]"
          >
            ✕
          </button>
        </header>

        <div className="flex-1 space-y-6 overflow-y-auto p-5">
          {/* metadata */}
          <section>
            <MetaGrid>
              <MetaRow label="ID">
                <span className="flex items-center gap-1">
                  <code className="font-mono text-xs">{doc.id}</code>
                  <CopyButton value={doc.id} label="resource ID" />
                </span>
              </MetaRow>
              <MetaRow label="Scope">
                <span className="flex items-center gap-1">
                  <span className="font-mono text-xs" title={`${doc.org}/${doc.project}/${doc.env}/${doc.kind}/${doc.name}`}>
                    {doc.org}/{doc.project}/{doc.env}/{doc.kind}/{doc.name}
                  </span>
                  <CopyButton
                    value={`${doc.org}/${doc.project}/${doc.env}/${doc.kind}/${doc.name}`}
                    label="logical key"
                  />
                </span>
              </MetaRow>
              <MetaRow label="Generation">
                <span className="font-semibold text-[var(--violet)]">gen {doc.generation}</span>
                <span className="ml-2 text-xs text-[var(--muted)]">
                  observed {doc.status?.observed_generation ?? "?"}
                </span>
              </MetaRow>
              <MetaRow label="Status">
                <span className="text-sm">{doc.status?.message ?? "no status message"}</span>
              </MetaRow>
              <MetaRow label="Created">
                <TimeAgo iso={doc.created_at} />
              </MetaRow>
              <MetaRow label="Updated">
                <TimeAgo iso={doc.updated_at} />
              </MetaRow>
            </MetaGrid>
            {labels.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {labels.map(([k, v]) => (
                  <span key={k} className="chip">
                    {k}={v}
                  </span>
                ))}
              </div>
            ) : null}
          </section>

          {/* spec editor */}
          <section>
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-[var(--muted)]">
                Spec JSON
              </h3>
              <span className="text-xs text-[var(--muted)]">
                {dirty ? "unsaved changes" : parsed.ok ? "in sync" : "invalid JSON"}
              </span>
            </div>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              rows={14}
              aria-label="Resource spec JSON"
              className={`w-full resize-y rounded-xl border bg-[var(--panel-2)] p-3 font-mono text-xs leading-relaxed outline-none transition focus:border-[var(--violet)] ${
                parsed.ok ? "border-[var(--line)]" : "border-red-400/60"
              }`}
            />
            {!parsed.ok ? (
              <p role="alert" className="mt-1.5 font-mono text-xs text-red-300">
                {parsed.error}
              </p>
            ) : null}

            {conflict ? (
              <div className="mt-3 rounded-xl border border-amber-400/40 bg-amber-400/10 p-3 text-sm">
                <p className="font-medium text-amber-200">
                  Resource changed concurrently — reload?
                </p>
                <p className="mt-1 text-xs text-amber-200/80">
                  A newer generation was stored while you were editing. Reload to continue from the stored
                  version — your current edits will be replaced.
                </p>
                <button
                  type="button"
                  onClick={() => void handleReload()}
                  className="mt-2 rounded-lg border border-amber-400/50 px-3 py-1.5 text-xs font-semibold text-amber-200 transition hover:bg-amber-400/15"
                >
                  ⟳ Reload
                </button>
              </div>
            ) : null}

            {saveError ? (
              <p role="alert" className="mt-3 rounded-xl border border-red-400/40 bg-red-400/10 p-3 text-sm text-red-200">
                {saveError}
              </p>
            ) : null}

            <div className="mt-3 flex items-center gap-3">
              <button
                type="button"
                disabled={!parsed.ok || !dirty || saving}
                onClick={() => void handleSave()}
                className="rounded-lg bg-[var(--violet)] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[var(--violet)]/85 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {saving ? "Saving…" : "Save spec"}
              </button>
              <span className="text-xs text-[var(--muted)]">
                PUT with generation {doc.generation} — stale writes are rejected with 409.
              </span>
            </div>
          </section>

          {/* danger zone */}
          <section className="rounded-xl border border-red-400/25 p-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-red-300">Danger zone</h3>
            <p className="mt-1 text-xs text-[var(--muted)]">
              Deleting removes {doc.kind.toLowerCase()} {doc.name} from {doc.org}/{doc.project}/{doc.env}.
              This cannot be undone.
            </p>
            {!confirmingDelete ? (
              <button
                type="button"
                onClick={() => {
                  setConfirmingDelete(true);
                  setConfirmName("");
                }}
                className="mt-3 rounded-lg border border-red-400/50 px-4 py-2 text-sm font-semibold text-red-300 transition hover:bg-red-400/10"
              >
                Delete resource
              </button>
            ) : (
              <div className="mt-3 space-y-2">
                <label htmlFor="delete-confirm" className="block text-xs text-[var(--muted)]">
                  Type <span className="font-mono font-semibold text-[var(--text)]">{doc.name}</span> to confirm
                </label>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    id="delete-confirm"
                    value={confirmName}
                    onChange={(e) => setConfirmName(e.target.value)}
                    autoComplete="off"
                    placeholder={doc.name}
                    className="w-48 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 font-mono text-sm outline-none placeholder:text-[var(--muted)] focus:border-red-400"
                  />
                  <button
                    type="button"
                    disabled={confirmName !== doc.name || deleting}
                    onClick={() => void handleDelete()}
                    className="rounded-lg bg-[var(--red)] px-4 py-1.5 text-sm font-semibold text-black transition hover:bg-[var(--red)]/85 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {deleting ? "Deleting…" : "Confirm delete"}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmingDelete(false)}
                    className="rounded-lg px-3 py-1.5 text-sm text-[var(--muted)] transition hover:text-[var(--text)]"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </section>
        </div>
      </aside>
    </>
  );
}

function MetaGrid({ children }: { children: React.ReactNode }) {
  return <dl className="grid grid-cols-[110px_1fr] gap-x-4 gap-y-2.5 text-sm">{children}</dl>;
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </>
  );
}
