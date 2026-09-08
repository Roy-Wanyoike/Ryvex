/**
 * Minimal context-free toast system.
 *
 * A module-level store with a tiny event-emitter keeps <Toasts/> decoupled
 * from the component tree — any client module (api client, drawer, views)
 * can import `toast` and fire a notification without prop drilling.
 * The <Toasts/> component (components/toasts.tsx) subscribes on mount and
 * renders the live list inside an aria-live="polite" region.
 */

export type ToastVariant = "success" | "error" | "info";

export interface ToastItem {
  id: number;
  variant: ToastVariant;
  message: string;
}

type Listener = (toasts: readonly ToastItem[]) => void;

const AUTO_DISMISS_MS = 4_000;

let toasts: ToastItem[] = [];
let nextId = 1;
const listeners = new Set<Listener>();

function emit(): void {
  const snapshot = [...toasts];
  for (const listen of listeners) listen(snapshot);
}

function push(variant: ToastVariant, message: string): void {
  toasts = [...toasts, { id: nextId++, variant, message }];
  emit();
}

export const toast = {
  success(message: string): void {
    push("success", message);
  },
  error(message: string): void {
    push("error", message);
  },
  info(message: string): void {
    push("info", message);
  },
  dismiss(id: number): void {
    if (!toasts.some((t) => t.id === id)) return;
    toasts = toasts.filter((t) => t.id !== id);
    emit();
  },
};

/** Subscribe from React; returns an unsubscribe function. */
export function subscribeToasts(listener: Listener): () => void {
  listeners.add(listener);
  listener([...toasts]);
  return () => {
    listeners.delete(listener);
  };
}

export const TOAST_AUTO_DISMISS_MS = AUTO_DISMISS_MS;
