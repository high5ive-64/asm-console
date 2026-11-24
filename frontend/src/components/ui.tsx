import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { navigate } from "../router";

export function Button(props: {
  children: ReactNode;
  onClick?: () => void;
  kind?: "primary" | "secondary" | "danger" | "ghost";
  type?: "button" | "submit";
  disabled?: boolean;
  small?: boolean;
}) {
  const cls = ["btn", `btn-${props.kind ?? "secondary"}`, props.small ? "btn-sm" : ""].join(" ");
  return (
    <button type={props.type ?? "button"} className={cls} onClick={props.onClick} disabled={props.disabled}>
      {props.children}
    </button>
  );
}

export function Link(props: { to: string; children: ReactNode; className?: string }) {
  return (
    <a
      href={props.to}
      className={props.className}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey) return;
        e.preventDefault();
        navigate(props.to);
      }}
    >
      {props.children}
    </a>
  );
}

export function Card(props: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(props.title || props.actions) && (
        <header className="card-head">
          {props.title && <h2>{props.title}</h2>}
          {props.actions && <div className="card-actions">{props.actions}</div>}
        </header>
      )}
      <div className="card-body">{props.children}</div>
    </section>
  );
}

export function Field(props: { label: string; hint?: ReactNode; error?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{props.label}</span>
      {props.children}
      {props.hint && <span className="field-hint">{props.hint}</span>}
      {props.error && <span className="field-error">{props.error}</span>}
    </label>
  );
}

export function Badge(props: { tone?: "good" | "warn" | "bad" | "info" | "muted"; children: ReactNode }) {
  return <span className={`badge badge-${props.tone ?? "muted"}`}>{props.children}</span>;
}

export function Empty(props: { children: ReactNode }) {
  return <div className="empty">{props.children}</div>;
}

// ---- toasts --------------------------------------------------------------

type Toast = { id: number; text: string; tone: "good" | "bad" | "info" };
const ToastCtx = createContext<(text: string, tone?: Toast["tone"]) => void>(() => {});

export function ToastProvider(props: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Toast["tone"] = "info") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {props.children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

export function fmtDate(iso: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Outsider ASM mark: your perimeter, and the view from just outside it. */
export function Brand(props: { large?: boolean }) {
  return (
    <div className={props.large ? "brand brand-lg" : "brand"}>
      <svg className="brand-mark" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="10.5" cy="13.5" r="7" fill="none" stroke="currentColor" strokeWidth="2.6" strokeDasharray="33 11" strokeDashoffset="-2.5" strokeLinecap="round" />
        <circle cx="19.6" cy="4.6" r="2.7" fill="currentColor" />
      </svg>
      <span className="brand-name">
        Outsider <span className="brand-sub">ASM</span>
      </span>
    </div>
  );
}

/** Current time, re-rendering every `ms` while `active`. */
export function useNow(active = true, ms = 1000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [active, ms]);
  return now;
}

/** 3725000 -> "1h 02m 05s"; 125000 -> "2m 05s"; 9000 -> "9s" */
export function fmtDur(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const p = (n: number) => String(n).padStart(2, "0");
  if (h) return `${h}h ${p(m)}m ${p(sec)}s`;
  if (m) return `${m}m ${p(sec)}s`;
  return `${sec}s`;
}

export function elapsed(start: string | null, end: string | null, now: number): number {
  if (!start) return 0;
  return (end ? Date.parse(end) : now) - Date.parse(start);
}
