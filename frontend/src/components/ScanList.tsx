import { useCallback, useEffect, useState } from "react";
import { api, ApiError, Scan } from "../api";
import { navigate } from "../router";
import { useToast } from "./ui";

const LABEL: Record<string, string> = {
  completed: "Completed",
  completed_with_errors: "Partial",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
  failed: "Failed",
  running: "Running",
  discovering: "Discovering",
  awaiting_scope: "Choosing scope",
  scope_confirmed: "Ready to run",
  draft: "Draft",
};
const DOT: Record<string, string> = {
  completed: "good",
  completed_with_errors: "warn",
  interrupted: "warn",
  cancelled: "muted",
  failed: "bad",
  running: "info",
  discovering: "info",
};
const BUSY = ["running", "discovering"];
const FILTERS = {
  all: (s: Scan) => true,
  finished: (s: Scan) => ["completed", "completed_with_errors", "cancelled", "interrupted", "failed"].includes(s.status),
} as const;

function short(iso: string) {
  const d = new Date(iso);
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function ScanList(props: { path: string }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [filter, setFilter] = useState<keyof typeof FILTERS>("all");
  const toast = useToast();

  const load = useCallback(() => {
    api<{ scans: Scan[] }>("/api/scans")
      .then((r) => setScans(r.scans))
      .catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load, props.path]);
  useEffect(() => {
    if (!confirm) return;
    const t = setTimeout(() => setConfirm(null), 4000);
    return () => clearTimeout(t);
  }, [confirm]);

  const remove = async (s: Scan) => {
    if (confirm !== s.id) {
      setConfirm(s.id);
      return;
    }
    try {
      await api(`/api/scans/${s.id}`, { method: "DELETE" });
      toast(`Deleted scan of ${s.root_domain}`, "info");
      setConfirm(null);
      if (props.path === `/scans/${s.id}`) navigate("/");
      load();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Delete failed", "bad");
    }
  };

  const shown = scans.filter(FILTERS[filter]);
  return (
    <div className="scanlist">
      <div className="scanlist-head">
        <span>Scans</span>
        <span className="seg" role="group" aria-label="Filter scans">
          {(["all", "finished"] as const).map((f) => (
            <button key={f} className={filter === f ? "on" : ""} onClick={() => setFilter(f)}>
              {f === "all" ? "All" : "Finished"}
            </button>
          ))}
        </span>
      </div>
      {shown.length === 0 ? (
        <div className="scanlist-empty">No scans{filter === "finished" ? " finished yet" : " yet"}.</div>
      ) : (
        <ul>
          {shown.map((s) => {
            const active = props.path === `/scans/${s.id}`;
            const busy = BUSY.includes(s.status);
            return (
              <li key={s.id} className={active ? "active" : ""}>
                <a
                  href={`/scans/${s.id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(`/scans/${s.id}`);
                  }}
                >
                  {busy ? <span className="spinner sm" aria-hidden="true" /> : <span className={`sdot sdot-${DOT[s.status] ?? "muted"}`} aria-hidden="true" />}
                  <span className="scanlist-text">
                    <span className="scanlist-domain">{s.root_domain}</span>
                    <span className="scanlist-meta">
                      {LABEL[s.status] ?? s.status} · {short(s.finished_at || s.created_at)}
                    </span>
                  </span>
                </a>
                {!busy && (
                  <button
                    className={`scanlist-del ${confirm === s.id ? "confirm" : ""}`}
                    onClick={() => remove(s)}
                    title={confirm === s.id ? "Click again to delete this scan and its files" : "Delete scan"}
                    aria-label={confirm === s.id ? `Confirm delete ${s.root_domain}` : `Delete ${s.root_domain}`}
                  >
                    {confirm === s.id ? "Delete?" : "×"}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
