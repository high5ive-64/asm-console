import { useEffect, useMemo, useState } from "react";
import { api, ApiError, ZapInfo } from "../api";
import { Badge, Button, fmtDur, useToast } from "./ui";

const GROUP_LABEL: Record<string, { label: string; tone: "good" | "info" | "muted" | "warn" }> = {
  content: { label: "has content", tone: "good" },
  login: { label: "login prompt", tone: "info" },
  redirect: { label: "redirects", tone: "muted" },
  unknown: { label: "unknown", tone: "muted" },
  "dead end": { label: "dead end", tone: "warn" },
};
const FILTERS = ["all", "selected", "content", "login", "redirect", "dead end"] as const;

/**
 * Which hosts ZAP scans. mode "pick": ZAP is waiting, confirm to start it. "edit": save a choice for the next ZAP run.
 * "view": ZAP is running; shows progress per host.
 */
export function ZapTargets(props: { scanId: string; mode: "pick" | "edit" | "view"; onDone?: () => void; poll?: boolean }) {
  const [info, setInfo] = useState<ZapInfo | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  useEffect(() => {
    let stop = false;
    const load = () =>
      api<ZapInfo>(`/api/scans/${props.scanId}/zap/targets`).then((r) => {
        if (stop) return;
        setInfo(r);
        setSel((cur) => (cur.size && props.mode !== "view" ? cur : new Set(r.selected)));
      });
    load();
    const t = props.poll ? setInterval(load, 3000) : undefined;
    return () => {
      stop = true;
      if (t) clearInterval(t);
    };
  }, [props.scanId, props.mode, props.poll]);

  const rows = useMemo(() => {
    if (!info) return [];
    const ql = q.trim().toLowerCase();
    return info.candidates.filter(
      (c) =>
        (filter === "all" || (filter === "selected" ? sel.has(c.host) : c.group === filter)) && (!ql || c.host.includes(ql))
    );
  }, [info, filter, q, sel]);

  if (!info) return <div className="muted small">Loading ZAP's host list…</div>;
  if (!info.candidates.length)
    return <div className="muted small">No live web hosts yet. The list fills in once BBOT (or TLS) has found which hosts answer.</div>;

  const ro = props.mode === "view";
  const prog = info.progress;
  const order = prog?.hosts ?? [];
  const minutes = sel.size * info.per_host_minutes;
  const toggle = (h: string, on: boolean) => {
    const n = new Set(sel);
    if (on) n.add(h);
    else n.delete(h);
    setSel(n);
  };
  const ordered = info.candidates.filter((c) => sel.has(c.host)).map((c) => c.host);

  const save = async () => {
    setBusy(true);
    try {
      if (props.mode === "pick") {
        const r = await api<{ confirmed: number }>(`/api/scans/${props.scanId}/zap/confirm`, { method: "POST", json: { hosts: ordered } });
        toast(`ZAP starting on ${r.confirmed} host${r.confirmed === 1 ? "" : "s"}`, "good");
      } else {
        const r = await api<ZapInfo>(`/api/scans/${props.scanId}/zap/targets`, { method: "PUT", json: { hosts: ordered } });
        setInfo(r);
        toast(`Saved: ZAP will scan ${r.selected.length} host${r.selected.length === 1 ? "" : "s"} next time it runs`, "good");
      }
      props.onDone?.();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Couldn't save", "bad");
    } finally {
      setBusy(false);
    }
  };

  const counts = Object.fromEntries(FILTERS.map((f) => [f, f === "all" ? info.candidates.length : f === "selected" ? sel.size : info.candidates.filter((c) => c.group === f).length]));

  return (
    <div className="zap-targets">
      <div className="zap-summary">
        <div>
          <div className="clock-value">
            {ro && prog ? `${Math.min(prog.current, order.length)} / ${order.length}` : sel.size}
          </div>
          <div className="clock-label">{ro && prog ? "hosts started" : `of ${info.candidates.length} live hosts selected`}</div>
        </div>
        {!ro && (
          <div>
            <div className="clock-value muted-strong">~{fmtDur(minutes * 60000).replace(/ \d+s$/, "")}</div>
            <div className="clock-label">at ~{info.per_host_minutes} min per host, one at a time</div>
          </div>
        )}
        <p className="muted small zap-why">
          Hosts are ranked by how useful they are to crawl: pages with content first, then login prompts, then redirects. "Dead ends" answer
          403/404/5xx at the front page (storage buckets, CDN defaults) and are left out unless you tick them.
          {info.from_tls && " BBOT found no live hosts, so this list comes from hosts that answered on TLS."}
        </p>
      </div>

      {!ro && (
        <div className="toolbar">
          <input className="search" placeholder="Filter hosts…" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="seg" role="group" aria-label="Show">
            {FILTERS.map((f) => (
              <button key={f} className={filter === f ? "on" : ""} onClick={() => setFilter(f)}>
                {f === "all" ? "All" : f === "selected" ? "Selected" : GROUP_LABEL[f].label} {counts[f]}
              </button>
            ))}
          </span>
          <span className="spacer" />
          <Button small kind="ghost" onClick={() => setSel(new Set(info.recommended))}>
            Recommended
          </Button>
          <Button small kind="ghost" onClick={() => setSel(new Set([...sel, ...rows.map((r) => r.host)]))}>
            Select shown
          </Button>
          <Button small kind="ghost" onClick={() => setSel(new Set([...sel].filter((h) => !rows.some((r) => r.host === h))))}>
            Clear shown
          </Button>
        </div>
      )}

      <div className="zap-list" role="list">
        {(ro && order.length ? info.candidates.filter((c) => order.includes(c.host)).sort((a, b) => order.indexOf(a.host) - order.indexOf(b.host)) : rows).map(
          (c) => {
            const idx = order.indexOf(c.host) + 1;
            const state = ro && prog ? (idx < prog.current || prog.job === "done" ? "done" : idx === prog.current ? "now" : "next") : null;
            return (
              <label key={c.host} className={`zap-row ${sel.has(c.host) ? "on" : ""} ${state ? `zr-${state}` : ""}`} role="listitem">
                {ro ? (
                  <span className="zr-mark" aria-label={state ?? ""}>
                    {state === "done" ? "✓" : state === "now" ? <span className="spinner sm" /> : idx || ""}
                  </span>
                ) : (
                  <input type="checkbox" checked={sel.has(c.host)} onChange={(e) => toggle(c.host, e.target.checked)} />
                )}
                <span className="mono zr-host">{c.host}</span>
                {c.root && <Badge tone="info">main domain</Badge>}
                <Badge tone={GROUP_LABEL[c.group].tone}>
                  {GROUP_LABEL[c.group].label}
                  {c.status ? ` · ${c.status}` : ""}
                </Badge>
                {c.recommended && !ro && <span className="muted small">recommended</span>}
                {state === "now" && <span className="small activity">{prog?.job === "spiderAjax" ? "browser crawl" : "spidering"}</span>}
              </label>
            );
          }
        )}
        {!ro && rows.length === 0 && <div className="muted small">No hosts match.</div>}
      </div>

      {!ro && (
        <div className="actions">
          {props.mode === "edit" && info.custom && (
            <Button
              small
              kind="ghost"
              onClick={async () => {
                const r = await api<ZapInfo>(`/api/scans/${props.scanId}/zap/targets`, { method: "PUT", json: { hosts: null } });
                setInfo(r);
                setSel(new Set(r.selected));
                toast("Back to the recommended hosts", "info");
              }}
            >
              Reset to recommended
            </Button>
          )}
          <span className="spacer" />
          <Button kind="primary" onClick={save} disabled={busy || sel.size === 0}>
            {props.mode === "pick" ? `Start ZAP on ${sel.size} host${sel.size === 1 ? "" : "s"}` : `Save ${sel.size} host${sel.size === 1 ? "" : "s"} for the next ZAP run`}
          </Button>
        </div>
      )}
    </div>
  );
}
