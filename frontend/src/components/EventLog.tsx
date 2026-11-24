import { useEffect, useMemo, useRef, useState } from "react";
import { api, ScanEvent } from "../api";

const STAGE_SHORT: Record<string, string> = {
  discovery: "Discovery",
  bbot_light: "BBOT",
  tls: "TLS",
  zap: "ZAP",
  ports: "Ports",
  email: "Email",
  gau: "History",
  lookalikes: "Lookalikes",
  hibp: "Breaches",
  cloud: "Extra IPs",
  consolidate: "Consolidate",
};

type Line = { id: number; ts: string; stage: string | null; text: string; kind: string; key: string | null };

/** Activity feed for a scan or one stage. "Readable" turns tool output into plain English; "Raw" shows it as-is. */
export function EventLog(props: { scanId: string; live: boolean; stage?: string | null; height?: number; compact?: boolean }) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [mode, setMode] = useState<"readable" | "raw">("readable");
  const last = useRef(0);
  const box = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);

  useEffect(() => {
    last.current = 0;
    setEvents([]);
  }, [props.scanId, props.stage]);

  useEffect(() => {
    let stop = false;
    const q = props.stage ? `&stage=${encodeURIComponent(props.stage)}` : "";
    const tick = async () => {
      try {
        // page through everything new (finished scans can have thousands of lines)
        for (let i = 0; i < 20 && !stop; i++) {
          const r = await api<{ events: ScanEvent[] }>(`/api/scans/${props.scanId}/events?after=${last.current}${q}`);
          if (!r.events.length) break;
          last.current = r.events[r.events.length - 1].id;
          setEvents((e) => [...e, ...r.events].slice(-6000));
          if (r.events.length < 1000) break;
        }
      } catch {
        /* transient; next tick retries */
      }
    };
    tick();
    const t = props.live ? setInterval(tick, 1500) : undefined;
    return () => {
      stop = true;
      if (t) clearInterval(t);
    };
  }, [props.scanId, props.live, props.stage]);

  const lines: Line[] = useMemo(() => {
    if (mode === "raw") {
      return events.map((e) => ({ id: e.id, ts: e.ts, stage: e.stage_key, text: e.message, kind: e.level, key: null }));
    }
    // readable: hide noise, and let a progress line replace the previous one of the same kind
    const out: Line[] = [];
    const at: Record<string, number> = {};
    for (const e of events) {
      if (!e.human) continue;
      const line = { id: e.id, ts: e.ts, stage: e.stage_key, text: e.human.text, kind: e.human.kind, key: e.human.key };
      if (line.key) {
        const k = `${line.stage}|${line.key}`;
        if (at[k] !== undefined && at[k] === out.length - 1) {
          out[at[k]] = line;
          continue;
        }
        if (at[k] !== undefined) out[at[k]] = { ...out[at[k]], text: "", kind: "drop" };
        at[k] = out.length;
      }
      out.push(line);
    }
    return out.filter((l) => l.kind !== "drop");
  }, [events, mode]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);

  return (
    <div className="eventlog">
      <div className="eventlog-bar">
        <span className="seg" role="group" aria-label="Log view">
          <button className={mode === "readable" ? "on" : ""} onClick={() => setMode("readable")}>
            Readable
          </button>
          <button className={mode === "raw" ? "on" : ""} onClick={() => setMode("raw")}>
            Raw
          </button>
        </span>
        {props.live && (
          <span className="live-dot" aria-label="live">
            live
          </span>
        )}
        {!follow && (
          <button className="linklike small" onClick={() => setFollow(true)}>
            Jump to latest
          </button>
        )}
      </div>
      <div
        className={`log ${mode === "readable" ? "log-readable" : ""} ${props.compact ? "log-compact" : ""}`}
        style={props.height ? { height: props.height } : undefined}
        ref={box}
        onScroll={(e) => {
          const el = e.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
        }}
      >
        {lines.length === 0 ? (
          <div className="muted">{props.live ? "Waiting for output…" : "No activity recorded."}</div>
        ) : (
          lines.map((l) => (
            <div key={l.id} className={`log-line log-${l.kind}`}>
              <span className="log-ts">{l.ts.slice(11, 19)}</span>
              {!props.stage && l.stage && <span className="log-stage">{STAGE_SHORT[l.stage] ?? l.stage}</span>}
              <span className="log-text">{l.text}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
