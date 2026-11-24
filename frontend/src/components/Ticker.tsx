import { useEffect, useRef, useState } from "react";
import { api, Counts } from "../api";

/** A number that counts up (or down) to its new value instead of jumping. */
function Rolling(props: { value: number }) {
  const [shown, setShown] = useState(props.value);
  const from = useRef(props.value);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    const b = props.value;
    if (a === b) return;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      from.current = b;
      setShown(b);
      return;
    }
    let raf = 0;
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / 700);
      const v = Math.round(a + (b - a) * (1 - Math.pow(1 - p, 3)));
      setShown(v);
      from.current = v;
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [props.value]);
  return <>{shown.toLocaleString()}</>;
}

type Tile = { key: string; label: string; value: number; sub?: string; tone?: "bad" | "warn" | "good"; active?: boolean };

function buildTiles(c: Counts, mode: "discovery" | "run"): Tile[] {
  const b = c.bbot_live || {};
  const sev = c.issues_by_severity || {};
  const high = (sev.critical ?? 0) + (sev.high ?? 0);
  return mode === "discovery"
      ? [
          { key: "names", label: "Names found", value: Math.max(b.DNS_NAME ?? 0, c.subdomains_found), active: c.stage === "discovery" },
          { key: "ips", label: "IP addresses", value: b.IP_ADDRESS ?? 0 },
          { key: "ports", label: "Open ports (Shodan)", value: b.OPEN_TCP_PORT ?? 0 },
          { key: "tech", label: "Technologies", value: b.TECHNOLOGY ?? 0 },
          { key: "emails", label: "Email addresses", value: b.EMAIL_ADDRESS ?? 0 },
          { key: "related", label: "Related domains", value: c.related_found },
        ]
      : [
          { key: "domains", label: "Domains", value: c.domains },
          { key: "subs", label: "Subdomains in scope", value: c.subdomains_in_scope },
          {
            key: "live",
            label: "Live web hosts",
            value: c.live_hosts,
            active: c.stage === "bbot_light",
          },
          { key: "endpoints", label: "Web endpoints", value: c.web_endpoints, active: c.stage === "bbot_light" },
          { key: "hist", label: "Historical URLs", value: c.historical_urls, active: c.stage === "gau" },
          { key: "certs", label: "Certificates checked", value: c.certificates, active: c.stage === "tls" },
          { key: "ports", label: "Open ports", value: c.open_ports, active: c.stage === "ports" },
          {
            key: "exposed",
            label: "Risky services",
            value: c.exposed_services,
            tone: c.exposed_services ? "warn" : undefined,
            active: c.stage === "ports",
          },
          {
            key: "takeover",
            label: "Takeover risks",
            value: c.takeover_risks ?? 0,
            tone: c.takeover_risks ? "bad" : undefined,
            active: c.stage === "bbot_light",
          },
          { key: "look", label: "Lookalike domains", value: c.lookalikes, active: c.stage === "lookalikes" },
          {
            key: "issues",
            label: "Issues",
            value: c.issues,
            sub: c.issues ? `${high} high · ${sev.medium ?? 0} medium · ${sev.low ?? 0} low` : undefined,
            tone: high ? "bad" : c.issues ? "warn" : "good",
          },
        ];

}

export function Ticker(props: { scanId: string; live: boolean; mode: "discovery" | "run"; refreshKey?: string }) {
  const [c, setC] = useState<Counts | null>(null);
  const [bumped, setBumped] = useState<Record<string, boolean>>({});
  const prev = useRef<Record<string, number>>({});

  useEffect(() => {
    let stop = false;
    const load = async () => {
      try {
        const r = await api<Counts>(`/api/scans/${props.scanId}/counts`);
        if (!stop) setC(r);
      } catch {
        /* keep last numbers */
      }
    };
    load();
    if (!props.live) return () => (stop = true);
    const t = setInterval(load, 2000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [props.scanId, props.live, props.refreshKey]);

  useEffect(() => {
    if (!c) return;
    const changed: Record<string, boolean> = {};
    for (const t of buildTiles(c, props.mode)) {
      if (prev.current[t.key] !== undefined && t.value > prev.current[t.key]) changed[t.key] = true;
      prev.current[t.key] = t.value;
    }
    if (!Object.keys(changed).length) return;
    setBumped(changed);
    const t = setTimeout(() => setBumped({}), 900);
    return () => clearTimeout(t);
  }, [c, props.mode]);

  if (!c) return null;
  const tiles = buildTiles(c, props.mode);
  return (
    <div className="ticker" aria-live="polite">
      {tiles.map((t) => (
        <div key={t.key} className={`tick ${t.tone ? `tick-${t.tone}` : ""} ${bumped[t.key] ? "tick-bump" : ""} ${t.active && props.live ? "tick-active" : ""}`}>
          <div className="tick-value">
            <Rolling value={t.value} />
          </div>
          <div className="tick-label">{t.label}</div>
          {t.sub && <div className="tick-sub">{t.sub}</div>}
        </div>
      ))}
    </div>
  );
}
