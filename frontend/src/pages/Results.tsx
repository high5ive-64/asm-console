import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, isDemo, ApiError, AttackPath, AttackPathsResponse, Asset, ChangeFinding, Changes, DnsResponse, EmailsResponse, EmailCheckResult, EndpointsResponse, EolInfo, FindingDetail, FindingEvidence, GraphSummary, IpRow, IpsResponse, FileEntry, Finding, MitreLink, NavLink, Overview, RefLink, ReportPreview, ResultsTab, Scan, SearchResponse, TriageHost } from "../api";
import { Badge, Button, Card, Empty, fmtDate, useToast } from "../components/ui";

const TABS: { key: ResultsTab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "changes", label: "Changes" },
  { key: "assets", label: "Assets" },
  { key: "ips", label: "IPs" },
  { key: "dns", label: "DNS" },
  { key: "paths", label: "Attack paths" },
  { key: "findings", label: "Findings" },
  { key: "triage", label: "Triage" },
  { key: "files", label: "Files" },
  { key: "reports", label: "Reports" },
];
const SEV_TONE: Record<string, "bad" | "warn" | "info" | "muted"> = { critical: "bad", high: "bad", medium: "warn", low: "info", info: "muted" };
const SEVS = ["critical", "high", "medium", "low", "info"];
const AREA_LABEL: Record<string, string> = {
  exposure: "Exposure",
  web: "Web",
  tls: "TLS",
  email: "Email",
  brand: "Brand",
  people: "People",
  vulns: "Vulnerabilities",
  surface: "Unknown assets",
  intel: "Threat intel",
};
const STATUS_LABEL: Record<string, string> = { observation: "Observation", verified: "Verified", false_positive: "False positive" };
export function toolLabel(t: string): string {
  if (t === "zap") return "ZAP";
  if (t === "bbot:baddns") return "BBOT takeover check";
  if (t.startsWith("bbot:")) return `BBOT (${t.slice(5)})`;
  return (
    {
      internetdb: "Shodan InternetDB",
      "internetdb-extra": "Shodan InternetDB (extra IPs)",
      tlsx: "tlsx",
      "dns-email": "DNS (email)",
      dnstwist: "dnstwist",
      hibp: "HIBP",
      xposedornot: "XposedOrNot",
      dnsreaper: "dnsReaper",
      checkdmarc: "checkdmarc",
      testssl: "testssl.sh",
      cloudlist: "cloudlist",
      "intel-cve": "KEV / EPSS",
      leakix: "LeakIX",
      netlas: "Netlas",
      opensquat: "openSquat",
      urlscan: "urlscan.io",
      spiderfoot: "SpiderFoot",
      takeover: "Takeover checks (BBOT + dnsReaper)",
      "baddns-live": "baddns (live-host takeover)",
      asn: "ASN / netblock (BBOT)",
      "bbot:nuclei": "BBOT active (nuclei)",
      naabu: "naabu (active port check)",
      dnsx: "dnsx",
    } as Record<string, string>
  )[t] ?? t;
}
const fileUrl = (scanId: string, path: string, download = false) =>
  `/api/scans/${scanId}/files/raw?path=${encodeURIComponent(path)}${download ? "&download=1" : ""}`;

type EntityKind = "finding" | "host" | "path" | "more" | "tech" | "port" | "exposed" | "step";
interface Entity { kind: EntityKind; id: string }

// internet-exposed port → service name, and which ports are high-risk to expose
const PORT_SVC: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
  139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS",
  993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
  5432: "Postgres", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
  9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
};
const RISKY_PORTS = new Set([21, 22, 23, 25, 110, 111, 135, 139, 143, 389, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017]);
type PortRow = { port: number; service: string; count: number; risky: boolean; web: boolean; hosts: string[] };
function portGroups(assets: Asset[]): PortRow[] {
  const byPort = new Map<number, Set<string>>();
  for (const a of assets) for (const p of a.ports) (byPort.get(p) ?? byPort.set(p, new Set()).get(p)!).add(a.host);
  return [...byPort.entries()]
    .map(([port, hosts]) => ({ port, service: PORT_SVC[port] ?? "", count: hosts.size, risky: RISKY_PORTS.has(port), web: port === 80 || port === 443, hosts: [...hosts] }))
    .sort((a, b) => Number(b.risky) - Number(a.risky) || b.count - a.count);
}

// parse a trailing dotted version out of a tech string ("jQuery Migrate 3.0.1" -> "3.0.1"); null when
// the passive fingerprint carried no version
function parseVer(ts: string): string | null {
  const m = ts.match(/\s(v?\d+(?:\.\d+)+[a-z0-9.\-]*)\s*$/i);
  return m ? m[1].replace(/^v/i, "") : null;
}
// worst finding severity present on a host (from its severity counts), "" if clean
function hostSeverity(a: Asset): string {
  for (const s of SEVS) if (((a.findings as Record<string, number>)[s] ?? 0) > 0) return s;
  return "";
}
const cveId = (s: string): string | null => (s.match(/CVE-\d{4}-\d{4,7}/i) || [null])[0];
const isKev = (f: { title: string }): boolean => /known-exploited|cisa kev/i.test(f.title);

export function Results(props: { scan: Scan }) {
  const [tab, setTab] = useState<ResultsTab>("overview");
  const [filter, setFilter] = useState<Record<string, string | boolean>>({});
  const [nav, setNav] = useState(0); // remounts the tab so a new link or tab click starts from its own filters
  const go = useCallback((l: NavLink) => {
    setFilter(l.filter ?? {});
    setTab(l.tab);
    setNav((n) => n + 1);
    window.scrollTo({ top: 0 });
  }, []);
  // detail pane: a back-stack of entities (finding / host / path), so every drill-in pops out here and
  // keeps a breadcrumb trail back to the overview
  const [detail, setDetail] = useState<Entity[]>([]);
  const openEntity = useCallback((kind: EntityKind, id: string | number) => {
    const e: Entity = { kind, id: String(id) };
    setDetail((s) => (s.length && s[s.length - 1].kind === e.kind && s[s.length - 1].id === e.id ? s : [...s, e]));
  }, []);
  const openFinding = useCallback((id: number) => openEntity("finding", id), [openEntity]);
  const closeDetail = useCallback(() => setDetail([]), []);
  const backDetail = useCallback(() => setDetail((s) => s.slice(0, -1)), []);
  const goFromDrawer = useCallback((l: NavLink) => { setDetail([]); go(l); }, [go]);
  const running = props.scan.status === "running";
  return (
    <div className="stack">
      {running && <div className="banner banner-info">The scan is still running: these results are partial and fill in as stages finish.</div>}
      <div className="results-header">
        <GlobalSearch scanId={props.scan.id} go={go} />
        <Button kind="secondary" small onClick={() => go({ tab: "reports", filter: {} })}>
          Export report
        </Button>
      </div>
      <nav className="tabs" role="tablist">
        {(isDemo() ? TABS.filter((t) => t.key !== "files") : TABS).map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            className={tab === t.key ? "tab on" : "tab"}
            onClick={() => go({ tab: t.key, filter: {} })}
          >
            {t.label}
          </button>
        ))}
      </nav>
      {tab === "overview" && <OverviewTab key={nav} scanId={props.scan.id} go={go} onEntity={openEntity} />}
      {tab === "changes" && <ChangesTab key={nav} scanId={props.scan.id} go={go} />}
      {tab === "assets" && <AssetsTab key={nav} scanId={props.scan.id} initial={filter} go={go} />}
      {tab === "ips" && <IpsTab key={nav} scanId={props.scan.id} go={go} initial={filter} />}
      {tab === "paths" && <AttackPathsTab key={nav} scanId={props.scan.id} go={go} />}
      {tab === "findings" && <FindingsTab key={nav} scanId={props.scan.id} initial={filter} onOpen={openFinding} onEntity={openEntity} go={go} />}
      {tab === "triage" && <TriageTab key={nav} scanId={props.scan.id} initial={filter} />}
      {tab === "dns" && <DnsTab key={nav} scanId={props.scan.id} />}
      {tab === "files" && <FilesTab key={nav} scanId={props.scan.id} initial={filter} />}
      {tab === "reports" && <ReportsTab key={nav} scanId={props.scan.id} />}
      {detail.length > 0 && (
        <EntityDrawer
          scanId={props.scan.id}
          stack={detail}
          go={goFromDrawer}
          onEntity={openEntity}
          onBack={backDetail}
          onClose={closeDetail}
        />
      )}
    </div>
  );
}

// ---- global search ----------------------------------------------------------------------
function GlobalSearch(props: { scanId: string; go: (l: NavLink) => void }) {
  const [q, setQ] = useState("");
  const [res, setRes] = useState<SearchResponse | null>(null);
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    const ql = q.trim();
    if (ql.length < 2) {
      setRes(null);
      return;
    }
    timer.current = setTimeout(() => {
      api<SearchResponse>(`/api/scans/${props.scanId}/search?q=${encodeURIComponent(ql)}`)
        .then((r) => {
          setRes(r);
          setOpen(true);
        })
        .catch(() => setRes(null));
    }, 180);
    return () => timer.current && clearTimeout(timer.current);
  }, [q, props.scanId]);
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);
  const pick = (l: NavLink) => {
    setOpen(false);
    setQ("");
    setRes(null);
    props.go(l);
  };
  const total = res ? res.hosts.length + res.ips.length + res.findings.length : 0;
  return (
    <div className="gsearch" ref={box}>
      <input
        className="search gsearch-input"
        placeholder="Search this scan — host, IP or finding…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onFocus={() => res && setOpen(true)}
        onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
        aria-label="Search this scan"
      />
      {open && res && (
        <div className="gsearch-panel" role="listbox">
          {total === 0 && <div className="gsearch-empty muted small">No hosts, IPs or findings match “{res.q}”.</div>}
          {res.hosts.length > 0 && (
            <div className="gsearch-group">
              <div className="gsearch-head">Hosts</div>
              {res.hosts.map((h) => (
                <button key={h.host} className="gsearch-item" onClick={() => pick({ tab: "assets", filter: { q: h.host } })}>
                  <span className="mono">{h.host}</span>
                  {h.agent && <Badge tone="warn">agent</Badge>}
                  {h.live && <Badge tone="info">live</Badge>}
                </button>
              ))}
              {res.more?.hosts ? <div className="gsearch-more muted small">+{res.more.hosts} more hosts</div> : null}
            </div>
          )}
          {res.ips.length > 0 && (
            <div className="gsearch-group">
              <div className="gsearch-head">IPs</div>
              {res.ips.map((e) => (
                <button key={e.ip} className="gsearch-item" onClick={() => pick({ tab: "ips", filter: { q: e.ip } })}>
                  <span className="mono">{e.ip}</span>
                  <span className="muted small">{e.hosts.length} host{e.hosts.length === 1 ? "" : "s"}</span>
                </button>
              ))}
              {res.more?.ips ? <div className="gsearch-more muted small">+{res.more.ips} more IPs</div> : null}
            </div>
          )}
          {res.findings.length > 0 && (
            <div className="gsearch-group">
              <div className="gsearch-head">Findings</div>
              {res.findings.map((f, i) => (
                <button key={i} className="gsearch-item" onClick={() => pick({ tab: "findings", filter: { q: f.group } })}>
                  <Badge tone={SEV_TONE[f.severity] ?? "muted"}>{f.severity}</Badge>
                  <span className="gsearch-ftitle">{f.group}</span>
                  {f.host && <span className="muted small mono">{f.host}</span>}
                </button>
              ))}
              {res.more?.findings ? <div className="gsearch-more muted small">+{res.more.findings} more findings</div> : null}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---- overview ---------------------------------------------------------------------------

// colour an at-a-glance tile when its number is worth noticing — red for exposure/exploitation, amber
// for hygiene gaps, blue for the agent surface; plain when zero or neutral
const TILE_BAD = new Set(["takeover_risks", "risky_services", "high_findings", "kev_cves"]);
const TILE_WARN = new Set(["unknown_hosts", "medium_findings", "expiring_certs", "dmarc_missing", "lookalikes_with_mail", "likely_exploited", "open_ports"]);
const TILE_INFO = new Set(["agent_surface"]);
function tileTone(key: string, value: number): "" | "bad" | "warn" | "info" {
  if (value <= 0) return "";
  if (TILE_BAD.has(key)) return "bad";
  if (TILE_WARN.has(key)) return "warn";
  if (TILE_INFO.has(key)) return "info";
  return "";
}

const VCONF_LABEL: Record<string, string> = { confirmed: "Confirmed", probable: "Probable", unconfirmed: "Unconfirmed" };
const VCONF_SUB: Record<string, string> = { confirmed: "version in affected range — act now", probable: "version fingerprinted — verify the build", unconfirmed: "no version — fingerprint first" };
const VCONF_TONE: Record<string, string> = { confirmed: "bad", probable: "warn", unconfirmed: "muted" };

function ConfBadge(props: { c: string }) {
  return <span className={`vconf-badge vconf-${VCONF_TONE[props.c] ?? "muted"}`}>{VCONF_LABEL[props.c] ?? props.c}</span>;
}

function VulnMatrix(props: { m: Overview["vuln_matrix"]; go: (l: NavLink) => void }) {
  const vm = props.m;
  if (!vm) return null;
  const sevs = ["critical", "high", "medium", "low", "info"].filter((s) => vm.order.some((c) => (vm.matrix[c]?.[s] ?? 0) > 0));
  if (sevs.length === 0) return null;
  return (
    <Card title="CVE confidence">
      <p className="muted small" style={{ marginTop: 0 }}>Version-based CVEs by how sure we are the host is actually affected — so the act-now cases don't drown in the maybes.</p>
      <table className="table compact vmx">
        <thead><tr><th>Confidence</th>{sevs.map((s) => <th key={s} className="vmx-sev">{s}</th>)}</tr></thead>
        <tbody>
          {vm.order.map((c) => {
            const rowTotal = sevs.reduce((n, s) => n + (vm.matrix[c]?.[s] ?? 0), 0);
            if (rowTotal === 0) return null;
            return (
              <tr key={c}>
                <td><ConfBadge c={c} /><div className="muted small">{VCONF_SUB[c]}</div></td>
                {sevs.map((s) => {
                  const n = vm.matrix[c]?.[s] ?? 0;
                  const act = c === "confirmed" && (s === "critical" || s === "high") && n > 0;
                  return (
                    <td key={s} className={"vmx-cell" + (act ? " vmx-act" : "")}>
                      {n > 0
                        ? <button className="linklike" onClick={() => props.go({ tab: "findings", filter: { area: "vulns", confidence: c } })} title={`${VCONF_LABEL[c]} · ${s}`}>{n}</button>
                        : <span className="muted">·</span>}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      {vm.act_now > 0 && (
        <p className="small" style={{ marginTop: 8 }}><strong className="vconf-bad-text">{vm.act_now} confirmed vulnerable</strong> — patch or mitigate now. The rest need the running version verified before acting.</p>
      )}
    </Card>
  );
}

function DiscoveredEmails(props: { scanId: string }) {
  const [data, setData] = useState<EmailsResponse | null>(null);
  const [checking, setChecking] = useState(false);
  const [results, setResults] = useState<EmailCheckResult[] | null>(null);
  useEffect(() => {
    api<EmailsResponse>(`/api/scans/${props.scanId}/emails`).then(setData).catch(() => setData(null));
  }, [props.scanId]);
  if (!data || data.count === 0) return null;
  const byEmail: Record<string, EmailCheckResult> = {};
  for (const r of results ?? []) byEmail[r.email] = r;
  const run = async () => {
    setChecking(true);
    try {
      const r = await api<{ results: EmailCheckResult[] }>(`/api/scans/${props.scanId}/emails/check`, { method: "POST" });
      setResults(r.results);
    } catch {
      setResults([]);
    }
    setChecking(false);
  };
  return (
    <Card title={`Discovered emails (${data.count})`}>
      <p className="muted small" style={{ marginTop: 0 }}>
        Addresses BBOT extracted from pages, DNS and certificates.
        {data.flagged ? " This domain shows breach exposure — you can run a per-address breach check (XposedOrNot)." : " A per-address breach check unlocks once the domain shows breach exposure."}
      </p>
      <div className="email-list">
        {data.emails.map((e) => {
          const r = byEmail[e.email];
          return (
            <div key={e.email} className="email-row">
              <span className="mono">{e.email}</span>
              {e.sources.length > 0 && <span className="muted small">{e.sources.join(", ")}</span>}
              {r && (r.breaches.length > 0
                ? <span className="vconf-badge vconf-bad" title={r.breaches.join(", ")}>{r.breaches.length} breach{r.breaches.length === 1 ? "" : "es"}: {r.breaches.slice(0, 3).join(", ")}{r.breaches.length > 3 ? "…" : ""}</span>
                : r.ok ? <span className="vconf-badge vconf-muted">not found</span> : <span className="muted small">check failed</span>)}
            </div>
          );
        })}
      </div>
      {data.flagged && (
        <div style={{ marginTop: 10 }}>
          <Button small kind="secondary" disabled={checking} onClick={run}>
            {checking ? "Checking…" : results ? "Re-check" : "Deep breach check on these emails →"}
          </Button>
          {results && <span className="muted small" style={{ marginLeft: 10 }}>{results.filter((x) => x.breaches.length).length} of {results.length} exposed.</span>}
        </div>
      )}
    </Card>
  );
}

function OverviewTab(props: { scanId: string; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [o, setO] = useState<Overview | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [allTech, setAllTech] = useState(false);
  useEffect(() => {
    api<Overview>(`/api/scans/${props.scanId}/overview`).then(setO);
    api<{ findings: Finding[] }>(`/api/scans/${props.scanId}/findings`).then((r) => setFindings(r.findings)).catch(() => setFindings([]));
    api<{ assets: Asset[] }>(`/api/scans/${props.scanId}/assets`).then((r) => setAssets(r.assets)).catch(() => setAssets([]));
  }, [props.scanId]);
  if (!o) return <Empty>Loading…</Empty>;
  const ragText = { red: "Needs action", amber: "Needs attention", green: "Nothing significant" }[o.rag];
  const v = o.values || {};
  return (
    <div className="stack">
      {o.partial && (
        <div className="incomplete-banner">
          <strong>Incomplete scan.</strong>{" "}
          {(o.failed_stages?.length ?? 0) > 0
            ? `${o.failed_stages!.length} stage${o.failed_stages!.length === 1 ? "" : "s"} failed (${o.failed_stages!.map((s) => s.replace(/_/g, " ")).join(", ")}).`
            : "Some stages didn't complete."}{" "}
          Findings and the rating below may understate risk — re-run the failed stage(s).
        </div>
      )}
      <div className={`status-strip rag-${o.rag}`}>
        <span className="rag-dot" aria-hidden="true" />
        <strong>{o.rag.toUpperCase()}</strong>
        <span className="status-sep">·</span>
        <span>{ragText}</span>
        <span className="muted status-nums">
          {(o.severity.critical ?? 0) + (o.severity.high ?? 0)} high/critical · {o.severity.medium ?? 0} medium · {(v.hosts_in_scope ?? 0).toLocaleString()} hosts
          {v.unknown_hosts ? `, ${v.unknown_hosts.toLocaleString()} to triage` : ""}
        </span>
        {o.previous && <span className="muted small status-prev">prev {fmtDate(o.previous.finished_at)}: {o.previous.rag}</span>}
      </div>

      {o.previous && <WhatChanged scanId={props.scanId} go={props.go} />}

      <div className="ov-top">
        <SurfaceMap scanId={props.scanId} findings={findings} go={props.go} onEntity={props.onEntity} />
        <Worklist o={o} findings={findings} go={props.go} onEntity={props.onEntity} />
      </div>

      <h2 className="sec-head">At a glance</h2>
      <div className="metrics-compact">
        {o.cards.map((c) => {
          const tone = tileTone(c.key, c.value);
          const exposed = c.key === "open_ports" || c.key === "risky_services";
          return (
            <button key={c.key} className={`mcard-c${tone ? " tone-" + tone : ""}`} onClick={() => (exposed ? props.onEntity("exposed", "") : props.go(c.link))} title={exposed ? "See the exposed services" : "Open the source of this number"}>
              <span className="mcard-c-value">{c.value.toLocaleString()}</span>
              <span className="mcard-c-label">{c.label}</span>
              {c.previous !== null && c.trend && <span className={`mcard-c-trend trend-${c.trend}`}>{c.value > c.previous ? "▲" : "▼"}</span>}
            </button>
          );
        })}
      </div>

      <ExposedServices assets={assets} onEntity={props.onEntity} />
      {o.vuln_matrix && <VulnMatrix m={o.vuln_matrix} go={props.go} />}
      <DiscoveredEmails scanId={props.scanId} />

      {((o.agent_hosts && o.agent_hosts.length > 0) || (o.tech && o.tech.length > 0)) && (
        <details className="secondary-detail">
          <summary>Agent surface &amp; technologies</summary>
          <div className="secondary-body">
            {o.agent_hosts && o.agent_hosts.length > 0 && (
              <Card title={`AI-agent / MCP surface (${o.agent_hosts.length})`} actions={<Button small kind="ghost" onClick={() => props.go({ tab: "assets", filter: { tag: "agent" } })}>View assets</Button>}>
                <p className="muted small">Live hosts whose names mark them as agent, MCP, model or digital-twin infrastructure. Review authentication, rate limits and tool scope on each.</p>
                <ul className="chips">
                  {o.agent_hosts.slice(0, 40).map((h) => (
                    <li key={h} className="chip mono" onClick={() => props.onEntity("host", h)} style={{ cursor: "pointer" }}>{h}</li>
                  ))}
                  {o.agent_hosts.length > 40 && <li className="muted small">…and {o.agent_hosts.length - 40} more</li>}
                </ul>
              </Card>
            )}
            {o.tech && o.tech.length > 0 && (
              <Card title="Technologies">
                <p className="muted small" style={{ marginTop: 0 }}>Click a technology to see the hosts and versions running it, and any issues linked to it.</p>
                <div className="techbars">
                  {(allTech ? o.tech : o.tech.slice(0, 18)).map((t) => (
                    <button key={t.name} className="techbar techbar-btn" onClick={() => props.onEntity("tech", t.name)} title={`Drill into ${t.name}`}>
                      <span className="techbar-name mono small">{t.name}</span>
                      <span className="techbar-track"><span className="techbar-fill" style={{ width: `${Math.round((t.count / o.tech[0].count) * 100)}%` }} /></span>
                      <span className="techbar-n small muted">{t.count}</span>
                    </button>
                  ))}
                </div>
                {o.tech.length > 18 && (
                  <button className="linklike small" style={{ marginTop: 8 }} onClick={() => setAllTech((v) => !v)}>
                    {allTech ? "Show fewer" : `Show all ${o.tech.length} technologies →`}
                  </button>
                )}
              </Card>
            )}
          </div>
        </details>
      )}
      {o.not_collected.length > 0 && <p className="muted small">Not collected in this run: {o.not_collected.join("; ")}.</p>}
    </div>
  );
}

type WorkRow = { severity: string; title: string; meta: string; onClick: () => void };

// the hero of the Overview: a single worst-first list that unifies finding groups with non-finding
// actions (unknown hosts to triage, the agent surface to review). Each row drills into the detail pane
// or the relevant workflow.
function Worklist(props: { o: Overview; findings: Finding[] | null; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const v = props.o.values || {};
  const items = useMemo<WorkRow[]>(() => {
    const fitems: WorkRow[] = props.findings
      ? rankIssues(aggregateIssues(props.findings), 2, 9999).head.map((i) => ({
          severity: i.severity, title: i.title, meta: `${i.count} host${i.count === 1 ? "" : "s"} · ${AREA_LABEL[i.area] ?? i.area}`,
          onClick: () => props.onEntity("finding", i.fid),
        }))
      : [];
    const actions: WorkRow[] = [];
    if (v.unknown_hosts) actions.push({ severity: "medium", title: `${v.unknown_hosts.toLocaleString()} hosts not in the CMDB — triage them`, meta: "unknown assets", onClick: () => props.go({ tab: "triage", filter: { decision: "undecided" } }) });
    if (v.agent_surface) actions.push({ severity: "medium", title: `${v.agent_surface} AI-agent / MCP host${v.agent_surface === 1 ? "" : "s"} exposed — review auth & rate limits`, meta: "agent surface", onClick: () => props.go({ tab: "assets", filter: { tag: "agent" } }) });
    return [...actions, ...fitems].sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity));
  }, [props.findings, props.o]);
  const CAPW = 14;
  const head = items.slice(0, CAPW);
  const extra = items.length - head.length;
  return (
    <Card title="Needs attention — worst first" actions={<Button small kind="ghost" onClick={() => props.go({ tab: "findings", filter: {} })}>All findings</Button>}>
      {props.findings === null ? (
        <Empty>Loading…</Empty>
      ) : items.length === 0 ? (
        <Empty>Nothing above low severity — nice.</Empty>
      ) : (
        <>
          <ul className="worklist">
            {head.map((it, i) => (
              <li key={i}>
                <button className="wl-row" onClick={it.onClick}>
                  <span className={`wl-accent sev-bg-${SEV_TONE[it.severity]}`} aria-hidden="true" />
                  <Badge tone={SEV_TONE[it.severity]}>{it.severity}</Badge>
                  <span className="wl-title">{it.title}</span>
                  <span className="muted small wl-meta">{it.meta}</span>
                  <span className="wl-chev">›</span>
                </button>
              </li>
            ))}
          </ul>
          {extra > 0 && (
            <button className="linklike small wl-more" onClick={() => props.go({ tab: "findings", filter: {} })}>+{extra} more — view all in Findings →</button>
          )}
        </>
      )}
    </Card>
  );
}

// ---- changes since another scan ------------------------------------------------------------------

function WhatChanged(props: { scanId: string; go: (l: NavLink) => void }) {
  const [c, setC] = useState<Changes | null>(null);
  useEffect(() => {
    api<Changes>(`/api/scans/${props.scanId}/changes`).then(setC).catch(() => setC(null));
  }, [props.scanId]);
  if (!c?.against || !c.headline) return null;
  const nNew = c.findings?.new.length ?? 0;
  const nRes = c.findings?.resolved.length ?? 0;
  return (
    <Card
      title={`What changed since ${fmtDate(c.against.finished_at)}`}
      actions={
        <Button small kind="ghost" onClick={() => props.go({ tab: "changes", filter: {} })}>
          Details
        </Button>
      }
    >
      <ul className="headline">
        {c.headline.map((h, i) => (
          <li key={i}>{h}</li>
        ))}
      </ul>
      <div className="change-stats">
        <ChangeStat n={c.hosts?.added.length ?? 0} label="new hosts" bad />
        <ChangeStat n={c.ports?.opened.length ?? 0} label="ports opened" bad />
        <ChangeStat n={nNew} label="new findings" bad />
        <ChangeStat n={nRes} label="resolved" />
      </div>
    </Card>
  );
}

function ChangeStat(props: { n: number; label: string; bad?: boolean }) {
  return (
    <div className={`change-stat ${props.n ? (props.bad ? "up" : "down") : ""}`}>
      <span className="change-n">{props.n}</span>
      <span className="small muted">{props.label}</span>
    </div>
  );
}

function ChangesTab(props: { scanId: string; go: (l: NavLink) => void }) {
  const [against, setAgainst] = useState<string>("");
  const [c, setC] = useState<Changes | null>(null);
  useEffect(() => {
    setC(null);
    api<Changes>(`/api/scans/${props.scanId}/changes${against ? `?against=${encodeURIComponent(against)}` : ""}`).then(setC);
  }, [props.scanId, against]);
  if (!c) return <Empty>Loading…</Empty>;
  if (!c.against) return <Empty>No earlier finished scan of this domain to compare with. Run another scan later to see what changed.</Empty>;
  const list = (title: string, items: ChangeFinding[], tone: "new" | "gone" | "moved") => (
    <Card title={`${title} (${items.length})`}>
      {items.length === 0 ? (
        <p className="muted small">None.</p>
      ) : (
        <ul className="risk-list">
          {items.slice(0, 300).map((f, i) => (
            <li key={i}>
              <button className="risk" onClick={() => props.go({ tab: "findings", filter: { q: f.host ?? f.title } })} disabled={tone === "gone"}>
                <Badge tone={SEV_TONE[f.severity]}>{f.was ? `${f.was} → ${f.severity}` : f.severity}</Badge>
                <span className="risk-title">{f.title}</span>
                <span className="muted small">
                  {f.host ?? ""} · {toolLabel(f.tool)}
                </span>
              </button>
            </li>
          ))}
          {items.length > 300 && <li className="muted small">…and {items.length - 300} more</li>}
        </ul>
      )}
    </Card>
  );
  const hostList = (title: string, items: string[]) => (
    <Card title={`${title} (${items.length})`}>
      {items.length === 0 ? (
        <p className="muted small">None.</p>
      ) : (
        <ul className="chips">
          {items.slice(0, 200).map((h) => (
            <li key={h} className="chip mono">
              {h}
            </li>
          ))}
          {items.length > 200 && <li className="muted small">…and {items.length - 200} more</li>}
        </ul>
      )}
    </Card>
  );
  return (
    <div className="stack">
      <div className="toolbar wrap">
        <label className="small">
          Compare with{" "}
          <select value={against || c.against.id} onChange={(e) => setAgainst(e.target.value)}>
            {c.options.map((o) => (
              <option key={o.id} value={o.id}>
                {fmtDate(o.finished_at)} ({o.status.replace(/_/g, " ")})
              </option>
            ))}
          </select>
        </label>
        {c.rag && (
          <span className="small">
            Status: <span className={`rag-pill rag-pill-${c.rag.before}`}>{c.rag.before}</span> →{" "}
            <span className={`rag-pill rag-pill-${c.rag.after}`}>{c.rag.after}</span>
          </span>
        )}
      </div>
      <Card title="Summary">
        <ul className="headline">
          {c.headline?.map((h, i) => (
            <li key={i}>{h}</li>
          ))}
        </ul>
        {c.metrics && Object.keys(c.metrics).length > 0 && (
          <table className="table compact gap-top">
            <thead>
              <tr>
                <th>Measure</th>
                <th>Before</th>
                <th>Now</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(c.metrics).map(([k, v]) => (
                <tr key={k}>
                  <td>{k.replace(/_/g, " ")}</td>
                  <td>{v.before ?? "—"}</td>
                  <td>{v.after}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {list("New findings", c.findings?.new ?? [], "new")}
      {list("Resolved findings", c.findings?.resolved ?? [], "gone")}
      {(c.findings?.changed.length ?? 0) > 0 && list("Severity changed", c.findings!.changed, "moved")}
      {c.dns && c.dns.length > 0 && (
        <Card title={`DNS changes on existing hosts (${c.dns.length})`}>
          <table className="table compact">
            <thead>
              <tr>
                <th>Host</th>
                <th>Type</th>
                <th>Record</th>
                <th>Change</th>
              </tr>
            </thead>
            <tbody>
              {c.dns.slice(0, 400).map((d, i) => (
                <tr key={i}>
                  <td className="mono">{d.host}</td>
                  <td>{d.type}</td>
                  <td className="mono small">{d.value}</td>
                  <td className={d.change === "added" ? "warn-text" : "muted"}>{d.change}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      <div className="grid-2">
        {hostList("Hosts that appeared", c.hosts?.added ?? [])}
        {hostList("Hosts that disappeared", c.hosts?.removed ?? [])}
        {hostList("Newly live", c.live?.added ?? [])}
        {hostList("No longer live", c.live?.removed ?? [])}
        {hostList("Ports newly open", (c.ports?.opened ?? []).map((p) => `${p.host}:${p.port}`))}
        {hostList("Ports closed", (c.ports?.closed ?? []).map((p) => `${p.host}:${p.port}`))}
      </div>
    </div>
  );
}

// ---- assets -------------------------------------------------------------------------------

const ASSET_FILTERS: { key: string; label: string; test: (a: Asset) => boolean }[] = [
  { key: "live", label: "Live web", test: (a) => a.is_live },
  { key: "unknown", label: "Not in CMDB", test: (a) => !a.in_cmdb },
  { key: "issues", label: "Has issues", test: (a) => (a.findings.critical ?? 0) + (a.findings.high ?? 0) + (a.findings.medium ?? 0) > 0 },
  { key: "ports", label: "Open ports", test: (a) => a.ports.length > 0 },
  { key: "risky", label: "Risky ports", test: (a) => a.risky_ports.length > 0 },
  { key: "third_party", label: "Third-party hosted", test: (a) => a.third_party },
  { key: "cdn", label: "Behind CDN", test: (a) => a.cdn },
  { key: "shots", label: "Has screenshot", test: (a) => !!a.screenshot },
  { key: "agent", label: "AI-agent / MCP", test: (a) => (a.tags ?? []).some((t) => ["mcp", "agent", "ai", "twin"].includes(t)) },
];

function AssetsTab(props: { scanId: string; initial: Record<string, string | boolean>; go: (l: NavLink) => void }) {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [on, setOn] = useState<Set<string>>(
    new Set([
      ...Object.keys(props.initial).filter((k) => props.initial[k] === true),
      ...(props.initial.tag === "agent" ? ["agent"] : []),
    ])
  );
  const [q, setQ] = useState(typeof props.initial.q === "string" ? props.initial.q : "");
  const [sort, setSort] = useState<"host" | "issues" | "expiry">("issues");
  const [open, setOpen] = useState<string | null>(null);
  const [limit, setLimit] = useState(100);
  const [decisions, setDecisions] = useState<Record<string, string>>({});
  useEffect(() => {
    api<{ assets: Asset[]; decisions?: Record<string, string> }>(`/api/scans/${props.scanId}/assets`).then((r) => {
      setAssets(r.assets);
      if (r.decisions) setDecisions(r.decisions);
    });
  }, [props.scanId]);
  const rows = useMemo(() => {
    if (!assets) return [];
    const ql = q.trim().toLowerCase();
    const sevScore = (a: Asset) => (a.findings.critical ?? 0) * 1000 + (a.findings.high ?? 0) * 100 + (a.findings.medium ?? 0) * 10 + (a.findings.low ?? 0);
    return assets
      .filter((a) => ASSET_FILTERS.every((f) => !on.has(f.key) || f.test(a)))
      .filter((a) => !ql || a.host.includes(ql) || a.ips.some((ip) => ip.includes(ql)) || a.tech.some((t) => t.toLowerCase().includes(ql)))
      .sort((a, b) =>
        sort === "host" ? a.host.localeCompare(b.host) : sort === "expiry" ? (a.tls_expiry ?? "9999").localeCompare(b.tls_expiry ?? "9999") : sevScore(b) - sevScore(a) || a.host.localeCompare(b.host)
      );
  }, [assets, on, q, sort]);
  if (!assets) return <Empty>Loading…</Empty>;
  const toggle = (k: string) => {
    const n = new Set(on);
    if (n.has(k)) n.delete(k);
    else n.add(k);
    setOn(n);
  };
  return (
    <div className="stack">
      <div className="toolbar wrap">
        <input className="search" placeholder="Search host, IP or technology…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="chips">
          {ASSET_FILTERS.map((f) => (
            <button key={f.key} className={`chip ${on.has(f.key) ? "on" : ""}`} onClick={() => toggle(f.key)}>
              {f.label} <span className="chip-n">{assets.filter(f.test).length}</span>
            </button>
          ))}
        </span>
        <span className="spacer" />
        <label className="small muted">
          Sort{" "}
          <select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}>
            <option value="issues">Most issues</option>
            <option value="host">Host name</option>
            <option value="expiry">Certificate expiry</option>
          </select>
        </label>
      </div>
      <p className="muted small">
        {rows.length} of {assets.length} assets
      </p>
      <div className="table-wrap">
        <table className="table assets">
          <thead>
            <tr>
              <th />
              <th>Host</th>
              <th>Status</th>
              <th>IPs</th>
              <th>Technology</th>
              <th>TLS expiry</th>
              <th>Ports</th>
              <th>Category</th>
              <th>Flags</th>
              <th>Issues</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, limit).map((a) => (
              <Fragment key={a.host}>
                <tr className={open === a.host ? "sel" : ""} onClick={() => setOpen(open === a.host ? null : a.host)}>
                  <td className="thumb-cell">
                    {a.screenshot ? <img className="thumb" src={fileUrl(props.scanId, a.screenshot)} alt="" loading="lazy" /> : <span className="thumb none" />}
                  </td>
                  <td className="mono">{a.host}</td>
                  <td>{a.http_status ?? (a.is_live ? "live" : "")}</td>
                  <td className="mono small">
                    {a.ips.slice(0, 2).join(", ")}
                    {a.ips.length > 2 ? ` +${a.ips.length - 2}` : ""}
                  </td>
                  <td className="small">{a.tech.slice(0, 3).join(", ")}</td>
                  <td className={`small ${a.tls_flags.length ? "warn-text" : ""}`}>{a.tls_expiry ?? ""}</td>
                  <td className="small">
                    {a.risky_ports.length ? <span className="bad-text">{a.risky_ports.join(", ")}</span> : a.ports.slice(0, 4).join(", ")}
                  </td>
                  <td className="small nowrap cat-cell">
                    {a.triage ? (
                      <span className={`cat cat-${a.triage}`}>{decisions[a.triage] ?? a.triage}</span>
                    ) : a.suggestion ? (
                      <span className="cat-suggest" title={a.suggestion.reasons.join(" · ")}>
                        <span className={`sg-dot sg-${a.suggestion.confidence}`} aria-hidden="true" />
                        {decisions[a.suggestion.decision] ?? a.suggestion.decision}
                        <span className="muted"> · {a.suggestion.confidence}</span>
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="small nowrap">
                    {!a.in_cmdb && <Badge tone="warn">not in CMDB</Badge>} {a.third_party && <Badge tone="muted">3rd party</Badge>}{" "}
                    {a.cdn && <Badge tone="muted">{a.edge?.waf ? `WAF: ${a.edge.waf}` : a.edge?.cdn ? `CDN: ${a.edge.cdn}` : "CDN"}</Badge>}{" "}
                    {!a.cdn && a.edge?.cloud && <Badge tone="muted">{a.edge.cloud}</Badge>}{" "}
                    {a.found_by?.length > 0 && <Badge tone="info">via {a.found_by.join(", ")}</Badge>}
                  </td>
                  <td className="nowrap">
                    {SEVS.slice(0, 3).map((s) =>
                      a.findings[s] ? (
                        <Badge key={s} tone={SEV_TONE[s]}>
                          {a.findings[s]} {s}
                        </Badge>
                      ) : null
                    )}
                  </td>
                </tr>
                {open === a.host && (
                  <tr className="detail-row">
                    <td colSpan={10}>
                      <AssetDetail scanId={props.scanId} a={a} go={props.go} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > limit && (
        <Button kind="ghost" onClick={() => setLimit(limit + 200)}>
          Show more ({rows.length - limit} left)
        </Button>
      )}
    </div>
  );
}

function AssetDetail(props: { scanId: string; a: Asset; go: (l: NavLink) => void }) {
  const { a } = props;
  return (
    <div className="asset-detail">
      {a.screenshot && (
        <a href={fileUrl(props.scanId, a.screenshot)} target="_blank" rel="noreferrer">
          <img className="shot" src={fileUrl(props.scanId, a.screenshot)} alt={`Screenshot of ${a.host}`} />
        </a>
      )}
      <dl className="kv small">
        <dt>Web</dt>
        <dd className="mono">{a.web_url ?? "not seen"}</dd>
        <dt>All IPs</dt>
        <dd className="mono">{a.ips.join(", ") || "none recorded"}</dd>
        <dt>Technology</dt>
        <dd>{a.tech.join(", ") || "none detected"}</dd>
        <dt>TLS</dt>
        <dd>
          {a.tls_version ? `${a.tls_version}, expires ${a.tls_expiry}` : "not checked"}
          {a.tls_flags.length ? ` · ${a.tls_flags.join(", ")}` : ""}
        </dd>
        <dt>Open ports</dt>
        <dd>{a.ports.join(", ") || "none seen by Shodan"}</dd>
        {a.ports_confirmed && (
          <>
            <dt>Confirmed open</dt>
            <dd>{a.ports_confirmed.join(", ") || "nothing answered the port check"}</dd>
          </>
        )}
        <dt>Network</dt>
        <dd>
          {[a.edge?.cdn && `CDN ${a.edge.cdn}`, a.edge?.waf && `WAF ${a.edge.waf}`, a.edge?.cloud && `cloud ${a.edge.cloud}`].filter(Boolean).join(" · ") ||
            "no CDN, WAF or cloud provider matched"}
        </dd>
        <dt>Triage</dt>
        <dd>{a.in_cmdb ? "in CMDB" : a.triage ? a.triage.replace(/_/g, " ") : "not triaged"}</dd>
      </dl>
      <div className="inline">
        <Button small onClick={() => props.go({ tab: "findings", filter: { q: a.host } })}>
          Findings for this host
        </Button>
        {!a.in_cmdb && (
          <Button small kind="ghost" onClick={() => props.go({ tab: "triage", filter: { q: a.host } })}>
            Triage
          </Button>
        )}
      </div>
    </div>
  );
}

// ---- IP-centric view --------------------------------------------------------------------------

function IpsTab(props: { scanId: string; go: (l: NavLink) => void; initial?: Record<string, string | boolean> }) {
  const initialQ = typeof props.initial?.q === "string" ? props.initial.q : "";
  const [data, setData] = useState<IpsResponse | null>(null);
  const [q, setQ] = useState(initialQ);
  const [onlyOwn, setOnlyOwn] = useState(!initialQ);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    api<IpsResponse>(`/api/scans/${props.scanId}/ips`).then(setData);
  }, [props.scanId]);
  if (!data) return <Empty>Loading…</Empty>;
  const ql = q.trim().toLowerCase();
  const rows = data.ips.filter(
    (r) => (!onlyOwn || !r.shared) && (!ql || r.ip.includes(ql) || r.hosts.some((h) => h.includes(ql)) || (r.owner ?? "").toLowerCase().includes(ql))
  );
  return (
    <div className="stack">
      <p className="muted small">
        {data.summary.own} of your own IPs · {data.summary.shared} on shared platforms · {data.summary.multi_host} carry more than one host. Shared-platform IPs
        (AWS, Cloudflare…) are the provider's, not yours.
      </p>
      <div className="toolbar wrap">
        <input className="search" placeholder="Search IP, host or owner…" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="check small">
          <input type="checkbox" checked={onlyOwn} onChange={(e) => setOnlyOwn(e.target.checked)} /> Hide shared-platform IPs
        </label>
        <span className="spacer" />
        <span className="muted small">
          {rows.length} IP{rows.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th />
              <th>IP</th>
              <th>Hosts</th>
              <th>Netblock / ASN</th>
              <th>Ports</th>
              <th>Technologies</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 300).map((r) => {
              const isOpen = open === r.ip;
              return (
                <Fragment key={r.ip}>
                  <tr className={r.agent_hosts.length ? "row-agent" : ""}>
                    <td>
                      <button className="chev" onClick={() => setOpen(isOpen ? null : r.ip)}>
                        {isOpen ? "▾" : "▸"}
                      </button>
                    </td>
                    <td className="mono">
                      {r.ip} {r.shared ? <Badge tone="muted">shared</Badge> : <Badge tone="info">yours</Badge>}
                      {r.agent_hosts.length > 0 && <Badge tone="warn">agent</Badge>}
                    </td>
                    <td>
                      {r.host_count === 1 ? <span className="mono small">{r.hosts[0]}</span> : <strong>{r.host_count} hosts</strong>}
                    </td>
                    <td className="small">
                      {r.netblock ? (
                        <>
                          <span className="mono">{r.netblock}</span>
                          {r.net_kind === "own" && <Badge tone="warn">org-owned?</Badge>}
                        </>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="small mono">{r.ports.join(", ") || "—"}</td>
                    <td className="small">{r.tech.slice(0, 4).join(", ")}{r.tech.length > 4 ? "…" : ""}</td>
                  </tr>
                  {isOpen && (
                    <tr className="detail-row">
                      <td />
                      <td colSpan={5}>
                        <dl className="kv small">
                          <dt>Hosts ({r.host_count})</dt>
                          <dd>
                            {r.hosts.map((h) => (
                              <button key={h} className="chip mono" onClick={() => props.go({ tab: "findings", filter: { q: h } })}>
                                {h}
                              </button>
                            ))}
                          </dd>
                          {r.ptr.length > 0 && (
                            <>
                              <dt>Reverse DNS (PTR)</dt>
                              <dd className="mono">{r.ptr.join(", ")}</dd>
                            </>
                          )}
                          <dt>Netblock</dt>
                          <dd>{r.owner || r.netblock || "not resolved (enable the ASN lookup on the BBOT stage)"}</dd>
                          <dt>Ports</dt>
                          <dd className="mono">
                            {r.ports.join(", ") || "none seen"}
                            {r.ports_confirmed.length > 0 && <span className="muted"> · confirmed open: {r.ports_confirmed.join(", ")}</span>}
                          </dd>
                          <dt>Responds</dt>
                          <dd>{r.live ? "answered HTTP/TLS during the scan" : "no web response observed"}</dd>
                          {r.tech.length > 0 && (
                            <>
                              <dt>Technologies</dt>
                              <dd>{r.tech.join(", ")}</dd>
                            </>
                          )}
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows.length > 300 && <p className="muted small">Showing the first 300.</p>}
    </div>
  );
}

// ---- attack paths (theoretical, AI-agent focused) ---------------------------------------------

const CAT_LABEL: Record<string, string> = {
  "agent-abuse": "AI-agent abuse",
  breach: "Breach / initial access",
  exfiltration: "Exfiltration",
  lateral: "Lateral movement",
  phishing: "Phishing",
  ddos: "Denial of service",
  takeover: "Subdomain takeover",
  mitm: "Adversary-in-the-middle",
  recon: "Reconnaissance",
};
const LIK_TONE: Record<string, "bad" | "warn" | "muted"> = { observed: "bad", plausible: "warn", theoretical: "muted" };

function AttackPathsTab(props: { scanId: string; go: (l: NavLink) => void }) {
  const [data, setData] = useState<AttackPathsResponse | null>(null);
  const [graph, setGraph] = useState<GraphSummary | null>(null);
  const [cat, setCat] = useState<string>("");
  const [open, setOpen] = useState<Set<string>>(new Set());
  useEffect(() => {
    api<AttackPathsResponse>(`/api/scans/${props.scanId}/attack-paths`).then(setData);
    api<GraphSummary>(`/api/scans/${props.scanId}/graph`).then(setGraph).catch(() => setGraph(null));
  }, [props.scanId]);
  if (!data) return <Empty>Loading…</Empty>;
  if (data.paths.length === 0) return <Empty>No attack paths derived — nothing in this scan chains into one yet.</Empty>;
  const paths = cat ? data.paths.filter((p) => p.category === cat) : data.paths;
  const s = data.summary;
  return (
    <div className="stack">
      <div className="banner banner-info small">
        <strong>Theoretical paths for prioritisation.</strong> Each chains exposure the scan already found — nothing was attempted against your
        systems. "Observed" means the enabling weakness was seen; "plausible" and "theoretical" are weaker signals. Verify before acting.
      </div>
      <div className="change-stats">
        <div className="change-stat up">
          <span className="change-n">{s.total}</span>
          <span className="small muted">paths</span>
        </div>
        <div className="change-stat up">
          <span className="change-n">{s.agent_related}</span>
          <span className="small muted">AI-agent related</span>
        </div>
      </div>
      <div className="toolbar wrap">
        <span className="chips">
          <button className={`chip ${cat === "" ? "on" : ""}`} onClick={() => setCat("")}>
            All <span className="chip-n">{data.paths.length}</span>
          </button>
          {Object.entries(s.by_category)
            .filter(([, n]) => n > 0)
            .map(([c, n]) => (
              <button key={c} className={`chip ${cat === c ? "on" : ""}`} onClick={() => setCat(c)}>
                {CAT_LABEL[c] ?? c} <span className="chip-n">{n}</span>
              </button>
            ))}
        </span>
      </div>
      {Object.keys(s.by_agent_tag).length > 0 && (
        <p className="muted small">
          Agent threat types seen:{" "}
          {Object.entries(s.by_agent_tag)
            .sort((a, b) => b[1] - a[1])
            .map(([t, n]) => `${t} (${n})`)
            .join(" · ")}
        </p>
      )}
      <div className="paths">
        {paths.map((p) => (
          <PathCard key={p.id} p={p} open={open.has(p.id)} toggle={() => {
            const n = new Set(open);
            n.has(p.id) ? n.delete(p.id) : n.add(p.id);
            setOpen(n);
          }} go={props.go} />
        ))}
      </div>
      {graph && (graph.summary.shared_certs.length > 0 || graph.summary.co_hosting.length > 0) && (
        <Card title="Blast radius (from the asset graph)">
          {graph.summary.shared_certs.slice(0, 5).map((c) => (
            <p key={c.cert} className="small">
              <Badge tone="warn">shared cert</Badge> <span className="mono">{c.cert}</span> is presented by {c.host_count} hosts — one key leak exposes them all.
            </p>
          ))}
          {graph.summary.co_hosting.slice(0, 5).map((c) => (
            <p key={c.ip} className="small">
              <Badge tone="info">co-hosted</Badge> <span className="mono">{c.ip}</span> carries {c.host_count} hosts
              {c.agent_hosts.length > 0 ? ` (incl. ${c.agent_hosts.length} agent)` : ""}.
            </p>
          ))}
        </Card>
      )}
    </div>
  );
}

function PathCard(props: { p: AttackPath; open: boolean; toggle: () => void; go: (l: NavLink) => void }) {
  const { p } = props;
  return (
    <div className={`fgroup path-${p.category} ${props.open ? "open" : ""}`}>
      <button className="fgroup-head" aria-expanded={props.open} onClick={props.toggle}>
        <Badge tone={SEV_TONE[p.severity]}>{p.severity}</Badge>
        <span className="fgroup-title">{p.title}</span>
        <span className="muted small nowrap">
          {CAT_LABEL[p.category] ?? p.category} · <Badge tone={LIK_TONE[p.likelihood]}>{p.likelihood}</Badge>
        </span>
        <span className="chev">{props.open ? "▾" : "▸"}</span>
      </button>
      {props.open && (
        <div className="fgroup-body">
          <div className="inline wrap small">
            {mitreChips(p.mitre_links, p.mitre)}
            {p.agent_tags.map((t) => tagChip(t, p.tag_refs))}
          </div>
          {p.framing && (p.framing.precondition || p.framing.impact) && (
            <div className="small" style={{ marginTop: 8 }}>
              {p.framing.precondition && (
                <p style={{ margin: "4px 0" }}>
                  <strong>Precondition:</strong> {p.framing.precondition}
                </p>
              )}
              {p.framing.impact && (
                <p style={{ margin: "4px 0" }}>
                  <strong>Impact:</strong> {p.framing.impact}
                </p>
              )}
              {p.framing.likelihood_reason && <p className="muted" style={{ margin: "4px 0" }}>{p.framing.likelihood_reason}</p>}
            </div>
          )}
          <ol className="steps">
            {p.steps.map((st, i) => (
              <li key={i}>
                <strong>{st.technique}</strong>
                {(st.mitre_links && st.mitre_links.length ? st.mitre_links : st.mitre.map((m) => ({ id: m, url: "" }))).length > 0 && (
                  <span className="inline wrap small" style={{ marginLeft: 6 }}>{mitreChips(st.mitre_links, st.mitre)}</span>
                )}
                <div className="small">{st.description}</div>
                {(st.evidence.host || st.evidence.hosts) && (
                  <div className="small">
                    {(st.evidence.hosts ?? (st.evidence.host ? [st.evidence.host] : [])).slice(0, 8).map((hhh) => (
                      <button key={hhh} className="chip mono" onClick={() => props.go({ tab: "findings", filter: { q: hhh } })}>
                        {hhh}
                      </button>
                    ))}
                  </div>
                )}
              </li>
            ))}
          </ol>
          {p.framing && p.framing.references.length > 0 && (
            <div className="inline wrap small" style={{ marginTop: 4 }}>
              {p.framing.references.map((r) => (
                <a key={r.url} className="chip" href={r.url} target="_blank" rel="noreferrer">
                  {r.label} ↗
                </a>
              ))}
            </div>
          )}
          <p className="small rec">
            <strong>Reduce it:</strong> {p.recommendation}
          </p>
        </div>
      )}
    </div>
  );
}

// ---- findings ---------------------------------------------------------------------------------

type Group = { key: string; title: string; severity: string; area: string; tool: string; items: Finding[] };

function FindingsTab(props: { scanId: string; initial: Record<string, string | boolean>; onOpen: (id: number) => void; onEntity: (kind: EntityKind, id: string | number) => void; go: (l: NavLink) => void }) {
  const [all, setAll] = useState<Finding[] | null>(null);
  const wide = useMediaQuery("(min-width: 1100px)");
  const [sel, setSel] = useState<number | null>(null); // selected finding for the split-pane (wide screens)
  const openDetail = (id: number) => (wide ? setSel(id) : props.onOpen(id));
  // inside the split-pane: a sibling finding stays in the pane; a host/path pops out in the overlay drawer
  const paneEntity = (kind: EntityKind, id: string | number) => (kind === "finding" ? setSel(Number(id)) : props.onEntity(kind, id));
  const init = props.initial;
  const [q, setQ] = useState(typeof init.q === "string" ? init.q : "");
  const [area, setArea] = useState(typeof init.area === "string" ? init.area : "");
  const [sev, setSev] = useState<Set<string>>(new Set(typeof init.severity === "string" ? (init.severity === "high" ? ["critical", "high"] : [init.severity]) : []));
  const [tool, setTool] = useState(typeof init.tool === "string" ? init.tool : "");
  const [conf, setConf] = useState(typeof init.confidence === "string" ? init.confidence : "");
  const [status, setStatus] = useState<string>("open");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toast = useToast();
  const load = useCallback(() => api<{ findings: Finding[] }>(`/api/scans/${props.scanId}/findings`).then((r) => setAll(r.findings)), [props.scanId]);
  useEffect(() => {
    load();
  }, [load]);

  const groups = useMemo(() => {
    if (!all) return [];
    const ql = q.trim().toLowerCase();
    const items = all.filter(
      (f) =>
        (!area || f.area === area) &&
        (!sev.size || sev.has(f.severity)) &&
        (!tool ||
          f.source_tool === tool ||
          (tool === "internetdb" && f.source_tool.startsWith("internetdb")) ||
          (tool === "takeover" && (f.source_tool === "bbot:baddns" || f.source_tool === "dnsreaper"))) &&
        (status === "all" || (status === "open" ? f.status !== "false_positive" : f.status === status)) &&
        (!conf || f.version_confidence === conf) &&
        (!ql || f.title.toLowerCase().includes(ql) || (f.host ?? "").toLowerCase().includes(ql))
    );
    const m = new Map<string, Group>();
    for (const f of items) {
      const k = `${f.severity}|${f.area}|${f.group}`;
      if (!m.has(k)) m.set(k, { key: k, title: f.group, severity: f.severity, area: f.area, tool: f.source_tool, items: [] });
      m.get(k)!.items.push(f);
    }
    return [...m.values()].sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity) || b.items.length - a.items.length);
  }, [all, q, area, sev, tool, status, conf]);

  if (!all) return <Empty>Loading…</Empty>;
  const areas = [...new Set(all.map((f) => f.area))];
  const tools = [...new Set(all.map((f) => f.source_tool))];
  const total = groups.reduce((n, g) => n + g.items.length, 0);

  const patch = async (ids: number[], body: { status?: string; note?: string }) => {
    try {
      await api(`/api/scans/${props.scanId}/findings`, { method: "PATCH", json: { ids, ...body } });
      setAll((cur) => cur!.map((f) => (ids.includes(f.id) ? { ...f, ...(body.status ? { status: body.status as Finding["status"] } : {}), ...(body.note !== undefined ? { note: body.note || null } : {}) } : f)));
      toast(body.status ? `${ids.length} finding${ids.length === 1 ? "" : "s"} marked ${STATUS_LABEL[body.status].toLowerCase()}` : "Note saved", "good");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Couldn't save", "bad");
    }
  };

  return (
    <div className="stack">
      <div className="toolbar wrap">
        <input className="search" placeholder="Search title or host…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="chips">
          {SEVS.map((s) => (
            <button
              key={s}
              className={`chip sev-${s} ${sev.has(s) ? "on" : ""}`}
              onClick={() => {
                const n = new Set(sev);
                if (n.has(s)) n.delete(s);
                else n.add(s);
                setSev(n);
              }}
            >
              {s} <span className="chip-n">{all.filter((f) => f.severity === s && f.status !== "false_positive").length}</span>
            </button>
          ))}
        </span>
        <select value={area} onChange={(e) => setArea(e.target.value)} aria-label="Area">
          <option value="">All areas</option>
          {areas.map((a) => (
            <option key={a} value={a}>
              {AREA_LABEL[a] ?? a}
            </option>
          ))}
        </select>
        <select value={tool} onChange={(e) => setTool(e.target.value)} aria-label="Source">
          <option value="">All sources</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {toolLabel(t)}
            </option>
          ))}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="open">Open (not false positive)</option>
          <option value="observation">Observation</option>
          <option value="verified">Verified</option>
          <option value="false_positive">False positive</option>
          <option value="all">All statuses</option>
        </select>
        {(q || area || sev.size || tool || status !== "open") && (
          <button
            className="linklike small"
            onClick={() => {
              setQ("");
              setArea("");
              setSev(new Set());
              setTool("");
              setStatus("open");
            }}
          >
            Clear filters
          </button>
        )}
      </div>
      <p className="muted small">
        {groups.length} issue{groups.length === 1 ? "" : "s"} ({total} finding{total === 1 ? "" : "s"}). Set a status on a whole issue or on single hosts; false
        positives drop out of the RAG and the counts.
      </p>
      <div className={wide && sel != null ? "triage-split" : undefined}>
      <div className="fgroups">
        {groups.map((g) => {
          const isOpen = open.has(g.key);
          const ids = g.items.map((f) => f.id);
          const st = g.items.reduce<Record<string, number>>((m, f) => ({ ...m, [f.status]: (m[f.status] ?? 0) + 1 }), {});
          return (
            <div key={g.key} className={`fgroup ${isOpen ? "open" : ""}`}>
              <button
                className="fgroup-head"
                aria-expanded={isOpen}
                onClick={() => {
                  const n = new Set(open);
                  if (n.has(g.key)) n.delete(g.key);
                  else n.add(g.key);
                  setOpen(n);
                }}
              >
                <Badge tone={SEV_TONE[g.severity]}>{g.severity}</Badge>
                <span className="fgroup-title">{g.title}</span>
                <span className="muted small nowrap">
                  {g.items.length === 1 ? g.items[0].host : `${g.items.length} hosts`} · {AREA_LABEL[g.area] ?? g.area} · {toolLabel(g.tool)}
                </span>
                <span className="small nowrap fstatus">
                  {Object.entries(st)
                    .map(([k, n]) => `${n} ${STATUS_LABEL[k].toLowerCase()}`)
                    .join(" · ")}
                </span>
                <span className="chev">{isOpen ? "▾" : "▸"}</span>
              </button>
              {isOpen && (
                <div className="fgroup-body">
                  <div className="inline wrap">
                    <span className="small muted">Mark all {g.items.length}:</span>
                    {(["verified", "observation", "false_positive"] as const).map((s) => (
                      <Button key={s} small kind={s === "false_positive" ? "ghost" : "secondary"} onClick={() => patch(ids, { status: s })}>
                        {STATUS_LABEL[s]}
                      </Button>
                    ))}
                    <NoteBox initial={g.items.every((f) => f.note === g.items[0].note) ? g.items[0].note ?? "" : ""} placeholder="Note for all hosts in this issue" onSave={(n) => patch(ids, { note: n })} />
                  </div>
                  <table className="table compact">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Detail</th>
                        <th>Evidence</th>
                        <th>Status</th>
                        <th>Note</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.items.map((f) => (
                        <tr key={f.id} className={sel === f.id ? "frow-sel" : undefined}>
                          <td className="mono small">{f.host ?? "-"}</td>
                          <td className="small detail-cell">
                            {detailOf(f.title, g.title)}
                            <button className="linklike small" style={{ display: "block", marginTop: 2 }} onClick={() => openDetail(f.id)}>
                              Details, references &amp; raw ›
                            </button>
                          </td>
                          <td className="small mono">
                            <Evidence scanId={props.scanId} f={f} />
                          </td>
                          <td>
                            <select value={f.status} onChange={(e) => patch([f.id], { status: e.target.value })} aria-label={`Status for ${f.host}`}>
                              {Object.entries(STATUS_LABEL).map(([k, v]) => (
                                <option key={k} value={k}>
                                  {v}
                                </option>
                              ))}
                            </select>
                          </td>
                          <td>
                            <NoteBox initial={f.note ?? ""} placeholder="Add a note" onSave={(n) => patch([f.id], { note: n })} compact />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          );
        })}
        {groups.length === 0 && <Empty>No findings match these filters.</Empty>}
      </div>
      {wide && sel != null && <FindingPane scanId={props.scanId} id={sel} go={props.go} onEntity={paneEntity} onClose={() => setSel(null)} />}
      </div>
    </div>
  );
}

function detailOf(title: string, group: string): string {
  if (title === group) return "";
  const rest = title.startsWith(group) ? title.slice(group.length).replace(/^[\s.:]+/, "") : title;
  return rest.replace(/^\((\d+) instances\)$/, "$1 instances");
}

function Evidence(props: { scanId: string; f: Finding }) {
  const { f } = props;
  if (f.source_tool === "zap") return <a href={fileUrl(props.scanId, "zap/zap-estate.html", true)}>ZAP report</a>;
  if (f.source_tool.startsWith("bbot")) return <span>{f.evidence_ref ?? "BBOT output"}</span>;
  return <span>{f.evidence_ref ?? ""}</span>;
}

function NoteBox(props: { initial: string; placeholder: string; onSave: (n: string) => void; compact?: boolean }) {
  const [v, setV] = useState(props.initial);
  useEffect(() => setV(props.initial), [props.initial]);
  return (
    <input
      className={`note ${props.compact ? "note-compact" : ""}`}
      value={v}
      placeholder={props.placeholder}
      maxLength={2000}
      onChange={(e) => setV(e.target.value)}
      onBlur={() => v !== props.initial && props.onSave(v)}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
    />
  );
}

// ---- triage ---------------------------------------------------------------------------------

function TriageTab(props: { scanId: string; initial: Record<string, string | boolean> }) {
  const [hosts, setHosts] = useState<TriageHost[] | null>(null);
  const [decisions, setDecisions] = useState<Record<string, string>>({});
  const [show, setShow] = useState<string>(typeof props.initial.decision === "string" ? props.initial.decision : "all");
  const [q, setQ] = useState(typeof props.initial.q === "string" ? props.initial.q : "");
  const [liveOnly, setLiveOnly] = useState(false);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState("");
  const toast = useToast();
  const load = useCallback(
    () =>
      api<{ hosts: TriageHost[]; decisions: Record<string, string> }>(`/api/scans/${props.scanId}/triage`).then((r) => {
        setHosts(r.hosts);
        setDecisions(r.decisions);
      }),
    [props.scanId]
  );
  useEffect(() => {
    load();
  }, [load]);
  const rows = useMemo(() => {
    if (!hosts) return [];
    const ql = q.trim().toLowerCase();
    return hosts
      .filter((h) => (show === "all" ? true : show === "undecided" ? !h.decision : h.decision === show))
      .filter((h) => !liveOnly || h.is_live)
      .filter((h) => !ql || h.host.includes(ql))
      .sort((a, b) => b.issues - a.issues || Number(b.is_live) - Number(a.is_live) || a.host.localeCompare(b.host));
  }, [hosts, show, q, liveOnly]);
  if (!hosts) return <Empty>Loading…</Empty>;

  const save = async (hs: string[], body: { decision?: string | null; note?: string }) => {
    try {
      await api(`/api/scans/${props.scanId}/triage`, { method: "PUT", json: { hosts: hs, ...body } });
      setHosts((cur) => cur!.map((h) => (hs.includes(h.host) ? { ...h, ...("decision" in body ? { decision: body.decision ?? null } : {}), ...("note" in body ? { note: body.note || null } : {}) } : h)));
      if ("decision" in body) toast(`${hs.length} host${hs.length === 1 ? "" : "s"}: ${body.decision ? decisions[body.decision] : "decision cleared"}`, "good");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Couldn't save", "bad");
    }
  };
  const toCmdb = async (hs: string[]) => {
    try {
      const r = await api<{ added: number }>(`/api/scans/${props.scanId}/triage/cmdb`, { method: "POST", json: { hosts: hs } });
      toast(`${r.added} host${r.added === 1 ? "" : "s"} added to the CMDB`, "good");
      setSel(new Set());
      load();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Couldn't add", "bad");
    }
  };
  const counts = { all: hosts.length, undecided: hosts.filter((h) => !h.decision).length } as Record<string, number>;
  for (const k of Object.keys(decisions)) counts[k] = hosts.filter((h) => h.decision === k).length;
  const highSug = hosts.filter((h) => !h.decision && h.suggestion && h.suggestion.confidence === "high");
  const acceptAllHigh = async () => {
    const byDec: Record<string, string[]> = {};
    for (const h of hosts) if (!h.decision && h.suggestion?.confidence === "high") (byDec[h.suggestion.decision] ??= []).push(h.host);
    for (const [dec, hs] of Object.entries(byDec)) await save(hs, { decision: dec });
  };

  return (
    <div className="stack">
      <p className="muted small">
        Hosts in scope that aren't in your CMDB. Decide what each one is: anything left undecided counts as an unknown asset (amber). "Add to CMDB"
        records a host as known for future scans. Each undecided host carries an auto-suggested category from the scan evidence — confirm or override it.
      </p>
      {highSug.length > 0 && (
        <div className="suggest-bar">
          <span><strong>{highSug.length}</strong> undecided host{highSug.length === 1 ? "" : "s"} have a high-confidence suggestion.</span>
          <Button small kind="primary" onClick={acceptAllHigh}>Accept all high-confidence</Button>
          <span className="muted small">You can still change any of them afterwards.</span>
        </div>
      )}
      <div className="toolbar wrap">
        <input className="search" placeholder="Filter hosts…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="chips">
          {["undecided", ...Object.keys(decisions), "all"].map((k) => (
            <button key={k} className={`chip ${show === k ? "on" : ""}`} onClick={() => setShow(k)}>
              {k === "all" ? "All" : k === "undecided" ? "Undecided" : decisions[k]} <span className="chip-n">{counts[k] ?? 0}</span>
            </button>
          ))}
        </span>
        <label className="check small">
          <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} /> Live only
        </label>
      </div>
      {sel.size > 0 && (
        <div className="bulkbar">
          <strong>{sel.size} selected</strong>
          <select value={bulk} onChange={(e) => setBulk(e.target.value)} aria-label="Decision for selected">
            <option value="">Choose a decision…</option>
            {Object.entries(decisions).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
          <Button small kind="primary" disabled={!bulk} onClick={() => save([...sel], { decision: bulk })}>
            Apply
          </Button>
          <Button small onClick={() => toCmdb([...sel])}>
            Add to CMDB
          </Button>
          <button className="linklike small" onClick={() => setSel(new Set())}>
            Clear selection
          </button>
        </div>
      )}
      <div className="table-wrap">
        <table className="table triage">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  aria-label="Select all shown"
                  checked={rows.length > 0 && rows.every((r) => sel.has(r.host))}
                  onChange={(e) => setSel(e.target.checked ? new Set([...sel, ...rows.map((r) => r.host)]) : new Set([...sel].filter((h) => !rows.some((r) => r.host === h))))}
                />
              </th>
              <th>Host</th>
              <th>Seen as</th>
              <th>Issues</th>
              <th>Decision</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 400).map((h) => (
              <tr key={h.host}>
                <td>
                  <input
                    type="checkbox"
                    checked={sel.has(h.host)}
                    onChange={(e) => {
                      const n = new Set(sel);
                      if (e.target.checked) n.add(h.host);
                      else n.delete(h.host);
                      setSel(n);
                    }}
                    aria-label={`Select ${h.host}`}
                  />
                </td>
                <td>
                  <span className="mono">{h.host}</span>
                  <div className="muted small">{h.reasons.slice(0, 2).join(" · ")}</div>
                </td>
                <td className="small">
                  {h.is_live ? `live${h.http_status ? ` (${h.http_status})` : ""}` : h.group.replace(/_/g, " ")}
                  {h.third_party ? " · third-party hosted" : ""}
                  {h.cdn ? " · CDN" : ""}
                </td>
                <td>{h.issues ? <Badge tone="warn">{h.issues}</Badge> : ""}</td>
                <td>
                  <select value={h.decision ?? ""} onChange={(e) => save([h.host], { decision: e.target.value || null })} aria-label={`Decision for ${h.host}`}>
                    <option value="">Undecided</option>
                    {Object.entries(decisions).map(([k, v]) => (
                      <option key={k} value={k}>
                        {v}
                      </option>
                    ))}
                  </select>
                  {!h.decision && h.suggestion && (
                    <div className="suggest" title={h.suggestion.reasons.join(" · ")}>
                      <span className="sg-line">
                        <span className={`sg-dot sg-${h.suggestion.confidence}`} aria-hidden="true" />
                        <span className="sg-txt">Suggested: <b>{decisions[h.suggestion.decision] ?? h.suggestion.decision}</b> · {h.suggestion.confidence}</span>
                        <button className="linklike small sg-accept" onClick={() => save([h.host], { decision: h.suggestion!.decision })}>Accept</button>
                      </span>
                      {h.suggestion.reasons[0] && <span className="sg-why muted">{h.suggestion.reasons[0]}</span>}
                    </div>
                  )}
                </td>
                <td>
                  <NoteBox initial={h.note ?? ""} placeholder="Owner, ticket…" onSave={(n) => save([h.host], { note: n })} compact />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > 400 && <p className="muted small">Showing the first 400 of {rows.length}; use the filters to narrow down.</p>}
    </div>
  );
}

// ---- files ----------------------------------------------------------------------------------

const PREVIEW_TEXT = /\.(txt|log|json|ya?ml|csv|tsv|md|xml|nmap|conf)$/i;
const PREVIEW_IMG = /\.(png|jpe?g|webp)$/i;

function FilesTab(props: { scanId: string; initial: Record<string, string | boolean> }) {
  const [path, setPath] = useState(typeof props.initial.path === "string" ? props.initial.path : "");
  const [entries, setEntries] = useState<FileEntry[] | null>(null);
  const [file, setFile] = useState<FileEntry | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setEntries(null);
    api<{ entries: FileEntry[] }>(`/api/scans/${props.scanId}/files?path=${encodeURIComponent(path)}`)
      .then((r) => setEntries(r.entries))
      .catch((e) => setErr(e instanceof ApiError ? e.message : "Couldn't list"));
  }, [props.scanId, path]);
  useEffect(() => {
    setText(null);
    if (!file || !PREVIEW_TEXT.test(file.name)) return;
    if ((file.size ?? 0) > 2 * 1024 * 1024) return;
    fetch(fileUrl(props.scanId, file.path), { credentials: "same-origin" })
      .then((r) => (r.ok ? r.text() : Promise.reject(r.status)))
      .then((t) => {
        if (/\.json$/i.test(file.name)) {
          try {
            return setText(JSON.stringify(JSON.parse(t), null, 2));
          } catch {
            /* NDJSON or invalid: show as-is */
          }
        }
        setText(t);
      })
      .catch(() => setText("(couldn't load this file)"));
  }, [file, props.scanId]);
  const crumbs = path ? path.split("/") : [];
  const fmtSize = (n: number | null) => (n === null ? "" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  return (
    <div className="files">
      <div className="files-list">
        <div className="crumbs">
          <button className="linklike" onClick={() => setPath("")}>
            run folder
          </button>
          {crumbs.map((c, i) => (
            <Fragment key={i}>
              <span className="muted"> / </span>
              <button className="linklike" onClick={() => setPath(crumbs.slice(0, i + 1).join("/"))}>
                {c}
              </button>
            </Fragment>
          ))}
        </div>
        {err && <div className="field-error">{err}</div>}
        {!entries ? (
          <Empty>Loading…</Empty>
        ) : entries.length === 0 ? (
          <Empty>Empty folder.</Empty>
        ) : (
          <ul className="file-entries">
            {entries.map((e) => (
              <li key={e.path}>
                <button
                  className={`file-entry ${file?.path === e.path ? "on" : ""}`}
                  onClick={() => (e.dir ? (setPath(e.path), setFile(null)) : setFile(e))}
                >
                  <span aria-hidden="true">{e.dir ? "📁" : PREVIEW_IMG.test(e.name) ? "🖼" : "📄"}</span>
                  <span className="mono fe-name">{e.name}</span>
                  <span className="muted small">{e.dir ? `${e.children} item${e.children === 1 ? "" : "s"}` : fmtSize(e.size)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="files-preview">
        {!file ? (
          <Empty>Choose a file to preview it. Everything here is read-only.</Empty>
        ) : (
          <>
            <div className="inline">
              <strong className="mono">{file.name}</strong>
              <span className="muted small">
                {fmtSize(file.size)} · {fmtDate(file.modified)}
              </span>
              <span className="spacer" />
              <a className="btn btn-secondary btn-sm" href={fileUrl(props.scanId, file.path, true)}>
                Download
              </a>
            </div>
            {PREVIEW_IMG.test(file.name) ? (
              <img className="shot" src={fileUrl(props.scanId, file.path)} alt={file.name} />
            ) : PREVIEW_TEXT.test(file.name) ? (
              (file.size ?? 0) > 2 * 1024 * 1024 ? (
                <p className="muted">Too large to preview here; download it instead.</p>
              ) : (
                <pre className="preview">{text ?? "Loading…"}</pre>
              )
            ) : (
              <p className="muted">
                No preview for this type. Download it to open locally{/\.html?$/i.test(file.name) ? " (reports are downloaded rather than shown here, for safety)" : ""}.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---- reports (M6: board-ready PDF export with a review step) -----------------------------------
const KIND_META: Record<string, { desc: string; audience: string; download?: boolean }> = {
  master: {
    desc: "The full report: executive summary, what changed, every finding with embedded evidence, authoritative references (NVD/KEV/EPSS, CWE, OWASP, NIST 800-53) and remediation, full kill-chain attack paths, and appendices (CVE register, asset inventory, agent surface, email & brand, framework coverage, evidence index).",
    audience: "Board → engineering (one document)",
  },
  "share-zip": {
    desc: "The full report, redacted (host names and IPs pseudonymised to asset-01 / ip-07), plus a README — zipped so it's safe to send to a vendor, insurer or the board. CVE ids, severities and all mappings are kept.",
    audience: "Vendors / insurers / board",
    download: true,
  },
};

function ReportsTab(props: { scanId: string }) {
  const [kind, setKind] = useState<string>("master");
  const [prev, setPrev] = useState<ReportPreview | null>(null);
  const [redact, setRedact] = useState(false);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const forcedRedact = kind === "share-zip";
  useEffect(() => {
    setPrev(null);
    api<ReportPreview>(`/api/scans/${props.scanId}/report/preview?kind=${kind}`)
      .then((p) => {
        setPrev(p);
        setRedact(p.redacted_by_default);
      })
      .catch(() => setPrev(null));
  }, [props.scanId, kind]);

  async function generate() {
    const red = forcedRedact || redact;
    const url = `/api/scans/${props.scanId}/report?kind=${kind}${red ? "&redacted=1" : ""}`;
    setBusy(true);
    try {
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) {
        let msg = `Report failed (${res.status})`;
        try {
          const j = await res.json();
          if (j.error) msg = j.error;
        } catch {
          /* non-JSON */
        }
        toast(msg.includes("typst") ? "PDF engine unavailable in this build — rebuild the image (make build) to enable reports." : msg, "bad");
        return;
      }
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      if (KIND_META[kind]?.download) {
        const a = document.createElement("a");
        a.href = blobUrl;
        a.download = res.headers.get("content-disposition")?.match(/filename="?([^"]+)"?/)?.[1] ?? `${kind}.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      } else {
        window.open(blobUrl, "_blank", "noopener");
      }
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000);
    } catch {
      toast("Could not reach the server to build the report.", "bad");
    } finally {
      setBusy(false);
    }
  }

  const kinds = prev?.kinds ?? Object.keys(KIND_META).map((k) => ({ kind: k, title: "" }));
  return (
    <div className="stack">
      <div className="banner banner-info small">
        <strong>Review before you share.</strong> Pick a report, check the summary of what it will contain, then generate the PDF. Reports are built
        from the same data as this dashboard, so nothing here will disagree with the figures above.
      </div>
      <div className="report-grid">
        {kinds.map((k) => {
          const m = KIND_META[k.kind];
          if (!m) return null;
          return (
            <button key={k.kind} className={`report-card ${kind === k.kind ? "on" : ""}`} onClick={() => setKind(k.kind)} aria-pressed={kind === k.kind}>
              <span className="report-card-title">
                {k.title || k.kind}
                {m.download && <Badge tone="muted">zip</Badge>}
              </span>
              <span className="small muted">{m.desc}</span>
              <span className="report-card-aud small">For: {m.audience}</span>
            </button>
          );
        })}
      </div>

      <Card title="What this report will contain">
        {!prev ? (
          <Empty>Loading…</Empty>
        ) : (
          <div className="stack">
            <div className="toolbar wrap">
              <span className="small muted">
                {prev.root_domain} · {prev.rag.toUpperCase()}
                {prev.against && prev.against.finished_at ? ` · compared with the scan from ${fmtDate(prev.against.finished_at)}` : " · no previous scan to compare"}
              </span>
            </div>
            <ul className="report-contents">
              {prev.sections.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
            <label className={`report-redact ${forcedRedact ? "muted" : ""}`}>
              <input type="checkbox" checked={forcedRedact || redact} disabled={forcedRedact || isDemo()} onChange={(e) => setRedact(e.target.checked)} />{" "}
              Redact host names and IPs (pseudonyms like asset-01, ip-07){forcedRedact ? " — always on for the share pack" : ""}
            </label>
            {isDemo() ? (
              <div className="toolbar">
                <span className="small muted">Report generation is disabled in the demo. This is a preview of what the full PDF / share pack contains — every host and IP in this snapshot is already pseudonymised (asset-01, ip-07).</span>
              </div>
            ) : (
              <div className="toolbar">
                <Button kind="primary" onClick={generate} disabled={busy}>
                  {busy ? "Generating…" : KIND_META[kind]?.download ? "Generate & download zip" : "Generate PDF"}
                </Button>
                <span className="small muted">Opens in a new tab. Saved under the scan's run folder (reports/).</span>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

// ---- finding detail drawer (drill-down to references + raw evidence) -------------------------------

const REF_KIND_LABEL: Record<RefLink["kind"], string> = {
  cve: "CVE",
  kev: "KEV",
  epss: "EPSS",
  nist: "NIST",
  cwe: "CWE",
  owasp: "OWASP",
  ref: "Ref",
};

// Render MITRE technique chips from the backend-supplied links (never build the URL here). Falls back
// to plain, unlinked chips only if an older payload lacks mitre_links.
function mitreChips(links: MitreLink[] | undefined, ids: string[]) {
  if (links && links.length) {
    return links.map((m) => (
      <a key={m.id} className="chip mitre" href={m.url} target="_blank" rel="noreferrer" title={`MITRE ATT&CK ${m.id}`}>
        {m.id}
      </a>
    ));
  }
  return ids.map((m) => (
    <span key={m} className="chip">
      {m}
    </span>
  ));
}

// shared finding-detail fetch, used by both the overlay drawer and the split-pane triage view
function useFindingDetail(scanId: string, id: number | null) {
  const [d, setD] = useState<FindingDetail | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    if (id == null) {
      setD(null);
      setErr(false);
      return;
    }
    let live = true;
    setD(null);
    setErr(false);
    api<FindingDetail>(`/api/scans/${scanId}/findings/${id}`)
      .then((x) => live && setD(x))
      .catch(() => live && setErr(true));
    return () => {
      live = false;
    };
  }, [scanId, id]);
  return { d, err };
}

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => (typeof window !== "undefined" ? window.matchMedia(query).matches : false));
  useEffect(() => {
    const mq = window.matchMedia(query);
    const onChange = () => setMatches(mq.matches);
    onChange();
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

function entityLabel(e: Entity): string {
  if (e.kind === "host") return e.id.length > 28 ? e.id.slice(0, 27) + "…" : e.id;
  if (e.kind === "path") return "attack path";
  if (e.kind === "more") return "more issues";
  if (e.kind === "tech") return e.id;
  if (e.kind === "port") return `port ${e.id}`;
  if (e.kind === "exposed") return "exposed services";
  if (e.kind === "step") { const i = e.id.lastIndexOf("::"); return "step " + (i >= 0 ? Number(e.id.slice(i + 2)) + 1 : ""); }
  return "finding";
}

// generic detail drawer: a stack of entities (finding / host / path) with a breadcrumb trail back to
// wherever the drill-in started. Every cross-link pushes onto the stack rather than leaving the page.
function EntityDrawer(props: {
  scanId: string;
  stack: Entity[];
  go: (l: NavLink) => void;
  onEntity: (kind: EntityKind, id: string | number) => void;
  onBack: () => void;
  onClose: () => void;
}) {
  const top = props.stack[props.stack.length - 1];
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") props.onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [props]);
  return (
    <>
      <div className="drawer-scrim" onClick={props.onClose} />
      <aside className="drawer" role="dialog" aria-label="Detail">
        <div className="drawer-head">
          {props.stack.length > 1 && (
            <button className="linklike" onClick={props.onBack}>‹ Back</button>
          )}
          <span className="drawer-crumbs">
            {props.stack.map((e, i) => (
              <span key={i} className={i === props.stack.length - 1 ? "cur" : undefined}>
                {i > 0 ? " › " : ""}{entityLabel(e)}
              </span>
            ))}
          </span>
          <button className="drawer-close" onClick={props.onClose} aria-label="Close">×</button>
        </div>
        <div className="drawer-body">
          {top.kind === "finding" && <FindingBody scanId={props.scanId} id={Number(top.id)} go={props.go} onEntity={props.onEntity} />}
          {top.kind === "path" && <PathDetailView scanId={props.scanId} id={top.id} go={props.go} onEntity={props.onEntity} />}
          {top.kind === "host" && <HostDetailView scanId={props.scanId} id={top.id} go={props.go} onEntity={props.onEntity} />}
          {top.kind === "more" && <MoreView scanId={props.scanId} minSev={Number(top.id)} onEntity={props.onEntity} />}
          {top.kind === "tech" && <TechView scanId={props.scanId} tech={top.id} go={props.go} onEntity={props.onEntity} />}
          {top.kind === "port" && <PortView scanId={props.scanId} port={Number(top.id)} onEntity={props.onEntity} />}
          {top.kind === "exposed" && <ExposedDrawer scanId={props.scanId} onEntity={props.onEntity} />}
          {top.kind === "step" && <StepDetailView scanId={props.scanId} id={top.id} go={props.go} onEntity={props.onEntity} />}
        </div>
      </aside>
    </>
  );
}

function FindingBody(props: { scanId: string; id: number; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const { d, err } = useFindingDetail(props.scanId, props.id);
  if (err) return <Empty>Couldn't load this finding.</Empty>;
  if (!d) return <Empty>Loading…</Empty>;
  return <FindingDetailView d={d} scanId={props.scanId} go={props.go} onEntity={props.onEntity} />;
}

function StepDetailView(props: { scanId: string; id: string; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const sep = props.id.lastIndexOf("::");
  const pathId = sep >= 0 ? props.id.slice(0, sep) : props.id;
  const idx = sep >= 0 ? Number(props.id.slice(sep + 2)) : 0;
  const [paths, setPaths] = useState<AttackPath[] | null>(null);
  const [assets, setAssets] = useState<Asset[] | null>(null);
  useEffect(() => {
    api<AttackPathsResponse>(`/api/scans/${props.scanId}/attack-paths`).then((r) => setPaths(r.paths)).catch(() => setPaths([]));
    api<{ assets: Asset[] }>(`/api/scans/${props.scanId}/assets`).then((r) => setAssets(r.assets)).catch(() => setAssets([]));
  }, [props.scanId]);
  const p = paths?.find((x) => x.id === pathId);
  const st = p?.steps[idx];
  const fid = st?.evidence.finding_id ?? null;
  const { d: fd } = useFindingDetail(props.scanId, fid);
  if (!paths || !assets) return <Empty>Loading…</Empty>;
  if (!p || !st) return <Empty>Step not found.</Empty>;
  const hosts = st.evidence.hosts ?? (st.evidence.host ? [st.evidence.host] : []);
  const others = p.nodes.filter((n) => !hosts.includes(n));
  const assetOf = (h: string) => assets.find((a) => a.host === h);
  return (
    <div>
      <div className="dtype">Kill-chain step {idx + 1} of {p.steps.length} · {p.title}</div>
      <div className="dtitle"><Badge tone={SEV_TONE[p.severity]}>{p.severity}</Badge> {st.technique}</div>
      <div className="dsec"><p style={{ marginTop: 4 }}>{st.description}</p></div>
      {(st.mitre_links?.length || st.mitre.length) ? (
        <div className="dsec"><h4>MITRE ATT&CK</h4><div className="inline wrap kc-chips">{mitreChips(st.mitre_links, st.mitre)}</div></div>
      ) : null}
      {hosts.length > 0 && (
        <div className="dsec">
          <h4>Hosts at this step ({hosts.length})</h4>
          {hosts.map((h) => { const a = assetOf(h); return (
            <div key={h} className="step-host">
              <button className="ev-loc mono linklike" onClick={() => props.onEntity("host", h)} title="Open host">{h}</button>
              <div className="kv step-kv">
                <div className="k">IPs</div><div className="mono small">{a && a.ips.length ? a.ips.join(", ") : "—"}</div>
                <div className="k">Open ports</div>
                <div className="inline wrap">{a && a.ports.length ? a.ports.map((pt) => (
                  <button key={pt} className={"chip mono" + (a.risky_ports.includes(pt) ? " sev-high" : "")} onClick={() => props.onEntity("port", pt)} title="Open port">{pt}</button>
                )) : <span className="muted small">none observed</span>}</div>
                <div className="k">Tech</div><div className="small">{a && a.tech.length ? a.tech.join(", ") : "—"}</div>
              </div>
            </div>
          ); })}
        </div>
      )}
      {fid != null && (
        <div className="dsec">
          <h4>Linked finding</h4>
          {!fd ? <p className="muted small">Loading finding…</p> : (
            <div>
              <button className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("finding", fid)} title="Open the full finding">
                <span className="rk">{fd.severity}</span><span>{fd.group}</span>
              </button>
              {(fd.kev || fd.cves.length > 0) && (
                <div className="inline wrap" style={{ marginTop: 6 }}>
                  {fd.kev && <span className="chip sev-critical">CISA KEV</span>}
                  {fd.cves.map((c) => <span key={c} className="chip mono">{c}</span>)}
                </div>
              )}
              {fd.evidence && fd.evidence.observed && <pre className="ev-raw" style={{ marginTop: 6 }}>{fd.evidence.observed}</pre>}
              {fd.evidence && fd.evidence.host && <p className="muted small" style={{ marginTop: 4 }}>on {fd.evidence.host}</p>}
            </div>
          )}
        </div>
      )}
      {others.length > 0 && (
        <div className="dsec">
          <h4>Other assets in this path ({others.length})</h4>
          <div className="inline wrap">{others.map((h) => (
            <button key={h} className="chip mono" onClick={() => props.onEntity("host", h)} title="Open host">{h}</button>
          ))}</div>
        </div>
      )}
      <div className="dsec"><Button small kind="secondary" onClick={() => props.onEntity("path", pathId)}>‹ Back to the full kill chain</Button></div>
    </div>
  );
}

// agent-risk tag -> a chip linking to its canonical reference (backend-supplied); unknown tags stay plain labels
function tagChip(tag: string, refs?: { tag: string; label: string; url: string }[]) {
  const ref = refs && refs.find((r) => r.tag === tag);
  if (!ref) return <span key={tag} className="chip chip-agent">{tag}</span>;
  return <a key={tag} className="chip chip-agent chip-link" href={ref.url} target="_blank" rel="noreferrer" title={ref.label}>{tag} ↗</a>;
}

// likelihood chip -> opens the finding that supplied the observed evidence, when a step carries one
function likelihoodChip(p: AttackPath, onEntity: (kind: EntityKind, id: string | number) => void) {
  const fid = p.steps.map((s) => s.evidence && s.evidence.finding_id).find((x) => x != null);
  if (fid == null) return <span className="chip">{p.likelihood}</span>;
  return <button className="chip chip-link" onClick={() => onEntity("finding", fid as number)} title="Open the observed evidence">{p.likelihood} ›</button>;
}

function PathDetailView(props: { scanId: string; id: string; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [paths, setPaths] = useState<AttackPath[] | null>(null);
  useEffect(() => {
    api<AttackPathsResponse>(`/api/scans/${props.scanId}/attack-paths`).then((r) => setPaths(r.paths)).catch(() => setPaths([]));
  }, [props.scanId]);
  if (!paths) return <Empty>Loading…</Empty>;
  const p = paths.find((x) => x.id === props.id);
  if (!p) return <Empty>Attack path not found.</Empty>;
  return (
    <div>
      <div className="dtype">Attack path · {CAT_LABEL[p.category] ?? p.category}</div>
      <div className="dtitle"><Badge tone={SEV_TONE[p.severity]}>{p.severity}</Badge> {p.title}</div>
      <div className="inline wrap small" style={{ marginTop: 6 }}>
        {likelihoodChip(p, props.onEntity)}
        {p.agent_tags.map((t) => tagChip(t, p.tag_refs))}
      </div>
      {p.framing && (p.framing.precondition || p.framing.impact) && (
        <div className="dsec">
          {p.framing.precondition && <p style={{ margin: "0 0 8px" }}><strong>Precondition.</strong> {p.framing.precondition}</p>}
          {p.framing.impact && <p style={{ margin: "0 0 8px" }}><strong>Impact.</strong> {p.framing.impact}</p>}
          {p.framing.likelihood_reason && <p className="muted small" style={{ margin: 0 }}>{p.framing.likelihood_reason}</p>}
        </div>
      )}
      <div className="dsec">
        <h4>Assets involved</h4>
        <div className="inline wrap">
          {p.nodes.map((h) => (
            <button key={h} className="chip mono" onClick={() => props.onEntity("host", h)} title="Open host">{h}</button>
          ))}
        </div>
      </div>
      <div className="dsec">
        <h4>Kill chain</h4>
        <div className={`kc sev-${SEV_TONE[p.severity]}`}>
          <div className="kc-stage kc-cap">
            <div className="kc-marker kc-fill">◢</div>
            <div className="kc-content"><div className="kc-stage-title">Exposure</div><div className="kc-sub muted">the internet-facing weakness</div></div>
          </div>
          {p.steps.map((st, i) => {
            const evHosts = st.evidence.hosts ?? (st.evidence.host ? [st.evidence.host] : []);
            return (
              <div className="kc-stage" key={i}>
                <div className="kc-marker">{i + 1}</div>
                <div className="kc-content kc-click" role="button" tabIndex={0}
                     onClick={() => props.onEntity("step", `${p.id}::${i}`)}
                     onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); props.onEntity("step", `${p.id}::${i}`); } }}
                     title="Drill into this step">
                  <div className="kc-stage-title">{st.technique}<span className="kc-drill"> ›</span></div>
                  <div className="kc-desc">{st.description}</div>
                  <div className="kc-chips" onClick={(e) => e.stopPropagation()}>
                    {mitreChips(st.mitre_links, st.mitre)}
                    {evHosts.map((h) => (
                      <button key={h} className="chip mono" onClick={() => props.onEntity("host", h)} title="Open host">{h}</button>
                    ))}
                    {st.evidence.finding_id != null && (
                      <button className="chip" onClick={() => props.onEntity("finding", st.evidence.finding_id as number)} title="Open the finding">View finding ›</button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
          <div className="kc-stage kc-cap">
            <div className="kc-marker kc-fill kc-target">◉</div>
            <div className="kc-content"><div className="kc-stage-title">Impact</div><div className="kc-sub muted">{p.severity === "critical" || p.severity === "high" ? "high-severity business impact" : "business impact"}</div></div>
          </div>
        </div>
      </div>
      {p.framing && p.framing.references.length > 0 && (
        <div className="dsec">
          <h4>References</h4>
          <div className="reflist">
            {p.framing.references.map((r) => (
              <span key={r.url} className="reflink"><span className="rk">Ref</span><a href={r.url} target="_blank" rel="noreferrer">{r.label}</a></span>
            ))}
          </div>
        </div>
      )}
      <div className="dsec"><div className="reduce"><strong>Reduce it.</strong> {p.recommendation}</div></div>
    </div>
  );
}

function DnsTab(props: { scanId: string }) {
  const [data, setData] = useState<DnsResponse | null>(null);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  useEffect(() => {
    api<DnsResponse>(`/api/scans/${props.scanId}/dns`).then(setData).catch(() => setData({ records: [], types: {}, total: 0, hosts: [] }));
  }, [props.scanId]);
  if (!data) return <Empty>Loading…</Empty>;
  const ql = q.trim().toLowerCase();
  const rows = data.records.filter((d) => (!type || d.rtype === type) && (!ql || d.host.toLowerCase().includes(ql) || d.value.toLowerCase().includes(ql)));
  const types = Object.keys(data.types).sort();
  return (
    <Card title={`DNS records (${data.total})`}>
      <p className="muted small" style={{ marginTop: 0, marginBottom: 10 }}>Every resolved record across the scan — A/AAAA, CNAME chains, NS/MX delegations, TXT (SPF, DKIM, verification) and CAA.</p>
      <div className="inline wrap" style={{ gap: 8, marginBottom: 10 }}>
        <input className="search" placeholder="Filter host or value…" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className={"chip" + (type === "" ? " chip-on" : "")} onClick={() => setType("")}>All</button>
        {types.map((t) => (
          <button key={t} className={"chip mono" + (type === t ? " chip-on" : "")} onClick={() => setType(type === t ? "" : t)}>{t} · {data.types[t]}</button>
        ))}
      </div>
      {rows.length === 0 ? (
        <Empty>No matching DNS records.</Empty>
      ) : (
        <table className="table compact">
          <thead><tr><th>Host</th><th>Type</th><th>Value</th></tr></thead>
          <tbody>
            {rows.slice(0, 1000).map((d, i) => (
              <tr key={i}>
                <td className="mono small">{d.host}</td>
                <td><span className="chip mono">{d.rtype}</span></td>
                <td className="mono small" style={{ wordBreak: "break-all" }}>{d.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rows.length > 1000 && <p className="muted small">Showing the first 1000 of {rows.length} matching records — narrow with the filter.</p>}
    </Card>
  );
}

function HostDetailView(props: { scanId: string; id: string; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  useEffect(() => {
    api<{ assets: Asset[] }>(`/api/scans/${props.scanId}/assets`).then((r) => setAssets(r.assets)).catch(() => setAssets([]));
    api<{ findings: Finding[] }>(`/api/scans/${props.scanId}/findings`).then((r) => setFindings(r.findings)).catch(() => setFindings([]));
  }, [props.scanId]);
  const [eps, setEps] = useState<EndpointsResponse | null>(null);
  useEffect(() => {
    let live = true;
    api<EndpointsResponse>(`/api/scans/${props.scanId}/endpoints?host=${encodeURIComponent(props.id)}`).then((x) => live && setEps(x)).catch(() => live && setEps(null));
    return () => { live = false; };
  }, [props.scanId, props.id]);
  if (!assets || !findings) return <Empty>Loading…</Empty>;
  const a = assets.find((x) => x.host === props.id);
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(props.id) || (props.id.includes(":") && /^[0-9a-f:]+$/i.test(props.id));
  const onIp = !a && isIp ? assets.filter((x) => (x.ips ?? []).includes(props.id)) : [];
  const ipHosts = onIp.map((x) => x.host);
  const hf = findings
    .filter((f) => f.host && f.status !== "false_positive" && (f.host === props.id || ipHosts.includes(f.host)))
    .sort((x, y) => SEVS.indexOf(x.severity) - SEVS.indexOf(y.severity));
  return (
    <div>
      <div className="dtype">{isIp ? "IP address" : "Host"}</div>
      <div className="dtitle"><span className="mono">{props.id}</span></div>
      {a && a.tags.length > 0 && <div className="inline wrap small" style={{ marginTop: 6 }}>{a.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>}
      {a ? (
        <div className="dsec">
          <h4>Summary</h4>
          <div className="kv">
            <div className="k">IP</div><div className="mono">{a.ips.join(", ") || "—"}</div>
            <div className="k">HTTP status</div><div className="mono">{a.http_status ?? "—"}</div>
            <div className="k">Live</div><div>{a.is_live ? "yes" : "no"}</div>
            <div className="k">Technologies</div><div>{a.tech.join(", ") || "—"}</div>
            <div className="k">TLS</div><div>{a.tls_version ?? "—"}{a.tls_expiry ? ` · expires ${a.tls_expiry}` : ""}{a.tls_flags.length ? ` · ${a.tls_flags.join(", ")}` : ""}</div>
          </div>
        </div>
      ) : onIp.length > 0 ? (
        <div className="dsec">
          <h4>Resolves for {onIp.length} host{onIp.length === 1 ? "" : "s"}</h4>
          <p className="muted small" style={{ marginTop: 0 }}>This IP isn't an asset itself — it's the address these in-scope hosts resolve to. Findings below are aggregated across them.</p>
          <div className="reflist">
            {onIp.map((x) => (
              <button key={x.host} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("host", x.host)} title="Open host">
                <span className="mono small">{x.host}</span>
                {x.is_live && <span className="muted small"> · live</span>}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <p className="muted small">{isIp
          ? "No in-scope asset resolves to this IP — it was seen only in a finding's evidence (e.g. an exposed service on infrastructure outside the discovered asset set)."
          : "This host isn't in the asset table (it may be a DNS-only or out-of-scope name referenced by a finding)."}</p>
      )}
      <div className="dsec">
        <h4>Findings on this host ({hf.length})</h4>
        {hf.length === 0 ? (
          <p className="muted small">No open findings on this host.</p>
        ) : (
          <div className="reflist">
            {hf.slice(0, 50).map((f) => (
              <button key={f.id} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("finding", f.id)} title="Open finding">
                <span className="rk">{f.severity}</span>
                <span>{f.group}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      {eps && (eps.counts.interesting + eps.counts.urls > 0) && (
        <div className="dsec">
          <h4>Endpoints ({eps.counts.interesting + eps.counts.urls})</h4>
          {eps.interesting.length > 0 && (
            <>
              <div className="muted small ev-insts-h">Interesting ({eps.counts.interesting})</div>
              <div className="reflist">
                {eps.interesting.map((u, i) => (
                  <a key={i} className="reflink linklike mono small" style={{ wordBreak: "break-all" }} href={u} target="_blank" rel="noreferrer" title="Open endpoint">{u}</a>
                ))}
              </div>
            </>
          )}
          {eps.urls.length > 0 && (
            <>
              <div className="muted small ev-insts-h" style={{ marginTop: 8 }}>Discovered URLs ({eps.counts.urls})</div>
              <div className="reflist">
                {eps.urls.slice(0, 50).map((u, i) => (
                  <a key={i} className="reflink linklike mono small" style={{ wordBreak: "break-all" }} href={u} target="_blank" rel="noreferrer" title="Open endpoint">{u}</a>
                ))}
              </div>
              {eps.counts.urls > 50 && <p className="muted small">+{eps.counts.urls - 50} more — crawled from historical and passive sources.</p>}
            </>
          )}
        </div>
      )}
      <div className="dsec">
        <Button small kind="secondary" onClick={() => props.go({ tab: "assets", filter: { q: props.id } })}>Open in Assets ›</Button>
      </div>
    </div>
  );
}

// persistent right-hand detail pane for the split-pane triage layout (wide screens)
function FindingPane(props: { scanId: string; id: number; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void; onClose: () => void }) {
  const { d, err } = useFindingDetail(props.scanId, props.id);
  return (
    <aside className="triage-pane card">
      <div className="triage-pane-head">
        <span className="dtype">Detail</span>
        <button className="drawer-close" onClick={props.onClose} aria-label="Close detail">
          ×
        </button>
      </div>
      <div className="triage-pane-body">
        {err ? <Empty>Couldn't load this finding.</Empty> : !d ? <Empty>Loading…</Empty> : <FindingDetailView d={d} scanId={props.scanId} go={props.go} onEntity={props.onEntity} />}
      </div>
    </aside>
  );
}

// the issues collapsed off the treemap, as a worst-first list (filtered to exactly the tail), each
// drilling into its finding — the "+N more" tile opens this, with a breadcrumb back to the overview
function MoreView(props: { scanId: string; minSev: number; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  useEffect(() => {
    api<{ findings: Finding[] }>(`/api/scans/${props.scanId}/findings`).then((r) => setFindings(r.findings)).catch(() => setFindings([]));
  }, [props.scanId]);
  if (!findings) return <Empty>Loading…</Empty>;
  const { tail } = rankIssues(aggregateIssues(findings), props.minSev, SMAP_CAP);
  return (
    <div>
      <div className="dtype">Surface map</div>
      <div className="dtitle">{tail.length} more issue type{tail.length === 1 ? "" : "s"}</div>
      <p className="muted small" style={{ marginTop: 4 }}>Lower-ranked issues collapsed off the treemap, worst first. Click any to open it.</p>
      <div className="dsec">
        <div className="reflist">
          {tail.map((i) => (
            <button key={i.fid} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("finding", i.fid)} title="Open finding">
              <span className="rk">{i.severity}</span>
              <span>{i.title} <span className="muted small">· {i.count} host{i.count === 1 ? "" : "s"}</span></span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// the detail that distinguishes one instance of a grouped finding — the lookalike domain in
// "Registered lookalike …: riro.com", else the affected host, else the finding title
function memberLabel(m: { title: string; host: string | null }, group: string): string {
  const t = m.title || "";
  if (t.includes(": ")) {
    const tail = t.slice(t.lastIndexOf(": ") + 2).trim();
    // only a single token (a domain/identifier, e.g. "riro.com") distinguishes the instance — a
    // descriptive clause like "the domain can be spoofed" does not, so fall back to the host there
    if (tail && tail !== t && !/\s/.test(tail)) return tail;
  }
  if (m.host) return m.host;
  return t !== group ? t : group;
}

// a visual, port-grouped view of the exposed surface: every open port across the estate, risky ones
// first, each drilling into the hosts that expose it
function ExposedList(props: { assets: Asset[]; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const { rows, sevMap } = useMemo(() => {
    const sm: Record<string, string> = {};
    for (const a of props.assets) sm[a.host] = hostSeverity(a);
    return { rows: portGroups(props.assets), sevMap: sm };
  }, [props.assets]);
  if (rows.length === 0) return <Empty>No open ports were observed.</Empty>;
  const max = rows[0].count || 1;
  return (
    <div className="exposed-list">
      {rows.map((r) => {
        const vuln = r.hosts.filter((h) => sevMap[h] === "critical" || sevMap[h] === "high").length;
        return (
          <button key={r.port} className={`exposed-row${r.risky ? " risky" : ""}${vuln ? " has-vuln" : ""}`} onClick={() => props.onEntity("port", r.port)} title={`${r.count} host${r.count === 1 ? "" : "s"} expose port ${r.port}${vuln ? ` · ${vuln} with high/critical findings` : ""}`}>
            <span className="exposed-port mono">{r.port}</span>
            <span className="exposed-svc">
              {r.service || (r.web ? "web" : "—")}
              {r.risky && <span className="exposed-flag">risky</span>}
              {vuln > 0 && <span className="exposed-vuln">⚠ {vuln}</span>}
            </span>
            <span className="exposed-track"><span className={`exposed-fill${r.risky || vuln ? " risky" : r.web ? " web" : ""}`} style={{ width: `${Math.round((r.count / max) * 100)}%` }} /></span>
            <span className="exposed-n small muted">{r.count}</span>
            <span className="exposed-chev">›</span>
          </button>
        );
      })}
    </div>
  );
}

function ExposedServices(props: { assets: Asset[] | null; onEntity: (kind: EntityKind, id: string | number) => void }) {
  if (props.assets === null) return <Card title="Exposed services"><Empty>Loading…</Empty></Card>;
  const rows = portGroups(props.assets);
  if (rows.length === 0) return null;
  const risky = rows.filter((r) => r.risky);
  const nonWeb = rows.filter((r) => !r.web);
  return (
    <Card title="Exposed services" actions={<span className="muted small">{risky.length} risky · {nonWeb.length} non-web ports</span>}>
      <p className="muted small" style={{ marginTop: 0 }}>Open ports observed across your assets — risky services first. Click a port to see which hosts expose it.</p>
      <ExposedList assets={props.assets} onEntity={props.onEntity} />
    </Card>
  );
}

function ExposedDrawer(props: { scanId: string; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  useEffect(() => {
    api<{ assets: Asset[] }>(`/api/scans/${props.scanId}/assets`).then((r) => setAssets(r.assets)).catch(() => setAssets([]));
  }, [props.scanId]);
  if (!assets) return <Empty>Loading…</Empty>;
  return (
    <div>
      <div className="dtype">Attack surface</div>
      <div className="dtitle">Exposed services</div>
      <p className="muted small" style={{ marginTop: 4 }}>Every open port across your assets, risky services first. Click a port for the hosts behind it.</p>
      <div className="dsec"><ExposedList assets={assets} onEntity={props.onEntity} /></div>
    </div>
  );
}

function PortView(props: { scanId: string; port: number; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  useEffect(() => {
    api<{ assets: Asset[] }>(`/api/scans/${props.scanId}/assets`).then((r) => setAssets(r.assets)).catch(() => setAssets([]));
  }, [props.scanId]);
  if (!assets) return <Empty>Loading…</Empty>;
  const hosts = assets
    .filter((a) => a.ports.includes(props.port))
    .map((a) => ({ a, sev: hostSeverity(a) }))
    .sort((x, y) => (SEVS.indexOf(x.sev) + 1 || 99) - (SEVS.indexOf(y.sev) + 1 || 99));
  const risky = RISKY_PORTS.has(props.port);
  const atRisk = hosts.filter((h) => h.sev === "critical" || h.sev === "high").length;
  return (
    <div>
      <div className="dtype">Exposed port</div>
      <div className="dtitle"><span className="mono">{props.port}</span> {PORT_SVC[props.port] || ""}{risky && <span className="exposed-flag" style={{ marginLeft: 8 }}>risky</span>}</div>
      <p className="muted small" style={{ marginTop: 4 }}>
        {hosts.length} host{hosts.length === 1 ? "" : "s"} expose this port{atRisk ? `, ${atRisk} with high/critical findings` : ""}.
        {risky ? " Internet-exposed management/data services are prime targets — put them behind a VPN/ZTNA or IP allowlist." : ""}
      </p>
      <div className="dsec">
        <h4>Hosts ({hosts.length}) — most at risk first</h4>
        <div className="reflist">
          {hosts.slice(0, 80).map(({ a, sev }) => (
            <button key={a.host} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("host", a.host)} title="Open host">
              {sev ? <span className={`sg-dot sg-${sev === "critical" || sev === "high" ? "high" : sev === "medium" ? "medium" : "low"}`} aria-hidden="true" /> : <span className="sg-dot" style={{ background: "var(--border2, var(--border))" }} />}
              <span className="mono small">{a.host}</span>
              {a.cdn ? <span className="muted small"> · CDN</span> : a.edge?.cloud ? <span className="muted small"> · {a.edge.cloud}</span> : null}
            </button>
          ))}
          {hosts.length > 80 && <span className="muted small">…and {hosts.length - 80} more</span>}
        </div>
      </div>
    </div>
  );
}

// drill into one technology: the hosts running it (with the version string seen), and the open issues
// on those hosts — so you can see what's affected and how it relates to findings/CVEs
function EolRow(props: { v: string; e: EolInfo }) {
  const { e } = props;
  let tone = "muted", label = "";
  if (e.status === "current") { tone = "good"; label = `Up to date — latest is ${e.latest_version ?? "the same"}`; }
  else if (e.status === "outdated_patch") { tone = "warn"; label = `Patch behind — latest in this line is ${e.cycle_latest ?? e.latest_version}`; }
  else if (e.status === "outdated") { tone = "warn"; label = `${e.cycles_behind} release line${e.cycles_behind === 1 ? "" : "s"} behind — latest is ${e.latest_version}`; }
  else if (e.status === "eol") { tone = "bad"; label = `End of life${e.eol_date ? ` since ${e.eol_date}` : ""}${e.eol_days_ago ? ` (${Math.round(e.eol_days_ago / 30)} months ago)` : ""} — upgrade to ${e.latest_version}`; }
  else if (e.status === "untracked") { tone = "muted"; label = "Not tracked by endoflife.date"; }
  else if (e.status === "unavailable") { tone = "muted"; label = "Couldn't reach endoflife.date"; }
  else { tone = "muted"; label = "Version not matched to a known release line"; }
  return (
    <div className="eol-row">
      <span className="chip mono">{props.v}</span>
      <span className={`eol-dot eol-${tone}`} aria-hidden="true" />
      <span className="small">{label}</span>
    </div>
  );
}

function TechView(props: { scanId: string; tech: string; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [eol, setEol] = useState<Record<string, EolInfo>>({});
  useEffect(() => {
    api<{ assets: Asset[] }>(`/api/scans/${props.scanId}/assets`).then((r) => setAssets(r.assets)).catch(() => setAssets([]));
    api<{ findings: Finding[] }>(`/api/scans/${props.scanId}/findings`).then((r) => setFindings(r.findings)).catch(() => setFindings([]));
  }, [props.scanId]);
  useEffect(() => {
    if (!assets) return;
    const tlx = props.tech.toLowerCase();
    const vers = new Set<string>();
    for (const a of assets) {
      for (const d of a.tech_detail ?? []) if ((d.name.toLowerCase() === tlx || d.name.toLowerCase().startsWith(tlx)) && d.version) vers.add(d.version);
      for (const t of a.tech) if (t.split(" ")[0].toLowerCase() === tlx || t.toLowerCase().startsWith(tlx)) { const pv = parseVer(t); if (pv) vers.add(pv); }
    }
    if (vers.size === 0) return;
    let live = true;
    Promise.all([...vers].map((v) =>
      api<EolInfo>(`/api/tech/eol?name=${encodeURIComponent(props.tech)}&version=${encodeURIComponent(v)}`).then((e) => [v, e] as const).catch(() => null)))
      .then((rs) => { if (!live) return; const m: Record<string, EolInfo> = {}; for (const x of rs) if (x) m[x[0]] = x[1]; setEol(m); });
    return () => { live = false; };
  }, [props.scanId, props.tech, assets]);
  if (!assets || !findings) return <Empty>Loading…</Empty>;
  const tl = props.tech.toLowerCase();
  const match = (ts: string) => ts.split(" ")[0].toLowerCase() === tl || ts.toLowerCase().startsWith(tl);
  // host -> the version detected (or null), plus the host's worst finding severity
  const hits: { host: string; version: string | null; sev: string }[] = [];
  for (const a of assets) {
    const strs = a.tech.filter(match);
    const det = (a.tech_detail ?? []).filter((d) => d.name.toLowerCase() === tl || d.name.toLowerCase().startsWith(tl));
    if (!strs.length && !det.length) continue;
    const ver = (det.map((d) => d.version).find(Boolean) as string | undefined) ?? strs.map(parseVer).find(Boolean) ?? null;
    hits.push({ host: a.host, version: ver, sev: hostSeverity(a) });
  }
  hits.sort((x, y) => (SEVS.indexOf(x.sev) + 1 || 99) - (SEVS.indexOf(y.sev) + 1 || 99));
  const hostSet = new Set(hits.map((x) => x.host));
  const versions = [...new Set(hits.map((h) => h.version).filter(Boolean))].sort() as string[];
  const unversioned = hits.filter((h) => !h.version).length;
  const verUrl: Record<string, string> = {};
  for (const a of assets) for (const d of a.tech_detail ?? []) {
    if ((d.name.toLowerCase() === tl || d.name.toLowerCase().startsWith(tl)) && d.version && d.cve_url) verUrl[d.version] = d.cve_url;
  }
  // vulnerabilities (CVE/KEV) on the hosts running this tech — the real "is it out of date / exploitable" signal
  const onHosts = findings.filter((f) => f.host && hostSet.has(f.host) && f.status !== "false_positive");
  const cves = onHosts.filter((f) => cveId(f.title)).sort((a, b) => Number(isKev(b)) - Number(isKev(a)) || SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity));
  const seen = new Set<string>();
  const other = onHosts.filter((f) => !cveId(f.title)).sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity)).filter((f) => (seen.has(f.group) ? false : (seen.add(f.group), true)));
  return (
    <div>
      <div className="dtype">Technology</div>
      <div className="dtitle">{props.tech}</div>
      <p className="muted small" style={{ marginTop: 4 }}>
        Seen on {hits.length} host{hits.length === 1 ? "" : "s"} · {versions.length ? `${versions.length} version${versions.length === 1 ? "" : "s"} detected` : "no version detected"}
        {cves.length ? ` · ${cves.length} CVE finding${cves.length === 1 ? "" : "s"}` : ""}.
      </p>
      <div className="dsec">
        <h4>Versions detected</h4>
        {versions.length > 0 ? (
          <div className="inline wrap">{versions.slice(0, 30).map((v) => verUrl[v] ? (<a key={v} className="chip mono linklike" href={verUrl[v]} target="_blank" rel="noreferrer" title={`Search NVD for ${props.tech} ${v}`}>{v} · CVEs ↗</a>) : (<span key={v} className="chip mono">{v}</span>))}</div>
        ) : (
          <p className="muted small">No version string was exposed by passive fingerprinting{unversioned ? ` on ${unversioned} host${unversioned === 1 ? "" : "s"}` : ""}. An authenticated or active check would be needed to confirm the exact build.</p>
        )}
        {versions.length > 0 && unversioned > 0 && <p className="muted small" style={{ marginTop: 6 }}>{unversioned} host{unversioned === 1 ? "" : "s"} exposed no version string.</p>}
      </div>
      {Object.keys(eol).length > 0 && (
        <div className="dsec">
          <h4>Version currency</h4>
          {versions.map((v) => { const e = eol[v]; if (!e) return null; return <EolRow key={v} v={v} e={e} />; })}
          <p className="muted small" style={{ marginTop: 6 }}>Currency and end-of-life data from endoflife.date (cached).</p>
        </div>
      )}
      <div className="dsec">
        <h4>Known vulnerabilities ({cves.length})</h4>
        {cves.length === 0 ? (
          <p className="muted small">No CVEs were matched to this technology in this scan.</p>
        ) : (
          <div className="reflist">
            {cves.slice(0, 30).map((f) => (
              <button key={f.id} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("finding", f.id)} title="Open finding">
                <span className="rk">{f.severity}</span>
                <span>
                  <span className="mono">{cveId(f.title)}</span>
                  {isKev(f) && <span className="exposed-flag" style={{ marginLeft: 6 }}>KEV</span>}
                  <span className="muted small"> · {f.host}</span>
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="dsec">
        <h4>Hosts running it ({hits.length})</h4>
        <div className="reflist">
          {hits.slice(0, 60).map((x) => (
            <button key={x.host} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("host", x.host)} title="Open host">
              {x.sev ? <span className={`sg-dot sg-${x.sev === "critical" || x.sev === "high" ? "high" : x.sev === "medium" ? "medium" : "low"}`} aria-hidden="true" /> : <span className="sg-dot" style={{ background: "var(--border2, var(--border))" }} />}
              <span className="mono small">{x.host}</span>
              <span className="muted small">{x.version ? ` · v${x.version}` : " · version n/a"}</span>
            </button>
          ))}
          {hits.length > 60 && <span className="muted small">…and {hits.length - 60} more</span>}
        </div>
      </div>
      {other.length > 0 && (
        <div className="dsec">
          <h4>Other issues on these hosts ({other.length})</h4>
          <div className="reflist">
            {other.slice(0, 20).map((f) => (
              <button key={f.id} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("finding", f.id)} title="Open finding">
                <span className="rk">{f.severity}</span>
                <span>{f.group} <span className="muted small">· {f.host}</span></span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function EvidenceView(props: { scanId: string; ev: FindingEvidence; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const { ev } = props;
  const loc = (l?: string) => {
    if (!l) return null;
    if (/^https?:\/\//i.test(l)) return (<a className="ev-loc mono" href={l} target="_blank" rel="noreferrer" title="Open location">{l} ↗</a>);
    const host = l.split(":")[0];
    return (<button className="ev-loc mono linklike" onClick={() => props.onEntity("host", host)} title="Open host">{l}</button>);
  };
  return (
    <div className="ev">
      {(ev.location || ev.host) && (<div className="ev-where">{ev.location && loc(ev.location)}{ev.locator && <span className="muted small"> · {ev.locator}</span>}{ev.host && (<><span className="muted small"> · on </span><button className="ev-loc mono linklike" onClick={() => props.onEntity("host", ev.host as string)} title="Open resolved host">{ev.host}</button></>)}</div>)}
      {ev.observed && <pre className="ev-raw">{ev.observed}</pre>}
      {ev.detail && <p className="muted small ev-detail">{ev.detail}</p>}
      {ev.fields && ev.fields.length > 0 && (
        <table className="ev-fields"><tbody>
          {ev.fields.map((f, i) => (<tr key={i}><td className="ev-fl">{f.label}</td><td className="ev-fv mono">{f.value}</td></tr>))}
        </tbody></table>
      )}
      {ev.instances && ev.instances.length > 1 && (
        <div className="ev-insts">
          <div className="muted small ev-insts-h">{ev.instances.length} instances</div>
          {ev.instances.slice(0, 12).map((it, i) => (
            <div className="ev-inst" key={i}>
              <div className="ev-inst-loc">{loc(it.location)}{it.locator && <span className="muted small"> · {it.locator}</span>}</div>
              {it.observed && <div className="ev-inst-obs mono">{it.observed}</div>}
            </div>
          ))}
          {ev.instances.length > 12 && <div className="muted small">+{ev.instances.length - 12} more</div>}
        </div>
      )}
      {ev.fix && <div className="ev-fix"><strong>Fix.</strong> {ev.fix}</div>}
    </div>
  );
}

function FindingDetailView(props: { d: FindingDetail; scanId: string; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const { d } = props;
  const filesLink: NavLink = { tab: "files", filter: d.raw.files_path ? { path: d.raw.files_path } : {} };
  return (
    <div>
      <div className="dtype">
        Finding · {AREA_LABEL[d.area] ?? d.area} · {toolLabel(d.tool)}
      </div>
      <div className="dtitle">
        <Badge tone={SEV_TONE[d.severity]}>{d.severity}</Badge> {d.group}
      </div>
      <div className="inline wrap small" style={{ marginTop: 6 }}>
        {d.version_confidence && <ConfBadge c={d.version_confidence} />}
        {d.kev && <span className="chip sev-critical">CISA KEV</span>}
        {d.cves.map((c) => (
          <span key={c} className="chip mono">
            {c}
          </span>
        ))}
      </div>

      {d.hosts.length > 0 && (
        <div className="dsec">
          <h4>Affected {d.hosts.length === 1 ? "host" : `hosts (${d.hosts.length})`}</h4>
          <div className="inline wrap">
            {d.hosts.slice(0, 24).map((h) => (
              <button key={h} className="chip mono" onClick={() => props.onEntity("host", h)} title="Open host">
                {h}
              </button>
            ))}
            {d.hosts.length > 24 && <span className="muted small">…and {d.hosts.length - 24} more</span>}
          </div>
        </div>
      )}

      {d.guidance.why && (
        <div className="dsec">
          <h4>Why it matters</h4>
          <p style={{ margin: 0 }}>{d.guidance.why}</p>
        </div>
      )}
      {d.guidance.what && (
        <div className="dsec">
          <h4>What this is</h4>
          <p style={{ margin: 0 }} className="muted">
            {d.guidance.what}
          </p>
        </div>
      )}

      <div className="dsec">
        <h4>Evidence</h4>
        {d.evidence && (d.evidence.observed || d.evidence.location || (d.evidence.fields && d.evidence.fields.length) || (d.evidence.instances && d.evidence.instances.length)) ? (
          <EvidenceView scanId={props.scanId} ev={d.evidence} onEntity={props.onEntity} />
        ) : d.raw.evidence ? <pre className="ev-raw">{d.raw.evidence}</pre> : <p className="muted small">No structured evidence string recorded for this finding.</p>}
        <div className="inline wrap">
          {d.raw.file && (
            <a className="chip" href={fileUrl(props.scanId, d.raw.file)} target="_blank" rel="noreferrer" title="Open the exact artifact this finding came from">
              View raw artifact: {d.raw.file.split("/").pop()} ↗
            </a>
          )}
          <Button small kind="secondary" onClick={() => props.go(filesLink)}>
            {d.raw.file || d.raw.files_path ? `Browse ${d.raw.files_path || "run folder"} in Files ›` : "Browse the run folder ›"}
          </Button>
        </div>
      </div>

      {d.members.length > 1 && (
        <div className="dsec">
          <h4>Instances ({d.members.length})</h4>
          <div className="reflist">
            {d.members.slice(0, 60).map((m) => {
              const label = memberLabel(m, d.group);
              const secondary = m.host && m.host !== label ? m.host : m.evidence_ref && m.evidence_ref !== label ? m.evidence_ref : "";
              return (
                <button key={m.id} className="reflink linklike" style={{ textAlign: "left" }} onClick={() => props.onEntity("finding", m.id)} title="Open this instance">
                  <span className="rk">{m.severity}</span>
                  <span><span className="mono small">{label}</span>{secondary ? <span className="muted small"> · {secondary}</span> : null}</span>
                </button>
              );
            })}
            {d.members.length > 60 && <span className="muted small">…and {d.members.length - 60} more</span>}
          </div>
        </div>
      )}

      {d.references.length > 0 && (
        <div className="dsec">
          <h4>References</h4>
          <div className="reflist">
            {d.references.map((r) => (
              <span key={r.url} className="reflink">
                <span className="rk">{REF_KIND_LABEL[r.kind]}</span>
                <a href={r.url} target="_blank" rel="noreferrer">
                  {r.label}
                </a>
              </span>
            ))}
          </div>
        </div>
      )}

      {d.guidance.fix && (
        <div className="dsec">
          <div className="reduce">
            <strong>Remediation.</strong> {d.guidance.fix}
          </div>
        </div>
      )}
    </div>
  );
}

// ---- surface map (treemap of issues + attack graph) -------------------------------------------

const SEV_SMAP: Record<string, [string, string]> = {
  critical: ["--bad", "--bad-bg"], high: ["--bad", "--bad-bg"], medium: ["--warn", "--warn-bg"],
  low: ["--info", "--info-bg"], info: ["--muted", "--panel-2"],
};
// Severity is the DOMINANT size dimension so a critical/high issue is always a big tile and the worst
// things read first; host count only breaks ties within a severity band (gentle log scaling).
const SEV_BOOST: Record<string, number> = { critical: 100, high: 40, medium: 12, low: 3, info: 1 };
const SMAP_CAP = 14;
// min-severity chips: label + the SEVS index at/above which (index <=) issues are shown ("and up")
const SMAP_THRESHOLDS: [string, number][] = [["High & up", 1], ["Medium & up", 2], ["Low & up", 3], ["All", 4]];
function issueWeight(i: { severity: string; count: number }): number {
  return (SEV_BOOST[i.severity] ?? 1) * (1 + Math.log2(1 + i.count));
}
type Rect = { x: number; y: number; w: number; h: number };
type Cell<T> = T & Rect;

// squarified treemap over a W×H box; items carry a numeric `value`
function squarify<T extends { value: number }>(items: T[], W: number, H: number): Cell<T>[] {
  const nodes = items.map((d) => ({ ...d, area: 0 }));
  const total = nodes.reduce((s, n) => s + n.value, 0) || 1;
  const scale = (W * H) / total;
  nodes.forEach((n) => (n.area = n.value * scale));
  nodes.sort((a, b) => b.area - a.area);
  const out: Cell<T>[] = [];
  let rect: Rect = { x: 0, y: 0, w: W, h: H };
  const worst = (row: typeof nodes, side: number) => {
    const sum = row.reduce((s, n) => s + n.area, 0);
    const mx = Math.max(...row.map((n) => n.area));
    const mn = Math.min(...row.map((n) => n.area));
    return Math.max((side * side * mx) / (sum * sum), (sum * sum) / (side * side * mn));
  };
  let i = 0;
  while (i < nodes.length) {
    const row = [nodes[i]];
    const side = Math.min(rect.w, rect.h);
    while (i + row.length < nodes.length) {
      const next = nodes[i + row.length];
      if (worst(row, side) >= worst([...row, next], side)) row.push(next);
      else break;
    }
    const sum = row.reduce((s, n) => s + n.area, 0);
    if (rect.w >= rect.h) {
      const rw = sum / rect.h;
      let yy = rect.y;
      row.forEach((n) => { out.push({ ...(n as T), x: rect.x, y: yy, w: rw, h: n.area / rw }); yy += n.area / rw; });
      rect = { x: rect.x + rw, y: rect.y, w: rect.w - rw, h: rect.h };
    } else {
      const rh = sum / rect.w;
      let xx = rect.x;
      row.forEach((n) => { out.push({ ...(n as T), x: xx, y: rect.y, w: n.area / rh, h: rh }); xx += n.area / rh; });
      rect = { x: rect.x, y: rect.y + rh, w: rect.w, h: rect.h - rh };
    }
    i += row.length;
  }
  return out;
}

type Issue = { title: string; severity: string; area: string; fid: number; count: number; value: number; more?: boolean };

// one issue per finding-group: worst severity, distinct hosts affected, and a representative finding id
function aggregateIssues(findings: Finding[]): Issue[] {
  const m = new Map<string, { title: string; area: string; sev: string; hosts: Set<string>; fid: number }>();
  for (const f of findings) {
    if (f.status === "false_positive") continue;
    const g = m.get(f.group) ?? { title: f.group, area: f.area, sev: f.severity, hosts: new Set<string>(), fid: f.id };
    if (SEVS.indexOf(f.severity) < SEVS.indexOf(g.sev)) g.sev = f.severity;
    if (f.host) g.hosts.add(f.host);
    g.fid = Math.min(g.fid, f.id);
    m.set(f.group, g);
  }
  return [...m.values()].map((g) => ({ title: g.title, severity: g.sev, area: g.area, fid: g.fid, count: Math.max(g.hosts.size, 1), value: 0 }));
}

// rank worst-first and split into the tiles to draw (head) and the collapsed tail. Critical/high are
// NEVER collapsed — they always stay as their own tiles regardless of host count.
function rankIssues(issues: Issue[], minSev: number, cap: number): { head: Issue[]; tail: Issue[] } {
  const filt = issues
    .filter((i) => SEVS.indexOf(i.severity) <= minSev)
    .map((i) => ({ ...i, value: issueWeight(i) }))
    .sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity) || b.value - a.value);
  if (filt.length <= cap) return { head: filt, tail: [] };
  const critHigh = filt.filter((i) => SEVS.indexOf(i.severity) <= 1);
  const rest = filt.filter((i) => SEVS.indexOf(i.severity) > 1);
  if (critHigh.length >= cap - 1) return { head: critHigh, tail: rest };
  const room = cap - 1 - critHigh.length;
  return { head: [...critHigh, ...rest.slice(0, room)], tail: rest.slice(room) };
}

function SurfaceMap(props: { scanId: string; findings: Finding[] | null; go: (l: NavLink) => void; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [mode, setMode] = useState<"tree" | "graph">("graph");
  const [minSev, setMinSev] = useState(2); // show severities with SEVS index <= minSev (default: medium+)
  const findings = props.findings;
  const [paths, setPaths] = useState<AttackPath[] | null>(null);
  useEffect(() => {
    api<AttackPathsResponse>(`/api/scans/${props.scanId}/attack-paths`).then((r) => setPaths(r.paths)).catch(() => setPaths([]));
  }, [props.scanId]);

  const issues = useMemo<Issue[]>(() => (findings ? aggregateIssues(findings) : []), [findings]);
  const { head, tail } = useMemo(() => rankIssues(issues, minSev, SMAP_CAP), [issues, minSev]);

  // the tiles to draw: the ranked head plus a single "+N more" tile for the collapsed tail
  const shown = useMemo<Issue[]>(() => {
    if (head.length === 0) return [];
    if (tail.length === 0) return head;
    const worst = tail.map((t) => t.severity).sort((a, b) => SEVS.indexOf(a) - SEVS.indexOf(b))[0];
    return [...head, {
      title: `+${tail.length} more issue type${tail.length === 1 ? "" : "s"}`, severity: worst, area: "", fid: -1, more: true,
      count: tail.reduce((s, t) => s + t.count, 0), value: tail.reduce((s, t) => s + t.value, 0),
    }];
  }, [head, tail]);

  const loading = findings === null || paths === null;
  if (loading) return <Card title="Surface map"><Empty>Loading…</Empty></Card>;
  if (issues.length === 0) return null;

  return (
    <Card
      title="Surface map"
      actions={
        <div className="smap-tabs">
          <button className={mode === "tree" ? "on" : ""} onClick={() => setMode("tree")}>Treemap</button>
          <button className={mode === "graph" ? "on" : ""} onClick={() => setMode("graph")}>Attack graph</button>
        </div>
      }
    >
      {mode === "tree" && (
        <div className="smap-sevfilter">
          <span className="muted small">Show:</span>
          {SMAP_THRESHOLDS.map(([label, idx]) => (
            <button key={idx} className={minSev === idx ? "on" : ""} onClick={() => setMinSev(idx)}>{label}</button>
          ))}
          <span className="muted small" style={{ marginLeft: "auto" }}>{shown.length === 0 ? "nothing at this level" : `${issues.filter((i) => SEVS.indexOf(i.severity) <= minSev).length} issue types`}</span>
        </div>
      )}
      {mode === "tree"
        ? (shown.length === 0
            ? <Empty>No issues at this severity. Lower the threshold to see more.</Empty>
            : <Treemap issues={shown} onEntity={props.onEntity} onMore={() => props.onEntity("more", minSev)} />)
        : <AttackGraph paths={paths!} onEntity={props.onEntity} />}
      <div className="smap-legend">
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <span key={s}><i style={{ background: `var(${SEV_SMAP[s][0]})` }} />{s[0].toUpperCase() + s.slice(1)}</span>
        ))}
        <span className="muted" style={{ marginLeft: "auto" }}>{mode === "tree" ? "Sized by severity × hosts · click a tile to drill in" : "Hosts ↔ the attack paths they enable · click a node"}</span>
      </div>
    </Card>
  );
}

function Treemap(props: { issues: Issue[]; onEntity: (kind: EntityKind, id: string | number) => void; onMore: () => void }) {
  const W = 1000, H = 340;
  const cells = useMemo(() => squarify(props.issues, W, H), [props.issues]);
  return (
    <div className="smap-tree" style={{ height: H }}>
      {cells.map((c) => {
        const [fg, bg] = c.more ? (["--muted", "--panel-2"] as [string, string]) : (SEV_SMAP[c.severity] ?? SEV_SMAP.info);
        const big = c.h > 54 && c.w > 90, mid = c.h > 30 && c.w > 54;
        return (
          <button
            key={c.title}
            className={`smap-cell${c.more ? " smap-more" : ""}`}
            title={c.more ? `${c.title} — open Findings` : `${c.title} — ${c.count} host${c.count === 1 ? "" : "s"} · ${c.severity}`}
            onClick={() => (c.more ? props.onMore() : props.onEntity("finding", c.fid))}
            style={{
              left: `calc(${(c.x / W) * 100}% + 2px)`, top: `calc(${(c.y / H) * 100}% + 2px)`,
              width: `calc(${(c.w / W) * 100}% - 4px)`, height: `calc(${(c.h / H) * 100}% - 4px)`,
              background: `color-mix(in srgb, var(${bg}) 60%, var(--panel))`, borderLeft: c.more ? "3px dashed var(--border2, var(--border))" : `3px solid var(${fg})`,
            }}
          >
            <span className="smap-cn">{c.title}</span>
            {c.more ? (
              <span className="smap-cnote muted">{c.count} host-hits · open Findings ›</span>
            ) : big ? (
              <><span className="smap-cc" style={{ color: `var(${fg})` }}>{c.count}</span><span className="smap-cnote" style={{ color: `var(${fg})` }}>{c.count === 1 ? "host" : "hosts"} · {c.severity}</span></>
            ) : mid ? (
              <span className="smap-cnote" style={{ color: `var(${fg})` }}>{c.count} · {c.severity}</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

function AttackGraph(props: { paths: AttackPath[]; onEntity: (kind: EntityKind, id: string | number) => void }) {
  const [hover, setHover] = useState<string | null>(null);
  // demo shows the full spread (incl. medium/amber paths); real scans keep the graph to the worst 8
  const paths = props.paths.slice(0, isDemo() ? 16 : 8);
  if (paths.length === 0) return <Empty>No attack paths were modelled for this scan.</Empty>;
  const hostSet: string[] = [];
  for (const p of paths) for (const h of p.nodes) if (!hostSet.includes(h) && hostSet.length < 14) hostSet.push(h);
  const H = Math.max(paths.length, hostSet.length) * 46 + 40;
  const hx = 250, px = 710, hw = 210, pw = 220;
  const hostY = (i: number) => 30 + (i + 0.5) * ((H - 60) / hostSet.length);
  const pathY = (i: number) => 30 + (i + 0.5) * ((H - 60) / paths.length);
  const sevVar = (s: string) => `var(${(SEV_SMAP[s] ?? SEV_SMAP.info)[0]})`;
  return (
    <div className="smap-graph">
      <svg viewBox={`0 0 960 ${H}`} role="img" aria-label="attack graph">
        <text x={hx} y={18} textAnchor="middle" className="smap-cap">Exposed hosts</text>
        <text x={px} y={18} textAnchor="middle" className="smap-cap">Attack paths</text>
        {paths.map((p, pi) =>
          hostSet.map((h, hi) =>
            p.nodes.includes(h) ? (
              <path key={`${pi}-${hi}`} className="smap-edge" d={`M${hx + hw / 2},${hostY(hi)} C${(hx + px) / 2},${hostY(hi)} ${(hx + px) / 2},${pathY(pi)} ${px - pw / 2},${pathY(pi)}`} stroke={sevVar(p.severity)} />
            ) : null
          )
        )}
        {hostSet.map((h, hi) => (
          <g key={h} className="smap-node" onClick={() => props.onEntity("host", h)}>
            <rect x={hx - hw / 2} y={hostY(hi) - 15} width={hw} height={30} rx={7} className="smap-host" />
            <text x={hx} y={hostY(hi) + 4} textAnchor="middle" className="smap-htext">{h.length > 26 ? h.slice(0, 25) + "…" : h}</text>
          </g>
        ))}
        {paths.map((p, pi) => {
          const on = hover === p.id;
          const bw = on ? Math.min(Math.max(pw, p.title.length * 6.4 + 28), 420) : pw;
          const label = on ? p.title : (p.title.length > 28 ? p.title.slice(0, 27) + "…" : p.title);
          return (
            <g key={p.id} className={`smap-node${on ? " on" : ""}`} onClick={() => props.onEntity("path", p.id)} onMouseEnter={() => setHover(p.id)} onMouseLeave={() => setHover((v) => (v === p.id ? null : v))}>
              <rect x={px - bw / 2} y={pathY(pi) - 15} width={bw} height={30} rx={7} className="smap-path" style={{ stroke: sevVar(p.severity) }} />
              <text x={px} y={pathY(pi) + 4} textAnchor="middle" className="smap-ptext" style={{ fill: sevVar(p.severity) }}>{label}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
