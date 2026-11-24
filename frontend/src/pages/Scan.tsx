import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, Candidate, CandidatesResponse, ScanEvent, SecretStatus, Settings } from "../api";
import { Badge, Button, Card, elapsed, Empty, fmtDate, fmtDur, Link, useNow, useToast } from "../components/ui";
import { navigate } from "../router";
import { Stepper } from "./NewScan";
import { LiveRun, PreRun, RunSetupView } from "./Run";
import { Results } from "./Results";
import { Ticker } from "../components/Ticker";
import { EventLog } from "../components/EventLog";
export { EventLog };

const RUN_STATES = ["running", "completed", "completed_with_errors", "cancelled", "interrupted", "failed"];

// ---- discovery source toggles (wording agreed in the Build Spec) ----------------

const SOURCE_INFO = [
  {
    key: "certificates",
    title: "Certificate names",
    signal: "High",
    needs: null as string | null,
    text: "Finds other domains listed on the same TLS certificates as yours. Organisations often put several of their domains on one certificate, so this is a strong sign of shared ownership.",
    defaultOn: true,
  },
  {
    key: "dns_infra",
    title: "Shared DNS infrastructure",
    signal: "Medium",
    needs: null,
    text: "Finds domains that use the same mail servers, name servers or SPF includes as yours. Big shared providers (Google, Microsoft, Cloudflare and similar) are ignored, but shared hosting can still cause false matches.",
    defaultOn: true,
  },
  {
    key: "whois",
    title: "Registration details (WHOIS)",
    signal: "Medium to high",
    needs: "whoisxml",
    text: "Looks up who registered your domain and finds other domains registered by the same organisation. Strong when details are public, but many registrations are privacy-protected. Reverse lookups need a WhoisXML API key, which is a paid service.",
    defaultOn: false,
  },
  {
    key: "affiliates",
    title: "Affiliates from passive sources",
    signal: "Low",
    needs: null,
    text: "Domains that BBOT's passive data sources associate with yours. Good for spotting marketing microsites and regional sites, but noisy: many results will be third parties. Links found by crawling your sites are added later, in the light-touch stage.",
    defaultOn: false,
  },
];

const SOURCE_LABEL: Record<string, string> = {
  certificates: "certificate",
  dns_infra: "DNS infra",
  dns_vendor: "vendor DNS/SPF",
  whois: "WHOIS",
  affiliates: "affiliate",
  "subdomain-enum": "subdomain sources",
  user: "you",
};

const GROUPS: { key: Candidate["group"]; title: string; text: string }[] = [
  { key: "resolves", title: "Resolves", text: "Points at infrastructure that isn't a known third party." },
  { key: "third_party", title: "Points to a third party", text: "CNAME to a SaaS or CDN. Included as an asset; its content is observed, not tested." },
  { key: "no_dns", title: "Doesn't resolve", text: "Seen historically but no current DNS. Kept for dangling-record checks." },
  { key: "wildcard", title: "Wildcard", text: "The domain answers any name, and these have no other evidence they're real (no certificate of their own). Unticked by default: tick the ones you recognise." },
  { key: null, title: "Added by you", text: "Added by hand." },
];

// ---- page ------------------------------------------------------------------

export function ScanPage(props: { id: string }) {
  const [data, setData] = useState<CandidatesResponse | null>(null);
  const [missing, setMissing] = useState(false);
  const [editScope, setEditScope] = useState(false);
  const [preView, setPreView] = useState<number | null>(null);
  const [preMax, setPreMax] = useState(3);
  const [view, setView] = useState<number | null>(null);
  const toast = useToast();

  const load = useCallback(async () => {
    try {
      setData(await api<CandidatesResponse>(`/api/scans/${props.id}/candidates`));
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setMissing(true);
    }
  }, [props.id]);

  useEffect(() => {
    setView(null);
    setPreView(null);
    setEditScope(false);
    load();
  }, [load]);

  const status = data?.scan.status;
  useEffect(() => {
    if (status !== "discovering" && status !== "running") return;
    const t = setInterval(load, status === "running" ? 4000 : 2000);
    return () => clearInterval(t);
  }, [status, load]);
  const setPre = useCallback((n: number) => {
    setPreView(n);
    setPreMax((m) => Math.max(m, n));
  }, []);
  const now = useNow(status === "running" && view !== null);

  if (missing) return <div className="page"><Empty>Scan not found.</Empty></div>;
  if (!data) return <div className="page"><Empty>Loading…</Empty></div>;
  const scan = data.scan;

  const remove = async () => {
    if (!window.confirm(`Delete the scan of ${scan.root_domain} and its run folder? This cannot be undone.`)) return;
    try {
      await api(`/api/scans/${scan.id}`, { method: "DELETE" });
      toast("Scan deleted", "good");
      navigate("/");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Delete failed", "bad");
    }
  };

  const inRun = RUN_STATES.includes(scan.status);
  const preRun = scan.status === "scope_confirmed" && !editScope;
  // the step the scan itself is at, how far you can navigate, and what you're looking at
  const finished = inRun && scan.status !== "running";
  const natural =
    scan.status === "draft" || scan.status === "discovering"
      ? 1
      : inRun
        ? finished ? 7 : 6
        : scan.status === "scope_confirmed" ? (editScope ? 2 : preView ?? 3) : 2;
  const reach = inRun ? 7 : scan.status === "scope_confirmed" ? Math.max(preMax, preView ?? 3) : natural;
  const shown = view ?? natural;

  const pick = (i: number) => {
    if (inRun) return setView(i === natural ? null : i);
    if (scan.status === "scope_confirmed") {
      if (i === 2) {
        setEditScope(true);
        return setView(null);
      }
      if (i >= 3) {
        setEditScope(false);
        setPre(i);
        return setView(null);
      }
      return setView(i);
    }
    setView(i === natural ? null : i);
  };

  const live = scan.status === "running" ? 6 : scan.status === "discovering" ? 1 : null;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="mono">{scan.root_domain}</h1>
          <span className="muted small">Created {fmtDate(scan.created_at)}</span>
        </div>
        <div className="inline">
          <Badge tone={scan.status === "discovering" || scan.status === "running" ? "info" : scan.status === "scope_confirmed" ? "good" : "muted"}>
            {scan.status.replace(/_/g, " ")}
          </Badge>
          {scan.status !== "discovering" && scan.status !== "running" && (
            <Button kind="danger" small onClick={remove}>
              Delete scan
            </Button>
          )}
        </div>
      </div>
      <Stepper current={shown} reach={reach} onPick={pick} live={live} natural={view !== null ? natural : undefined} />

      {view !== null && live !== null && view !== 7 && (
        <div className="banner banner-info inline">
          <span className="spinner sm" aria-hidden="true" />
          <span>
            {scan.status === "running" ? "Scan running" : "Discovery running"}
            {scan.started_at && scan.status === "running" ? ` · ${fmtDur(elapsed(scan.started_at, null, now))} elapsed` : ""}
          </span>
          <span className="spacer" />
          <Button small kind="primary" onClick={() => setView(null)}>
            View progress
          </Button>
        </div>
      )}

      {view === 0 && <DomainView data={data} />}
      {view === 1 && <DiscoveryView data={data} />}
      {inRun && view === 2 && <ScopeStep data={data} reload={load} onContinue={() => {}} readOnly />}
      {inRun && view === 3 && <RunSetupView scan={scan} section="auth" />}
      {inRun && view === 4 && <RunSetupView scan={scan} section="options" />}
      {inRun && view === 5 && <RunSetupView scan={scan} section="all" />}
      {inRun && shown === 6 && view !== null && <LiveRun scan={scan} reload={load} />}
      {inRun && shown === 7 && <Results key={scan.id} scan={scan} />}

      {view === null && (
        <>
          {scan.status === "draft" && <SourcesStep scanId={scan.id} previous={data} onStarted={load} />}
          {scan.status === "discovering" && <DiscoveryProgress scanId={scan.id} />}
          {(scan.status === "awaiting_scope" || (scan.status === "scope_confirmed" && editScope)) && (
            <ScopeStep
              data={data}
              reload={load}
              onContinue={() => {
                setEditScope(false);
                setPre(3);
              }}
            />
          )}
          {preRun && <PreRun scan={scan} view={preView} setView={setPre} onStarted={load} onEditScope={() => setEditScope(true)} />}
          {inRun && !finished && <LiveRun scan={scan} reload={load} />}
        </>
      )}
    </div>
  );
}

// ---- read-only views of earlier steps -------------------------------------------------

function DomainView(props: { data: CandidatesResponse }) {
  const s = props.data.scan;
  return (
    <Card title="Domain">
      <dl className="kv">
        <dt>Main domain</dt>
        <dd className="mono">{s.root_domain}</dd>
        <dt>Created</dt>
        <dd>{fmtDate(s.created_at)}</dd>
        <dt>Status</dt>
        <dd>{s.status.replace(/_/g, " ")}</dd>
      </dl>
    </Card>
  );
}

function DiscoveryView(props: { data: CandidatesResponse }) {
  const { scan, discovery, items } = props.data;
  const used = ((scan.options as { discovery_sources?: string[] }).discovery_sources ?? []).map(
    (k) => SOURCE_INFO.find((x) => x.key === k)?.title ?? k
  );
  const subs = items.filter((i) => i.kind === "subdomain").length;
  const related = items.filter((i) => i.kind === "related").length;
  const now = useNow(discovery?.status === "running");
  // scans started before this version lost their discovery record when the scan began
  const status = discovery?.status ?? (items.length ? "done" : "not run");
  return (
    <div className="stack">
      <Card title="Discovery">
        <dl className="kv">
          <dt>Status</dt>
          <dd>{status}</dd>
          <dt>Took</dt>
          <dd>{discovery?.started_at ? fmtDur(elapsed(discovery.started_at, discovery.finished_at, now)) : "-"}</dd>
          <dt>Related-domain sources</dt>
          <dd>{used.length ? used.join(", ") : "subdomains only"}</dd>
          <dt>Found</dt>
          <dd>
            {subs} subdomains, {related} related-domain suggestions
          </dd>
        </dl>
      </Card>
      <Card title="Discovery activity">
        <EventLog scanId={scan.id} live={discovery?.status === "running"} stage="discovery" />
      </Card>
    </div>
  );
}

// ---- step 2: sources -------------------------------------------------------

function SourcesStep(props: { scanId: string; previous: CandidatesResponse; onStarted: () => void }) {
  const opts = props.previous.scan.options as { discovery_sources?: string[] };
  const [on, setOn] = useState<Set<string>>(
    new Set(opts.discovery_sources ?? SOURCE_INFO.filter((s) => s.defaultOn).map((s) => s.key))
  );
  const [keys, setKeys] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  useEffect(() => {
    api<{ secrets: SecretStatus[] }>("/api/secrets").then((r) => setKeys(Object.fromEntries(r.secrets.map((s) => [s.name, s.set]))));
  }, []);

  const failed = props.previous.discovery?.status === "failed" || props.previous.discovery?.status === "cancelled";

  const start = async () => {
    setBusy(true);
    try {
      await api(`/api/scans/${props.scanId}/discover`, { method: "POST", json: { sources: [...on] } });
      props.onStarted();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Could not start discovery", "bad");
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      {failed && (
        <div className="banner banner-warn">
          The last discovery run {props.previous.discovery?.status}. Check the log below, adjust sources, and try again.
        </div>
      )}
      <Card title="Related-domain sources">
        <p className="muted">
          Subdomains of your domain are always discovered, using certificate logs and BBOT's passive data sources. These toggles control which
          extra signals are used to suggest <strong>related domains</strong> the organisation may also own. Suggestions are never added to scope
          automatically; you review each one.
        </p>
        <div className="sources">
          {SOURCE_INFO.map((s) => {
            const blocked = s.needs !== null && !keys[s.needs];
            return (
              <label key={s.key} className={`source ${on.has(s.key) ? "on" : ""} ${blocked ? "blocked" : ""}`}>
                <input
                  type="checkbox"
                  checked={on.has(s.key) && !blocked}
                  disabled={blocked}
                  onChange={(e) => {
                    const n = new Set(on);
                    if (e.target.checked) n.add(s.key);
                    else n.delete(s.key);
                    setOn(n);
                  }}
                />
                <div>
                  <div className="source-head">
                    <strong>{s.title}</strong>
                    <Badge tone={s.signal === "High" ? "good" : s.signal === "Low" ? "muted" : "info"}>signal: {s.signal.toLowerCase()}</Badge>
                    {blocked && (
                      <span className="small">
                        <Badge tone="warn">needs key</Badge> <Link to="/settings">add in Settings</Link>
                      </span>
                    )}
                  </div>
                  <p className="muted small">{s.text}</p>
                </div>
              </label>
            );
          })}
        </div>
        <div className="note">
          <strong>Passive only.</strong> Discovery queries certificate logs, DNS resolvers and third-party datasets. Nothing is sent to the
          domain's own servers.
        </div>
        <div className="actions gap-top">
          <Button kind="primary" onClick={start} disabled={busy}>
            {busy ? "Starting…" : "Discover"}
          </Button>
        </div>
      </Card>
      {failed && <EventLog scanId={props.scanId} live={false} />}
    </div>
  );
}

// ---- live progress ---------------------------------------------------------------

function DiscoveryProgress(props: { scanId: string }) {
  const toast = useToast();
  const cancel = async () => {
    try {
      await api(`/api/scans/${props.scanId}/cancel`, { method: "POST" });
      toast("Cancelling…", "info");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Cancel failed", "bad");
    }
  };
  return (
    <Card
      title={
        <span className="inline">
          <span className="spinner" aria-hidden="true" /> Discovering…
        </span>
      }
      actions={
        <Button small kind="ghost" onClick={cancel}>
          Cancel
        </Button>
      }
    >
      <p className="muted small">BBOT's passive modules can take 5 to 30 minutes depending on the domain and your API keys. You can leave this page; it keeps running.</p>
      <Ticker scanId={props.scanId} live mode="discovery" />
      <EventLog scanId={props.scanId} live />
    </Card>
  );
}


// ---- step 3: scope -------------------------------------------------------------------

function ScopeStep(props: { data: CandidatesResponse; reload: () => void; onContinue: () => void; readOnly?: boolean }) {
  const { scan, items, discovery } = props.data;
  const toast = useToast();
  const [filter, setFilter] = useState("");
  const [addText, setAddText] = useState("");
  const [exclText, setExclText] = useState("");
  const [limit, setLimit] = useState(300);
  const [warnAt, setWarnAt] = useState(500);
  const [showLog, setShowLog] = useState(false);

  useEffect(() => {
    api<Settings>("/api/settings").then((s) => setWarnAt(s.large_scope_warning));
  }, []);

  const f = filter.trim().toLowerCase();
  const visible = (c: Candidate) => !f || c.value.includes(f) || c.reasons.some((r) => r.toLowerCase().includes(f));
  const subs = items.filter((i) => i.kind === "subdomain");
  const related = items
    .filter((i) => i.kind === "related")
    .sort((a, b) => rank(a) - rank(b) || a.value.localeCompare(b.value));
  const exclusions = items.filter((i) => i.kind === "exclusion");
  const root = items.find((i) => i.kind === "root");
  const includedSubs = subs.filter((s) => s.decision === "included").length;
  const includedRelated = related.filter((s) => s.decision === "included").length;
  const confirmed = scan.status === "scope_confirmed";

  const patch = async (body: Record<string, string[]>) => {
    try {
      const r = await api<{ ok: boolean; problems: string[] }>(`/api/scans/${scan.id}/scope`, { method: "PATCH", json: body });
      if (!r.ok) toast(r.problems.slice(0, 3).join("; "), "bad");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Update failed", "bad");
    }
    props.reload();
  };
  const toggle = (c: Candidate, include: boolean) => patch(include ? { include: [c.value] } : { exclude: [c.value] });

  const expand = async (c: Candidate) => {
    try {
      await api(`/api/scans/${scan.id}/discover`, {
        method: "POST",
        json: { sources: (scan.options as { discovery_sources?: string[] }).discovery_sources ?? [], expand: c.value },
      });
      toast(`Discovering subdomains of ${c.value}…`, "info");
      props.reload();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Could not start", "bad");
    }
  };

  const confirm = async () => {
    try {
      const r = await api<{ roots: string[]; hosts: number }>(`/api/scans/${scan.id}/scope/confirm`, { method: "POST" });
      toast(`Scope confirmed: ${r.hosts} hosts across ${r.roots.length} domain(s)`, "good");
      props.reload();
      props.onContinue();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Could not confirm", "bad");
    }
  };

  const rerun = async () => {
    await api(`/api/scans/${scan.id}/discover`, {
      method: "POST",
      json: { sources: (scan.options as { discovery_sources?: string[] }).discovery_sources ?? [] },
    }).catch((e) => toast(e instanceof ApiError ? e.message : "Could not start", "bad"));
    props.reload();
  };

  const ro = !!props.readOnly;
  return (
    <div className="stack">
      {ro && <div className="banner banner-info">Read-only: the scope is locked once a scan starts. Start a new scan to change it.</div>}
      {confirmed && !ro && (
        <div className="banner banner-good inline">
          <span>Scope confirmed. Changing anything below un-confirms it.</span>
          <span className="spacer" />
          <Button small kind="primary" onClick={props.onContinue}>
            Continue to authorisation
          </Button>
        </div>
      )}
      {includedSubs > warnAt && (
        <div className="banner banner-warn">
          {includedSubs} hosts are in scope, above your warning level of {warnAt}. Consider excluding groups you don't need; light-touch stages
          scale with host count.
        </div>
      )}

      <div className="toolbar">
        <input className="search" placeholder="Filter by name or reason…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted small">
          Discovery {discovery?.status ?? "-"}
          {discovery?.finished_at ? `, ${fmtDate(discovery.finished_at)}` : ""}
        </span>
        <span className="spacer" />
        <Button small kind="ghost" onClick={() => setShowLog(!showLog)}>
          {showLog ? "Hide log" : "Show log"}
        </Button>
        {!ro && (
          <Button small onClick={rerun}>
            Re-run discovery
          </Button>
        )}
      </div>
      {showLog && <EventLog scanId={scan.id} live={false} stage="discovery" />}
      <fieldset className="plain" disabled={ro}>

      <div className="scope-grid">
        <Card title={`Subdomains (${includedSubs} of ${subs.length} in scope)`}>
          {root && (
            <div className="cand root">
              <input type="checkbox" checked disabled />
              <span className="mono">{root.value}</span>
              <Badge tone="info">root</Badge>
            </div>
          )}
          {GROUPS.map((g) => {
            const list = subs.filter((s) => s.group === g.key && visible(s));
            if (!list.length) return null;
            const inc = list.filter((s) => s.decision === "included").length;
            return (
              <div key={String(g.key)} className="group">
                <div className="group-head">
                  <div>
                    <strong>{g.title}</strong> <span className="muted small">({inc}/{list.length})</span>
                    <div className="muted small">{g.text}</div>
                  </div>
                  <div className="inline">
                    <Button small kind="ghost" onClick={() => patch({ include: list.map((s) => s.value) })}>
                      All
                    </Button>
                    <Button small kind="ghost" onClick={() => patch({ exclude: list.map((s) => s.value) })}>
                      None
                    </Button>
                  </div>
                </div>
                {list.slice(0, limit).map((c) => (
                  <CandRow key={c.value} c={c} onToggle={toggle} />
                ))}
                {list.length > limit && (
                  <button className="linklike small" onClick={() => setLimit(limit + 500)}>
                    Show {Math.min(500, list.length - limit)} more…
                  </button>
                )}
              </div>
            );
          })}
          {subs.length === 0 && <Empty>No subdomains found beyond the root.</Empty>}
        </Card>

        <Card title={`Related domains (${includedRelated} in scope)`}>
          <p className="muted small">
            Never added automatically. Tick only domains you're sure the organisation owns and that your authorisation covers.
          </p>
          {related.filter(visible).length === 0 && <Empty>No related-domain suggestions.</Empty>}
          {related.filter(visible).slice(0, limit).map((c) => (
            <CandRow key={c.value} c={c} onToggle={toggle} related onExpand={expand} />
          ))}
        </Card>
      </div>

      </fieldset>
      {!ro && <div className="grid-2">
        <Card title="Add domains by hand">
          <textarea rows={3} value={addText} onChange={(e) => setAddText(e.target.value)} placeholder={"extra.example.com\nexample-shop.co.uk"} spellCheck={false} />
          <div className="actions gap-top">
            <Button
              small
              onClick={() => {
                patch({ add: addText.split(/\s+/).filter(Boolean) });
                setAddText("");
              }}
              disabled={!addText.trim()}
            >
              Add to scope
            </Button>
          </div>
        </Card>
        <Card title={`Exclusions (${exclusions.length})`}>
          <textarea rows={3} value={exclText} onChange={(e) => setExclText(e.target.value)} placeholder={"pay.example.com"} spellCheck={false} />
          <p className="muted small">An excluded domain also excludes its subdomains. Use it for hosted pages run by others, e.g. payments.</p>
          {exclusions.length > 0 && (
            <ul className="chips">
              {exclusions.map((e) => (
                <li key={e.value} className="chip mono">
                  {e.value}
                </li>
              ))}
            </ul>
          )}
          <div className="actions gap-top">
            <Button
              small
              onClick={() => {
                patch({ exclude_add: exclText.split(/\s+/).filter(Boolean) });
                setExclText("");
              }}
              disabled={!exclText.trim()}
            >
              Exclude
            </Button>
          </div>
        </Card>
      </div>}

      <div className="footer-bar">
        <span>
          <strong>{includedSubs + 1}</strong> hosts across <strong>{includedRelated + 1}</strong> domain{includedRelated ? "s" : ""} in scope,{" "}
          {exclusions.length} exclusion{exclusions.length === 1 ? "" : "s"}
        </span>
        <span className="spacer" />
        {!ro && (
          <Button kind="primary" onClick={confirm} disabled={confirmed}>
            {confirmed ? "Scope confirmed" : "Confirm scope"}
          </Button>
        )}
      </div>
    </div>
  );
}

function rank(c: Candidate): number {
  if (c.third_party) return 9;
  return { high: 0, medium: 1, low: 2 }[c.confidence ?? "low"] ?? 3;
}

function CandRow(props: { c: Candidate; onToggle: (c: Candidate, include: boolean) => void; related?: boolean; onExpand?: (c: Candidate) => void }) {
  const { c } = props;
  const included = c.decision === "included";
  const srcs = useMemo(() => c.sources.map((s) => SOURCE_LABEL[s] ?? s), [c.sources]);
  return (
    <div className={`cand ${included ? "inc" : ""} ${c.third_party ? "tp" : ""}`}>
      <input
        type="checkbox"
        checked={included}
        disabled={c.third_party && props.related}
        onChange={(e) => props.onToggle(c, e.target.checked)}
        aria-label={`Include ${c.value}`}
      />
      <div className="cand-main">
        <div className="inline wrap">
          <span className="mono">{c.value}</span>
          {props.related && c.third_party && <Badge tone="muted">third party</Badge>}
          {props.related && !c.third_party && c.confidence && (
            <Badge tone={c.confidence === "high" ? "good" : c.confidence === "medium" ? "info" : "muted"}>{c.confidence}</Badge>
          )}
          {c.in_cmdb && <Badge tone="good">in CMDB</Badge>}
          {props.related && included && props.onExpand && (
            <button className="linklike small" onClick={() => props.onExpand!(c)}>
              Discover its subdomains
            </button>
          )}
        </div>
        {(props.related || c.reasons.length > 1) && (
          <div className="reasons">
            {c.reasons.slice(0, 3).map((r) => (
              <span key={r} className="reason">
                {r}
              </span>
            ))}
            {props.related && <span className="muted small">via {srcs.join(", ")}</span>}
          </div>
        )}
      </div>
    </div>
  );
}
