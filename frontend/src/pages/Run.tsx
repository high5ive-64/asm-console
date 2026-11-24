import { FormEvent, Fragment, useCallback, useEffect, useState } from "react";
import { api, ApiError, Authorisation, Estimate, Metrics, Readiness, RunOptions, Scan, StageDef, StageState } from "../api";
import { Badge, Button, Card, elapsed, Empty, Field, fmtDate, fmtDur, useNow, useToast } from "../components/ui";
import { EventLog } from "../components/EventLog";
import { Ticker } from "../components/Ticker";
import { ZapTargets } from "../components/ZapTargets";

const TRAFFIC: Record<string, { label: string; tone: "good" | "info" | "warn" | "bad" }> = {
  none: { label: "no traffic to targets", tone: "good" },
  dns: { label: "DNS only", tone: "info" },
  light: { label: "light-touch", tone: "warn" },
  active: { label: "active · off by default", tone: "bad" },
};

/** Short cost label for a stage: free services are the default; paid ones are called out. */
export function serviceBadge(service?: string): { label: string; tone: "good" | "info" | "warn" } | null {
  if (!service) return null;
  const s = service.toLowerCase();
  if (s.startsWith("paid")) return { label: "Paid", tone: "warn" };
  if (s.includes("free key")) return { label: "Free key", tone: "info" };
  if (s.includes("needs your")) return { label: "Free · your data", tone: "info" };
  return { label: "Free", tone: "good" };
}

function Invasive(props: { children: React.ReactNode }) {
  return (
    <div className="banner banner-warn small invasive" role="alert">
      <strong>Goes beyond light-touch.</strong> {props.children}
    </div>
  );
}

// ---- steps 4-6 ---------------------------------------------------------------------

export function PreRun(props: { scan: Scan; view: number | null; setView: (n: number) => void; onStarted: () => void; onEditScope: () => void }) {
  const { view, setView } = props;
  useEffect(() => {
    if (view !== null) return;
    api<{ authorisation: Authorisation | null }>(`/api/scans/${props.scan.id}/authorisation`).then((r) => setView(r.authorisation ? 4 : 3));
  }, [props.scan.id, view, setView]);
  if (view === null) return <Empty>Loading…</Empty>;
  return (
    <>
      {view === 3 && <AuthStep scanId={props.scan.id} onDone={() => setView(4)} onBack={props.onEditScope} />}
      {view === 4 && <OptionsStep scanId={props.scan.id} onDone={() => setView(5)} onBack={() => setView(3)} />}
      {view === 5 && <ReviewStep scan={props.scan} onBack={() => setView(4)} onStarted={props.onStarted} onEditAuth={() => setView(3)} />}
    </>
  );
}

/** What a scan that has started ran with: read-only. */
export function RunSetupView(props: { scan: Scan; section: "auth" | "options" | "all" }) {
  return <ReviewStep scan={props.scan} readOnly section={props.section} onBack={() => {}} onStarted={() => {}} onEditAuth={() => {}} />;
}

const EMPTY_AUTH: Authorisation = {
  approved_by: "",
  role: "",
  approved_on: new Date().toISOString().slice(0, 10),
  scope_reference: "",
  soc_notified: false,
  soc_contact: "",
  source_ip: "",
  test_window: "",
  attested: false,
};

function AuthStep(props: { scanId: string; onDone: () => void; onBack: () => void }) {
  const [a, setA] = useState<Authorisation>(EMPTY_AUTH);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const toast = useToast();
  useEffect(() => {
    api<{ authorisation: Authorisation | null }>(`/api/scans/${props.scanId}/authorisation`).then((r) => {
      if (r.authorisation) setA({ ...r.authorisation, soc_notified: !!r.authorisation.soc_notified, attested: !!r.authorisation.attested });
    });
  }, [props.scanId]);
  const set = <K extends keyof Authorisation>(k: K, v: Authorisation[K]) => setA({ ...a, [k]: v });
  const text = (k: keyof Authorisation, label: string, hint?: string) => (
    <Field label={label} hint={hint} error={errors[k]}>
      <input value={String(a[k] ?? "")} onChange={(e) => set(k, e.target.value as never)} />
    </Field>
  );
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setErrors({});
    try {
      await api(`/api/scans/${props.scanId}/authorisation`, { method: "PUT", json: a });
      props.onDone();
    } catch (err) {
      if (err instanceof ApiError && err.issues) setErrors(Object.fromEntries(err.issues.map((i) => [i.field, i.message])));
      toast(err instanceof ApiError ? err.message : "Save failed", "bad");
    }
  };
  return (
    <form onSubmit={save} className="stack">
      <Card title="Authorisation">
        <p className="muted">
          The next stages send ordinary, light-touch traffic to the hosts in scope. Record who authorised it. This is stored with the run as
          audit evidence and included in the report appendix.
        </p>
        <div className="grid-2">
          {text("approved_by", "Approved by")}
          {text("role", "Their role")}
          <Field label="Approved on" error={errors.approved_on}>
            <input type="date" value={a.approved_on} onChange={(e) => set("approved_on", e.target.value)} />
          </Field>
          {text("scope_reference", "Scope reference", "Ticket, email or document recording the approval.")}
          {text("soc_contact", "SOC / MDR contact")}
          {text("source_ip", "Scan source IP", "Your public IP, so the SOC can recognise the traffic.")}
          {text("test_window", "Test window", "e.g. 2026-11-18 09:00–17:00 UK time")}
        </div>
        <label className="check">
          <input type="checkbox" checked={a.soc_notified} onChange={(e) => set("soc_notified", e.target.checked)} />
          The SOC / MDR has been told the source IP and test window.
        </label>
        {errors.soc_notified && <span className="field-error">{errors.soc_notified}</span>}
        <label className="check attest">
          <input type="checkbox" checked={a.attested} onChange={(e) => set("attested", e.target.checked)} />
          I am authorised to perform passive and light-touch testing of the confirmed scope during this window.
        </label>
        {errors.attested && <span className="field-error">{errors.attested}</span>}
      </Card>
      <div className="actions">
        <Button kind="ghost" onClick={props.onBack}>
          Back to scope
        </Button>
        <Button kind="primary" type="submit" disabled={!a.attested || !a.soc_notified}>
          Save and continue
        </Button>
      </div>
    </form>
  );
}

function OptionsStep(props: { scanId: string; onDone: () => void; onBack: () => void }) {
  const [o, setO] = useState<RunOptions | null>(null);
  const [defs, setDefs] = useState<StageDef[]>([]);
  const [ready, setReady] = useState<Record<string, Readiness>>({});
  const [ips, setIps] = useState("");
  const [sslHosts, setSslHosts] = useState("");
  const [est, setEst] = useState<Estimate | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const toast = useToast();

  useEffect(() => {
    api<{ options: RunOptions; stages: StageDef[]; readiness: Record<string, Readiness> }>(`/api/scans/${props.scanId}/options`).then((r) => {
      setO(r.options);
      setDefs(r.stages.filter((s) => s.key !== "consolidate"));
      setReady(r.readiness ?? {});
      setIps(r.options.extra_ips.join("\n"));
      setSslHosts((r.options.testssl_hosts ?? []).join("\n"));
    });
  }, [props.scanId]);

  const payload = useCallback(
    () => (o ? { ...o, extra_ips: ips.split(/\s+/).filter(Boolean), testssl_hosts: sslHosts.split(/\s+/).filter(Boolean) } : null),
    [o, ips, sslHosts]
  );

  // Save quietly and refresh the estimate as options change
  useEffect(() => {
    const p = payload();
    if (!p) return;
    const t = setTimeout(async () => {
      try {
        await api(`/api/scans/${props.scanId}/options`, { method: "PUT", json: p });
        setErrors({});
        setEst(await api<Estimate>(`/api/scans/${props.scanId}/estimate`));
      } catch (e) {
        if (e instanceof ApiError && e.issues) setErrors(Object.fromEntries(e.issues.map((i) => [i.field, i.message])));
      }
    }, 350);
    return () => clearTimeout(t);
  }, [payload, props.scanId]);

  if (!o) return <Empty>Loading…</Empty>;
  const toggle = (k: string, on: boolean) => setO({ ...o, stages: on ? [...o.stages, k] : o.stages.filter((s) => s !== k) });
  const num = (k: keyof RunOptions) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setO({ ...o, [k]: Number(e.target.value) });
  const flag = (k: keyof RunOptions) => (e: React.ChangeEvent<HTMLInputElement>) => setO({ ...o, [k]: e.target.checked });
  const has = (k: string) => o.stages.includes(k);

  const next = async () => {
    const p = payload();
    try {
      await api(`/api/scans/${props.scanId}/options`, { method: "PUT", json: p });
      props.onDone();
    } catch (e) {
      if (e instanceof ApiError && e.issues) setErrors(Object.fromEntries(e.issues.map((i) => [i.field, i.message])));
      toast("Some options need fixing", "bad");
    }
  };

  return (
    <div className="stack">
      <Card title="Stages">
        <div className="sources">
          {defs.map((s) => {
            const on = o.stages.includes(s.key);
            const activeNow = s.traffic === "active" || (!!ACTIVE_WHEN[s.key] && !!o[ACTIVE_WHEN[s.key] as keyof RunOptions]);
            const cost = serviceBadge(s.service);
            const r = ready[s.key];
            return (
              <label key={s.key} className={`source ${on ? "on" : ""}`}>
                <input type="checkbox" checked={on} onChange={(e) => toggle(s.key, e.target.checked)} />
                <div>
                  <div className="source-head">
                    <strong>{s.title}</strong>
                    <Badge tone={TRAFFIC[activeNow ? "active" : s.traffic].tone}>{TRAFFIC[activeNow ? "active" : s.traffic].label}</Badge>
                    {cost && (
                      <span title={s.service}>
                        <Badge tone={cost.tone}>{cost.label}</Badge>
                      </span>
                    )}
                    {est?.minutes[s.key] !== undefined && on && <span className="muted small">~{Math.max(1, Math.round(est.minutes[s.key]))} min</span>}
                  </div>
                  <p className="muted small">{s.description}</p>
                  {s.service && <p className="small service-line">{s.service}</p>}
                  {r && <p className={`small ${r.ok ? "muted" : "warn-text"}`}>{r.ok ? "✓ " : "⚠ "}{r.message}</p>}
                  {on && activeNow && (
                    <Invasive>
                      {s.key === "port_check"
                        ? "This stage sends packets that probe your servers directly (port scanning). Only tick it if your authorisation covers active scanning."
                        : "This stage is set to ACTIVE mode: it sends scan/attack traffic to your hosts. Only with authorisation for active testing. The switch is in this stage's options below."}
                    </Invasive>
                  )}
                </div>
              </label>
            );
          })}
        </div>
      </Card>
      <div className="grid-2">
        <div className="opt-divider">Passive &amp; light-touch — these run by default</div>
        <Card title="Web scanning limits">
          <div className="grid-2">
            <Field label="ZAP: max hosts" hint="Root domains and www first." error={errors.zap_max_hosts}>
              <input type="number" min={1} max={1000} value={o.zap_max_hosts} onChange={num("zap_max_hosts")} />
            </Field>
            <Field label="TLS concurrency" error={errors.tlsx_concurrency}>
              <input type="number" min={1} max={50} value={o.tlsx_concurrency} onChange={num("tlsx_concurrency")} />
            </Field>
            <Field label="ZAP spider (min/host)" error={errors.zap_spider_minutes}>
              <input type="number" min={1} max={30} value={o.zap_spider_minutes} onChange={num("zap_spider_minutes")} />
            </Field>
            <Field label="ZAP AJAX spider (min/host)" error={errors.zap_ajax_minutes}>
              <input type="number" min={1} max={30} value={o.zap_ajax_minutes} onChange={num("zap_ajax_minutes")} />
            </Field>
          </div>
        </Card>
        <Card title="Before ZAP starts">
          <label className="check">
            <input type="checkbox" checked={o.zap_confirm_targets !== false} onChange={(e) => setO({ ...o, zap_confirm_targets: e.target.checked })} />
            Confirm hosts before an active ZAP scan
          </label>
          <p className="muted small">
            A passive scan starts automatically on the recommended hosts — no wait. When active scanning is on (attack payloads), ZAP pauses first
            and shows you the host list to confirm, while the rest of the scan carries on. Untick to skip that too.
          </p>
        </Card>
        <Card title="Discovery">
          <label className="check">
            <input type="checkbox" checked={o.asn_lookup} onChange={flag("asn_lookup")} />
            Map IPs to their ASN / netblock (passive)
          </label>
          <label className="check">
            <input type="checkbox" checked={o.reverse_dns} onChange={flag("reverse_dns")} />
            Reverse DNS (PTR) on your own IPs — finds co-hosted names (passive)
          </label>
          <p className="muted small">
            Looks up which autonomous systems and IP ranges serve your hosts, from public data — no traffic to anyone. Netblocks are labelled
            as a shared platform (AWS, Cloudflare…) or as possibly org-owned and worth a look.
          </p>
        </Card>
        {has("tls_deep") && (
          <Card title="Deep TLS review (testssl.sh)">
            <Field label="Hosts to test (max)" error={errors.testssl_max_hosts}>
              <input type="number" min={1} max={25} value={o.testssl_max_hosts} onChange={num("testssl_max_hosts")} />
            </Field>
            <Field label="Specific hosts (optional)" hint="One per line. Leave empty to pick automatically: root domains first, then the best live hosts." error={errors.testssl_hosts}>
              <textarea rows={3} value={sslHosts} onChange={(e) => setSslHosts(e.target.value)} placeholder={"www.example.com\napp.example.com"} spellCheck={false} />
            </Field>
            <label className="check">
              <input type="checkbox" checked={o.testssl_vuln_checks} onChange={flag("testssl_vuln_checks")} />
              Vulnerability probes (Heartbleed, CCS injection, Ticketbleed, ROBOT…)
            </label>
            {o.testssl_vuln_checks ? (
              <Invasive>
                These probes send deliberately malformed TLS handshakes. They can trip IDS/IPS alerts and, rarely, upset old load balancers or
                appliances. Only switch on when your authorisation explicitly covers vulnerability testing and the SOC knows.
              </Invasive>
            ) : (
              <p className="muted small">Off: protocols, ciphers, certificate chain and headers only (ordinary handshakes).</p>
            )}
          </Card>
        )}
        {has("email") && (
          <Card title="Email security">
            <label className="check">
              <input type="checkbox" checked={o.email_starttls} onChange={flag("email_starttls")} />
              Test STARTTLS on your mail servers
            </label>
            <p className="muted small">
              {o.email_starttls
                ? "Light-touch: connects to each MX host on port 25 and asks for STARTTLS (no mail is sent)."
                : "Off: DNS records and the public MTA-STS policy file only. No connections to your mail servers."}
            </p>
          </Card>
        )}
        {has("takeover") && (
          <Card title="Subdomain takeover">
            <label className="check">
              <input type="checkbox" checked={o.takeover_zones} onChange={flag("takeover_zones")} />
              Also check every record in my Cloudflare zones
            </label>
            <label className="check">
              <input type="checkbox" checked={o.takeover_include_unlikely} onChange={flag("takeover_include_unlikely")} />
              Report "unlikely" matches too
            </label>
            <label className="check">
              <input type="checkbox" checked={o.takeover_deep} onChange={flag("takeover_deep")} />
              Deep check: run baddns over live hosts (catches dangling SaaS CNAMEs, e.g. Framer/Heroku)
            </label>
            <p className="muted small">DNS lookups (and a little HTTP metadata). The zone check needs a read-only Cloudflare token in Settings › Sources.</p>
          </Card>
        )}
        {has("squat") && (
          <Card title="Newly registered lookalikes (openSquat)">
            <Field label="Match confidence">
              <select value={o.opensquat_confidence} onChange={num("opensquat_confidence")}>
                <option value={0}>Very high (fewest results)</option>
                <option value={1}>High (default)</option>
                <option value={2}>Medium</option>
                <option value={3}>Low</option>
                <option value={4}>Very low (most noise)</option>
              </select>
            </Field>
            <label className="check">
              <input type="checkbox" checked={o.opensquat_premium} onChange={flag("opensquat_premium")} />
              Use the premium feed <Badge tone="warn">Paid</Badge>
            </label>
            {o.opensquat_premium && <p className="muted small">Needs an openSquat premium key in Settings › Sources; without one the free feed is used.</p>}
            <label className="check">
              <input type="checkbox" checked={o.opensquat_portcheck} onChange={flag("opensquat_portcheck")} />
              Check whether suspect domains have web servers (ports 80/443)
            </label>
            {o.opensquat_portcheck && (
              <Invasive>
                This connects to the suspected lookalike domains: servers you don't control that may belong to an attacker. They will see this
                machine's IP address and may learn they've been spotted.
              </Invasive>
            )}
          </Card>
        )}
        {has("lookalikes") && (
          <Card title="Lookalike domains (dnstwist)">
            <label className="check">
              <input type="checkbox" checked={o.lookalike_probe} onChange={flag("lookalike_probe")} />
              Probe registered lookalikes (web/mail banners, mail-interception check)
            </label>
            {o.lookalike_probe ? (
              <Invasive>
                dnstwist will connect to every registered lookalike domain over HTTP and SMTP. Those servers belong to other people, possibly
                attackers, and will see this machine's IP address.
              </Invasive>
            ) : (
              <p className="muted small">Off: DNS lookups only. Nothing connects to the lookalike domains.</p>
            )}
          </Card>
        )}
        {has("spiderfoot") && (
          <Card title="SpiderFoot">
            <Field label="Use case">
              <select value={o.spiderfoot_usecase} onChange={(e) => setO({ ...o, spiderfoot_usecase: e.target.value as RunOptions["spiderfoot_usecase"] })}>
                <option value="passive">Passive (default): third-party sources only</option>
                <option value="footprint">Footprint: also touches your hosts</option>
                <option value="investigate">Investigate: also touches your hosts</option>
                <option value="all">All modules: includes port scans and brute force</option>
              </select>
            </Field>
            {o.spiderfoot_usecase !== "passive" && (
              <Invasive>
                SpiderFoot modules outside the passive set connect to your hosts directly
                {o.spiderfoot_usecase === "all" ? ", including port scanning and brute-force modules" : ""}. Only with authorisation for
                active testing.
              </Invasive>
            )}
          </Card>
        )}
        {has("feeds") && (
          <Card title="Exposure feeds">
            <Field label="Netlas requests per scan" hint="The free Netlas tier allows 50 requests a day in total; each request returns 20 records." error={errors.netlas_max_requests}>
              <input type="number" min={1} max={50} value={o.netlas_max_requests} onChange={num("netlas_max_requests")} />
            </Field>
          </Card>
        )}
        <Card title="Extra public IPs (optional)">
          <textarea
            rows={5}
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder={"Cloud, ISP or NAT addresses DNS doesn't reveal\n198.51.100.10"}
            spellCheck={false}
          />
          {errors.extra_ips && <span className="field-error">{errors.extra_ips}</span>}
          <p className="muted small">
            Paste output of e.g. <code>aws ec2 describe-addresses</code> as plain IPs. Checked passively via Shodan InternetDB, together with any
            public IPs from cloudlist.
          </p>
        </Card>
        {(has("zap") || has("bbot_light") || has("dns")) && (
          <div className="opt-divider active">Active testing — off by default, and each scan asks you to confirm before it starts</div>
        )}
        {(has("zap") || has("bbot_light") || has("dns")) && (
          <Card title="Active scanning (off by default)">
            <p className="muted small">
              These go beyond light-touch and send scan or attack traffic to your own hosts. Each is off unless you turn it on, and a scan that
              uses any of them asks you to confirm before it starts. Only enable them where your authorisation explicitly covers active testing
              and the SOC has been told.
            </p>
            {has("zap") && (
              <>
                <label className="check">
                  <input type="checkbox" checked={o.zap_active} onChange={flag("zap_active")} />
                  ZAP active scan (sends injection/XSS and other attack payloads to the chosen web hosts)
                </label>
                {o.zap_active && (
                  <>
                    <label className="small indent">
                      Active-scan minutes per host{" "}
                      <input type="number" min={1} max={60} value={o.zap_active_minutes} onChange={num("zap_active_minutes")} />
                    </label>
                    <Invasive>
                      ZAP will actively attack each selected host (and the AJAX spider submits forms). This can create data, trigger workflows and
                      set off alerts. Never run it without authorisation for active web-app testing.
                    </Invasive>
                  </>
                )}
              </>
            )}
            {has("bbot_light") && (
              <>
                <label className="check">
                  <input type="checkbox" checked={o.bbot_active} onChange={flag("bbot_active")} />
                  BBOT active modules (nuclei, lightfuzz, telerik, SSRF probes, secret/.git exposure… fuzzing and vuln probes)
                </label>
                {o.bbot_active && (
                  <>
                    <label className="small indent">
                      Max hosts to actively scan{" "}
                      <input type="number" min={1} max={500} value={o.bbot_active_max_hosts} onChange={num("bbot_active_max_hosts")} />
                    </label>
                    <Invasive>
                      Sends fuzzing, content-discovery and vulnerability-probe traffic to your hosts. Credential brute-forcers and
                      data-download modules stay disabled and can't be enabled here.
                    </Invasive>
                  </>
                )}
              </>
            )}
            {has("dns") && (
              <>
                <label className="check">
                  <input type="checkbox" checked={o.dns_bruteforce} onChange={flag("dns_bruteforce")} />
                  DNS brute-force (resolve a wordlist of subdomain names against your DNS)
                </label>
                {o.dns_bruteforce && (
                  <Invasive>
                    Sends a large burst of DNS queries from this machine's IP for each root domain. Noisy, though it never touches your web
                    servers. Finds subdomains that passive discovery missed.
                  </Invasive>
                )}
              </>
            )}
          </Card>
        )}
      </div>
      <div className="footer-bar">
        <span>
          {est ? (
            <>
              Estimated <strong>~{est.total_minutes} min</strong> for <strong>{est.hosts}</strong> hosts
              {est.dns_only_hosts ? ` (+${est.dns_only_hosts} DNS-only)` : ""}
            </>
          ) : (
            "Estimating…"
          )}
        </span>
        <span className="spacer" />
        <Button kind="ghost" onClick={props.onBack}>
          Back
        </Button>
        <Button kind="primary" onClick={next} disabled={!o.stages.length}>
          Review
        </Button>
      </div>
    </div>
  );
}

function ReviewStep(props: {
  scan: Scan;
  onBack: () => void;
  onStarted: () => void;
  onEditAuth: () => void;
  readOnly?: boolean;
  section?: "auth" | "options" | "all";
}) {
  const section = props.section ?? "all";
  const [auth, setAuth] = useState<Authorisation | null>(null);
  const [opts, setOpts] = useState<{ options: RunOptions; stages: StageDef[] } | null>(null);
  const [est, setEst] = useState<Estimate | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  useEffect(() => {
    const id = props.scan.id;
    api<{ authorisation: Authorisation }>(`/api/scans/${id}/authorisation`).then((r) => setAuth(r.authorisation));
    api<{ options: RunOptions; stages: StageDef[] }>(`/api/scans/${id}/options`).then(setOpts);
    api<Estimate>(`/api/scans/${id}/estimate`).then(setEst);
  }, [props.scan.id]);
  if (!auth || !opts || !est) return <Empty>Loading…</Empty>;
  const start = async () => {
    setBusy(true);
    try {
      await api(`/api/scans/${props.scan.id}/start`, { method: "POST" });
      props.onStarted();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Could not start", "bad");
      setBusy(false);
    }
  };
  const chosen = opts.stages.filter((s) => opts.options.stages.includes(s.key));
  const light = chosen.filter((s) => s.traffic === "light");
  const ro = !!props.readOnly;
  const oo = opts.options;
  const has = (k: string) => oo.stages.includes(k);
  const invasive = [
    ...chosen.filter((s) => s.traffic === "active").map((s) => s.title),
    has("zap") && oo.zap_active && "ZAP active scan (attack payloads to your web hosts)",
    has("bbot_light") && oo.bbot_active && "BBOT active modules (fuzzing / vulnerability probes)",
    has("dns") && oo.dns_bruteforce && "DNS brute-force (burst of queries to your DNS)",
    has("tls_deep") && oo.testssl_vuln_checks && "testssl.sh vulnerability probes (malformed TLS handshakes)",
    has("squat") && oo.opensquat_portcheck && "openSquat port check (connects to suspected lookalike domains)",
    has("lookalikes") && oo.lookalike_probe && "dnstwist probes of lookalike domains (HTTP/SMTP connections)",
    has("spiderfoot") && oo.spiderfoot_usecase !== "passive" && `SpiderFoot '${oo.spiderfoot_usecase}' use case (contacts your hosts)`,
  ].filter(Boolean) as string[];
  const lightExtras = [has("email") && oo.email_starttls && "STARTTLS test on your mail servers (port 25)"].filter(Boolean) as string[];
  const paid = chosen.filter((s) => serviceBadge(s.service)?.label === "Paid").map((s) => s.title)
    .concat(has("squat") && oo.opensquat_premium ? ["openSquat premium feed"] : []);
  const scopeCard = (
    <Card title="Scope">
      <dl className="kv">
        <dt>Domains</dt>
        <dd className="mono">{est.roots.join(", ")}</dd>
        <dt>Hosts (light-touch)</dt>
        <dd>{est.hosts}</dd>
        <dt>Hosts (DNS checks only)</dt>
        <dd>{est.dns_only_hosts}</dd>
      </dl>
      <p className="muted small">Third-party-hosted and non-resolving names only get DNS-level takeover checks.</p>
    </Card>
  );
  const authCard = (
    <Card title="Authorisation" actions={ro ? undefined : <Button small kind="ghost" onClick={props.onEditAuth}>Edit</Button>}>
      <dl className="kv">
        <dt>Approved by</dt>
        <dd>
          {auth.approved_by} ({auth.role}), {auth.approved_on}
        </dd>
        <dt>Reference</dt>
        <dd>{auth.scope_reference}</dd>
        <dt>Window</dt>
        <dd>{auth.test_window}</dd>
        <dt>Source IP</dt>
        <dd className="mono">{auth.source_ip}</dd>
        <dt>SOC</dt>
        <dd>{auth.soc_contact} (notified)</dd>
        {ro && (
          <>
            <dt>Attested</dt>
            <dd>Yes, by the operator before the scan started</dd>
          </>
        )}
      </dl>
    </Card>
  );
  const stagesCard = (
    <Card title={`Stages (${chosen.length})`}>
      <ul className="stage-list">
        {chosen.map((s) => (
          <li key={s.key}>
            <span>{s.title}</span>
            <Badge tone={TRAFFIC[s.traffic].tone}>{TRAFFIC[s.traffic].label}</Badge>
            {serviceBadge(s.service)?.label === "Paid" && <Badge tone="warn">Paid</Badge>}
            <span className="muted small">~{Math.max(1, Math.round(est.minutes[s.key] ?? 0))} min</span>
          </li>
        ))}
      </ul>
      {(invasive.length > 0 || lightExtras.length > 0) && (
        <dl className="kv small gap-top">
          {invasive.length > 0 && (
            <>
              <dt className="bad-text">Beyond light-touch</dt>
              <dd className="bad-text">{invasive.join("; ")}</dd>
            </>
          )}
          {lightExtras.length > 0 && (
            <>
              <dt>Extra light-touch</dt>
              <dd>{lightExtras.join("; ")}</dd>
            </>
          )}
        </dl>
      )}
      {ro && (
        <dl className="kv small gap-top">
          <dt>ZAP: max hosts</dt>
          <dd>{opts.options.zap_max_hosts}</dd>
          <dt>ZAP spider / AJAX spider</dt>
          <dd>
            {opts.options.zap_spider_minutes} / {opts.options.zap_ajax_minutes} min per host
          </dd>
          <dt>TLS concurrency</dt>
          <dd>{opts.options.tlsx_concurrency}</dd>
          <dt>ZAP hosts</dt>
          <dd>{opts.options.zap_active && opts.options.zap_confirm_targets !== false ? "you confirm before the active scan" : "recommended, automatically"}</dd>
          <dt>Extra public IPs</dt>
          <dd className="mono">{opts.options.extra_ips.length ? opts.options.extra_ips.join(", ") : "none"}</dd>
        </dl>
      )}
    </Card>
  );
  if (ro) {
    return (
      <div className="stack">
        <div className="banner banner-info">Read-only: this is what the scan ran with. Start a new scan to change it.</div>
        {section === "auth" && authCard}
        {section === "options" && stagesCard}
        {section === "all" && (
          <>
            <div className="grid-2">
              {scopeCard}
              {authCard}
            </div>
            {stagesCard}
          </>
        )}
      </div>
    );
  }
  return (
    <div className="stack">
      <div className="grid-2">
        {scopeCard}
        {authCard}
      </div>
      {stagesCard}
      {invasive.length > 0 && (
        <div className="banner banner-warn" role="alert">
          <strong>Invasive options are on:</strong> {invasive.join("; ")}. Confirm your authorisation covers this and the SOC has been told, or
          go back to Options and switch them off.
        </div>
      )}
      {paid.length > 0 && <div className="banner banner-info">Uses paid services: {paid.join(", ")}. They're skipped if the key isn't saved.</div>}
      {light.length > 0 && (
        <div className="banner banner-warn">
          {light.length} stage{light.length > 1 ? "s" : ""} will send light-touch traffic to {est.hosts} hosts during the next ~{est.total_minutes}{" "}
          minutes. Make sure that's inside your authorised window.
        </div>
      )}
      <div className="footer-bar">
        <span>
          Estimated <strong>~{est.total_minutes} min</strong> (stages run side by side where they can). You can leave this page; the scan keeps
          running.
        </span>
        <span className="spacer" />
        <Button kind="ghost" onClick={props.onBack}>
          Back
        </Button>
        <Button kind="primary" onClick={start} disabled={busy}>
          {busy ? "Starting…" : "Start scan"}
        </Button>
      </div>
    </div>
  );
}

// ---- live run ---------------------------------------------------------------------------

const STATUS_TONE: Record<string, "good" | "warn" | "bad" | "info" | "muted"> = {
  done: "good",
  running: "info",
  pending: "muted",
  not_run: "muted",
  skipped: "muted",
  failed: "bad",
  cancelled: "warn",
  waiting: "warn",
};

type StagesResp = {
  status: string;
  started_at: string | null;
  finished_at: string | null;
  paused: boolean;
  zap_waiting: boolean;
  stages: StageState[];
};

export function LiveRun(props: { scan: Scan; reload: () => void }) {
  const [data, setData] = useState<StagesResp | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [est, setEst] = useState<Estimate | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [armed, setArmed] = useState<string | null>(null); // active stage awaiting its confirming second click
  const [confirmAll, setConfirmAll] = useState(false);
  const toast = useToast();
  const id = props.scan.id;
  const running = data?.status === "running";
  const now = useNow(running);

  const load = useCallback(async () => {
    const d = await api<StagesResp>(`/api/scans/${id}/stages`);
    setData(d);
    if (d.status !== "running") {
      const m = await api<{ metrics: Metrics | null }>(`/api/scans/${id}/metrics`);
      setMetrics(m.metrics);
    }
  }, [id]);

  useEffect(() => {
    load();
    api<Estimate>(`/api/scans/${id}/estimate`).then(setEst).catch(() => {});
  }, [load, id]);
  useEffect(() => {
    if (!running) return;
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  }, [running, load]);
  const { reload } = props;
  const scanStatus = props.scan.status;
  useEffect(() => {
    if (data && data.status !== scanStatus) reload();
  }, [data, scanStatus, reload]);

  if (!data) return <Empty>Loading…</Empty>;
  const enabled = data.stages.filter((s) => (s.status !== "skipped" || s.summary?.reason !== "turned off in options") && s.status !== "not_run");
  const notRun = data.stages.filter((s) => s.status === "not_run" && s.key !== "spiderfoot");
  const doneN = enabled.filter((s) => ["done", "skipped", "failed"].includes(s.status)).length;
  const runningN = enabled.filter((s) => s.status === "running" || s.status === "waiting").length;
  const pct = Math.round((doneN / Math.max(1, enabled.length)) * 100);
  const total = elapsed(data.started_at, running ? null : data.finished_at, now);
  const estMs = (est?.total_minutes ?? 0) * 60000;
  const title = (k: string) => data.stages.find((x) => x.key === k)?.title ?? k;
  const unfinished = new Set(data.stages.filter((x) => ["pending", "running"].includes(x.status)).map((x) => x.key));

  const act = async (path: string, msg: string) => {
    try {
      await api(path, { method: "POST" });
      toast(msg, "info");
      [300, 1200, 3000].forEach((ms) => setTimeout(load, ms));
      props.reload();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Failed", "bad");
    }
  };
  const toggle = (k: string) => {
    const n = new Set(open);
    if (n.has(k)) n.delete(k);
    else n.add(k);
    setOpen(n);
  };

  return (
    <div className="stack">
      <Ticker
        scanId={id}
        live={running}
        mode="run"
        refreshKey={`${data.status}|${data.finished_at}|${data.stages.map((s) => s.status + (s.finished_at ?? "")).join(",")}`}
      />
      {data.zap_waiting && (
        <Card
          title={
            <span className="inline">
              <span className="pulse warn" aria-hidden="true" /> ZAP is waiting for you: choose which hosts to scan
            </span>
          }
        >
          <p className="muted small">
            BBOT has found the live web hosts. Pick the ones ZAP should spider (passive checks only). Everything else in the scan carries on
            while you decide.
          </p>
          <ZapTargets scanId={id} mode="pick" onDone={() => [300, 1500].forEach((ms) => setTimeout(load, ms))} />
        </Card>
      )}
      <Card
        title={
          <span className="inline">
            {running && !data.paused && <span className="spinner" aria-hidden="true" />}
            {running && data.paused
              ? "Paused"
              : running
                ? `Scanning: ${runningN} stage${runningN === 1 ? "" : "s"} running`
                : `Scan ${data.status.replace(/_/g, " ")}`}
          </span>
        }
        actions={
          running ? (
            <span className="inline">
              {data.paused ? (
                <Button small kind="primary" onClick={() => act(`/api/scans/${id}/resume`, "Resuming…")}>
                  ▶ Resume
                </Button>
              ) : (
                <Button small onClick={() => act(`/api/scans/${id}/pause`, "Pausing: running tools will freeze")}>
                  ❚❚ Pause
                </Button>
              )}
              <Button small kind="ghost" onClick={() => act(`/api/scans/${id}/cancel`, "Cancelling…")}>
                Cancel
              </Button>
            </span>
          ) : (
            <span className="inline">
              {["interrupted", "cancelled"].includes(data.status) && (
                <Button small kind="primary" onClick={() => act(`/api/scans/${id}/start`, "Resuming…")}>
                  Resume
                </Button>
              )}
              {notRun.length > 0 && (
                <Button small kind="primary" onClick={() => act(`/api/scans/${id}/run-new`, `Running ${notRun.length} new stages…`)}>
                  Run {notRun.length} new stage{notRun.length > 1 ? "s" : ""}
                </Button>
              )}
              <Button
                small
                kind={confirmAll ? "danger" : "secondary"}
                onClick={() => {
                  if (!confirmAll) {
                    setConfirmAll(true);
                    setTimeout(() => setConfirmAll(false), 4000);
                    return;
                  }
                  setConfirmAll(false);
                  act(`/api/scans/${id}/rerun`, "Re-running all stages…");
                }}
              >
                {confirmAll ? "Click again: re-run every stage" : "Retry all"}
              </Button>
            </span>
          )
        }
      >
        <div className="run-clock">
          <div>
            <div className="clock-value">{fmtDur(total)}</div>
            <div className="clock-label">{running ? (data.paused ? "elapsed · paused" : "elapsed") : "total time"}</div>
          </div>
          {estMs > 0 && (
            <div>
              <div className="clock-value muted-strong">~{fmtDur(estMs).replace(/ \d+s$/, "")}</div>
              <div className="clock-label">estimated</div>
            </div>
          )}
          {running && estMs > 0 && (
            <div>
              <div className="clock-value muted-strong">{total < estMs ? `~${fmtDur(estMs - total).replace(/ \d+s$/, "")}` : "any minute"}</div>
              <div className="clock-label">left (rough)</div>
            </div>
          )}
          <div className="clock-progress">
            <div className="progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
              <div className={`progress-bar ${running ? "progress-live" : ""}`} ref={(el) => el && (el.style.width = `${pct}%`)} />
            </div>
            <div className="clock-label">
              {doneN} of {enabled.length} stages finished
              {notRun.length > 0 ? ` · ${notRun.length} added, not run yet` : ""} · started {fmtDate(data.started_at)}
              {!running && data.finished_at ? ` · finished ${fmtDate(data.finished_at)}` : ""}
            </div>
          </div>
        </div>

        <div className={`stage-rows ${running ? "" : "with-actions"}`}>
          {data.stages.map((s) => {
            const isOpen = open.has(s.key);
            const waiting = s.status === "pending" && running ? s.depends_on.filter((d) => unfinished.has(d)) : [];
            const t = elapsed(s.started_at, s.status === "running" ? null : s.finished_at, now);
            const stEst = (est?.minutes[s.key] ?? 0) * 60000;
            return (
              <div key={s.key} className={`stage-row st-${s.status} ${isOpen ? "open" : ""}`}>
                <button className="stage-head" onClick={() => toggle(s.key)} aria-expanded={isOpen}>
                  <span className="w-icon">
                    {s.status === "running" && !data.paused ? (
                      <span className="spinner" aria-hidden="true" />
                    ) : (
                      <span className={`dot dot-${s.status}`} />
                    )}
                  </span>
                  <span className="stage-main">
                    <strong>{s.title}</strong>
                    <span className="muted small stage-sub">
                      {s.status === "waiting" ? (
                        <span className="activity warn-text">Waiting for you to choose hosts (see above)</span>
                      ) : s.status === "running" && s.activity ? (
                        <span className="activity">
                          <span className="pulse" aria-hidden="true" />
                          {s.activity}
                        </span>
                      ) : waiting.length ? (
                        `Waiting for ${waiting.map(title).join(" and ")}`
                      ) : (
                        summaryText(s)
                      )}
                    </span>
                  </span>
                  <span className="stage-time mono small">
                    {s.status === "running" ? (
                      <>
                        {fmtDur(t)}
                        {stEst > 0 && <span className="muted"> / ~{Math.max(1, Math.round(stEst / 60000))}m</span>}
                      </>
                    ) : s.started_at && s.finished_at && ["done", "failed", "cancelled"].includes(s.status) ? (
                      fmtDur(t)
                    ) : (
                      ""
                    )}
                  </span>
                  <Badge tone={STATUS_TONE[s.status] ?? "muted"}>{s.status}</Badge>
                  <span className="chev" aria-hidden="true">
                    {isOpen ? "▾" : "▸"}
                  </span>
                </button>
                <span className="stage-actions">
                  {!running && s.key === "bbot_light" && ["done", "failed"].includes(s.status) && (
                    <Button small kind="ghost" onClick={() => act(`/api/scans/${id}/stages/${s.key}/retry?reuse=1`, "Re-reading BBOT's saved output…")}>
                      Re-read output
                    </Button>
                  )}
                  {!running && s.status !== "running" && s.status !== "pending" && (
                    <Button
                      small
                      kind={armed === s.key ? "danger" : s.status === "failed" || s.status === "cancelled" ? "secondary" : "ghost"}
                      onClick={() => {
                        if (s.traffic === "active" && armed !== s.key) {
                          setArmed(s.key);
                          setOpen(new Set(open).add(s.key));
                          setTimeout(() => setArmed((a) => (a === s.key ? null : a)), 6000);
                          return;
                        }
                        setArmed(null);
                        act(`/api/scans/${id}/stages/${s.key}/retry${s.traffic === "active" ? "?confirm=active" : ""}`, `${retryLabel(s)}: ${s.title}…`);
                      }}
                    >
                      {armed === s.key ? "Click again: start active scan" : retryLabel(s)}
                    </Button>
                  )}
                </span>
                {isOpen && <StageDetail scanId={id} s={s} live={s.status === "running"} scanRunning={running} />}
              </div>
            );
          })}
        </div>
      </Card>
      {metrics && !running && <MetricsCard m={metrics} />}
      <Card title="All activity">
        <EventLog scanId={id} live={running} />
      </Card>
    </div>
  );
}

function StageDetail(props: { scanId: string; s: StageState; live: boolean; scanRunning: boolean }) {
  const { s } = props;
  const zapMode = s.status === "running" ? "view" : props.scanRunning ? null : "edit";
  const kv = Object.entries(s.summary || {}).filter(([, v]) => typeof v === "number" || typeof v === "string");
  return (
    <div className="stage-detail">
      <p className="muted small">{s.description}</p>
      {s.depends_on.length > 0 && (
        <p className="muted small">Runs after: {s.depends_on.map((d) => d.replace(/_/g, " ")).join(", ")}.</p>
      )}
      {kv.length > 0 && (
        <dl className="kv small">
          {kv.map(([k, v]) => (
            <Fragment key={k}>
              <dt>{k.replace(/_/g, " ")}</dt>
              <dd>{String(v)}</dd>
            </Fragment>
          ))}
        </dl>
      )}
      {SWITCHED_STAGES.has(s.key) && <StageSwitches scanId={props.scanId} stage={s.key} editable={!props.scanRunning && s.status !== "running"} />}
      {s.key === "zap" && zapMode && (
        <div className="zap-box">
          <h4>{zapMode === "view" ? "Hosts ZAP is scanning" : "Hosts for the next ZAP run"}</h4>
          <ZapTargets scanId={props.scanId} mode={zapMode} poll={zapMode === "view"} />
        </div>
      )}
      <EventLog scanId={props.scanId} live={props.live} stage={s.key} height={240} compact />
    </div>
  );
}

const SWITCHED_STAGES = new Set(["tls_deep", "email", "takeover", "squat", "lookalikes", "spiderfoot", "feeds", "port_check",
  "zap", "bbot_light", "dns"]);
// a stage becomes active traffic when its switch is on, even though its StageDef traffic is light/dns
const ACTIVE_WHEN: Record<string, keyof RunOptions> = { zap: "zap_active", bbot_light: "bbot_active", dns: "dns_bruteforce" };

/** Per-stage switches, editable on a finished scan before a re-run. Non-passive options are off by default and warned. */
function StageSwitches(props: { scanId: string; stage: string; editable: boolean }) {
  const [o, setO] = useState<RunOptions | null>(null);
  const toast = useToast();
  useEffect(() => {
    api<{ options: RunOptions }>(`/api/scans/${props.scanId}/options`).then((r) => setO(r.options));
  }, [props.scanId]);
  if (!o) return null;
  const save = async (changes: Partial<RunOptions>) => {
    try {
      const r = await api<{ switches: Partial<RunOptions> }>(`/api/scans/${props.scanId}/switches`, { method: "PATCH", json: changes });
      setO({ ...o, ...r.switches });
      toast("Saved. Re-run the stage to use it.", "good");
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Couldn't save", "bad");
    }
  };
  const dis = !props.editable;
  const check = (k: keyof RunOptions, label: string, warn?: string, paid?: boolean) => (
    <>
      <label className="check">
        <input type="checkbox" disabled={dis} checked={!!o[k]} onChange={(e) => save({ [k]: e.target.checked } as Partial<RunOptions>)} />
        {label} {paid && <Badge tone="warn">Paid</Badge>}
      </label>
      {warn && o[k] && <Invasive>{warn}</Invasive>}
    </>
  );
  return (
    <div className="switches">
      <h4>Switches {dis && <span className="muted small">(read-only while the scan runs)</span>}</h4>
      {props.stage === "tls_deep" && (
        <>
          <label className="small">
            Hosts to test (max){" "}
            <input type="number" min={1} max={25} disabled={dis} value={o.testssl_max_hosts} onChange={(e) => save({ testssl_max_hosts: Number(e.target.value) })} />
          </label>
          {check("testssl_vuln_checks", "Vulnerability probes (Heartbleed, CCS, Ticketbleed, ROBOT…)",
            "Sends deliberately malformed TLS handshakes. Can trip IDS/IPS and, rarely, upset old appliances. Only with authorisation for vulnerability testing.")}
        </>
      )}
      {props.stage === "email" &&
        check("email_starttls", "Test STARTTLS on your mail servers", "Light-touch: connects to each MX host on port 25 (no mail is sent).")}
      {props.stage === "takeover" && (
        <>
          {check("takeover_deep", "Deep check: run baddns over live hosts (catches dangling SaaS CNAMEs like Framer/Heroku)")}
          {check("takeover_zones", "Also check every record in my Cloudflare zones (needs a read-only token)")}
          {check("takeover_include_unlikely", 'Report "unlikely" matches too')}
        </>
      )}
      {props.stage === "zap" && (
        <>
          {check("zap_active", "ACTIVE scan: send attack payloads (injection, XSS…) to the chosen web hosts",
            "ZAP actively attacks each selected host and the AJAX spider submits forms. Can create data and trigger alerts. Re-running the stage asks you to confirm. Authorisation for active web-app testing only.")}
          {o.zap_active && (
            <label className="small indent">
              Active-scan minutes per host{" "}
              <input type="number" min={1} max={60} disabled={dis} value={o.zap_active_minutes} onChange={(e) => save({ zap_active_minutes: Number(e.target.value) })} />
            </label>
          )}
        </>
      )}
      {props.stage === "bbot_light" && (
        <>
          {check("asn_lookup", "Map IPs to their ASN / netblock (passive)")}
          {check("bbot_active", "ACTIVE modules: nuclei, lightfuzz, secret/.git exposure, SSRF, telerik… (fuzzing and vuln probes)",
            "Sends fuzzing, content-discovery and vulnerability-probe traffic to your hosts. Credential brute-forcers and data-download modules stay disabled. Re-running asks you to confirm.")}
          {o.bbot_active && (
            <label className="small indent">
              Max hosts to actively scan{" "}
              <input type="number" min={1} max={500} disabled={dis} value={o.bbot_active_max_hosts} onChange={(e) => save({ bbot_active_max_hosts: Number(e.target.value) })} />
            </label>
          )}
        </>
      )}
      {props.stage === "dns" && check("reverse_dns", "Reverse DNS (PTR) on your own IPs (passive)")}
      {props.stage === "dns" &&
        check("dns_bruteforce", "ACTIVE: brute-force subdomain names against your DNS",
          "Sends a large burst of DNS queries from this machine's IP for each root domain. Never touches your web servers. Re-running asks you to confirm.")}
      {props.stage === "squat" && (
        <>
          {check("opensquat_premium", "Use the premium feed", undefined, true)}
          {check("opensquat_portcheck", "Check whether suspect domains have web servers (ports 80/443)",
            "Connects to the suspected lookalike domains: servers you don't control that may belong to an attacker. They'll see this machine's IP.")}
        </>
      )}
      {props.stage === "lookalikes" &&
        check("lookalike_probe", "Probe registered lookalikes (web/mail banners, mail-interception check)",
          "Connects to every registered lookalike domain over HTTP and SMTP: other people's servers, possibly attackers'. They'll see this machine's IP.")}
      {props.stage === "spiderfoot" && (
        <>
          <label className="small">
            Use case{" "}
            <select disabled={dis} value={o.spiderfoot_usecase} onChange={(e) => save({ spiderfoot_usecase: e.target.value as RunOptions["spiderfoot_usecase"] })}>
              <option value="passive">Passive (default)</option>
              <option value="footprint">Footprint: touches your hosts</option>
              <option value="investigate">Investigate: touches your hosts</option>
              <option value="all">All: includes port scans and brute force</option>
            </select>
          </label>
          {o.spiderfoot_usecase !== "passive" && <Invasive>SpiderFoot modules outside the passive set contact your hosts directly. Only with authorisation for active testing.</Invasive>}
        </>
      )}
      {props.stage === "feeds" && (
        <label className="small">
          Netlas requests per scan (free tier: 50/day){" "}
          <input type="number" min={1} max={50} disabled={dis} value={o.netlas_max_requests} onChange={(e) => save({ netlas_max_requests: Number(e.target.value) })} />
        </label>
      )}
      {props.stage === "port_check" && (
        <Invasive>
          This whole stage is active: TCP connect checks from this machine to your own IPs (port scanning). Running it asks you to confirm
          first. Only do so if your authorisation covers active scanning and the SOC knows.
        </Invasive>
      )}
    </div>
  );
}

function retryLabel(s: StageState): string {
  if (s.status === "not_run") return "Run";
  if (s.status === "skipped" && s.summary?.reason === "turned off in options") return "Run";
  if (s.status === "done") return "Re-run";
  return "Retry";
}

function summaryText(s: StageState): string {
  const sm = s.summary || {};
  if (s.status === "skipped" && sm.reason) return `Skipped: ${sm.reason}`;
  if (s.status === "failed" && sm.error) return String(sm.error);
  const parts = Object.entries(sm)
    .filter(([, v]) => typeof v === "number" || typeof v === "string")
    .slice(0, 5)
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`);
  return parts.join(" · ") || s.description;
}

const AREA_LABEL: Record<string, string> = { exposure: "Exposure", web: "Web", tls: "TLS", email: "Email", brand: "Brand", people: "People" };

function MetricsCard(props: { m: Metrics }) {
  return (
    <Card title="Findings by area">
      <table className="table compact">
        <thead>
          <tr>
            <th>Area</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Info</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(props.m.findings).map(([area, c]) => (
            <tr key={area}>
              <td>{AREA_LABEL[area] ?? area}</td>
              <td>{(c.high ?? 0) + (c.critical ?? 0)}</td>
              <td>{c.medium ?? 0}</td>
              <td>{c.low ?? 0}</td>
              <td>{c.info ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">Open the Results step for the overview, assets, findings, triage and files.</p>
    </Card>
  );
}
