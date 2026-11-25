// Typed fetch wrapper. Adds the CSRF header on writes; the session cookie is HttpOnly.

let csrf: string | null = null;

export function setCsrf(token: string | null) {
  csrf = token;
}

export class ApiError extends Error {
  status: number;
  issues?: { field: string; message: string }[];
  constructor(status: number, message: string, issues?: { field: string; message: string }[]) {
    super(message);
    this.status = status;
    this.issues = issues;
  }
}

type Handler = () => void;
let onUnauthorised: Handler = () => {};
export function setUnauthorisedHandler(h: Handler) {
  onUnauthorised = h;
}

export async function api<T = unknown>(path: string, opts: { method?: string; json?: unknown; body?: BodyInit } = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};
  if (opts.json !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.json !== undefined ? JSON.stringify(opts.json) : opts.body,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    if (res.status === 401 && path !== "/api/auth/login") onUnauthorised();
    throw new ApiError(res.status, data.error ?? `HTTP ${res.status}`, data.issues);
  }
  return data as T;
}

// ---- types -------------------------------------------------------------

export interface Settings {
  user_agent: string;
  company_name: string;
  tlsx_concurrency: number;
  zap_spider_minutes: number;
  zap_ajax_minutes: number;
  shodan_lookups: boolean;
  spiderfoot_url: string;
  stage_timeout_minutes: Record<string, number>;
  third_party_providers: string[];
  large_scope_warning: number;
}

export interface SecretStatus {
  name: string;
  label: string;
  set: boolean;
  updated_at: string | null;
  tier?: "free" | "freemium" | "paid";
  group?: "intel" | "discovery" | "cloud";
  note?: string;
  signup?: string | null;
}

export interface CloudlistImport {
  present: boolean;
  assets?: number;
  public_ips?: number;
  hosts?: number;
  providers?: string[];
  updated_at?: string;
}

export interface Readiness {
  ok: boolean;
  message: string;
}

export interface ChangeFinding {
  area: string;
  severity: string;
  title: string;
  host: string | null;
  tool: string;
  was?: string;
}

export interface Changes {
  against: { id: string; finished_at: string | null; rag: string } | null;
  options: { id: string; finished_at: string | null; status: string }[];
  rag?: { before: string; after: string };
  headline?: string[];
  hosts?: { added: string[]; removed: string[] };
  live?: { added: string[]; removed: string[] };
  ports?: { opened: { host: string; port: number }[]; closed: { host: string; port: number }[] };
  findings?: { new: ChangeFinding[]; resolved: ChangeFinding[]; changed: ChangeFinding[] };
  dns?: { host: string; type: string; value: string; change: "added" | "removed" }[];
  metrics?: Record<string, { before: number | null; after: number }>;
}

export interface Scan {
  id: string;
  root_domain: string;
  status: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  options: Record<string, unknown>;
}

export interface About {
  app_version: string;
  tools: Record<string, string>;
  data_dir: string;
}

export interface Candidate {
  value: string;
  kind: "root" | "subdomain" | "related" | "exclusion";
  group: "resolves" | "third_party" | "no_dns" | "wildcard" | null;
  confidence: "high" | "medium" | "low" | null;
  decision: "suggested" | "included" | "excluded";
  third_party: boolean;
  sources: string[];
  reasons: string[];
  in_cmdb: boolean;
}

export interface CandidatesResponse {
  scan: Scan;
  discovery: { status: string; summary: Record<string, number>; started_at: string | null; finished_at: string | null } | null;
  items: Candidate[];
}

export interface HumanLine {
  text: string;
  kind: "info" | "good" | "warn" | "bad" | "progress" | "step";
  key: string | null;
}

export interface ScanEvent {
  id: number;
  stage_key: string | null;
  ts: string;
  level: string;
  message: string;
  human: HumanLine | null;
}

export interface Authorisation {
  approved_by: string;
  role: string;
  approved_on: string;
  scope_reference: string;
  soc_notified: boolean;
  soc_contact: string;
  source_ip: string;
  test_window: string;
  attested: boolean;
}

export interface StageDef {
  key: string;
  title: string;
  traffic: "none" | "dns" | "light" | "active";
  description: string;
  default: boolean;
  service?: string;
}

export interface RunOptions {
  stages: string[];
  zap_spider_minutes: number;
  zap_ajax_minutes: number;
  zap_max_hosts: number;
  tlsx_concurrency: number;
  extra_ips: string[];
  zap_confirm_targets: boolean;
  testssl_hosts: string[];
  testssl_max_hosts: number;
  testssl_vuln_checks: boolean;
  email_starttls: boolean;
  takeover_zones: boolean;
  takeover_include_unlikely: boolean;
  opensquat_confidence: number;
  opensquat_portcheck: boolean;
  opensquat_premium: boolean;
  netlas_max_requests: number;
  lookalike_probe: boolean;
  spiderfoot_usecase: "passive" | "footprint" | "investigate" | "all";
  takeover_deep: boolean;
  asn_lookup: boolean;
  reverse_dns: boolean;
  zap_active: boolean;
  zap_active_minutes: number;
  bbot_active: boolean;
  bbot_active_max_hosts: number;
  dns_bruteforce: boolean;
}

export interface StageState {
  key: string;
  title: string;
  traffic: string;
  description: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  summary: Record<string, unknown>;
  activity: string | null;
  depends_on: string[];
  active_now?: boolean;
}

export interface Estimate {
  minutes: Record<string, number>;
  total_minutes: number;
  hosts: number;
  dns_only_hosts: number;
  roots: string[];
}

export interface Metrics {
  generated_at: string;
  surface: Record<string, number>;
  findings: Record<string, Record<string, number>>;
  findings_total: Record<string, number>;
}

export interface Counts {
  stage: string | null;
  domains: number;
  related_found: number;
  subdomains_found: number;
  subdomains_in_scope: number;
  live_hosts: number;
  web_endpoints: number;
  historical_urls: number;
  open_ports: number;
  exposed_services: number;
  takeover_risks: number;
  certificates: number;
  lookalikes: number;
  issues: number;
  issues_by_severity: Record<string, number>;
  bbot_live: Record<string, number>;
}

export interface ZapCandidate {
  host: string;
  url: string;
  status: number | null;
  group: "content" | "login" | "redirect" | "unknown" | "dead end";
  root: boolean;
  recommended: boolean;
  selected: boolean;
  note: string | null;
}

export interface ZapInfo {
  candidates: ZapCandidate[];
  selected: string[];
  recommended: string[];
  from_tls: boolean;
  dead_ends: number;
  per_host_minutes: number;
  waiting: boolean;
  confirm_before: boolean;
  custom: boolean;
  progress: { hosts: string[]; current: number; job: string } | null;
}

export type NavLink = { tab: ResultsTab; filter: Record<string, string | boolean> };
export type ResultsTab = "overview" | "changes" | "assets" | "ips" | "paths" | "findings" | "triage" | "dns" | "files" | "reports";

export interface ReportKind {
  kind: string;
  title: string;
}
export interface ReportPreview {
  kind: string;
  title: string;
  root_domain: string;
  finished_at: string | null;
  rag: string;
  against: { id: string; finished_at: string | null } | null;
  sections: string[];
  redacted_by_default: boolean;
  kinds: ReportKind[];
}

export interface TechCount {
  name: string;
  count: number;
}

export interface MitreLink {
  id: string;
  url: string;
}

export interface AttackStep {
  technique: string;
  mitre: string[];
  agent_tags: string[];
  description: string;
  evidence: { host?: string; hosts?: string[]; finding_id?: number };
  mitre_links?: MitreLink[];
}

export interface PathFraming {
  precondition: string;
  impact: string;
  references: { label: string; url: string }[];
  likelihood_reason: string;
}

export interface AttackPath {
  id: string;
  title: string;
  category: "agent-abuse" | "breach" | "exfiltration" | "lateral" | "phishing" | "ddos";
  severity: string;
  likelihood: "observed" | "plausible" | "theoretical";
  steps: AttackStep[];
  nodes: string[];
  mitre: string[];
  agent_tags: string[];
  recommendation: string;
  score: number;
  mitre_links?: MitreLink[];
  framing?: PathFraming;
  tag_refs?: { tag: string; label: string; url: string }[];
}

export interface AttackPathsResponse {
  paths: AttackPath[];
  summary: {
    total: number;
    agent_related: number;
    by_category: Record<string, number>;
    by_agent_tag: Record<string, number>;
    top_severity: string | null;
  };
}

export interface GraphSummary {
  summary: {
    nodes: Record<string, number>;
    edges: number;
    shared_certs: { cert: string; wildcard: boolean; not_after: string | null; hosts: string[]; host_count: number }[];
    co_hosting: { ip: string; host_count: number; hosts: string[]; agent_hosts: string[] }[];
  };
}

export interface IpRow {
  ip: string;
  hosts: string[];
  host_count: number;
  ports: number[];
  ports_confirmed: number[];
  tech: string[];
  tech_detail?: { name: string; version: string | null; cpe: string | null; cve_url?: string | null }[];
  shared: boolean;
  live: boolean;
  netblock: string | null;
  asn: string | null;
  owner: string | null;
  net_kind: "own" | "shared" | null;
  ptr: string[];
  agent_hosts: string[];
}
export interface IpsResponse {
  ips: IpRow[];
  summary: { total: number; own: number; shared: number; multi_host: number };
}

export interface SearchResponse {
  q: string;
  hosts: { host: string; live: boolean; agent: boolean }[];
  ips: { ip: string; hosts: string[] }[];
  findings: { severity: string; group: string; area: string; host: string | null }[];
  more?: { hosts: number; ips: number; findings: number };
}

export interface Overview {
  rag: "red" | "amber" | "green";
  reasons: { level: "red" | "amber"; count: number; text: string; link: NavLink }[];
  cards: { key: string; label: string; value: number; previous: number | null; trend: "better" | "worse" | "changed" | null; link: NavLink }[];
  top_risks: { severity: string; title: string; area: string; tool: string; hosts: string[]; link: NavLink; fid?: number }[];
  not_collected: string[];
  partial?: boolean;
  failed_stages?: string[];
  severity: Record<string, number>;
  values: Record<string, number>;
  previous: { id: string; rag: string; finished_at: string | null } | null;
  status: string;
  finished_at: string | null;
  tech: TechCount[];
  agent_hosts: string[];
  vuln_matrix?: { matrix: Record<string, Record<string, number>>; order: string[]; act_now: number };
}

export interface Asset {
  host: string;
  ips: string[];
  is_live: boolean;
  web_url: string | null;
  http_status: number | null;
  tech: string[];
  ports: number[];
  risky_ports: number[];
  in_cmdb: boolean;
  cdn: boolean;
  third_party: boolean;
  tls_expiry: string | null;
  tls_version: string | null;
  tls_flags: string[];
  findings: Record<string, number>;
  triage: string | null;
  screenshot: string | null;
  edge: { cdn?: string; waf?: string; cloud?: string };
  ports_confirmed: number[] | null;
  found_by: string[];
  tags: string[];
  suggestion?: { decision: string; confidence: "high" | "medium" | "low"; reasons: string[] };
}

export interface Finding {
  id: number;
  area: string;
  severity: string;
  title: string;
  group: string;
  host: string | null;
  source_tool: string;
  evidence_ref: string | null;
  status: "observation" | "verified" | "false_positive";
  note: string | null;
  status_at: string | null;
  version_confidence?: "confirmed" | "probable" | "unconfirmed" | null;
}

export type RefKind = "cve" | "kev" | "epss" | "nist" | "cwe" | "owasp" | "ref";

export interface RefLink {
  label: string;
  url: string;
  kind: RefKind;
}

// Everything the detail pane needs for one finding. Every URL here is built backend-side
// (report_refs.py) — the UI never constructs a reference URL itself.
export interface EvidenceInstance {
  location?: string;
  locator?: string;
  observed?: string;
  detail?: string;
}
export interface FindingEvidence {
  location?: string;
  host?: string;
  locator?: string;
  observed?: string;
  detail?: string;
  fields?: { label: string; value: string }[];
  instances?: EvidenceInstance[];
  fix?: string;
  source?: string;
}
export interface FindingDetail {
  id: number;
  group: string;
  area: string;
  severity: string;
  title: string;
  tool: string;
  host: string | null;
  evidence_ref: string | null;
  status: string;
  hosts: string[];
  cves: string[];
  kev: boolean;
  epss: boolean;
  guidance: { what: string; why: string; fix: string };
  references: RefLink[];
  raw: { evidence: string | null; tool: string; files_path: string; file: string | null };
  evidence?: FindingEvidence;
  version_confidence?: "confirmed" | "probable" | "unconfirmed" | null;
  members: { id: number; severity: string; title: string; host: string | null; evidence_ref: string | null }[];
}

export interface TriageHost {
  host: string;
  group: string;
  reasons: string[];
  is_live: boolean;
  http_status: number | null;
  ips: string[];
  third_party: boolean;
  cdn: boolean;
  issues: number;
  decision: string | null;
  note: string | null;
  decided_at: string | null;
  suggestion?: { decision: string; confidence: "high" | "medium" | "low"; reasons: string[] };
}

export interface FileEntry {
  name: string;
  path: string;
  dir: boolean;
  size: number | null;
  modified: string;
  children: number | null;
}

export interface DnsRecord { host: string; rtype: string; value: string }
export interface DnsResponse { records: DnsRecord[]; types: Record<string, number>; total: number; hosts: string[] }
export interface EndpointsResponse { host: string; interesting: string[]; urls: string[]; counts: { interesting: number; urls: number } }

export interface EolInfo {
  status: "current" | "outdated_patch" | "outdated" | "eol" | "untracked" | "unavailable" | "unknown_version";
  product?: string; slug?: string; installed?: string;
  installed_cycle?: string; latest_cycle?: string; latest_version?: string | null;
  latest_release_date?: string | null; cycle_latest?: string | null;
  cycles_behind?: number; eol_date?: string | null; eol_days_ago?: number;
}

export interface HarvestedEmail { email: string; host: string | null; sources: string[] }
export interface EmailsResponse { emails: HarvestedEmail[]; count: number; flagged: boolean }
export interface EmailCheckResult { email: string; breaches: string[]; ok: boolean; error?: string }
