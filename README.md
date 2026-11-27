# Outsider ASM

**A local, single-operator external attack-surface-management app.** Point it at a domain you're authorised to test and it discovers the internet-facing estate, runs a passive / light-touch scan pipeline of best-in-class open-source tools, enriches findings with threat intelligence, models kill-chain attack paths, and produces board-to-engineering reports — all inside one Docker container on your machine, bound to loopback.

<p>
<img alt="Python" src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white">
<img alt="Starlette" src="https://img.shields.io/badge/Starlette-ASGI-0F172A?style=flat-square">
<img alt="Uvicorn" src="https://img.shields.io/badge/Uvicorn-499848?style=flat-square">
<img alt="SQLite" src="https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white">
<img alt="React 19" src="https://img.shields.io/badge/React_19-20232A?style=flat-square&logo=react&logoColor=61DAFB">
<img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white">
<img alt="esbuild" src="https://img.shields.io/badge/esbuild-FFCF00?style=flat-square&logo=esbuild&logoColor=black">
<img alt="Docker" src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white">
<img alt="Typst" src="https://img.shields.io/badge/Typst-239DAD?style=flat-square&logo=typst&logoColor=white">
<img alt="GitHub Actions CI" src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white">
<img alt="gitleaks" src="https://img.shields.io/badge/gitleaks-secret_scan-DC2626?style=flat-square">
</p>

> **Status: milestones 1–6 of 7.** Discovery & scope, authorisation, the light-touch pipeline (parallel stages, live view, pause/resume, ZAP host picker), results (overview with RAG, surface map, trends, attack paths, assets, IPs, DNS, findings with embedded evidence, triage, file browser) and reports (a full document plus a redacted share-zip). Next: AI providers (M7).

## What it does

- **Discovers** your external footprint passively — subdomains, related domains, DNS, certificates, cloud assets — before touching a single target server.
- **Scans light-touch by default** — one front-page request per host, TLS and DNS posture, email/brand spoofing exposure, technology versions. Anything that sends attack traffic (port scanning, ZAP active, vuln probes) is **off by default, authorisation-gated, and confirmed per stage**.
- **Enriches** every finding with authoritative intel: CISA KEV, FIRST EPSS, NVD/CVSS, CWE, OWASP, NIST SP 800-53, plus breach exposure and end-of-life version currency.
- **Models attack paths** as kill chains (MITRE ATT&CK / ATLAS), including the AI-agent / MCP surface — theoretically, reasoning over collected exposure without sending traffic.
- **Reports** with a RAG verdict, a surface map, trend-vs-last-scan, and a redacted share pack safe to hand to a vendor, insurer or the board.

Built for security teams to review **their own** infrastructure, and for consultants to run authorised pre-engagement reviews.

## Demo

> 🔗 **[Live demo (redacted)](https://high5ive-64.github.io/asm-console/)** — the full results UI running against a frozen, redacted snapshot of a real scan. No backend, nothing sensitive.

The demo is the real results experience — RAG verdict, surface map, attack paths / kill chains, technologies and versions, CVE and MITRE ATT&CK/ATLAS mappings, findings with evidence — run against [pentest-ground.com](https://pentest-ground.com), a public penetration-testing practice range. Every host name, IP and email is pseudonymised (`asset-01`, `ip-07`, `email-01`) by the same redactor used for the share pack; standards references (MITRE, CWE, OWASP, NVD, EPSS, CISA KEV) are preserved so the mappings stay clickable. It is a point-in-time export, so report generation and raw-evidence files are disabled.

![Outsider ASM surface map — exposed hosts wired to the attack paths they enable](screenshots/surface-map.jpg)

The same snapshot also powers the in-app **Demo** tab (`/demo`), so you can show the tool without exposing a live scan.

## Architecture

```mermaid
flowchart TB
  user(["👤 Operator"])

  subgraph host[" 🖥️ Your machine · loopback only "]
    direction TB
    subgraph ctr[" 🐳 Docker container · non-root · caps dropped · no-new-privileges "]
      direction TB
      ui["🖼️ React UI<br/>strict CSP · no inline script"]
      guard["🛡️ Guard<br/>Host/Origin · session · CSRF · headers"]
      api["🧭 Starlette API<br/>scans · runs · results · reports"]
      pipe["⚙️ Pipeline<br/>dependency DAG · 5-way scheduler"]
      runner["🏃 Runner<br/>argv allowlist · no shell · masking"]
      tools["🧰 Scanner tools<br/>BBOT · ZAP · tlsx · dnsx · testssl · …"]
      db[("🗄️ SQLite WAL<br/>+ run folders")]
      sec["🔑 Secret store<br/>AES-256-GCM"]

      ui --> guard --> api
      api --> pipe --> runner --> tools
      api -.-> db
      api -.-> sec
    end
  end

  user -->|"localhost:8443 · token → session + CSRF"| ui
  tools -->|"authorised scope only"| target["🎯 Target attack surface<br/>your infra / an authorised prospect"]
  pipe -->|"SSRF-guarded · fixed hosts"| intel["🌐 Threat intel &amp; feeds<br/>Shodan · KEV · EPSS · NVD · LeakIX · urlscan · …"]

  classDef operator fill:#312e81,stroke:#6366f1,color:#eef2ff;
  classDef app fill:#1e3a8a,stroke:#60a5fa,color:#eff6ff;
  classDef security fill:#064e3b,stroke:#34d399,color:#ecfdf5;
  classDef data fill:#334155,stroke:#94a3b8,color:#f8fafc;
  classDef external fill:#7c2d12,stroke:#fb923c,color:#fff7ed;

  class user operator;
  class ui,api,pipe app;
  class guard,runner,sec security;
  class db data;
  class target,intel external;

  style host fill:transparent,stroke:#64748b,stroke-width:1px,color:#94a3b8;
  style ctr fill:#0b1220,stroke:#475569,stroke-width:1px,color:#cbd5e1;
```

Every command a stage runs is built as an argument list (never a shell string) and checked against an allowlist before execution; outbound fetches are guarded against SSRF; secrets are encrypted at rest and masked out of logs.

## How it works

A scan is a staged pipeline with four jobs: **discover** the external estate, **collect** evidence with passive/light-touch probes, **correlate** everything into one entity graph, and **present** a prioritised verdict with kill-chain attack paths and reports. Each scan is a self-contained, re-runnable snapshot — nothing leaks between scans, and re-running produces a fresh snapshot you can diff against the last.

```mermaid
flowchart LR
  disc["🛰️ Passive discovery<br/>subdomains · CT logs · DNS"] --> scope["✅ Confirm scope<br/>in_scope() gate"]
  scope --> auth["📝 Authorisation<br/>recorded with the run"]
  auth --> stages

  subgraph stages["⚙️ Light-touch pipeline · dependency DAG, up to 5 in parallel"]
    direction TB
    live["Liveness &amp; fingerprint"]
    dnsx["DNS &amp; certificates"]
    web["Web hygiene · ZAP passive"]
    svc["Services &amp; vulns · KEV / EPSS"]
    mail["Email &amp; brand"]
    osint["Breach &amp; OSINT"]
  end

  stages --> reenrich["🔁 Re-enrich<br/>late in-scope hosts"]
  reenrich -.->|feed back| stages
  stages --> cons["🧩 Consolidate"]
  cons --> store[("🕸️ Entity graph<br/>+ assets · findings · metrics")]
  store --> ov["🚦 Overview · RAG"]
  store --> paths["🎯 Attack paths"]
  store --> rep["📄 Reports · share pack"]

  classDef a fill:#1e3a8a,stroke:#60a5fa,color:#eff6ff;
  classDef b fill:#064e3b,stroke:#34d399,color:#ecfdf5;
  classDef c fill:#334155,stroke:#94a3b8,color:#f8fafc;
  class disc,scope,auth a;
  class reenrich,cons b;
  class store,ov,paths,rep c;
  style stages fill:#0b1220,stroke:#475569,color:#cbd5e1;
```

*The scan end to end: discover and confirm scope, run the parallel light-touch pipeline (with a re-enrichment loop for late discoveries), then consolidate everything into one entity graph that the Overview, attack paths and reports all read from.*


### 1 · The scan, step by step

**Discover & confirm scope.** From a single root domain, passive discovery (BBOT passive modules, certificate-transparency logs, DNS, and optional keyed datasets) enumerates subdomains, related domains and cloud names **before a single target server is touched**. Candidates are grouped (*resolves* / *third-party* / *no-DNS* / *wildcard*) and you confirm an explicit scope. A single `in_scope()` filter then gates every later stage, and authorisation (who approved it, the reference, the window, your source IP, SOC awareness) is recorded with the run as audit evidence.

**The light-touch pipeline.** Once scope and authorisation are confirmed, 24 stages run. Every stage carries a **traffic tier** so you always know what it sends:

- **no traffic** — API lookups or fully offline (Shodan InternetDB, KEV/EPSS, breach feeds, cdncheck).
- **DNS only** — resolver queries (DNS snapshot, takeover checks, email posture, lookalikes).
- **light-touch** — ordinary web requests, roughly one front-page fetch per host (liveness, tech fingerprint, TLS, ZAP passive).
- **active** — off by default, authorisation-gated and confirmed per stage (naabu port confirmation, ZAP active, testssl vuln probes).

The stages don't run in a fixed line. A dependency DAG (`STAGE_DEPS`) lets **up to five run in parallel**, each starting the moment the stages it depends on have finished. Grouped by what they do:

| Group | Stages (tier) | What it collects |
|---|---|---|
| **Liveness & fingerprint** | `bbot_light` (light) · `tech` (light) · `screenshots` (light) | Which hosts are live, their technologies and **versions**, and a headless screenshot of each web host. |
| **DNS & certificates** | `dns` (DNS) · `cdn` (none) · `takeover` (DNS) · `tls` / `tls_deep` (light) | Full record snapshot (A/AAAA/CNAME/MX/NS/TXT/CAA); cdncheck classifies each IP as *yours* vs a CDN/cloud edge; 50+ takeover signatures; certificate and protocol posture. |
| **Web hygiene** | `zap` (light) | ZAP spiders live hosts with **passive rules only** — headers, cookie flags, vulnerable JS libraries, info leaks. No attack payloads. |
| **Services & vulns** | `ports` (none) · `cloudlist` / `cloud` (none) · `feeds` (none) · `intel` (none) · `port_check` (active) | Open ports from Shodan; public IPs from your cloud accounts; LeakIX/Netlas exposure; CVEs ranked by CISA **KEV** and FIRST **EPSS**; optional active port confirmation. |
| **Email & brand** | `email` (DNS) · `lookalikes` (DNS) · `squat` (none) · `urlscan` (none) | SPF/DMARC/MTA-STS/TLS-RPT/BIMI; registered typo/homoglyph domains; newly-registered squats; urlscan sightings (a live lookalike page is a phishing signal). |
| **Breach & OSINT** | `gau` (none) · `hibp` (none) · `spiderfoot` (none) | Historical URLs (Wayback/Common Crawl/OTX); per-domain breach exposure; optional passive SpiderFoot sidecar. |
| **Re-enrich & consolidate** | `reenrich` (light) · `consolidate` (none) | Loops back to probe late-discovered in-scope hosts, then combines every stage's raw output into assets, findings and metrics. |

**The re-enrichment loop** is what stops the scan from missing things it uncovers mid-flight: historical URLs, certificate SANs, DNS and ZAP all surface new in-scope hosts, so `reenrich` probes those (liveness, tech, TLS, screenshots) and feeds them back into the CVE, port, takeover and DNS checks — strictly in-scope and bounded. **Cancel** stops cleanly; **Resume** continues from the first unfinished stage; **Retry** re-runs a single failed one.

### 2 · How the data is structured

Everything a scan produces lands in SQLite (WAL) as a per-scan snapshot, with raw tool output kept on disk under `data/runs/<date>-<id>/`.

- **`scans`** — one row per scan (root domain, status, options, pinned tool versions, run folder). **`scope_items`** and **`authorisations`** capture the confirmed scope and the audit record.
- **`stages`** + **`events`** — per-stage status, exit code, a JSON summary and a log path, plus a live event stream (what powers the live view).
- **`assets`** — one row per host: resolved `ips`, `is_live`, `web_url`/`http_status`, detected `tech` (name + version), `tls` posture, `ports`, `cdn`/`third_party` flags, `in_cmdb`, which sources `found_by` it, and `ports_confirmed` if the active check ran.
- **`findings`** — one row per issue: an `area` (email, tls, web, exposure, vulns, surface, dns, cloud, brand), a `severity` (critical → info), a title, the `host`, the `source_tool`, and an `evidence_ref` pointing back to the exact raw file. **`dns_records`** stores every record so DNS drift shows up in Changes.
- **`metrics`** — the consolidated roll-up the dashboard reads; **`triage`** holds your per-host decisions; **`cmdb_entries`** is your known-asset list, used to flag the unknowns.

Because each finding references its raw evidence file, every number on the dashboard traces back to the tool output that produced it — nothing is asserted without a source.

### 3 · How correlation happens

The consolidate stage builds a single **entity graph** from the raw output, and the rest of the product reasons over that graph rather than over loose tool logs. Nodes are typed — **host, ip, netblock, cert, tech, finding, lookalike** — and joined by typed edges: a host *resolves_to* an IP, an IP sits *in_netblock*, a host *runs* a technology, *presents* a certificate, *cname_to* another name, *has_finding*, or is *impersonated_by* a lookalike.

```mermaid
flowchart LR
  host(["host"]) -->|resolves_to| ip(["ip"])
  ip -->|in_netblock| nb(["netblock"])
  host -->|runs| tech(["tech + version"])
  host -->|presents| cert(["cert"])
  host -->|cname_to| host2(["host"])
  host -->|has_finding| find(["finding"])
  host -->|impersonated_by| look(["lookalike"])

  tech -. "version → KEV / EPSS" .-> find
  ip -. "co-hosting = blast radius" .-> host2
  cert -. "shared cert groups hosts" .-> host2

  classDef n fill:#1e3a8a,stroke:#60a5fa,color:#eff6ff;
  classDef d fill:#7c2d12,stroke:#fb923c,color:#fff7ed;
  class host,host2,ip,nb,tech,cert n; class find,look d;
```

*The typed entity graph the product reasons over; dotted links are the correlations it derives from the structure.*

From that structure the tool derives the correlations that loose logs can't show:

- **Whose IP is it?** cdncheck reclassifies every resolved IP against published CDN/WAF/cloud ranges **before** ports and CVEs are checked, so "your" exposure isn't really a shared edge.
- **Blast radius** — co-hosting groups the hosts that share one origin IP, and shared-certificate analysis groups the hosts behind one cert, so a single compromise's reach is visible.
- **Version → known-exploited vuln** — technology versions from the fingerprint stage are matched to CVEs and ranked by CISA KEV and FIRST EPSS. These are banner matches, so they surface as *"verify"*, not confirmed vulnerabilities.
- **AI-agent surface** — hosts that look like agent/MCP endpoints are tagged, because inconsistent or missing auth on them is a distinct, high-impact class of exposure.
- **Attack paths** — the engine chains graph exposure into theoretical kill chains (e.g. an open agent/MCP endpoint, a known-exploited CVE as an entry point, a subdomain takeover, SSRF into cloud metadata, a leaked secret reused against its API). Each path is mapped to **MITRE ATT&CK / ATLAS**, carries a likelihood (*observed* / *plausible* / *theoretical*), and **sends no traffic** — it reasons over what the scan already collected.

### 4 · How results are presented, and the logic behind it

The Overview turns the graph into a single **RAG verdict** with transparent, rule-based reasons — never a black-box score:

- **Red** if any of: a risky service is exposed (RDP, databases, SSH), a dangling DNS record (possible takeover), a high-severity LeakIX/SpiderFoot leak, an expired certificate, or a high-risk ZAP alert.
- **Amber** if any of: hosts not in your CMDB and not yet triaged, a KEV-listed CVE matched to a version (verify), SPF over the 10-lookup limit, a lookalike domain with a live page, a domain without DMARC reject, medium ZAP alerts, a certificate expiring within 30 days, or an exposed AI-agent / MCP host.
- **Green** only when none of the above fire.

Every reason is a deep link into the tab and filter that explains it. Around the verdict:

- **Metric cards** surface the counts that matter (hosts in scope, live web hosts, unknown hosts, risky services, open ports, KEV CVEs, agent surface, expiring certs…), each comparing against the previous scan.
- **Top risks** are the worst issue *groups*, ranked by a risk weight (severity × spread) and capped to the few that deserve attention first.
- **Surface map** has two lenses: a **treemap** sized by severity × affected hosts for "where is the risk concentrated", and an **attack graph** wiring exposed hosts to the attack paths they enable for "how would someone chain this".
- **Ten result tabs** go deep — Overview, Changes, Assets, IPs, DNS, Attack paths, Findings (with embedded per-tool evidence), Triage, Files (raw output) and Reports; see [Results](#results) for what each one holds.
- **Changes** diffs this scan against the previous one — new and resolved findings, hosts that appeared or disappeared, newly opened ports, DNS drift — so a new deployment's fresh exposure surfaces immediately.
- **Reports** render from the same data (so nothing disagrees with the dashboard): a full board-to-engineering document, and a **share pack** that is force-redacted — host names, IPs and emails replaced with `asset-01` / `ip-07` / `email-01` pseudonyms — safe to hand to a vendor, insurer or the board.

## Run it

Requirements: Docker Desktop (or OrbStack) on macOS, plus about 6 GB of free RAM for scans.

```bash
cp Makefile.dist Makefile   # one-time
make build      # first build takes a while: ZAP, Firefox, Java, BBOT and its module dependencies
make up         # starts on http://localhost:8443 and prints the access token on first start
```

Open <http://localhost:8443> and paste the token. Lost it? Run `make token`.

Other commands: `make logs`, `make down`, `make test`, `make versions` (tool versions inside the image), `make smoke` (checks every tool runs).

## Tools & integrations

All open-source, pinned in `docker/versions.env`, and allowlist-gated. Passive / DNS-only / light-touch unless a switch explicitly opts into active traffic.

| Area | Engines & services | Traffic |
|---|---|---|
| **Discovery & enumeration** | BBOT (passive modules), certificate transparency (crt.sh), DNS resolvers; optional keyed datasets: Censys, SecurityTrails, VirusTotal, Chaos, GitHub, WhoisXML | passive / DNS-only |
| **Web & TLS** | OWASP ZAP (passive crawl; active opt-in), tlsx, testssl.sh, Wappalyzer rules (tech + versions), gau (historical URLs), uro | light-touch |
| **DNS & takeover** | dnsx, dig, dnsReaper, cdncheck (CDN/WAF/cloud), BBOT baddns | DNS-only |
| **Email & brand** | checkdmarc (SPF/DMARC/MTA-STS/TLS-RPT/BIMI), dnstwist, openSquat (lookalikes) | DNS-only |
| **Exposure & threat intel** | Shodan / InternetDB, Shodan CVEDB, LeakIX, Netlas, urlscan.io, CISA KEV, FIRST EPSS, NVD, endoflife.date, XposedOrNot, Have I Been Pwned | none (fixed-host API calls) |
| **Cloud inventory** | cloudlist (AWS, GCP, Azure, Cloudflare, DigitalOcean — read-only) | none |
| **Screenshots & reporting** | Firefox + geckodriver (gowitness), Typst (PDF) | light-touch |
| **Optional sidecar** | SpiderFoot (passive use case only) | none |

Breach exposure stays domain-level by default; harvested emails are listed on the Overview, and a per-email breach check unlocks only once a domain is already flagged.

**Active switches** (off by default, warned, authorisation-gated, confirmed per stage): naabu port scan, ZAP active scan, testssl.sh vulnerability probes, openSquat port check, dnstwist lookalike probes, SpiderFoot non-passive use cases, STARTTLS mail test.

SpiderFoot: `docker compose --env-file docker/versions.env --profile spiderfoot up -d` — its own UI on `127.0.0.1:5001` has no login and can run active modules, so use it for viewing only.

## Results

When a scan finishes, its **Results** step opens with ten tabs:

![Overview — the RAG verdict, a change-since-last-scan summary, metric cards and the surface map](screenshots/overview.jpg)

![Attack paths — kill chains grouped by type, with AI-agent threat tags, likelihood and MITRE mapping](screenshots/attack-paths.jpg)

![Findings — issues grouped by severity and area, each tracing back to the tool and evidence that produced it](screenshots/findings.jpg)

- **Overview** — the RAG verdict and its reasons, a surface map (issue treemap + attack-path graph), a worst-first worklist, metric cards with trend vs the previous scan, a vulnerability version-confidence matrix, discovered emails, and the agent / MCP surface. An **"Incomplete scan"** banner appears if any stage failed, so a green rating is never mistaken for a clean bill.
- **Changes** — new/removed hosts, ports opened/closed, new/resolved findings and RAG movement vs any earlier scan.
- **Assets** — every in-scope host: status, IPs, technology & versions, TLS expiry, ports, CMDB/third-party/CDN flags, issue counts, screenshots.
- **IPs** — resolved IPs, their services, and the hosts sharing each one.
- **DNS** — every resolved record (A/AAAA, CNAME, NS/MX, TXT, CAA).
- **Attack paths** — kill chains with precondition, impact, assets, MITRE ATT&CK/ATLAS links, agent-risk tags, likelihood and remediation. Theoretical only.
- **Findings** — grouped by issue, each with structured evidence and authoritative references; mark observation / verified / false positive.
- **Triage** — hosts not in your CMDB; decide what each is. Undecided = unknown (amber).
- **Files** — read-only browser of the run folder (HTML downloads rather than opens, since tool output can be hostile).
- **Reports** — a full board-to-engineering document, plus a **redacted share-zip** (hosts/IPs → `asset-01`/`ip-07`, IPv6 and emails included) safe to send outside the team.

## Security

### Inbuilt protections

- **Loopback only.** Published to `127.0.0.1`; requests are rejected unless the `Host` header is `localhost`/`127.0.0.1` (blocks DNS rebinding), and cross-site `Origin`s are rejected.
- **Auth.** One-time access token → `HttpOnly`, `SameSite=Strict` session cookie; every state-changing request needs a CSRF token.
- **Strict CSP**, no inline script or style; React escapes all scan-derived text; reports download rather than render.
- **Secrets** are AES-256-GCM encrypted at rest (key name bound as associated data), never returned by the API, and masked out of every log line. The master key is generated on first run and kept in `secrets/master.key` with `0600` (owner-only) permissions; `secrets/` is git-ignored, so the key never enters the repo.
- **Command execution** is allowlist-gated: every argv is validated (binary, flags, numeric ranges, file paths confined to the run folder) and run without a shell. Credential brute-forcers and raw port scanners are blocked *and absent from the image*.
- **Outbound fetches** are SSRF-guarded — per-host requests and redirects are refused if the target resolves to a loopback, link-local (incl. cloud-metadata), private or reserved address.
- **Active traffic** can't run without a completed, SOC-notified authorisation record, and each active stage requires an explicit per-stage confirmation.
- **Container** runs as a non-root user with all Linux capabilities dropped and `no-new-privileges`.

### Standards & frameworks

Findings and attack paths are mapped to, and deep-linked against, authoritative sources (the UI never constructs a reference URL itself):

**NVD / CVSS · CISA KEV · FIRST EPSS · CWE · OWASP Top 10 · OWASP LLM Top 10 · NIST SP 800-53 · MITRE ATT&CK · MITRE ATLAS**

### CI & quality gates

GitHub Actions runs on every push / PR to `main` (`.github/workflows/ci.yml`):

A **gate** fails the build and blocks merge; **advisory** steps run and report but don’t block.

| Job (runner) | Step | Exactly what runs | |
|---|---|---|---|
| **backend** · Python 3.12 | Tests | `python -m pytest -q` — full suite, 191 tests | ✅ gate |
| | Dependency audit | `pip-audit -r backend/requirements.txt` | advisory |
| **frontend** · Node 20 | Typecheck | `npx tsc --noEmit` | advisory |
| | Build | `node build.mjs` — esbuild production bundle | ✅ gate |
| | Dependency audit | `npm audit` | advisory |
| **secrets** | Secret scan | `gitleaks-action@v2` over full history, config `.gitleaks.toml` | ✅ gate |

A local **gitleaks pre-commit hook** (`.githooks/pre-commit`, config in `.gitleaks.toml`) catches secrets before they're committed. See `DEV.md` for the dev loop.

## What's where

| Path | Purpose |
| --- | --- |
| `backend/asm/allowlist.py` | Every command the app runs is checked here first |
| `backend/asm/scope.py` | Domain validation and the single `in_scope()` filter |
| `backend/asm/security.py` | Access token, sessions, CSRF, Host/Origin checks, security headers |
| `backend/asm/secrets_store.py` | AES-256-GCM encrypted, write-only API keys |
| `backend/asm/discovery.py` | Passive discovery + the SSRF-guarded HTTP client |
| `backend/asm/pipeline.py` | Stage definitions, dependency DAG and the parallel scheduler |
| `backend/asm/extras.py` | The extra non-invasive sources (breach exposure, KEV/EPSS, lookalikes, urlscan, cloud…) |
| `backend/asm/attackpaths.py` | Derives kill-chain attack paths (MITRE ATT&CK / ATLAS) — theoretical, sends no traffic |
| `backend/asm/evidence.py` | Maps each finding to its structured per-tool evidence |
| `backend/asm/reports.py` | Builds the Typst reports (full document and redacted share-zip) |
| `backend/asm/report_refs.py` | Canonical reference URLs (NVD/KEV/EPSS, CWE, OWASP, NIST, MITRE) |
| `backend/asm/runner.py` | Runs allowlisted commands, streams masked output, handles cancel/timeouts |
| `backend/tests/` | 191 tests: unit (allowlist, scope, crypto, SSRF, redaction) + integration (full pipeline with stubbed tools) |
| `frontend/src/` | React + TypeScript UI, bundled by esbuild |
| `docker/` | Dockerfile and pinned tool versions |
| `data/` | Database, run folders, exports — created on first start (git-ignored) |
| `secrets/master.key` | Encrypts your API keys (mode 600). Back it up with `data/` or saved keys can't be decrypted |

## Running a scan

1. **New scan** — enter the domain, pick discovery sources, review and confirm the scope.
2. **Authorisation** — record who approved the test, the reference, the window, your source IP and SOC awareness. Saved with the run as audit evidence.
3. **Options** — choose stages (labelled *no traffic* / *DNS only* / *light-touch*), set ZAP/TLS limits, optionally add public IPs. The estimate updates live.
4. **Review → Start.** You can close the tab; the scan runs in the container. **Cancel** stops cleanly, **Resume** continues from the first unfinished stage, **Retry** re-runs one failed stage.
5. Run files live in `data/runs/<date>-<id>/` (scope snapshot, `authorisation.json`, per-stage logs, raw tool output).

Downstream stages loop back to pick up hosts found after the initial sweep; hosts that no longer resolve are recorded as historical rather than dropped. A container restart mid-scan marks the scan *interrupted* and it can be resumed.

## Tests

`make test` runs the full suite (191 tests) inside the image; the same tests gate every push in CI. Bare/stubbed runs and the dev loop are in [DEV.md](DEV.md).


## Roadmap

Built in milestones; **1–6 of 7 are done** — discovery & scope, authorisation, the light-touch pipeline, results, and reports.

**Next — M7: AI providers.** Optional AI-assisted analysis and triage over scan data, plus modelling of the AI-agent / MCP attack surface (OWASP LLM Top 10, MITRE ATLAS). Guardrails-first by design: provider keys live in the encrypted secret store, agent permissions are least-privilege, no secret egress, and every action is auditable — consistent with the theoretical-only approach the attack-path engine already takes (reason over exposure, send no traffic).

Full change history and what's planned next: **[CHANGELOG.md](CHANGELOG.md)**.

## Open-source tools & data sources

Outsider ASM is a thin, safety-focused orchestration layer over established open-source projects and public data sources. Full credit to their authors and maintainers.

**Built with** — [Starlette](https://www.starlette.io/) · [Uvicorn](https://www.uvicorn.org/) · [React](https://react.dev/) · [TypeScript](https://www.typescriptlang.org/) · [esbuild](https://esbuild.github.io/) · [Typst](https://typst.app/) · [cryptography](https://cryptography.io/) · [SQLite](https://www.sqlite.org/)

**Discovery & enumeration** — [BBOT](https://github.com/blacklanternsecurity/bbot) · [crt.sh](https://crt.sh/) (certificate transparency)

**Web & TLS** — [OWASP ZAP](https://www.zaproxy.org/) · [tlsx](https://github.com/projectdiscovery/tlsx) · [testssl.sh](https://github.com/drwetter/testssl.sh) · [gau](https://github.com/lc/gau) · [uro](https://github.com/s0md3v/uro) · [Wappalyzer fingerprints](https://github.com/wappalyzer/wappalyzer)

**DNS & takeover** — [dnsx](https://github.com/projectdiscovery/dnsx) · [DNSReaper](https://github.com/punk-security/dnsReaper) · [cdncheck](https://github.com/projectdiscovery/cdncheck) · [baddns](https://github.com/blacklanternsecurity/baddns)

**Email & brand** — [checkdmarc](https://github.com/domainaware/checkdmarc) · [dnstwist](https://github.com/elceef/dnstwist) · [openSquat](https://github.com/atenreiro/opensquat)

**Cloud inventory** — [cloudlist](https://github.com/projectdiscovery/cloudlist)

**Screenshots & reporting** — [gowitness](https://github.com/sensepost/gowitness) · [geckodriver](https://github.com/mozilla/geckodriver) · [Firefox](https://www.mozilla.org/firefox/) · [Typst](https://github.com/typst/typst)

**Exposure & threat intelligence** — [Shodan InternetDB](https://internetdb.shodan.io/) · [Shodan CVEDB](https://cvedb.shodan.io/) · [LeakIX](https://leakix.net/) · [Netlas](https://netlas.io/) · [urlscan.io](https://urlscan.io/) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [NVD](https://nvd.nist.gov/) · [endoflife.date](https://endoflife.date/) · [XposedOrNot](https://xposedornot.com/) · [Have I Been Pwned](https://haveibeenpwned.com/)

**Standards & frameworks** — [MITRE ATT&CK](https://attack.mitre.org/) · [MITRE ATLAS](https://atlas.mitre.org/) · [CWE](https://cwe.mitre.org/) · [OWASP Top 10](https://owasp.org/Top10/) · [OWASP LLM Top 10](https://genai.owasp.org/) · [NIST SP 800-53](https://csf.tools/reference/nist-sp-800-53/) · [CVSS](https://www.first.org/cvss/)

**Optional sidecar** — [SpiderFoot](https://github.com/smicallef/spiderfoot)

Optional keyed datasets (bring your own API key): Censys, SecurityTrails, VirusTotal, [Chaos](https://chaos.projectdiscovery.io/), GitHub, WhoisXML.
