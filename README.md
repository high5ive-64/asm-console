# Outsider ASM

A local, single-user web app for non-invasive external attack surface reviews. It covers discovery, scope confirmation, a passive and light-touch scan pipeline, results, and a board pack. Everything runs in one Docker container on your Mac. The design is in the "ASM Web App — Build Spec v0.1" doc.

> **Status: milestones 1–5 of 7.** Discovery and scope, authorisation, the light-touch pipeline (stages run in parallel, live view, pause/resume, ZAP host picker) and results: overview with RAG and trends, assets, findings with analyst status, unknown-host triage and a read-only file browser. Next: reports (M6) and AI providers (M7).

## Run it

Requirements: Docker Desktop (or OrbStack) on macOS, plus about 6 GB of free RAM for scans.

```bash
cp Makefile.dist Makefile   # one-time
make build      # first build takes a while: ZAP, Firefox, Java, BBOT and its module dependencies
make up         # starts on http://localhost:8443 and prints the access token on first start
```

Open <http://localhost:8443> and paste the token. Lost it? Run `make token`.

Other commands: `make logs`, `make down`, `make versions` (tool versions inside the image), `make smoke` (checks every tool runs).

## What's where

| Path | Purpose |
| --- | --- |
| `backend/asm/` | Python app (Starlette + Pydantic, SQLite) |
| `backend/asm/allowlist.py` | Every command the app runs is checked here first |
| `backend/asm/scope.py` | Domain validation and the single `in_scope()` filter |
| `backend/asm/security.py` | Access token, sessions, CSRF, Host/Origin checks, security headers |
| `backend/asm/secrets_store.py` | AES-256-GCM encrypted, write-only API keys |
| `backend/asm/discovery.py` | Passive discovery: BBOT passive modules, certificate transparency, DNS grouping, related-domain sources |
| `backend/asm/runner.py` | Runs allowlisted commands, streams masked output to the live log, handles cancel and timeouts |
| `backend/tests/` | 62 tests: API security, allowlist, scope, crypto, discovery and scope rules |
| `frontend/src/` | React + TypeScript UI, bundled by esbuild |
| `docker/` | Dockerfile and pinned tool versions |
| `data/` | Created on first start: database, run folders, exports (git-ignored) |
| `secrets/master.key` | Created on first start (mode 600); encrypts your API keys. Back it up with `data/`, because without it saved keys can't be decrypted |

## Running a scan

1. **New scan**: enter the main domain, pick discovery sources, review and confirm the scope.
2. **Authorisation**: record who approved the test, the reference, the window, your source IP and that the SOC knows. Saved with the run as audit evidence.
3. **Options**: choose stages (each is labelled *no traffic*, *DNS only* or *light-touch*), set ZAP and TLS limits, optionally paste extra public IPs. The estimate updates as you go.
4. **Review → Start**. You can close the tab; the scan runs in the container. Cancel stops the current tool cleanly; **Resume** continues from the first unfinished stage, and **Retry** re-runs a single failed stage.
5. Run files live in `data/runs/<date>-<id>/` (scope snapshot, `authorisation.json`, per-stage logs and raw tool output).

If the container restarts mid-scan, the scan is marked *interrupted* and can be resumed.

## Results

When a scan finishes, its **Results** step opens with five tabs:

- **Overview**: the headline RAG (red / amber / green) with the reasons behind it, metric cards with trends against the previous scan of the same domain, and the top risks. Every reason, card and risk links to its source.
- **Assets**: every host in scope with status, IPs, technology, TLS expiry, ports, CMDB / third-party / CDN flags, issue counts and screenshots.
- **Findings**: grouped by issue. Mark a whole issue or single hosts as *observation*, *verified* or *false positive*, and add notes. False positives drop out of the RAG and the counts.
- **Triage**: hosts not in your CMDB. Decide what each one is, or add hosts to the CMDB so future scans know them. Undecided hosts count as unknown (amber).
- **Files**: a read-only browser of the run folder. Reports and other HTML download rather than open, because tool output can contain hostile content from scanned sites.

RAG rules: red for a risky service, dangling DNS, an expired certificate or a high ZAP alert; amber for unknown hosts, a domain without DMARC reject, medium ZAP alerts or certificates expiring within 30 days.

## Extra sources (v0.6)

All non-invasive by default and free by default. Paid options are labelled in the UI and stay off without a key.

| Stage | Tool / service | Traffic | Cost |
|---|---|---|---|
| CDN, WAF and cloud classification | cdncheck | none (offline ranges) | free |
| Subdomain takeover | dnsReaper (+ Cloudflare zones with a read-only token) | DNS only | free |
| Deep TLS review | testssl.sh on 5 key hosts | light-touch | free |
| Email security | checkdmarc (SPF lookup limit, DMARC sp/pct/rua, MTA-STS, TLS-RPT, BIMI) | DNS only | free |
| Cloud inventory | cloudlist: upload its JSON, or save read-only keys | none | free |
| Exposure feeds | LeakIX, Netlas | none | free keys (daily quotas); Netlas paid tiers |
| Known-exploited vulnerabilities | InternetDB / Shodan host lookups + CISA KEV + EPSS | none | free (Shodan search needs the paid membership) |
| Newly registered lookalikes | openSquat community feed | none | free; premium feed paid |
| Seen in the wild | urlscan.io search (never submits) | none | free |
| SpiderFoot | optional sidecar, passive use case only | none | free, self-hosted |

| Technology fingerprints | Wappalyzer rules (dochne community fork), one front-page GET per live host; versions → Shodan CVEDB → KEV/EPSS | light-touch | free |
| DNS record snapshot | dnsx (A/AAAA/CNAME/MX/NS/TXT/CAA); DNS changes appear in the Changes tab | DNS only | free |
| Confirm open ports | naabu, TCP connect only, ~100 pps, your own non-CDN IPs, Shodan's ports + top 100 | **active** | free |

Switches that go beyond light-touch, all off by default and warned about in Options and Review:
- the **Confirm open ports (naabu)** stage itself (port scanning),
- testssl.sh vulnerability probes (malformed handshakes),
- openSquat's port check and dnstwist's lookalike probes (both connect to suspect domains),
- SpiderFoot use cases other than passive.
The STARTTLS test on your mail servers is light-touch and also off by default.

SpiderFoot: `docker compose --env-file docker/versions.env --profile spiderfoot up -d`. Its own UI on 127.0.0.1:5001
has no login and can run active modules; use it for viewing only.

Results gain a **Changes** tab (and a "What changed" panel on Overview): new/removed hosts, ports opened/closed,
new/resolved findings and the RAG movement against any earlier scan of the same domain.

## Security posture

- Bound to `127.0.0.1` only. Requests are rejected unless the Host header is `localhost` or `127.0.0.1` (this blocks DNS rebinding), and a cross-site Origin is rejected.
- Login uses a one-time access token, then an `HttpOnly`, `SameSite=Strict` session cookie. Every write needs a CSRF token.
- Strict Content-Security-Policy with no inline script or style. React escapes all scan-derived text.
- API keys are encrypted at rest and never returned by the API or written to logs.
- The container runs as a non-root user with all Linux capabilities dropped and `no-new-privileges`. The root filesystem is writable in v1, because BBOT and ZAP keep state in their home folder.
- The image contains no port scanner, fuzzer or vulnerability scanner. The command allowlist rejects them anyway, along with forbidden BBOT modules and presets, ZAP daemon/API mode, and any file path outside the run folder.

## Pinning versions

`docker/versions.env` pins ZAP, geckodriver and Typst. BBOT, dnstwist, uro and the Go tools default to the latest version at build time. After your first good build, run `make versions` and pin what you got. Set `ZAP_SHA256` to the checksum printed in the build log, so future builds verify the download.

## Tests

```bash
cd backend && pip install -r requirements.txt pytest && python3 -m pytest -q
```
