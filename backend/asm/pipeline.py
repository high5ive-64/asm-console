"""The light-touch scan pipeline (stages 1-10), run after scope and authorisation are confirmed.

Each stage reads only the scope snapshot written when the scan starts, runs allowlisted tools
through the Runner, parses their output into assets/findings rows, and returns a summary.
Third-party-hosted names (CNAME to a SaaS/CDN) and names with no DNS get DNS-level takeover
checks only; nothing else touches them.
"""
from __future__ import annotations

import ast
import asyncio
import json
import re
import shutil
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import yaml

from .allowlist import ACTIVE_BBOT_FLAGS, ACTIVE_BBOT_MODULES, FORBIDDEN_BBOT_MODULES, NEVER_BBOT_MODULES
from .db import DB, now
from .discovery import BBOT_EXCLUDE_FLAGS, Providers, _write_bbot_config, parse_bbot_events
from .runner import ZAP_GATES, ZAP_PROGRESS, ACTIVE, Runner, StageCancelled, StageFailed
from .scope import host_of, is_public_ip
from .secrets_store import SecretStore
from .settings_model import Settings

# baddns (takeover checks) runs only in the DNS-only pass: those are the CNAME-to-third-party and
# non-resolving names where takeovers happen. In the light pass it queued every name found in page
# content (600+) and took hours at its fixed 8-at-a-time rate.
LIGHT_MODULES = ["http", "sslcert", "robots", "securitytxt"]
# gowitness (headless-browser screenshots) is the slow tail of the light pass. It runs in its own
# `screenshots` stage, in parallel with ZAP, so it no longer blocks the critical path.
SCREENSHOT_MODULES = ["http", "gowitness"]
# JS single-page-app frameworks: the only hosts where ZAP's headless AJAX spider earns its (slow) time.
SPA_TECH = {"react", "angular", "angularjs", "vue", "vue.js", "nuxt", "nuxt.js", "next.js", "svelte",
            "sveltekit", "ember", "ember.js", "backbone", "backbone.js", "preact", "gatsby", "remix",
            "solidjs", "alpine", "alpine.js"}
# Modules enabled by the opt-in "BBOT active modules" switch: active enumeration, content discovery and
# vulnerability checks. Credential brute-forcers and data-pull modules are deliberately absent and are blocked
# by the allowlist regardless; port scanning is left to the gated naabu stage.
# BBOT 3.0 module names. 3.0 removed several 2.x modules (smuggler, wpscan, wappalyzer, ...) and renamed
# others (ffuf_shortnames -> webbrute_shortnames, which is a brute-forcer and stays in the NEVER tier), so
# this list sticks to active vuln/probe modules that exist in 3.0 and are not brute-forcers. lightfuzz is
# 3.0's consolidated active web fuzzer (XSS/SQLi/SSTI/path-traversal/etc.). Any name this specific BBOT
# build does not have is dropped by the dry-run self-heal below rather than failing the stage.
ACTIVE_PASS_MODULES = ["nuclei", "lightfuzz", "telerik", "ajaxpro", "generic_ssrf", "host_header",
                       "url_manipulation", "iis_shortnames", "bypass403", "fingerprintx",
                       "reflected_parameters", "dnsbrute",
                       # BBOT 3.x "safe" active checks (high value for external ASM, not brute-forcers):
                       "badsecrets",   # weak/known framework secrets — JWT, ASP.NET ViewState, signed cookies
                       "git",          # exposed .git directory (source-code leak)
                       "hunt",         # commonly-exploitable HTTP parameters (feeds lightfuzz targeting)
                       "ntlm"]         # internet-facing NTLM auth endpoints (internal hostname disclosure)
# (secrets exposed in HTTP responses are already extracted by BBOT's internal `excavate` module.)
DNS_ONLY_MODULES = ["baddns"]
GECKODRIVER = "/usr/local/bin/geckodriver"
ZAP_JOB_TYPES = {"spider", "spiderAjax", "passiveScan-wait", "report"}
ZAP_ACTIVE_JOB_TYPES = ZAP_JOB_TYPES | {"activeScan"}   # only when the ZAP active-scan switch is on
RISKY_PORTS = {
    3389: ("high", "RDP"), 445: ("high", "SMB"), 139: ("high", "NetBIOS/SMB"), 135: ("high", "MS RPC"),
    23: ("high", "Telnet"), 2375: ("high", "Docker API (unauthenticated)"), 6379: ("high", "Redis"),
    9200: ("high", "Elasticsearch"), 27017: ("high", "MongoDB"), 11211: ("high", "Memcached"),
    5900: ("high", "VNC"), 1433: ("high", "MSSQL"), 1521: ("high", "Oracle DB"), 3306: ("high", "MySQL"),
    5432: ("high", "PostgreSQL"), 5985: ("high", "WinRM"), 21: ("medium", "FTP"), 22: ("medium", "SSH"),
    25: ("low", "SMTP"), 110: ("medium", "POP3"), 143: ("medium", "IMAP"), 8443: ("low", "Alternate HTTPS / admin portal"),
}
INTERESTING_URL = re.compile(
    r"/api/|/v[0-9]+/|/admin|/internal|/graphql|swagger|openapi|api-docs|actuator|/debug|/console|phpinfo|"
    r"\.env($|[?/])|\.git/|\.bak($|\?)|\.sql($|\?)|\.zip($|\?)|\.log($|\?)|backup|wp-admin|jenkins|kibana|grafana|/server-status",
    re.I)


@dataclass
class StageDef:
    key: str
    title: str
    traffic: str          # none | dns | light | active (opt-in only)
    description: str
    default: bool = True
    service: str = ""     # what it costs: free / free key / paid


STAGES: list[StageDef] = [
    StageDef("bbot_light", "Live hosts and takeover checks", "light",
             "BBOT visits each in-scope host with ordinary requests: which hosts are live, technologies, TLS "
             "certificates, robots.txt and security.txt. Third-party-hosted and non-resolving names get "
             "DNS-only dangling-record / takeover checks. Screenshots run in their own stage so they no longer "
             "hold up the web scan.", service="Free, open source"),
    StageDef("screenshots", "Screenshots (gowitness)", "light",
             "Headless-browser screenshots of every live web host. Runs in parallel with the ZAP web scan so it no "
             "longer sits on the critical path.", service="Free, open source"),
    StageDef("reenrich", "Re-enrich late discoveries", "light",
             "Probes in-scope hosts that other sources (historical URLs, certificate SANs, DNS, ZAP) surfaced but the "
             "first pass never added — liveness, technologies, TLS, screenshots — so they flow into the CVE, port, "
             "takeover and DNS checks. Strictly in-scope and bounded.", service="Free, open source"),
    StageDef("tech", "Technology fingerprints (Wappalyzer rules)", "light",
             "Fetches the front page of each live host once and matches it against the open-source Wappalyzer "
             "fingerprints (community fork): frameworks, CMSs, servers and their versions. Versions feed the "
             "known-exploited vulnerability check.", service="Free, open source"),
    StageDef("dns", "DNS record snapshot (dnsx)", "dns",
             "Every A, AAAA, CNAME, MX, NS, TXT and CAA record for every host, saved each scan so DNS changes show up "
             "in Changes. Flags public names that resolve to private addresses.", service="Free, open source"),
    StageDef("cdn", "CDN, WAF and cloud classification", "none",
             "cdncheck matches every resolved IP against the published ranges of CDNs, WAFs and cloud providers (built "
             "into the tool, nothing is sent). Corrects which IPs are really yours before ports and CVEs are checked.",
             service="Free, open source (offline)"),
    StageDef("takeover", "Subdomain takeover (dnsReaper)", "dns",
             "dnsReaper checks every name against 50+ takeover signatures using DNS lookups only. With a read-only "
             "Cloudflare token saved, it also checks every record in your zones.", service="Free, open source"),
    StageDef("tls", "TLS and certificates", "light",
             "One TLS handshake per host: expired, expiring, self-signed and mismatched certificates, legacy protocols.",
             service="Free, open source"),
    StageDef("tls_deep", "Deep TLS review (testssl.sh)", "light",
             "testssl.sh on a handful of key hosts (5 by default): protocols, cipher strength, certificate chain, HSTS "
             "and security headers. Vulnerability probes are off unless you switch them on below.",
             service="Free, open source"),
    StageDef("zap", "Web hygiene (ZAP passive)", "light",
             "ZAP spiders live web hosts and applies passive rules only: security headers, cookie flags, "
             "vulnerable JS libraries, information leaks. No attack payloads.", service="Free, open source"),
    StageDef("ports", "Exposed services", "none",
             "Open ports from Shodan's InternetDB for in-scope IPs. No packets are sent to your hosts.",
             service="Free, no key"),
    StageDef("port_check", "Confirm open ports (naabu, active)", "active",
             "OFF BY DEFAULT. Plain TCP connect checks from this machine to your own non-CDN IPs, on the ports Shodan "
             "reports plus the 100 most common, at ~100 packets/second. Confirms what's really open and what Shodan "
             "lists that has since closed. This is port scanning: only turn it on if your authorisation covers it.",
             default=False, service="Free, open source"),
    StageDef("cloudlist", "Cloud inventory (cloudlist)", "none",
             "Assets listed straight from your cloud accounts: public IPs and DNS names that discovery can't see. Uses an "
             "uploaded cloudlist export or read-only keys from Settings; skipped if neither is there.",
             service="Free tool · needs your cloud export or read-only keys"),
    StageDef("cloud", "Extra public IPs", "none",
             "Exposure of public IPs from cloudlist and any you paste below (cloud, ISP or NAT addresses DNS doesn't "
             "reveal). Skipped if there are none.", service="Free, no key"),
    StageDef("feeds", "Exposure feeds (LeakIX, Netlas)", "none",
             "Exposed services, leaks and hosts that internet-wide scanners have already seen on your domains. Needs a "
             "free LeakIX and/or Netlas key; Netlas is capped at a few requests per scan to fit the free quota.",
             service="Free keys (daily quotas) · paid tiers available"),
    StageDef("intel", "Known-exploited vulnerabilities (KEV, EPSS)", "none",
             "CVEs that Shodan (InternetDB, plus host lookups with a free key) and Netlas associate with your IPs, ranked "
             "by CISA's Known Exploited Vulnerabilities list and FIRST's EPSS score. Version-banner matches: leads to "
             "verify, not confirmed vulnerabilities.", service="Free, no key (Shodan key optional)"),
    StageDef("email", "Email security (checkdmarc)", "dns",
             "SPF (including the 10-lookup limit), DMARC policy, subdomain policy and reporting, MTA-STS, TLS-RPT and "
             "BIMI for each root domain.", service="Free, open source"),
    StageDef("gau", "Historical URLs", "none",
             "Archived URLs from the Wayback Machine, Common Crawl, OTX and URLScan, filtered to scope.",
             service="Free, no key"),
    StageDef("lookalikes", "Lookalike domains", "dns", "Registered typo and homoglyph variants of each root domain.",
             service="Free, open source"),
    StageDef("squat", "Newly registered lookalikes (openSquat)", "none",
             "Today's newly registered domains (openSquat's free community feed) that contain your brand name. Nothing "
             "is sent to the suspect domains unless you turn on the port check.",
             service="Free community feed · premium feed is paid"),
    StageDef("urlscan", "Seen in the wild (urlscan.io)", "none",
             "Searches urlscan.io for pages already scanned on your domains and on the lookalikes found above (a live "
             "lookalike page is a phishing signal). Search only; never submits anything.",
             service="Free (a free key raises the rate limit)"),
    StageDef("hibp", "Breach exposure (XposedOrNot, HIBP)", "none",
             "Known data breaches per domain from XposedOrNot (free, no key). With a free XposedOrNot domain key or a "
             "paid HIBP key (domain verified), also reports per-domain account exposure.",
             service="Free (XposedOrNot) · HIBP paid"),
    StageDef("spiderfoot", "SpiderFoot (passive sidecar)", "none",
             "Runs SpiderFoot's passive modules in the optional sidecar container and imports new hosts, leak-site "
             "mentions and threat-feed hits. Start the sidecar first: docker compose --profile spiderfoot up -d.",
             default=False, service="Free, open source (self-hosted)"),
    StageDef("consolidate", "Consolidate", "none", "Combines everything into metrics, assets and findings."),
]
STAGE_KEYS = [s.key for s in STAGES]


class StageSkip(Exception):
    pass


@dataclass
class Ctx:
    state: Any
    scan_id: str
    run_dir: Path
    runner: Runner
    providers: Any
    settings: Settings
    options: dict
    roots: list[str]
    light_hosts: list[str]
    dns_hosts: list[str]
    exclusions: list[str]
    secrets: dict[str, str]
    use_bbot: bool = True
    reuse_output: bool = False
    results: dict = field(default_factory=dict)

    @property
    def all_hosts(self) -> set[str]:
        return set(self.light_hosts) | set(self.dns_hosts)

    def db(self) -> DB:
        return self.state.db()

    def timeout(self, stage: str, default: int) -> int:
        return int(self.settings.stage_timeout_minutes.get(stage, default)) * 60

    def file(self, rel: str) -> Path:
        p = self.run_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


# ---- scope snapshot ------------------------------------------------------------

def snapshot_scope(db: DB, scan_id: str, run_dir: Path) -> dict:
    scan = db.one("SELECT root_domain FROM scans WHERE id = ?", scan_id)
    rows = db.all("SELECT value, kind, grp, decision, third_party FROM scope_items WHERE scan_id = ?", scan_id)
    roots = [scan["root_domain"]] + sorted(r["value"] for r in rows
                                           if r["kind"] == "related" and r["decision"] == "included" and not r["third_party"])
    light, dns_only, excl = set(roots), set(), set()
    for r in rows:
        v = r["value"]
        if r["kind"] == "exclusion" or (r["kind"] == "subdomain" and r["decision"] == "excluded"):
            excl.add(v)
        elif r["kind"] == "subdomain" and r["decision"] == "included" and not v.startswith("*."):
            (dns_only if r["grp"] in ("third_party", "no_dns") else light).add(v)
    light -= excl
    dns_only -= excl | light
    snap = {"roots": roots, "light_hosts": sorted(light), "dns_hosts": sorted(dns_only), "exclusions": sorted(excl)}
    (run_dir / "scope").mkdir(parents=True, exist_ok=True)
    for name, items in (("roots.txt", roots), ("hosts_light.txt", snap["light_hosts"]),
                        ("hosts_dnsonly.txt", snap["dns_hosts"]), ("blacklist.txt", snap["exclusions"])):
        (run_dir / "scope" / name).write_text("\n".join(items) + ("\n" if items else ""))
    (run_dir / "scope" / "snapshot.json").write_text(json.dumps(snap, indent=2))
    return snap


# ---- helpers ------------------------------------------------------------------------

def status_rank(code: int | None) -> int:
    """Which root responses are worth a crawler's time: content first, then login prompts, then redirects."""
    if code is None:
        return 5
    if code == 204:
        return 9      # "No Content": nothing to crawl
    if 200 <= code < 300:
        return 0
    if code == 401:
        return 1
    if 300 <= code < 400:
        return 2
    return 9          # 403 / 404 / 405 / 5xx: a bucket, CDN default or dead end; nothing to crawl


def _upsert_asset(db: DB, scan_id: str, host: str, **fields) -> None:
    row = db.one("SELECT * FROM assets WHERE scan_id = ? AND host = ?", scan_id, host)
    if not row:
        db.run("INSERT INTO assets (scan_id, host) VALUES (?, ?)", scan_id, host)
        row = db.one("SELECT * FROM assets WHERE scan_id = ? AND host = ?", scan_id, host)
    sets, args = [], []
    for k, v in fields.items():
        if k in ("ips", "tech", "ports", "found_by"):
            merged = sorted(set(json.loads(row[k])) | set(v), key=str)
            sets.append(f"{k} = ?"); args.append(json.dumps(merged))
        elif k in ("tls", "edge"):
            sets.append(f"{k} = ?"); args.append(json.dumps(v))
        elif k == "cdn_exact":           # cdncheck's verdict replaces the tag-based guess
            sets.append("cdn = ?"); args.append(int(bool(v)))
        elif k in ("is_live", "cdn", "third_party", "in_cmdb"):
            sets.append(f"{k} = MAX({k}, ?)"); args.append(int(bool(v)))
        elif k == "http_status" and v:
            if row["http_status"] is None or status_rank(int(v)) < status_rank(int(row["http_status"])):
                sets.append("http_status = ?"); args.append(int(v))
        elif k == "web_url":
            if v and not _valid_web_url(v):
                continue
            if v and (not row["web_url"] or (v.startswith("https://") and not row["web_url"].startswith("https://"))):
                sets.append("web_url = ?"); args.append(v)
    if sets:
        db.run(f"UPDATE assets SET {', '.join(sets)} WHERE scan_id = ? AND host = ?", *args, scan_id, host)


def _finding(db: DB, scan_id: str, area: str, severity: str, title: str, host: str | None, tool: str,
             evidence: str | None = None, efile: str | None = None) -> None:
    db.run("INSERT INTO findings (scan_id, area, severity, title, host, source_tool, evidence_ref, evidence_file) "
           "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
           scan_id, area, severity, title[:500], host, tool, evidence, efile)


def _clear(db: DB, scan_id: str, tool_prefix: str) -> None:
    db.run("DELETE FROM findings WHERE scan_id = ? AND source_tool LIKE ?", scan_id, tool_prefix + "%")


def _sev(raw: str | None) -> str:
    r = (raw or "").lower()
    for s in ("critical", "high", "medium", "low"):
        if r.startswith(s):
            return s
    return "info"


def _rotate(path: Path) -> None:
    if path.exists():
        path.rename(path.with_name(path.name + ".prev." + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")))


# ---- stage 1: BBOT light-touch ------------------------------------------------------

# A BBOT pass that produces no new events for this long is treated as wedged and reaped (results kept).
# Long enough to sit through a single slow request/OOB wait, short enough that a true hang costs minutes.
BBOT_IDLE_TIMEOUT_S = 180


def _bbot_progress_line(line: str) -> bool:
    """False for BBOT's idle heartbeat lines, so a pass that only emits them is seen as making no progress.
    When a module is genuinely working, events complete ('N processed' with N>0) or other lines appear,
    which reset the idle watchdog; a wedged module prints only these three with no forward motion."""
    if "No events in queue (0 processed" in line:        # nothing completed in the last interval
        return False
    if "Modules running (" in line:                      # per-module status tally
        return False
    if "Events produced so far:" in line:                # cumulative tally (unchanged while wedged)
        return False
    return True


async def _bbot_pass(c: Ctx, name: str, hosts: list[str], modules: list[str], active: bool = False,
                     stage: str = "bbot_light") -> Path | None:
    if not hosts:
        return None
    existing = c.run_dir / "bbot" / name / "output.json"
    if c.reuse_output and existing.exists() and existing.stat().st_size:
        c.runner.event(stage, f"Re-reading the saved output of BBOT pass {name} (not re-scanning).")
        return existing
    tfile = c.file(f"scope/{name}_targets.txt")
    tfile.write_text("\n".join(hosts) + "\n")
    out_root = c.run_dir / "bbot"
    _rotate(out_root / name)

    def _build(mods: list[str]) -> list[str]:
        b = ["bbot", "-t", str(tfile)]
        if c.exclusions:
            b += ["-b", str(c.run_dir / "scope" / "blacklist.txt")]
        if active:
            # Active enumeration/vuln pass. The curated ACTIVE-tier modules are driven by -m only: no -f flag
            # selection, because -f active would pull in BBOT's entire active module set (brute-forcers and
            # all). portscan is excluded (the gated naabu stage owns port scanning) and the credential/content
            # brute-forcers are excluded by name as defence-in-depth should a dependency try to enable them —
            # the NEVER tier is blocked by the allowlist and the dry-run gate regardless.
            b += ["--strict-scope", "-m", *mods, "-em", "portscan", "webbrute", "webbrute_shortnames",
                  "-om", "json", "asset_inventory", "-o", str(out_root), "-n", name,
                  "-y", "--force", "--no-deps", "--no-color"]
        else:
            b += ["--strict-scope", "-m", *mods, "-ef", *BBOT_EXCLUDE_FLAGS, "-em", "portscan",
                  "-om", "json", "asset_inventory", "-o", str(out_root), "-n", name,
                  "-y", "--force", "--no-deps", "--no-color"]
        return b

    log = c.run_dir / "logs" / f"{stage}.log"

    async def _dry(mods: list[str]) -> tuple[str, str]:
        start = log.stat().st_size if log.exists() else 0
        await c.runner.run(stage, _build(mods) + ["--dry-run"], 300, allow_active=active,
                           line_filter=lambda l: "Loaded" in l or "[ERRR]" in l or "[CRIT]" in l)
        # start is a byte offset: slice bytes, then decode (earlier runs may have left multi-byte characters)
        txt = log.read_bytes()[start:].decode("utf-8", errors="replace") if log.exists() else ""
        ld = " ".join(l for l in txt.splitlines() if "Loaded" in l and "modules" in l)
        return txt, ld

    # Dry run first: confirm the exact module list BBOT will load contains nothing forbidden.
    # Module names drift between BBOT versions (2.x -> 3.0 renamed and removed many), and a single
    # unknown name makes BBOT refuse to start. So drop any module BBOT reports as unknown and retry,
    # looping until the list loads or nothing is left — the pass runs with whatever modules this BBOT
    # build actually has instead of failing the whole stage on one stale name.
    cur = list(modules)
    dropped: list[str] = []
    text, loaded = await _dry(cur)
    for _ in range(len(modules) + 1):
        if "scan modules" in loaded:
            break
        unknown = re.findall(r'[Cc]ould not find scan module "([^"]+)"', text)
        if not unknown:
            break
        cur = [m for m in cur if m not in unknown]
        dropped += unknown
        if not cur:
            break
        text, loaded = await _dry(cur)
    if dropped:
        c.runner.event(stage, f"This BBOT build does not have module(s) {', '.join(sorted(set(dropped)))}; "
                              f"skipping them and continuing with the rest.", "warn")
    if "scan modules" not in loaded:
        if dropped and not cur:
            c.runner.event(stage, "None of the requested modules are available in this BBOT build; "
                                  "skipping this pass.", "warn")
            return None
        errs = [l.strip() for l in text.splitlines() if "[ERRR]" in l or "[CRIT]" in l]
        raise StageFailed("BBOT would not start: " + (errs[0] if errs else "no modules loaded in the dry run"))
    modules = cur
    base = _build(modules)
    forbidden = NEVER_BBOT_MODULES if active else FORBIDDEN_BBOT_MODULES
    bad = sorted(m for m in forbidden if re.search(rf"[(,\s]{re.escape(m)}[,)\s]", loaded))
    if bad:
        raise StageFailed(f"dry run would load forbidden modules: {', '.join(bad)}")
    # The active pass can wedge on a single slow module (e.g. generic_ssrf waiting out OOB callbacks
    # against dead ports), so cap it tighter than the passive passes — a hung module reaps quickly and
    # the results gathered so far are kept. Both honour a settings override on the bbot_light stage.
    # The idle watchdog is the snappy path: a pass that stops producing events for BBOT_IDLE_TIMEOUT_S
    # is reaped (results kept) long before the outer budget, so a hang costs minutes, not the full clock.
    budget = c.timeout(stage, 30 if active else 90)
    try:
        rc = await c.runner.run(stage, base, budget, allow_active=active,
                                idle_timeout_s=BBOT_IDLE_TIMEOUT_S, is_progress=_bbot_progress_line,
                                line_filter=lambda l: any(t in l for t in ("[INFO]", "[WARN]", "[ERRR]", "[SUCC]", "[FINDING]", "[VULN")))
    except StageFailed as exc:
        if str(exc) != "timeout":
            raise
        # BBOT writes output.json as it goes: keep what it found rather than losing the whole pass
        # (the runner already logged why it stopped — idle watchdog or the outer time budget).
        c.runner.event(stage, f"BBOT pass {name} stopped early; keeping the results gathered so far.", "warn")
        return out_root / name / "output.json"
    out = out_root / name / "output.json"
    if rc != 0:
        c.runner.event(stage, f"BBOT pass {name} exited with code {rc}", "warn")
    if not out.exists():
        raise StageFailed(f"BBOT pass {name} produced no output (exit code {rc}); see the log")
    return out


def ev_data(ev: dict):
    """BBOT 3 puts plain values in "data" and structured ones (URL, TECHNOLOGY, FINDING...) in "data_json"."""
    d = ev.get("data_json")
    if d is None:
        d = ev.get("data")
    if isinstance(d, str) and d[:1] in "{[":
        try:
            return json.loads(d)
        except json.JSONDecodeError:
            try:
                return ast.literal_eval(d)
            except (ValueError, SyntaxError):
                return d
    return d


def _valid_web_url(u: str | None) -> bool:
    try:
        p = urllib.parse.urlsplit(u or "")
        return p.scheme in ("http", "https") and bool(p.hostname)
    except ValueError:
        return False


def ev_url(ev: dict) -> str | None:
    d = ev_data(ev)
    url = d.get("url") if isinstance(d, dict) else d
    if not isinstance(url, str):
        return None
    p = urllib.parse.urlsplit(url)
    return url if p.scheme in ("http", "https") and p.hostname else None


SCREENSHOT_EXT = (".png", ".jpg", ".jpeg", ".webp")
# Hosts behind a CDN / WAF edge: their IPs belong to the provider, so open ports there are the provider's, not yours
EDGE_TAGS = {"cdn", "cdn-cloudflare", "cloudflare", "cloudfront", "akamai", "fastly", "imperva", "incapsula", "sucuri", "waf"}
# ASN owners that are shared cloud/hosting/CDN providers: a netblock here is the provider's, not the org's own range.
SHARED_ASN_WORDS = ("amazon", "aws", "cloudflare", "google", "microsoft", "azure", "akamai", "fastly", "oracle",
                    "digitalocean", "linode", "ovh", "hetzner", "gcore", "incapsula", "imperva", "sucuri", "vercel",
                    "netlify", "heroku", "github", "salesforce", "fastly", "cloudfront", "edgecast", "stackpath",
                    "automattic", "squarespace", "shopify", "zscaler", "limelight", "level3", "cogent", "hosting")


def asn_kind(name: str, desc: str) -> str:
    """'shared' if the ASN belongs to a cloud/CDN/hosting provider, else 'own' (worth checking as org-owned)."""
    blob = f"{name} {desc}".lower()
    return "shared" if any(w in blob for w in SHARED_ASN_WORDS) else "own"


async def st_bbot_light(c: Ctx) -> dict:
    if not c.use_bbot:
        raise StageSkip("BBOT disabled")
    light_mods = list(LIGHT_MODULES)
    if c.options.get("asn_lookup", True):
        light_mods.append("asn")        # passive: maps resolved IPs to their ASN and netblock from public data
    a = await _bbot_pass(c, "light", c.light_hosts, light_mods)
    b = await _bbot_pass(c, "dnsonly", c.dns_hosts, DNS_ONLY_MODULES)
    passes = [a, b]
    if c.options.get("bbot_active") and c.light_hosts:
        c.runner.event("bbot_light", "ACTIVE scanning is ON: BBOT will send fuzzing, vulnerability-probe and "
                       "exposure-check traffic (nuclei, lightfuzz, telerik, SSRF/host-header probes, and secret / "
                       ".git / NTLM exposure checks) to your hosts. Credential brute-force and data-download modules "
                       "stay disabled. Only with authorisation for active testing.", "warn")
        e = await _bbot_pass(c, "active", c.light_hosts[:int(c.options.get("bbot_active_max_hosts", 150))],
                             ACTIVE_PASS_MODULES, active=True)
        passes.append(e)
    hosts = c.all_hosts
    live: dict[str, str] = {}
    counts = {"live_hosts": 0, "findings": 0, "technologies": 0, "netblocks": 0, "own_netblocks": 0}
    urls: set[str] = set()
    seen_asn: set[str] = set()
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "bbot:")
            for out in passes:
                rel = str(out.relative_to(c.run_dir)) if out else None   # the exact artifact this pass's findings came from
                for ev in parse_bbot_events(out) if out else []:
                    t = ev.get("type")
                    host = (ev.get("host") or "").lower()
                    if t == "DNS_NAME":
                        host = str(ev_data(ev) or "").lower()
                    if t == "ASN":
                        d = ev_data(ev)
                        d = d if isinstance(d, dict) else {"subnet": str(d or "")}
                        subnet = str(d.get("subnet") or d.get("cidr") or d.get("netblock") or "").strip()
                        asn = str(d.get("asn") or d.get("number") or "").lstrip("AS")
                        name = str(d.get("name") or d.get("organization") or "")
                        desc = str(d.get("description") or d.get("org") or "")
                        if not subnet or subnet in seen_asn:
                            continue
                        seen_asn.add(subnet)
                        kind = asn_kind(name, desc)
                        counts["netblocks"] += 1
                        counts["own_netblocks"] += int(kind == "own")
                        label = (name or desc or "unknown").strip()[:80]
                        title = (f"Netblock worth checking as org-owned: {subnet} (AS{asn} {label})" if kind == "own"
                                 else f"Netblock on a shared platform: {subnet} (AS{asn} {label})")
                        _finding(db, c.scan_id, "surface", "low" if kind == "own" else "info", title,
                                 subnet, "asn", (desc or name or None), efile=rel)
                        continue
                    if host not in hosts:
                        continue
                    tags = ev.get("tags") or []
                    if t == "DNS_NAME":
                        rh = ev.get("resolved_hosts") or []
                        if isinstance(rh, str):
                            rh = ev_data({"data": rh}) if rh.startswith("[") else [rh]
                        ips = [ip for ip in rh if isinstance(ip, str) and is_public_ip(ip)]
                        _upsert_asset(db, c.scan_id, host, ips=ips, cdn=bool(EDGE_TAGS & {str(x) for x in tags}),
                                      third_party=host in c.dns_hosts)
                    elif t == "URL":
                        url = ev_url(ev)
                        if not url:
                            continue
                        urls.add(url)
                        p = urllib.parse.urlsplit(url)
                        base = f"{p.scheme}://{p.netloc}"
                        if host in c.light_hosts:
                            live.setdefault(host, base)
                            if p.scheme == "https":
                                live[host] = base
                        code = next((int(t[7:]) for t in tags if str(t).startswith("status-") and str(t)[7:].isdigit()), None)
                        if p.path in ("", "/"):
                            _upsert_asset(db, c.scan_id, host, is_live=True, web_url=base, http_status=code)
                        else:
                            _upsert_asset(db, c.scan_id, host, is_live=True, web_url=base)
                    elif t == "TECHNOLOGY":
                        d = ev_data(ev)
                        tech = d.get("technology") if isinstance(d, dict) else None
                        if tech:
                            _upsert_asset(db, c.scan_id, host, tech=[str(tech)]); counts["technologies"] += 1
                    elif t == "OPEN_TCP_PORT" and ev.get("module") != "speculate":   # speculate just assumes 80/443
                        port = str(ev_data(ev) or "").rsplit(":", 1)[-1]
                        if port.isdigit():
                            _upsert_asset(db, c.scan_id, host, ports=[int(port)])
                    elif t in ("FINDING", "VULNERABILITY"):
                        d = ev_data(ev)
                        d = d if isinstance(d, dict) else {"description": str(d or "")}
                        desc = d.get("description") or json.dumps(d)[:300]
                        mod = ev.get("module", "bbot")
                        area = "exposure" if "baddns" in mod or "takeover" in desc.lower() else "web"
                        if d.get("severity"):        # BBOT 3 rates its own findings
                            sev = _sev(d.get("severity"))
                        else:
                            sev = "high" if "takeover" in desc.lower() else "info"
                        _finding(db, c.scan_id, area, sev, desc, host, f"bbot:{mod}", d.get("url"), efile=rel)
                        counts["findings"] += 1
    finally:
        db.close()
    shots = [f for f in (c.run_dir / "bbot" / "light").rglob("*") if f.suffix.lower() in SCREENSHOT_EXT] if a else []
    c.results["web_bases"] = live
    counts.update(live_hosts=len(live), web_endpoints=len(urls), screenshots=len(shots))
    return counts


async def st_screenshots(c: Ctx) -> dict:
    """gowitness screenshots of the live web hosts, split out of bbot_light so it runs alongside ZAP
    instead of holding it up. Best-effort: a screenshot failure never fails the scan."""
    if not c.use_bbot:
        raise StageSkip("BBOT disabled")
    hosts = list(c.results.get("web_bases", {}))
    if not hosts:
        db = c.db()
        try:
            hosts = [r["host"] for r in db.all(
                "SELECT host FROM assets WHERE scan_id = ? AND is_live = 1 AND web_url IS NOT NULL AND web_url != ''",
                c.scan_id)]
        finally:
            db.close()
    if not hosts:
        return {"screenshots": 0, "hosts": 0, "note": "no live web hosts"}
    try:
        await _bbot_pass(c, "shots", hosts, SCREENSHOT_MODULES, stage="screenshots")
    except StageFailed as exc:
        c.runner.event("screenshots", f"Screenshot pass stopped early; keeping any shots taken: {exc}", "warn")
    shots_dir = c.run_dir / "bbot" / "shots"
    shots = [f for f in shots_dir.rglob("*") if f.suffix.lower() in SCREENSHOT_EXT] if shots_dir.exists() else []
    return {"screenshots": len(shots), "hosts": len(hosts)}


def _new_inscope_hosts(c: Ctx, cap: int = 300) -> list[str]:
    """In-scope hostnames some source has seen that are not yet assets — the late discovery the single
    pass missed: gau historical URLs, certificate SANs, resolved DNS and the ZAP crawl. Strictly in
    scope (a root or a subdomain of one); third-party names a crawl links to are never included."""
    roots = [r.lower() for r in (c.roots or [])]
    def inscope(h: str) -> bool:
        return any(h == r or h.endswith("." + r) for r in roots)
    db = c.db()
    try:
        assets = {r["host"].lower() for r in db.all("SELECT host FROM assets WHERE scan_id = ?", c.scan_id)}
        cand = {r["host"].lower() for r in db.all("SELECT DISTINCT host FROM dns_records WHERE scan_id = ?", c.scan_id)}
    finally:
        db.close()
    for rel in ("urls/historical.txt", "urls/gau_inscope.txt", "urls/interesting.txt"):
        p = c.run_dir / rel
        if p.exists():
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    h = (urllib.parse.urlsplit(line.strip()).hostname or "").lower()
                    if h:
                        cand.add(h)
            except Exception:
                pass
    tlsx = c.run_dir / "tls" / "tlsx.json"
    if tlsx.exists():
        try:
            for line in tlsx.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                for s in (rec.get("subject_an") or []):
                    s = str(s).lstrip("*.").strip().lower()
                    if s:
                        cand.add(s)
        except Exception:
            pass
    zp = c.run_dir / "zap" / "zap-estate.json"
    if zp.exists():
        try:
            z = json.loads(zp.read_text(encoding="utf-8", errors="replace"))
            for site in (z.get("site") or []):
                h = (urllib.parse.urlsplit(site.get("@name", "")).hostname or site.get("@host", "")).lower()
                if h:
                    cand.add(h)
        except Exception:
            pass
    return sorted(h for h in cand if h and inscope(h) and h not in assets)[:cap]


async def st_reenrich(c: Ctx) -> dict:
    """Close the discovery loop: probe and enrich in-scope hosts that later sources surfaced but the
    first pass never added (liveness, technologies, TLS, screenshots), so they flow into the CVE, port,
    takeover and DNS checks downstream. Bounded and strictly in-scope; best-effort — never fails the scan."""
    if not c.use_bbot:
        raise StageSkip("BBOT disabled")
    new_hosts = _new_inscope_hosts(c)
    if not new_hosts:
        return {"candidates": 0, "added_live": 0}
    c.runner.event("reenrich", f"{len(new_hosts)} in-scope host(s) that other sources found weren't probed yet; "
                               "checking which are live and enriching them.")
    out = c.run_dir / "bbot" / "reenrich" / "output.json"
    try:
        out = await _bbot_pass(c, "reenrich", new_hosts, LIGHT_MODULES + ["gowitness"], stage="reenrich") or out
    except StageFailed as exc:
        c.runner.event("reenrich", f"Re-enrichment probe stopped early; keeping what it found: {exc}", "warn")
    newset = set(new_hosts)
    live = 0
    resolved: set[str] = set()      # hosts that actually resolve / answer — the only ones we persist as assets
    db = c.db()
    try:
        rel = str(out.relative_to(c.run_dir)) if out and out.exists() else None
        with db.tx():
            for ev in (parse_bbot_events(out) if out and out.exists() else []):
                t = ev.get("type")
                host = (ev.get("host") or "").lower()
                if t == "DNS_NAME":
                    host = str(ev_data(ev) or "").lower()
                if host not in newset:
                    continue
                tags = ev.get("tags") or []
                if t == "DNS_NAME":
                    rh = ev.get("resolved_hosts") or []
                    if isinstance(rh, str):
                        rh = ev_data({"data": rh}) if rh.startswith("[") else [rh]
                    ips = [ip for ip in rh if isinstance(ip, str) and is_public_ip(ip)]
                    if ips:     # resolves to a real address -> a live-surface asset; a dead name is handled below
                        resolved.add(host)
                        _upsert_asset(db, c.scan_id, host, ips=ips, cdn=bool(EDGE_TAGS & {str(x) for x in tags}))
                elif t == "URL":
                    url = ev_url(ev)
                    if not url:
                        continue
                    p = urllib.parse.urlsplit(url)
                    base = f"{p.scheme}://{p.netloc}"
                    code = next((int(x[7:]) for x in tags if str(x).startswith("status-") and str(x)[7:].isdigit()), None)
                    resolved.add(host)
                    if p.path in ("", "/"):
                        _upsert_asset(db, c.scan_id, host, is_live=True, web_url=base, http_status=code)
                        live += 1
                    else:
                        _upsert_asset(db, c.scan_id, host, is_live=True, web_url=base)
                elif t == "TECHNOLOGY":
                    d = ev_data(ev)
                    tech = d.get("technology") if isinstance(d, dict) else None
                    if tech:
                        _upsert_asset(db, c.scan_id, host, tech=[str(tech)])
                elif t == "OPEN_TCP_PORT" and ev.get("module") != "speculate":
                    port = str(ev_data(ev) or "").rsplit(":", 1)[-1]
                    if port.isdigit():
                        _upsert_asset(db, c.scan_id, host, ports=[int(port)])
                elif t in ("FINDING", "VULNERABILITY"):
                    d = ev_data(ev)
                    d = d if isinstance(d, dict) else {"description": str(d or "")}
                    desc = d.get("description") or json.dumps(d)[:300]
                    mod = ev.get("module", "bbot")
                    sev = _sev(d.get("severity")) if d.get("severity") else "info"
                    _finding(db, c.scan_id, "web", sev, desc, host, f"bbot:{mod}", d.get("url"), efile=rel)
            dead = [h for h in new_hosts if h not in resolved]
            for h in dead:    # in-scope names seen only in history that no longer resolve — tracked, not counted as surface
                _finding(db, c.scan_id, "surface", "info",
                         "Historical subdomain, no longer resolves (historical/unresolved)",
                         h, "reenrich", "seen in historical URLs / certificate SANs; no current DNS record")
    finally:
        db.close()
    c.runner.event("reenrich", f"Re-enrichment: {len(resolved)} of {len(new_hosts)} candidate(s) still resolve "
                               f"({live} live web); {len(new_hosts) - len(resolved)} historical/unresolved.")
    return {"candidates": len(new_hosts), "added_live": live, "resolved": len(resolved),
            "historical": len(new_hosts) - len(resolved)}


async def run_baddns(c: Ctx, hosts: list[str], stage: str = "takeover") -> list[dict]:
    """Run BBOT's baddns over the given (live) hosts and return takeover findings.

    baddns sends only DNS lookups and a little HTTP metadata, so this is light-touch, not an active scan. It
    catches dangling records on *live* hosts that resolve to a third-party/SaaS target (e.g. a CNAME to
    sites.framer.app or *.herokuapp.com) — the class the default dnsonly pass and dnsReaper can miss.
    """
    if not c.use_bbot or not hosts:
        return []
    out = await _bbot_pass(c, "baddns", sorted(set(hosts)), DNS_ONLY_MODULES, stage=stage)
    rel = str(out.relative_to(c.run_dir)) if out else None
    found: list[dict] = []
    for ev in parse_bbot_events(out) if out else []:
        if ev.get("type") not in ("FINDING", "VULNERABILITY"):
            continue
        host = (ev.get("host") or "").lower()
        mod = ev.get("module", "")
        d = ev_data(ev)
        d = d if isinstance(d, dict) else {"description": str(d or "")}
        desc = d.get("description") or json.dumps(d)[:300]
        if "baddns" not in mod and "takeover" not in desc.lower() and "dangling" not in desc.lower():
            continue
        sev = _sev(d.get("severity")) if d.get("severity") else ("high" if "takeover" in desc.lower() else "medium")
        found.append({"host": host, "severity": sev, "title": desc[:400], "url": d.get("url"), "efile": rel})
    return found


# ---- stage 2: ZAP passive plan --------------------------------------------------------

ZAP_GROUP = {0: "content", 1: "login", 2: "redirect", 5: "unknown", 9: "dead end"}


def zap_candidates(db: DB, scan_id: str, light_hosts: list[str], roots: list[str], max_hosts: int,
                   selected: list[str] | None = None) -> dict:
    """Every host ZAP could scan, best first, with the default (recommended) pick and the current selection."""
    light = set(light_hosts)
    rows = db.all("SELECT host, web_url, http_status, tls FROM assets WHERE scan_id = ?", scan_id)
    live = {r["host"]: r["web_url"] for r in rows if r["host"] in light and r["web_url"]}
    from_tls = False
    if not live:
        # BBOT found nothing (failed or skipped): use hosts that completed a TLS handshake with a matching certificate
        for r in rows:
            t = json.loads(r["tls"] or "{}")
            if r["host"] in light and t and not t.get("mismatched"):
                live[r["host"]] = f"https://{r['host']}/"
        from_tls = bool(live)
    live = {h: u for h, u in live.items()
            if urllib.parse.urlsplit(u or "").scheme in ("http", "https") and urllib.parse.urlsplit(u).hostname}
    status = {r["host"]: r["http_status"] for r in rows}
    root_set = set(roots)
    order = sorted(live, key=lambda h: (h not in root_set, status_rank(status.get(h)), not h.startswith("www."), h))
    recommended = [h for h in order if h in root_set or status_rank(status.get(h)) != 9][:max_hosts]
    rec = set(recommended)
    chosen = [h for h in order if h in set(selected)] if selected is not None else recommended
    cs = set(chosen)
    items = []
    for h in order:
        rk = status_rank(status.get(h))
        items.append({"host": h, "url": live[h], "status": status.get(h), "group": ZAP_GROUP.get(rk, "unknown"),
                      "root": h in root_set, "recommended": h in rec, "selected": h in cs,
                      "note": ("answers " + str(status.get(h)) + " at the front page; usually nothing to crawl") if rk == 9 else None})
    return {"candidates": items, "selected": chosen, "recommended": recommended, "from_tls": from_tls,
            "dead_ends": sum(1 for h in order if h not in root_set and status_rank(status.get(h)) == 9)}


def zap_targets(c: Ctx) -> list[str]:
    db = c.db()
    try:
        info = zap_candidates(db, c.scan_id, c.light_hosts, c.roots, int(c.options.get("zap_max_hosts", 30)),
                              c.options.get("zap_selected"))
    finally:
        db.close()
    c.results["zap_from_tls"] = info["from_tls"]
    c.results["zap_skipped_dead"] = info["dead_ends"]
    url = {i["host"]: i["url"] for i in info["candidates"]}
    return [url[h] for h in info["selected"]]


ZAP_SPIDER_MAX_DEPTH = 5       # links followed from the start page
ZAP_SPIDER_MAX_CHILDREN = 25   # child links per node: keeps big marketing sites from exploding into tens of thousands of URLs


def _spa_hosts(c: Ctx) -> set[str]:
    """Hosts fingerprinted as JS single-page apps, where ZAP's headless AJAX spider is worth its time."""
    db = c.db()
    try:
        rows = db.all("SELECT host, tech FROM assets WHERE scan_id = ?", c.scan_id)
    finally:
        db.close()
    out: set[str] = set()
    for r in rows:
        for t in json.loads(r["tech"] or "[]"):
            if str(t).split(" ")[0].strip().lower() in SPA_TECH:
                out.add(r["host"]); break
    return out


def build_zap_plan(c: Ctx, targets: list[str]) -> dict:
    """One ZAP context per host, so each crawl stays on its own host instead of re-crawling the whole estate."""
    spider = int(c.options.get("zap_spider_minutes", c.settings.zap_spider_minutes))
    ajax = int(c.options.get("zap_ajax_minutes", c.settings.zap_ajax_minutes))
    ajax_mode = str(c.options.get("zap_ajax_hosts", getattr(c.settings, "zap_ajax_hosts", "spa"))).lower()
    spa = _spa_hosts(c) if ajax_mode == "spa" else set()
    excludes = [rf"https?://([a-z0-9-]+\.)*{re.escape(e)}(:\d+)?([/?#].*)?" for e in c.exclusions]
    contexts, jobs = [], []
    for i, t in enumerate(targets, 1):
        host = urllib.parse.urlsplit(t).hostname
        name = f"host{i:03d}"
        contexts.append({"name": name, "urls": [t], "includePaths": [rf"https?://{re.escape(host)}(:\d+)?([/?#].*)?"],
                         "excludePaths": excludes})
        jobs.append({"type": "spider", "parameters": {"context": name, "url": t, "maxDuration": spider,
                                                      "maxDepth": ZAP_SPIDER_MAX_DEPTH, "maxChildren": ZAP_SPIDER_MAX_CHILDREN}})
        if ajax_mode == "all" or (ajax_mode == "spa" and host in spa):   # headless AJAX crawl only where it pays off
            jobs.append({"type": "spiderAjax", "parameters": {"context": name, "url": t, "maxDuration": ajax,
                                                              "maxCrawlDepth": ZAP_SPIDER_MAX_DEPTH, "browserId": "firefox-headless"}})
    active = bool(c.options.get("zap_active"))
    if active:
        per = int(c.options.get("zap_active_minutes", 10))
        for ctx in contexts:
            jobs.append({"type": "activeScan", "parameters": {
                "context": ctx["name"], "policy": "Default Policy",
                "maxScanDurationInMins": per, "maxRuleDurationInMins": max(1, per // 5)}})
    out = str(c.run_dir / "zap")
    jobs += [
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 30}},
        {"type": "report", "parameters": {"template": "traditional-json", "reportDir": out, "reportFile": "zap-estate.json"}},
        {"type": "report", "parameters": {"template": "traditional-html", "reportDir": out, "reportFile": "zap-estate.html"}},
    ]
    return {
        "env": {"contexts": contexts,
                "parameters": {"failOnError": False, "failOnWarning": False, "progressToStdout": True}},
        "jobs": jobs,
    }


def zap_minutes(c: Ctx, n_targets: int) -> int:
    """A time limit that fits the plan: per-host spider + browser crawl + startup slack, plus passive wait."""
    spider = int(c.options.get("zap_spider_minutes", c.settings.zap_spider_minutes))
    ajax = int(c.options.get("zap_ajax_minutes", c.settings.zap_ajax_minutes))
    active_per = int(c.options.get("zap_active_minutes", 10)) if c.options.get("zap_active") else 0
    return max(int(c.settings.stage_timeout_minutes.get("zap", 240)),
               int(n_targets * (spider + ajax + active_per + 1.5)) + 45)


def validate_zap_plan(plan: dict, allow_active: bool = False) -> None:
    allowed = ZAP_ACTIVE_JOB_TYPES if allow_active else ZAP_JOB_TYPES
    types = {j.get("type") for j in plan.get("jobs", [])}
    if not types <= allowed:
        extra = sorted(types - allowed)
        raise StageFailed(f"ZAP plan contains jobs that aren't permitted here: {extra}"
                          + (" (active scanning is off)" if "activeScan" in extra else ""))


def _reload_options(c: Ctx) -> None:
    db = c.db()
    try:
        c.options = json.loads(db.one("SELECT options FROM scans WHERE id = ?", c.scan_id)["options"])
    finally:
        db.close()


async def st_zap(c: Ctx) -> dict:
    active = bool(c.options.get("zap_active"))
    # A passive scan sends no attack traffic, so it starts automatically on the recommended hosts.
    # Only an active scan (attack payloads) pauses to let the operator confirm the target list.
    if active and c.options.get("zap_confirm_targets", True):
        # Checkpoint: wait for the operator to choose hosts. Other stages carry on meanwhile.
        n = len(zap_targets(c))
        if n:
            gate = ZAP_GATES[c.scan_id] = asyncio.Event()
            c.runner.set_stage("zap", "waiting")
            c.runner.event("zap", f"Waiting for you to choose which hosts ZAP should scan ({n} recommended). "
                                  "Other stages carry on meanwhile.", "warn")
            try:
                while not gate.is_set():
                    if c.runner.cancelled:
                        raise StageCancelled()
                    try:
                        await asyncio.wait_for(gate.wait(), timeout=2)
                    except asyncio.TimeoutError:
                        pass
            finally:
                ZAP_GATES.pop(c.scan_id, None)
            c.runner.set_stage("zap", "running", keep_started=True)
            _reload_options(c)
            c.runner.event("zap", f"Hosts confirmed: {len(c.options.get('zap_selected') or [])} selected.")
    targets = zap_targets(c)
    if not targets:
        raise StageSkip("no live web hosts (BBOT found none and no host completed a TLS handshake with a matching certificate)")
    if c.results.get("zap_from_tls"):
        c.runner.event("zap", "BBOT found no live web hosts; using hosts that answered on TLS instead.", "warn")
    if active:
        c.runner.event("zap", "ACTIVE scanning is ON: ZAP will send attack payloads (injection, XSS and other "
                              "checks) to the selected hosts, and the AJAX spider submits forms. Only run this with "
                              "authorisation for active web-app testing and the SOC informed.", "warn")
    plan = build_zap_plan(c, targets)
    validate_zap_plan(plan, allow_active=active)
    path = c.file("zap/plan.yaml")
    path.write_text(yaml.safe_dump(plan, sort_keys=False))
    validate_zap_plan(yaml.safe_load(path.read_text()), allow_active=active)  # re-check what's on disk, right before running
    skipped = c.results.get("zap_skipped_dead", 0)
    limit = zap_minutes(c, len(targets))
    c.runner.event("zap", f"ZAP passive plan: {len(targets)} hosts, one at a time (time limit {limit} min)"
                          + (f"; skipped {skipped} hosts that only answer 403/404/5xx at the root" if skipped else ""))
    argv = ["zap.sh", "-cmd", "-autorun", str(path),
            "-config", f"network.connection.defaultUserAgent={c.settings.user_agent}",
            "-config", f"selenium.firefoxDriver={GECKODRIVER}"]
    hosts = [urllib.parse.urlsplit(t).hostname for t in targets]
    prog = ZAP_PROGRESS[c.scan_id] = {"hosts": hosts, "host": 0, "job": "starting", "since": time.monotonic()}

    def watch(line: str) -> bool:
        m = re.match(r"Job (spider|spiderAjax|passiveScan-wait|report) started", line.strip())
        if m:
            if m.group(1) == "spider":
                prog["host"] += 1
            prog["job"], prog["since"] = m.group(1), time.monotonic()
        return any(t in line.lower() for t in ("job", "error", "warn", "report", "finished"))

    async def heartbeat():
        words = {"spider": "spidering", "spiderAjax": "crawling with headless Firefox", "passiveScan-wait": "finishing passive checks",
                 "report": "writing the report", "starting": "starting up"}
        while True:
            await asyncio.sleep(60)
            if c.runner.paused:
                continue
            n = prog["host"]
            where = f" {hosts[n - 1]} (host {n} of {len(hosts)})" if 0 < n <= len(hosts) and prog["job"] in ("spider", "spiderAjax") else ""
            mins = int((time.monotonic() - prog["since"]) // 60)
            c.runner.event("zap", f"ZAP still working: {words.get(prog['job'], prog['job'])}{where}, {mins} min on this step")

    hb = asyncio.create_task(heartbeat())
    try:
        await c.runner.run("zap", argv, limit * 60, line_filter=watch)
    finally:
        hb.cancel()
        prog["job"] = "done"
    report = c.run_dir / "zap" / "zap-estate.json"
    if not report.exists():
        raise StageFailed("ZAP produced no report")
    data = json.loads(report.read_text(errors="replace") or "{}")
    in_scope_hosts = c.all_hosts
    counts: dict[str, int] = {"sites": 0, "third_party_sites": 0, "alerts": 0}
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "zap")
            for site in data.get("site", []):
                host = host_of(site.get("@name", ""))
                if host not in in_scope_hosts:
                    counts["third_party_sites"] += 1
                    continue
                counts["sites"] += 1
                for al in site.get("alerts", []):
                    n = al.get("count") or len(al.get("instances") or [])
                    _finding(db, c.scan_id, "web", _sev(al.get("riskdesc")), f"{al.get('name')} ({n} instances)",
                             host, "zap", f"zap:{al.get('pluginid', '')}", efile="zap/zap-estate.json")
                    counts["alerts"] += 1
    finally:
        db.close()
    return counts


# ---- stage 3: TLS ----------------------------------------------------------------------

async def st_tls(c: Ctx) -> dict:
    if not c.light_hosts:
        raise StageSkip("no hosts")
    hosts_file = c.file("tls/hosts.txt")
    hosts_file.write_text("\n".join(c.light_hosts) + "\n")
    out = c.file("tls/tlsx.json")
    conc = int(c.options.get("tlsx_concurrency", c.settings.tlsx_concurrency))
    await c.runner.run("tls", ["tlsx", "-l", str(hosts_file), "-p", "443", "-c", str(conc), "-tv", "-cipher",
                               "-ex", "-ss", "-mm", "-json", "-silent", "-o", str(out)], c.timeout("tls", 30))
    counts = {"hosts": 0, "expired": 0, "expiring_30d": 0, "self_signed": 0, "mismatched": 0, "legacy_tls": 0}
    soon = datetime.now(timezone.utc).timestamp() + 30 * 86400
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "tlsx")
            for line in out.read_text(errors="replace").splitlines() if out.exists() else []:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = str(r.get("host", "")).lower()
                if host not in c.all_hosts:
                    continue
                counts["hosts"] += 1
                info = {k: r.get(k) for k in ("tls_version", "cipher", "not_after", "expired", "self_signed", "mismatched", "subject_cn")}
                _upsert_asset(db, c.scan_id, host, tls=info)
                if r.get("expired"):
                    counts["expired"] += 1; _finding(db, c.scan_id, "tls", "high", "Expired TLS certificate", host, "tlsx", r.get("not_after"), efile="tls/tlsx.json")
                else:
                    try:
                        na = datetime.fromisoformat(str(r.get("not_after")).replace("Z", "+00:00")).timestamp()
                        if na < soon:
                            counts["expiring_30d"] += 1
                            _finding(db, c.scan_id, "tls", "medium", "TLS certificate expires within 30 days", host, "tlsx", r.get("not_after"), efile="tls/tlsx.json")
                    except (ValueError, TypeError):
                        pass
                if r.get("self_signed"):
                    counts["self_signed"] += 1; _finding(db, c.scan_id, "tls", "medium", "Self-signed TLS certificate", host, "tlsx", efile="tls/tlsx.json")
                if r.get("mismatched"):
                    counts["mismatched"] += 1; _finding(db, c.scan_id, "tls", "low", "Certificate name doesn't match host", host, "tlsx", efile="tls/tlsx.json")
                if r.get("tls_version") in ("tls10", "tls11"):
                    counts["legacy_tls"] += 1
                    _finding(db, c.scan_id, "tls", "medium", f"Legacy protocol negotiated ({r.get('tls_version')})", host, "tlsx", efile="tls/tlsx.json")
    finally:
        db.close()
    return counts


# ---- stage 4 & 9: exposed services from InternetDB ---------------------------------------

NMAP_REPORT_RE = re.compile(r"^Nmap scan report for (?:\S+ \(([^)]+)\)|(\S+))\s*$")
NMAP_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\b")


def parse_nmap_names(text: str) -> dict[str, str]:
    """The hostname smap reports for each IP (from Shodan), when it gives one."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^Nmap scan report for (\S+) \(([^)]+)\)\s*$", line.strip())
        if m:
            out[m.group(2).strip("[]")] = m.group(1).lower().rstrip(".")
    return out


def parse_nmap_normal(text: str) -> dict[str, list[int]]:
    """smap writes nmap's normal (-oN) format: a 'Nmap scan report for name (ip)' line, then 'port/tcp open ...' lines."""
    out: dict[str, list[int]] = {}
    ip = None
    for line in text.splitlines():
        m = NMAP_REPORT_RE.match(line.strip())
        if m:
            ip = (m.group(1) or m.group(2)).strip("[]")
            continue
        m = NMAP_PORT_RE.match(line.strip())
        if m and ip:
            out.setdefault(ip, []).append(int(m.group(1)))
    return out


async def _smap(c: Ctx, stage: str, ips: list[str], tag: str) -> dict[str, list[int]]:
    if not ips:
        return {}
    ip_file = c.file(f"services/{tag}_ips.txt")
    ip_file.write_text("\n".join(ips) + "\n")
    normal = c.file(f"services/{tag}.txt")
    # smap doesn't write nmap's -oP "pairs" format, so read the normal output it does write
    await c.runner.run(stage, ["smap", "-iL", str(ip_file), "-oN", str(normal)], c.timeout(stage, 30))
    text = normal.read_text(errors="replace") if normal.exists() else ""
    c.results[f"smap_names_{tag}"] = parse_nmap_names(text)
    return parse_nmap_normal(text)


def _risky(db: DB, c: Ctx, ip: str, ports: list[int], hosts: list[str], tool: str) -> int:
    n = 0
    for p in sorted(set(ports)):
        if p in RISKY_PORTS:
            sev, label = RISKY_PORTS[p]
            _finding(db, c.scan_id, "exposure", sev, f"{label} exposed on port {p}", ", ".join(hosts[:3]) or ip, tool, f"{ip}:{p}", efile="services/shared_ips.json")
            n += 1
    return n


def is_shared_infra(shodan_name: str | None, roots: list[str]) -> bool:
    if not shodan_name:
        return False
    return not any(shodan_name == r or shodan_name.endswith("." + r) for r in roots)


async def st_ports(c: Ctx) -> dict:
    db = c.db()
    try:
        rows = db.all("SELECT host, ips, cdn FROM assets WHERE scan_id = ?", c.scan_id)
    finally:
        db.close()
    ip_hosts: dict[str, list[str]] = {}
    for r in rows:
        if r["cdn"]:
            continue
        for ip in json.loads(r["ips"]):
            if is_public_ip(ip):
                ip_hosts.setdefault(ip, []).append(r["host"])
    if not ip_hosts:
        raise StageSkip("no non-CDN public IPs known yet")
    found = await _smap(c, "ports", sorted(ip_hosts), "dns")
    names = c.results.get("smap_names_dns", {})
    risky, shared = 0, 0
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "internetdb")
            for ip, ports in found.items():
                for h in ip_hosts.get(ip, []):
                    _upsert_asset(db, c.scan_id, h, ports=ports)
                if is_shared_infra(names.get(ip), c.roots):
                    # Shodan names the IP after someone else (a SaaS or hosting platform your subdomain points at):
                    # its open ports are the vendor's, so they aren't reported as your exposed services.
                    shared += 1
                    continue
                risky += _risky(db, c, ip, ports, ip_hosts.get(ip, []), "internetdb")
    finally:
        db.close()
    own = {ip: p for ip, p in found.items() if not is_shared_infra(names.get(ip), c.roots)}
    c.file("services/shared_ips.json").write_text(json.dumps(sorted(ip for ip in found if ip not in own)))
    if shared:
        c.runner.event("ports", f"{shared} IPs belong to shared third-party platforms (Shodan names them after other "
                                "organisations); their ports aren't counted as your exposed services.")
    return {"ips_checked": len(ip_hosts), "ips_with_ports": len(own), "shared_platform_ips": shared,
            "open_ports": sum(len(set(p)) for p in own.values()), "risky_services": risky}


async def st_cloud(c: Ctx) -> dict:
    from .extras import _extra_ips
    ips = _extra_ips(c)        # pasted IPs plus cloudlist's public IPs
    if not ips:
        raise StageSkip("no extra IPs supplied and none from cloudlist")
    found = await _smap(c, "cloud", ips, "extra")
    risky = 0
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "internetdb-extra")
            for ip, ports in found.items():
                _upsert_asset(db, c.scan_id, ip, ips=[ip], ports=ports)
                risky += _risky(db, c, ip, ports, [], "internetdb-extra")
    finally:
        db.close()
    return {"ips_checked": len(ips), "ips_with_ports": len(found), "open_ports": sum(len(set(p)) for p in found.values()),
            "risky_services": risky}


# ---- stage 5: email security ------------------------------------------------------------

def _dmarc_policy(rec: str) -> str | None:
    m = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", rec.lower())
    return m.group(1) if m else None


async def st_email(c: Ctx) -> dict:
    if shutil.which("checkdmarc"):
        from .extras import st_email_checkdmarc
        return await st_email_checkdmarc(c)
    posture = []
    db = c.db()
    try:
        _clear(db, c.scan_id, "dns-email")
    finally:
        db.close()
    for d in c.roots:
        mx = await c.providers.records(d, "MX")
        txt = await c.providers.records(d, "TXT")
        dmarc = [t for t in await c.providers.records(f"_dmarc.{d}", "TXT") if t.lower().startswith("v=dmarc1")]
        sts = await c.providers.records(f"_mta-sts.{d}", "TXT")
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        pol = _dmarc_policy(dmarc[0]) if dmarc else None
        posture.append({"domain": d, "mx": mx, "spf": spf, "dmarc": dmarc[0] if dmarc else None, "dmarc_policy": pol, "mta_sts": bool(sts)})
        db = c.db()
        try:
            if not dmarc:
                _finding(db, c.scan_id, "email", "high", "No DMARC record: the domain can be spoofed", d, "dns-email", efile="email/posture.json")
            elif pol == "none":
                _finding(db, c.scan_id, "email", "medium", "DMARC policy is p=none (monitoring only)", d, "dns-email", efile="email/posture.json")
            elif pol == "quarantine":
                _finding(db, c.scan_id, "email", "low", "DMARC policy is quarantine, not reject", d, "dns-email", efile="email/posture.json")
            if not spf:
                _finding(db, c.scan_id, "email", "medium", "No SPF record", d, "dns-email", efile="email/posture.json")
            elif spf.rstrip().endswith("+all"):
                _finding(db, c.scan_id, "email", "high", "SPF allows any sender (+all)", d, "dns-email", efile="email/posture.json")
            if not mx and (not spf or "-all" not in spf):
                _finding(db, c.scan_id, "email", "low", "Domain sends no mail but isn't locked down (v=spf1 -all)", d, "dns-email", efile="email/posture.json")
        finally:
            db.close()
    c.file("email/posture.json").write_text(json.dumps(posture, indent=2))
    return {"domains": len(posture), "dmarc_reject": sum(p["dmarc_policy"] == "reject" for p in posture)}


# ---- stage 6: historical URLs ------------------------------------------------------------

async def st_gau(c: Ctx) -> dict:
    raw = c.file("urls/gau_raw.txt")
    await c.runner.run("gau", ["gau", "--subs", "--threads", "5", "--providers", "wayback,commoncrawl,otx,urlscan",
                               "--blacklist", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,webp",
                               "--o", str(raw), *c.roots], c.timeout("gau", 30), line_filter=lambda l: False)
    from .scope import in_scope
    urls = in_scope(raw.read_text(errors="replace").splitlines() if raw.exists() else [], c.roots, c.exclusions)
    inscope = c.file("urls/gau_inscope.txt")
    inscope.write_text("\n".join(urls) + "\n")
    dedup = c.file("urls/historical.txt")
    if shutil.which("uro"):
        await c.runner.run("gau", ["uro", "-i", str(inscope), "-o", str(dedup)], 600, line_filter=lambda l: False)
    if not dedup.exists() or dedup.stat().st_size == 0:
        dedup.write_text("\n".join(sorted(set(urls))) + "\n")
    hist = [u for u in dedup.read_text(errors="replace").splitlines() if u]
    interesting = sorted({u for u in hist if INTERESTING_URL.search(u)})
    c.file("urls/interesting.txt").write_text("\n".join(interesting) + "\n")
    return {"historical_urls": len(hist), "interesting": len(interesting)}


# ---- stage 7: lookalikes ---------------------------------------------------------------

def lookalike_severity(root: str, domain: str, fuzzer: str) -> tuple[str, str]:
    """Short brands collide with many real, unrelated names (mira.com, mito.com); one-letter edits of
    those are usually someone else's business. Brand-plus-word and look-alike characters are the ones
    worth a person's time."""
    brand = root.split(".")[0].replace("-", "")
    label = domain.split(".")[0]
    flat = label.replace("-", "")
    if label.startswith("xn--") or fuzzer == "homoglyph":
        return "medium", " (look-alike characters)"
    if brand in flat and len(flat) >= len(brand) + 3:
        return "medium", " (brand plus extra words)"
    if len(brand) <= 5:
        return "low", " (one-letter variant; often an unrelated business)"
    return "medium", ""


async def st_lookalikes(c: Ctx) -> dict:
    reg, with_mx = 0, 0
    db = c.db()
    try:
        _clear(db, c.scan_id, "dnstwist")
    finally:
        db.close()
    for d in c.roots:
        out = c.file(f"lookalikes/{d}.json")
        probe = ["--banners", "--mxcheck"] if c.options.get("lookalike_probe") else []
        if probe and d == c.roots[0]:
            c.runner.event("lookalikes", "Probing is ON: dnstwist will connect to registered lookalike domains (HTTP/SMTP banners "
                                         "and a mail-interception check). Those are other people's servers.", "warn")
        await c.runner.run("lookalikes", ["dnstwist", "--registered", *probe, "--format", "json", d],
                           c.timeout("lookalikes", 30), stdout_file=out)
        try:
            rows = json.loads(out.read_text(errors="replace") or "[]")
        except json.JSONDecodeError:
            rows = []
        db = c.db()
        try:
            for r in rows:
                if r.get("fuzzer") == "*original":
                    continue
                reg += 1
                if r.get("dns_mx"):
                    with_mx += 1
                    sev, note = lookalike_severity(d, str(r.get("domain", "")), str(r.get("fuzzer", "")))
                    _finding(db, c.scan_id, "brand", sev, f"Registered lookalike with mail servers{note}: {r.get('domain')}",
                             d, "dnstwist", r.get("fuzzer"), efile=f"lookalikes/{d}.json")
        finally:
            db.close()
    return {"registered": reg, "with_mx": with_mx}


# ---- stage 8: HIBP ----------------------------------------------------------------------

def _xon_breaches(obj) -> list:
    """Defensively pull the breach list out of an XposedOrNot response, whatever key it lands under."""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in ("exposedBreaches", "breaches", "Breaches_Details", "data"):
            if isinstance(obj.get(k), list):
                return obj[k]
        m = obj.get("metrics")
        if isinstance(m, dict):
            for k in ("Breaches_Details", "breaches", "exposedBreaches"):
                if isinstance(m.get(k), list):
                    return m[k]
    return []


def _xon_name(b) -> str:
    if isinstance(b, dict):
        for k in ("breach", "breachID", "Name", "name", "title", "domain"):
            if b.get(k):
                return str(b[k])
    return "?"


async def st_hibp(c: Ctx) -> dict:
    """Breach exposure. Free by default via XposedOrNot (known breaches per domain, no key); richer
    per-domain account exposure with a free XposedOrNot domain key or a paid HIBP key. Best-effort —
    an unreachable provider warns and the scan carries on."""
    xon_key = c.secrets.get("xposedornot")
    hibp_key = c.secrets.get("hibp")
    per: dict[str, dict] = {}
    catalog_total = 0
    exposed_total = 0
    db = c.db()
    try:
        # (1) XposedOrNot breach catalogue per root domain — free, no key
        for d in c.roots:
            try:
                cat = await c.providers.http_json(
                    f"https://api.xposedornot.com/v1/breaches?domain={urllib.parse.quote(d)}", timeout=30)
            except Exception as exc:
                c.runner.event("hibp", f"XposedOrNot catalogue lookup failed for {d}: {exc}", "warn")
                cat = None
            bl = _xon_breaches(cat)
            per.setdefault(d, {})["known_breaches"] = len(bl)
            if bl:
                catalog_total += len(bl)
                names = ", ".join(_xon_name(b) for b in bl[:8])
                _finding(db, c.scan_id, "people", "info",
                         f"{len(bl)} known data breach{'es' if len(bl) != 1 else ''} associated with {d}"
                         + (f": {names}" if names else ""),
                         d, "xposedornot", "https://xposedornot.com/", efile="hibp/xposedornot.json")
            await asyncio.sleep(1)       # keep under the 2/sec cap
        # (2) XposedOrNot domain-breaches — the free, per-domain verified key (the domain comes from the key)
        if xon_key:
            try:
                dom = await c.providers.http_json(
                    "https://api.xposedornot.com/v1/domain-breaches/",
                    headers={"x-api-key": xon_key, "Content-Length": "0"}, data=b"", timeout=60)
            except Exception as exc:
                c.runner.event("hibp", f"XposedOrNot domain-breaches failed: {exc} "
                                       "(key invalid, or the domain isn't verified yet?)", "warn")
                dom = None
            bl = _xon_breaches(dom)
            m = dom.get("metrics") if isinstance(dom, dict) else {}
            summ = m.get("Domain_Summary") if isinstance(m, dict) else {}
            exposed = 0
            if isinstance(summ, dict):
                for k in ("total_breaches", "breaches", "exposed", "count"):
                    if isinstance(summ.get(k), int):
                        exposed = summ[k]
                        break
            exposed = exposed or len(bl)
            if exposed:
                exposed_total += exposed
                _finding(db, c.scan_id, "people", "medium",
                         f"{exposed} breach exposure{'s' if exposed != 1 else ''} reported for your verified domain (XposedOrNot)",
                         (c.roots[0] if c.roots else None), "xposedornot", "https://xposedornot.com/",
                         efile="hibp/xposedornot_domain.json")
            try:
                c.file("hibp/xposedornot_domain.json").write_text(json.dumps(dom, indent=2))
            except Exception:
                pass
        # (3) HIBP (paid) — kept unchanged for those who have it
        if hibp_key:
            for d in c.roots:
                try:
                    data = await c.providers.http_json(
                        f"https://haveibeenpwned.com/api/v3/breacheddomain/{urllib.parse.quote(d)}",
                        headers={"hibp-api-key": hibp_key}, timeout=60)
                except Exception as exc:
                    msg = str(exc)
                    if "404" in msg:
                        data = {}
                    else:
                        c.runner.event("hibp", f"{d}: {msg} (domain not verified on your HIBP dashboard, or tier too small?)", "warn")
                        continue
                n = len(data or {})
                per.setdefault(d, {})["hibp_accounts"] = n
                exposed_total += n
                if n:
                    _finding(db, c.scan_id, "people", "medium",
                             f"{n} staff email address{'es' if n != 1 else ''} appear in known breaches (HIBP)",
                             d, "hibp", efile="hibp/summary.json")
                await asyncio.sleep(2)
    finally:
        db.close()
    try:
        c.file("hibp/summary.json").write_text(json.dumps(per, indent=2))
    except Exception:
        pass
    sources = ["XposedOrNot"] + (["XposedOrNot domain key"] if xon_key else []) + (["HIBP"] if hibp_key else [])
    return {"known_breaches": catalog_total, "exposed_accounts": exposed_total,
            "domains": len(per), "sources": sources}


# ---- stage 10: consolidate ---------------------------------------------------------------

async def st_consolidate(c: Ctx) -> dict:
    db = c.db()
    try:
        cmdb = {r["value"] for r in db.all("SELECT value FROM cmdb_entries")}
        with db.tx():
            for r in db.all("SELECT host, ips FROM assets WHERE scan_id = ?", c.scan_id):
                known = r["host"] in cmdb or any(ip in cmdb for ip in json.loads(r["ips"]))
                db.run("UPDATE assets SET in_cmdb = ? WHERE scan_id = ? AND host = ?", int(known), c.scan_id, r["host"])
            # every in-scope host is an asset, even if no stage touched it
            for h in c.light_hosts + c.dns_hosts:
                if not db.one("SELECT 1 FROM assets WHERE scan_id = ? AND host = ?", c.scan_id, h):
                    db.run("INSERT INTO assets (scan_id, host, in_cmdb, third_party) VALUES (?, ?, ?, ?)",
                           c.scan_id, h, int(h in cmdb), int(h in c.dns_hosts))
        assets = db.all("SELECT * FROM assets WHERE scan_id = ?", c.scan_id)
        f = db.all("SELECT area, severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY area, severity", c.scan_id)
        stages = {r["stage_key"]: r["status"] for r in db.all("SELECT stage_key, status FROM stages WHERE scan_id = ?", c.scan_id)}
        ips = {ip for a in assets if not a["cdn"] for ip in json.loads(a["ips"])}   # CDN edge IPs aren't yours
        by_area: dict[str, dict[str, int]] = {}
        for r in f:
            by_area.setdefault(r["area"], {})[r["severity"]] = r["n"]
        metrics = {
            "scan_id": c.scan_id, "generated_at": now(), "stages": stages,
            "surface": {
                "root_domains": len(c.roots), "hosts_in_scope": len(c.light_hosts) + len(c.dns_hosts),
                "third_party_hosted": len(c.dns_hosts), "not_in_cmdb": sum(1 for a in assets if not a["in_cmdb"]),
                "public_ips": len(ips), "live_web_hosts": sum(1 for a in assets if a["is_live"]),
            },
            "findings": by_area,
            "findings_total": {s: sum(a.get(s, 0) for a in by_area.values()) for s in ("critical", "high", "medium", "low", "info")},
        }
        db.run("INSERT INTO metrics (scan_id, metrics) VALUES (?, ?) ON CONFLICT(scan_id) DO UPDATE SET metrics = excluded.metrics",
               c.scan_id, json.dumps(metrics))
    finally:
        db.close()
    c.file("summary/metrics.json").write_text(json.dumps(metrics, indent=2))
    return metrics["surface"] | {"findings": sum(metrics["findings_total"].values())}


def _lazy(name: str) -> Callable[[Ctx], Awaitable[dict]]:
    """v0.6 stages live in extras.py, which imports helpers from this module; resolve them at call time."""
    async def run(c: Ctx) -> dict:
        from . import extras
        return await getattr(extras, name)(c)
    run.__name__ = name
    return run


STAGE_FUNCS: dict[str, Callable[[Ctx], Awaitable[dict]]] = {
    "bbot_light": st_bbot_light, "screenshots": st_screenshots, "reenrich": st_reenrich, "zap": st_zap, "tls": st_tls, "ports": st_ports, "email": st_email, "gau": st_gau,
    "lookalikes": st_lookalikes, "hibp": st_hibp, "cloud": st_cloud, "consolidate": st_consolidate,
    **{k: _lazy(f"st_{k}") for k in ("cdn", "takeover", "tls_deep", "cloudlist", "intel", "feeds", "squat", "urlscan",
                                     "spiderfoot", "tech", "dns", "port_check")},
}


# ---- orchestration ----------------------------------------------------------------------

def _set_status(state, scan_id: str, status: str, **extra) -> None:
    db = state.db()
    try:
        db.run("UPDATE scans SET status = ? WHERE id = ?", status, scan_id)
        if "started_at" in extra:
            db.run("UPDATE scans SET started_at = COALESCE(started_at, ?) WHERE id = ?", extra["started_at"], scan_id)
        if "finished_at" in extra:
            db.run("UPDATE scans SET finished_at = ? WHERE id = ?", extra["finished_at"], scan_id)
    finally:
        db.close()


async def run_pipeline(state, scan_id: str, only: list[str] | None = None, providers=None, use_bbot: bool = True,
                       reuse_output: bool = False) -> None:
    db = state.db()
    try:
        scan = db.one("SELECT * FROM scans WHERE id = ?", scan_id)
        settings = Settings.model_validate(db.get_setting("app", {}))
        store = SecretStore(db, state.master_key)
        secrets = {r["name"]: store.get(r["name"]) for r in db.all("SELECT name FROM secrets")}
        if use_bbot:
            _write_bbot_config(store, settings.user_agent)
        done = {r["stage_key"] for r in db.all("SELECT stage_key FROM stages WHERE scan_id = ? AND status = 'done'", scan_id)}
    finally:
        db.close()
    run_dir = Path(scan["run_dir"])
    options = json.loads(scan["options"])
    snap = json.loads((run_dir / "scope" / "snapshot.json").read_text())
    runner = Runner(state.cfg.db_path, scan_id, run_dir, [v for v in secrets.values() if v])
    ACTIVE[scan_id] = runner
    c = Ctx(state=state, scan_id=scan_id, run_dir=run_dir, runner=runner, providers=providers or Providers(settings.user_agent),
            settings=settings, options=options, roots=snap["roots"], light_hosts=snap["light_hosts"],
            dns_hosts=snap["dns_hosts"], exclusions=snap["exclusions"], secrets=secrets, use_bbot=use_bbot,
            reuse_output=reuse_output)
    enabled = set(options.get("stages", [])) | {"consolidate"}
    _set_status(state, scan_id, "running", started_at=now())
    errors = {"any": False}

    async def run_one(key: str) -> None:
        runner.set_stage(key, "running")
        runner.event(key, f"Stage started: {next(s.title for s in STAGES if s.key == key)}")
        try:
            summary = await STAGE_FUNCS[key](c)
            runner.set_stage(key, "done", summary=json.dumps(summary))
            runner.event(key, "Stage complete: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in summary.items()))
        except StageSkip as exc:
            runner.set_stage(key, "skipped", summary=json.dumps({"reason": str(exc)}))
            runner.event(key, f"Skipped: {exc}", "warn")
        except StageCancelled:
            raise
        except Exception as exc:
            errors["any"] = True
            runner.set_stage(key, "failed", summary=json.dumps({"error": f"{type(exc).__name__}: {exc}"[:500]}))
            runner.event(key, f"Stage failed: {type(exc).__name__}: {exc}", "error")

    try:
        queue: list[str] = []
        for key in STAGE_KEYS:
            if only is not None and key not in only:
                continue
            if only is None and key in done:
                runner.event(key, "Already complete; skipping on resume.")
                continue
            if key not in enabled:
                runner.set_stage(key, "skipped", summary=json.dumps({"reason": "turned off in options"}))
                continue
            queue.append(key)
        # Run stages side by side where nothing they need is still waiting or running (see STAGE_DEPS)
        running: dict[asyncio.Task, str] = {}
        cancelled = False
        while queue or running:
            if runner.paused and not running:
                await runner.wait_while_paused()
            if not runner.cancelled and not runner.paused:
                busy = set(queue) | set(running.values())
                for key in list(queue):
                    if len(running) >= MAX_PARALLEL_STAGES:
                        break
                    if not (STAGE_DEPS.get(key, set()) & (busy - {key})):
                        queue.remove(key)
                        running[asyncio.create_task(run_one(key))] = key
                        busy = set(queue) | set(running.values())
            if not running:
                break
            finished, _ = await asyncio.wait(running, timeout=3, return_when=asyncio.FIRST_COMPLETED)
            for t in finished:
                running.pop(t)
                if isinstance(t.exception(), StageCancelled):
                    cancelled = True
            if cancelled or runner.cancelled:
                runner.cancel()
                if running:
                    await asyncio.wait(running)
                raise StageCancelled()
        errors = errors["any"]
        db = state.db()
        try:
            st = {r["stage_key"]: r["status"] for r in db.all("SELECT stage_key, status FROM stages WHERE scan_id = ?", scan_id)}
        finally:
            db.close()
        unfinished = [k for k in enabled if st.get(k) in ("pending", "cancelled", "running")]
        failed = [k for k, v in st.items() if v == "failed"]
        final = "cancelled" if unfinished else "completed_with_errors" if (errors or failed) else "completed"
        _set_status(state, scan_id, final, finished_at=now())
    except StageCancelled:
        db = state.db()
        try:
            db.run("UPDATE stages SET status = 'cancelled', finished_at = ? WHERE scan_id = ? AND status IN ('running', 'waiting')",
                   now(), scan_id)
        finally:
            db.close()
        runner.event(None, "Scan cancelled.", "warn")
        _set_status(state, scan_id, "cancelled", finished_at=now())
    except Exception as exc:
        runner.event(None, f"Pipeline error: {type(exc).__name__}: {exc}", "error")
        _set_status(state, scan_id, "failed", finished_at=now())
    finally:
        ACTIVE.pop(scan_id, None)


# What each stage needs finished first. Everything else can run alongside other stages.
STAGE_DEPS: dict[str, set[str]] = {
    "cdn": {"bbot_light", "reenrich"},  # classifies the IPs BBOT resolved (incl. re-enriched hosts)
    "takeover": {"bbot_light", "reenrich"},  # deep baddns over live hosts, re-enriched ones included
    "dns": {"bbot_light", "reenrich"},  # reverse DNS over the full asset set, re-enriched hosts included
    "zap": {"bbot_light", "tls", "tech"},  # targets from BBOT live hosts (TLS fallback); tech gives SPA detection for AJAX gating
    "screenshots": {"bbot_light"},    # gowitness over the live hosts, in parallel with ZAP
    "reenrich": {"bbot_light", "gau", "tls"},  # probe late in-scope discoveries before the IP/host checks run
    "tls_deep": {"bbot_light"},       # key hosts are picked from the live ones
    "ports": {"bbot_light", "cdn"},   # IPs come from BBOT; cdncheck decides which are CDN edges
    "cloud": {"cloudlist"},           # cloudlist's IPs are checked alongside pasted ones
    "tech": {"bbot_light"},           # fingerprints the live hosts BBOT found
    "port_check": {"ports", "cloud"}, # checks the ports InternetDB reported, on your own IPs only
    "intel": {"ports", "cloud", "feeds", "cloudlist", "tech"},   # own IPs + Netlas CVEs + fingerprinted versions
    "urlscan": {"lookalikes", "squat"},                 # checks the lookalikes found for live pages
    "consolidate": {k for k in STAGE_KEYS if k != "consolidate"},
}
MAX_PARALLEL_STAGES = 5


def estimate_minutes(options: dict, snap: dict) -> dict[str, float]:
    n_light, n_dns, n_roots = len(snap["light_hosts"]), len(snap["dns_hosts"]), len(snap["roots"])
    st = set(options.get("stages", []))
    zap_hosts = min(int(options.get("zap_max_hosts", 30)), max(1, int(n_light * 0.7)))
    per = {
        "bbot_light": 5 + (n_light + n_dns) * 0.08
                      + (min(int(options.get("bbot_active_max_hosts", 150)), n_light) * 0.4 if options.get("bbot_active") else 0),
        "zap": zap_hosts * (int(options.get("zap_spider_minutes", 3)) + int(options.get("zap_ajax_minutes", 3)) + 0.5) + 2,
        "tls": 1 + n_light / 150, "ports": 1 + n_light / 300, "email": 0.2 * n_roots, "gau": 3 * n_roots,
        "lookalikes": 2 * n_roots, "hibp": 0.2 * n_roots, "cloud": 1, "consolidate": 0.2,
        "cdn": 0.3, "cloudlist": 1, "feeds": 0.5 * n_roots + 0.5,
        "takeover": 1 + (n_light + n_dns) / 400 + (n_light / 60 if options.get("takeover_deep", True) else 0),
        "intel": 1 + n_light / 200, "squat": 2, "urlscan": 1 + 0.3 * n_roots, "spiderfoot": 45 * n_roots,
        "tech": 1 + n_light / 60, "port_check": 2 + n_light / 40,
        "dns": 1 + (n_light + n_dns) / 300 + (n_roots * 1.5 if options.get("dns_bruteforce") else 0),
        "tls_deep": int(options.get("testssl_max_hosts", 5)) * (9 if options.get("testssl_vuln_checks") else 4),
    }
    return {k: round(v, 1) for k, v in per.items() if k in st or k == "consolidate"}


def estimate_total(per: dict[str, float]) -> float:
    """Wall-clock minutes when stages run side by side: simulate the scheduler (deps + parallel cap)."""
    queue = [k for k in STAGE_KEYS if k in per]
    t, running, finish = 0.0, {}, {}
    while queue or running:
        busy = set(queue) | set(running)
        for k in list(queue):
            if len(running) >= MAX_PARALLEL_STAGES:
                break
            if not (STAGE_DEPS.get(k, set()) & (busy - {k})):
                queue.remove(k)
                running[k] = t + per[k]
                busy = set(queue) | set(running)
        if not running:
            break
        k = min(running, key=running.get)
        t = running.pop(k)
        finish[k] = t
    return t


def mark_interrupted(db: DB) -> int:
    """On startup: scans left running by a restart are marked interrupted (resumable)."""
    n = db.run("UPDATE scans SET status = 'interrupted' WHERE status = 'running'").rowcount
    db.run("UPDATE scans SET status = 'draft' WHERE status = 'discovering'")
    db.run("UPDATE stages SET status = 'cancelled' WHERE status IN ('running', 'waiting')")
    return n
