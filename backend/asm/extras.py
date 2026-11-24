"""Stages added in v0.6: deeper takeover, CDN, email and TLS checks, cloud inventory, exposure intelligence,
lookalike monitoring, and an optional passive SpiderFoot sidecar.

Defaults stay non-invasive. Every tool here is passive (no traffic to your hosts), DNS-only or light-touch.
The few options that go further are off unless switched on per scan, and the UI warns about them:
  - testssl_vuln_checks: testssl.sh's vulnerability probes (Heartbleed, CCS, ROBOT, ...) send malformed handshakes
  - email_starttls: checkdmarc connects to your mail servers on port 25 to test STARTTLS
  - opensquat_portcheck: openSquat connects to suspected lookalike domains (someone else's servers) on 80/443
Free services are the default; anything that needs a paid plan is labelled and off until a key/plan is present.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.parse
from pathlib import Path

import yaml

from .pipeline import Ctx, StageSkip, _clear, _finding, _rotate, _upsert_asset, lookalike_severity, status_rank
from .runner import StageFailed
from .scope import is_ip, is_public_ip

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TAKEOVER_TOOLS = ("bbot:baddns", "dnsreaper")
EPSS_LIKELY = 0.10            # 10%+ chance of exploitation in the next 30 days: worth a person's time


def _under(host: str, roots: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == r or host.endswith("." + r) for r in roots)


def _http_code(exc: Exception) -> int | None:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code
    m = re.search(r"HTTP Error (\d{3})", str(exc))
    return int(m.group(1)) if m else None


def _load_json_any(path: Path):
    """JSON document or JSON lines."""
    if not path.exists():
        return []
    text = path.read_text(errors="replace").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("{", "[")):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out


def _lower_keys(d: dict) -> dict:
    return {str(k).lower().replace(" ", "_"): v for k, v in d.items()}


def _own_ips(c: Ctx) -> dict[str, list[str]]:
    """Public IPs that are yours: not CDN edges, not shared third-party platforms."""
    db = c.db()
    try:
        rows = db.all("SELECT host, ips, cdn, third_party FROM assets WHERE scan_id = ?", c.scan_id)
    finally:
        db.close()
    shared = set(json.loads(c.file("services/shared_ips.json").read_text() or "[]")) \
        if (c.run_dir / "services" / "shared_ips.json").exists() else set()
    out: dict[str, list[str]] = {}
    for r in rows:
        if r["cdn"] or r["third_party"]:
            continue
        for ip in json.loads(r["ips"]):
            if is_public_ip(ip) and ip not in shared:
                out.setdefault(ip, []).append(r["host"])
    for ip in _extra_ips(c):
        out.setdefault(ip, [])
    return out


def _extra_ips(c: Ctx) -> list[str]:
    ips = [ip for ip in c.options.get("extra_ips", []) if is_public_ip(ip)]
    f = c.run_dir / "cloud" / "cloudlist_ips.txt"
    if f.exists():
        ips += [ip for ip in f.read_text().split() if is_public_ip(ip)]
    return sorted(set(ips))


# ---- cdncheck: CDN / WAF / cloud classification (offline) ------------------------------

def parse_cdncheck(text: str) -> dict[str, dict]:
    """cdncheck -jsonl lines, or its plain '1.2.3.4 [waf] [cloudflare]' output. Only matched inputs are printed."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = str(r.get("ip") or r.get("input") or "").strip()
            if not key:
                continue
            e = out.setdefault(key, {})
            for kind in ("cdn", "waf", "cloud"):
                if r.get(kind) or r.get(f"{kind}_name"):
                    e[kind] = str(r.get(f"{kind}_name") or kind)
            continue
        m = re.match(r"^(\S+)\s+\[(cdn|waf|cloud)\]\s+\[([^\]]+)\]", line)
        if m:
            out.setdefault(m.group(1), {})[m.group(2)] = m.group(3)
    return out


async def st_cdn(c: Ctx) -> dict:
    db = c.db()
    try:
        rows = db.all("SELECT host, ips, cdn FROM assets WHERE scan_id = ?", c.scan_id)
    finally:
        db.close()
    ips = sorted({ip for r in rows for ip in json.loads(r["ips"]) if is_public_ip(ip)})
    if not ips:
        raise StageSkip("no resolved IPs yet")
    inp = c.file("cdn/ips.txt")
    inp.write_text("\n".join(ips) + "\n")
    out = c.file("cdn/cdncheck.jsonl")
    # IP input only: cdncheck matches against provider ranges built into the binary, so nothing is sent anywhere
    await c.runner.run("cdn", ["cdncheck", "-i", str(inp), "-resp", "-jsonl", "-silent", "-nc"], c.timeout("cdn", 5),
                       stdout_file=out)
    verdict = parse_cdncheck(out.read_text(errors="replace") if out.exists() else "")
    counts = {"ips_checked": len(ips), "cdn": 0, "waf": 0, "cloud": 0, "hosts_reclassified": 0}
    for v in verdict.values():
        for k in ("cdn", "waf", "cloud"):
            counts[k] += int(k in v)
    db = c.db()
    try:
        with db.tx():
            for r in rows:
                host_ips = [ip for ip in json.loads(r["ips"]) if is_public_ip(ip)]
                if not host_ips:
                    continue
                edge: dict[str, str] = {}
                for ip in host_ips:
                    for k, name in verdict.get(ip, {}).items():
                        edge.setdefault(k, name)
                is_edge = bool(edge.get("cdn") or edge.get("waf"))
                if is_edge != bool(r["cdn"]):
                    counts["hosts_reclassified"] += 1
                _upsert_asset(db, c.scan_id, r["host"], edge=edge, cdn_exact=is_edge)
    finally:
        db.close()
    c.file("cdn/verdict.json").write_text(json.dumps(verdict, indent=2))
    return counts


# ---- dnsReaper: subdomain takeover signatures (DNS only) ------------------------------

DNSREAPER_SEV = {"confirmed": "high", "potential": "medium", "unlikely": "low"}


def parse_dnsreaper(data) -> list[dict]:
    rows = data if isinstance(data, list) else (data.get("findings") or data.get("results") or []) if isinstance(data, dict) else []
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        r = _lower_keys(r)
        dom = str(r.get("domain") or r.get("subdomain") or "").lower().rstrip(".")
        if not dom:
            continue
        out.append({"domain": dom, "signature": str(r.get("signature") or "unknown"),
                    "info": str(r.get("info") or ""), "confidence": str(r.get("confidence") or "POTENTIAL").lower(),
                    "more_info": str(r.get("more_info_url") or r.get("more_info") or "")})
    return out


async def _dnsreaper_run(c: Ctx, tag: str, args: list[str]) -> list[dict]:
    base = c.file(f"takeover/{tag}")
    for p in (base, base.with_suffix(".json")):
        _rotate(p)
    await c.runner.run("takeover", ["dnsreaper", *args, "--out", str(base), "--out-format", "json", "--parallelism", "20"],
                       c.timeout("takeover", 30))
    # dnsReaper appends the format extension to --out
    for p in (base.with_suffix(".json"), base):
        if p.exists():
            return parse_dnsreaper(_load_json_any(p))
    return []


async def st_takeover(c: Ctx) -> dict:
    hosts = sorted(c.all_hosts)
    if not hosts:
        raise StageSkip("no hosts")
    f = c.file("takeover/hosts.txt")
    f.write_text("\n".join(hosts) + "\n")
    found = await _dnsreaper_run(c, "dnsreaper", ["file", "--filename", str(f)])
    zone_names = 0
    token = c.secrets.get("cloud_cloudflare")
    if token and c.options.get("takeover_zones", True):
        # Every record in your Cloudflare zones, including names no enumeration found. Still DNS-only.
        c.runner.event("takeover", "Also checking every record in your Cloudflare zones (read-only token).")
        try:
            zone = await _dnsreaper_run(c, "dnsreaper-cloudflare", ["cloudflare", "--cloudflare-token", token])
            zone = [z for z in zone if _under(z["domain"], c.roots) and z["domain"] not in set(c.exclusions)]
            zone_names = len({z["domain"] for z in zone} - set(hosts))
            found += zone
        except StageFailed as exc:
            c.runner.event("takeover", f"Cloudflare zone check failed ({exc}); file-based results kept.", "warn")
    # baddns over the LIVE hosts catches dangling SaaS/CNAME records that resolve fine (and so never reach the
    # dnsonly pass) — e.g. a CNAME to sites.framer.app or *.herokuapp.com. Light-touch (DNS + a little HTTP).
    from .pipeline import run_baddns
    baddns = await run_baddns(c, sorted(c.light_hosts)) if c.options.get("takeover_deep", True) else []
    seen = set()
    counts = {"hosts_checked": len(hosts), "confirmed": 0, "potential": 0, "unlikely": 0, "from_zones_only": zone_names,
              "baddns_live_hits": 0}
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "dnsreaper")
            _clear(db, c.scan_id, "baddns-live")   # deep-pass findings are kept separate from the dnsonly baddns ones
            for b in baddns:
                if not _under(b["host"], c.roots):
                    continue
                counts["baddns_live_hits"] += 1
                _finding(db, c.scan_id, "exposure", b["severity"], b["title"], b["host"], "baddns-live", b.get("url"), efile=b.get("efile"))
            for r in found:
                key = (r["domain"], r["signature"])
                if key in seen or not _under(r["domain"], c.roots):
                    continue
                seen.add(key)
                conf = r["confidence"] if r["confidence"] in DNSREAPER_SEV else "potential"
                counts[conf] += 1
                if conf == "unlikely" and not c.options.get("takeover_include_unlikely"):
                    continue
                _finding(db, c.scan_id, "exposure", DNSREAPER_SEV[conf],
                         f"Possible subdomain takeover ({r['signature']}, {conf})", r["domain"], "dnsreaper",
                         (r["info"] + (" " + r["more_info"] if r["more_info"] else "")).strip()[:400] or None, efile="takeover/dnsreaper.json")
    finally:
        db.close()
    return counts


# ---- checkdmarc: SPF / DMARC / MTA-STS / TLS-RPT / BIMI ---------------------------------

def _tag(dmarc: dict, name: str):
    t = (dmarc.get("tags") or {}).get(name)
    return t.get("value") if isinstance(t, dict) else t


def email_findings(r: dict) -> list[tuple[str, str]]:
    """(severity, title) for one checkdmarc domain result."""
    out: list[tuple[str, str]] = []
    mx_hosts = (r.get("mx") or {}).get("hosts") or []
    spf = r.get("spf") or {}
    dmarc = r.get("dmarc") or {}
    rec = str(spf.get("record") or "")
    if not rec:
        out.append(("medium" if mx_hosts else "low",
                    "No SPF record" if mx_hosts else "Domain sends no mail but isn't locked down (v=spf1 -all)"))
    else:
        lookups = spf.get("dns_lookups")
        if isinstance(lookups, int) and lookups > 10:
            out.append(("high", f"SPF needs {lookups} DNS lookups (limit 10): receivers treat it as a permanent error"))
        elif spf.get("valid") is False or spf.get("error"):
            out.append(("medium", f"SPF record is invalid: {str(spf.get('error') or 'parse error')[:160]}"))
        voids = spf.get("dns_void_lookups")
        if isinstance(voids, int) and voids > 2:
            out.append(("low", f"SPF has {voids} void lookups (limit 2)"))
        tail = rec.rstrip().split()[-1].lower() if rec.split() else ""
        if tail in ("+all", "all"):
            out.append(("high", "SPF allows any sender (+all)"))
        elif tail == "?all":
            out.append(("low", "SPF ends with ?all (neutral): it doesn't reject anyone"))
    if not dmarc.get("record"):
        out.append(("high", "No DMARC record: the domain can be spoofed"))
    else:
        p = str(_tag(dmarc, "p") or "").lower()
        sp = str(_tag(dmarc, "sp") or p).lower()
        pct = _tag(dmarc, "pct")
        if dmarc.get("valid") is False or dmarc.get("error"):
            out.append(("medium", f"DMARC record has errors: {str(dmarc.get('error') or 'invalid')[:160]}"))
        if p == "none":
            out.append(("medium", "DMARC policy is p=none (monitoring only)"))
        elif p == "quarantine":
            out.append(("low", "DMARC policy is quarantine, not reject"))
        if p in ("quarantine", "reject") and sp == "none":
            out.append(("medium", "DMARC subdomain policy is sp=none: subdomains can be spoofed"))
        try:
            if pct is not None and int(pct) < 100:
                out.append(("low", f"DMARC applies to only {int(pct)}% of mail (pct={int(pct)})"))
        except (TypeError, ValueError):
            pass
        if not _tag(dmarc, "rua"):
            out.append(("low", "No DMARC aggregate reports (rua): spoofing attempts go unseen"))
    if mx_hosts:
        sts = r.get("mta_sts") or {}
        if not sts.get("valid"):
            out.append(("low", "No valid MTA-STS policy: mail to you can be downgraded to plaintext"))
        elif str((sts.get("policy") or {}).get("mode") or "").lower() == "testing":
            out.append(("low", "MTA-STS policy is in testing mode"))
        rpt = r.get("smtp_tls_reporting") or r.get("tls_rpt") or {}
        if not rpt.get("valid"):
            out.append(("info", "No TLS-RPT record (SMTP TLS failure reports)"))
        for h in mx_hosts:
            if h.get("starttls") is False and "starttls" in h:
                out.append(("medium", f"Mail server doesn't offer STARTTLS: {h.get('hostname')}"))
    return out


def _posture(r: dict) -> dict:
    spf, dmarc = r.get("spf") or {}, r.get("dmarc") or {}
    sts = r.get("mta_sts") or {}
    return {
        "domain": r.get("domain"), "mx": [h.get("hostname") for h in (r.get("mx") or {}).get("hosts") or []],
        "spf": spf.get("record"), "spf_lookups": spf.get("dns_lookups"), "dmarc": dmarc.get("record"),
        "dmarc_policy": (str(_tag(dmarc, "p") or "").lower() or None) if dmarc.get("record") else None,
        "mta_sts": bool(sts.get("valid")), "mta_sts_mode": (sts.get("policy") or {}).get("mode"),
        "tls_rpt": bool((r.get("smtp_tls_reporting") or {}).get("valid")), "bimi": bool((r.get("bimi") or {}).get("record")),
        "dnssec": r.get("dnssec"),
    }


async def st_email_checkdmarc(c: Ctx) -> dict:
    out = c.file("email/checkdmarc.json")
    _rotate(out)
    argv = ["checkdmarc", *c.roots, "-f", "json", "-o", str(out)]
    if not c.options.get("email_starttls"):
        argv.append("--skip-tls")      # default: DNS (and the public MTA-STS policy file) only, no SMTP connections
    await c.runner.run("email", argv, c.timeout("email", 10))
    data = _load_json_any(out)
    results = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    if not results:
        raise StageFailed("checkdmarc wrote no results")
    posture, n = [], 0
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "dns-email")
            _clear(db, c.scan_id, "checkdmarc")
            for r in results:
                d = str(r.get("domain") or "").lower()
                if not d:
                    continue
                posture.append(_posture(r))
                for sev, title in email_findings(r):
                    _finding(db, c.scan_id, "email", sev, title, d, "checkdmarc", efile="email/checkdmarc.json")
                    n += 1
    finally:
        db.close()
    c.file("email/posture.json").write_text(json.dumps(posture, indent=2))
    return {"domains": len(posture), "dmarc_reject": sum(p["dmarc_policy"] == "reject" for p in posture),
            "spf_over_limit": sum(1 for p in posture if (p["spf_lookups"] or 0) > 10),
            "mta_sts": sum(p["mta_sts"] for p in posture), "findings": n}


# ---- testssl.sh on a handful of key hosts ---------------------------------------------

TESTSSL_SEV = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
TESTSSL_SAFE = ["--protocols", "--server-defaults", "--server-preference", "--std", "--headers"]
TESTSSL_SKIP_IDS = re.compile(r"^(scanTime|engine_problem|service|pre_|clientsimulation|cipher_order|DNS_CAArecord$|cert_crlDistributionPoints)")


def testssl_hosts(c: Ctx) -> list[str]:
    chosen = [h for h in c.options.get("testssl_hosts") or [] if h in c.light_hosts]
    if chosen:
        return chosen[: int(c.options.get("testssl_max_hosts", 5))]
    db = c.db()
    try:
        rows = {r["host"]: r for r in db.all("SELECT host, is_live, http_status FROM assets WHERE scan_id = ?", c.scan_id)}
    finally:
        db.close()
    live = [h for h in c.light_hosts if rows.get(h) and rows[h]["is_live"]]
    roots_first = sorted(live, key=lambda h: (0 if h in c.roots else 1 if h.startswith("www.") and h[4:] in c.roots else 2,
                                              status_rank(rows[h]["http_status"]), len(h)))
    return roots_first[: int(c.options.get("testssl_max_hosts", 5))]


def parse_testssl(data) -> list[dict]:
    rows = data if isinstance(data, list) else data.get("scanResult", []) if isinstance(data, dict) else []
    flat = []
    for r in rows:
        if isinstance(r, dict) and "id" in r:
            flat.append(r)
        elif isinstance(r, dict):           # --json-pretty layout: sections of lists
            for v in r.values():
                if isinstance(v, list):
                    flat += [x for x in v if isinstance(x, dict) and "id" in x]
    return flat


async def st_tls_deep(c: Ctx) -> dict:
    hosts = testssl_hosts(c)
    if not hosts:
        raise StageSkip("no live hosts to test")
    vuln = bool(c.options.get("testssl_vuln_checks"))
    if vuln:
        c.runner.event("tls_deep", "Vulnerability probes are ON: testssl.sh will send deliberately malformed TLS handshakes "
                                   "(Heartbleed, CCS, ROBOT...). Make sure this is covered by your authorisation.", "warn")
    counts = {"hosts": 0, "high": 0, "medium": 0, "low": 0, "grades": {}}
    per_host = max(300, c.timeout("tls_deep", 60) // max(1, len(hosts)))
    db = c.db()
    try:
        _clear(db, c.scan_id, "testssl")
    finally:
        db.close()
    for h in hosts:
        out = c.file(f"tls/testssl/{h}.json")
        _rotate(out)
        argv = ["testssl.sh", "--quiet", "--warnings", "batch", "--color", "0", "--ip", "one", "--connect-timeout", "10",
                "--openssl-timeout", "10", *TESTSSL_SAFE, *(["--vulnerable"] if vuln else []), "--jsonfile", str(out), h]
        try:
            await c.runner.run("tls_deep", argv, per_host, line_filter=lambda l: False)
        except StageFailed as exc:
            c.runner.event("tls_deep", f"{h}: {exc}; moving on.", "warn")
        rows = parse_testssl(_load_json_any(out))
        if not rows:
            continue
        counts["hosts"] += 1
        db = c.db()
        try:
            with db.tx():
                for r in rows:
                    rid = str(r.get("id", ""))
                    if rid == "overall_grade":
                        counts["grades"][h] = r.get("finding")
                    sev = TESTSSL_SEV.get(str(r.get("severity", "")).upper())
                    if not sev or TESTSSL_SKIP_IDS.match(rid):
                        continue
                    counts[sev] += 1
                    title = f"TLS ({rid}): {str(r.get('finding', '')).strip()}"[:200]
                    _finding(db, c.scan_id, "tls", sev, title, h, "testssl",
                             " ".join(x for x in (str(r.get("cve") or ""), str(r.get("cwe") or "")) if x).strip() or None, efile=f"tls/testssl/{h}.json")
        finally:
            db.close()
    grades = counts.pop("grades")
    return counts | {"vulnerability_probes": vuln, "tested": ", ".join(hosts),
                     "grades": ", ".join(f"{h} {g}" for h, g in grades.items()) or "n/a"}


# ---- cloudlist: cloud inventory (import, or read-only keys) ---------------------------

def cloudlist_import_path(c_or_state) -> Path:
    cfg = c_or_state.state.cfg if hasattr(c_or_state, "state") else c_or_state.cfg
    return cfg.data_dir / "imports" / "cloudlist.jsonl"


def parse_cloudlist(text: str) -> list[dict]:
    """cloudlist -json lines, or a plain list of IPs/hostnames (what `cloudlist -silent` prints)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append({
                "provider": str(r.get("provider") or ""), "service": str(r.get("service") or ""), "id": str(r.get("id") or ""),
                "ip": str(r.get("public_ipv4") or r.get("ip") or r.get("public_ipv6") or ""),
                "host": str(r.get("dns_name") or r.get("host") or r.get("hostname") or "").lower().rstrip("."),
            })
        else:
            tok = line.split()[0].strip(",")
            if is_ip(tok):
                if is_public_ip(tok):
                    out.append({"provider": "", "service": "", "id": "", "ip": tok, "host": ""})
            elif re.fullmatch(r"[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\.?", tok):
                out.append({"provider": "", "service": "", "id": "", "ip": "", "host": tok.lower().rstrip(".")})
    return [r for r in out if r["ip"] or r["host"]]


def cloudlist_provider_config(secrets: dict[str, str]) -> list[dict]:
    cfg = []
    if secrets.get("cloud_aws") and ":" in secrets["cloud_aws"]:
        k, s = secrets["cloud_aws"].split(":", 1)
        cfg.append({"provider": "aws", "id": "outsider", "aws_access_key": k, "aws_secret_key": s})
    if secrets.get("cloud_gcp"):
        cfg.append({"provider": "gcp", "id": "outsider", "gcp_service_account_key": secrets["cloud_gcp"]})
    if secrets.get("cloud_azure") and secrets["cloud_azure"].count(":") >= 3:
        t, cl, sec, sub = secrets["cloud_azure"].split(":", 3)
        cfg.append({"provider": "azure", "id": "outsider", "tenant_id": t, "client_id": cl, "client_secret": sec,
                    "subscription_id": sub})
    if secrets.get("cloud_cloudflare"):
        cfg.append({"provider": "cloudflare", "id": "outsider", "api_token": secrets["cloud_cloudflare"]})
    if secrets.get("cloud_do"):
        cfg.append({"provider": "do", "id": "outsider", "digitalocean_token": secrets["cloud_do"]})
    return cfg


async def st_cloudlist(c: Ctx) -> dict:
    items: list[dict] = []
    sources = []
    imp = cloudlist_import_path(c)
    if imp.exists():
        items += [r | {"via": "import"} for r in parse_cloudlist(imp.read_text(errors="replace"))]
        sources.append("upload")
    providers = cloudlist_provider_config(c.secrets)
    if providers:
        cfg = c.file("cloud/.provider-config.yaml")
        fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            yaml.safe_dump(providers, fh)
        out = c.file("cloud/cloudlist.jsonl")
        try:
            await c.runner.run("cloudlist", ["cloudlist", "-pc", str(cfg), "-json", "-silent", "-duc", "-o", str(out)],
                               c.timeout("cloudlist", 15))
        finally:
            cfg.unlink(missing_ok=True)       # never leave keys on disk
        if out.exists():
            items += [r | {"via": "keys"} for r in parse_cloudlist(out.read_text(errors="replace"))]
        sources.append("keys (" + ", ".join(p["provider"] for p in providers) + ")")
    if not items and not providers and not imp.exists():
        raise StageSkip("no cloudlist upload and no cloud keys saved")
    db = c.db()
    try:
        known_ips = {ip for r in db.all("SELECT ips FROM assets WHERE scan_id = ?", c.scan_id) for ip in json.loads(r["ips"])}
        known_hosts = {r["host"] for r in db.all("SELECT host FROM assets WHERE scan_id = ?", c.scan_id)} | c.all_hosts
    finally:
        db.close()
    ips = sorted({r["ip"] for r in items if r["ip"] and is_public_ip(r["ip"])})
    c.file("cloud/cloudlist_ips.txt").write_text("\n".join(ips) + ("\n" if ips else ""))
    unknown_ips = [ip for ip in ips if ip not in known_ips]
    outside = sorted({r["host"] for r in items if r["host"] and r["host"] not in known_hosts})
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "cloudlist")
            for r in items:
                if r["ip"] and r["ip"] in unknown_ips:
                    _upsert_asset(db, c.scan_id, r["ip"], ips=[r["ip"]], found_by=["cloudlist"])
            if unknown_ips:
                label = lambda ip: next((f"{r['provider']} {r['service']}".strip() for r in items if r["ip"] == ip), "cloud")
                for ip in unknown_ips[:300]:
                    _finding(db, c.scan_id, "surface", "low", "Public cloud IP that no DNS name points to", ip, "cloudlist",
                             label(ip) or None, efile="cloud/cloudlist.jsonl")
            for h in outside[:300]:
                sev = "low" if _under(h, c.roots) else "info"
                _finding(db, c.scan_id, "surface", sev,
                         "Cloud DNS name not found by discovery" if _under(h, c.roots) else "Cloud DNS name outside the scan's root domains",
                         h, "cloudlist", efile="cloud/cloudlist.jsonl")
    finally:
        db.close()
    return {"sources": ", ".join(sources) or "none", "assets": len(items), "public_ips": len(ips),
            "ips_without_dns": len(unknown_ips), "names_not_discovered": len(outside)}


# ---- exposure intelligence: InternetDB / Shodan CVEs ranked by CISA KEV and EPSS -------

async def _kev(c: Ctx) -> dict[str, dict]:
    cache = c.state.cfg.data_dir / "cache" / "kev.json"
    if not cache.exists() or time.time() - cache.stat().st_mtime > 86400:
        try:
            data = await c.providers.http_json(KEV_URL, timeout=60)
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data))
        except Exception as exc:
            if not cache.exists():
                c.runner.event("intel", f"Couldn't download the CISA KEV catalogue: {exc}", "warn")
                return {}
            c.runner.event("intel", "Using yesterday's cached KEV catalogue (download failed).", "warn")
    data = json.loads(cache.read_text())
    return {v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")}


EPSS_TTL = 86400              # EPSS is a once-a-day model, so a day-old score is fine to reuse


async def _epss(c: Ctx, cves: list[str]) -> dict[str, float]:
    """EPSS score per CVE, cached for a day so repeat scans don't re-query the same CVEs."""
    cache = c.state.cfg.data_dir / "cache" / "epss.json"
    blob: dict = {}
    if cache.exists():
        try:
            blob = json.loads(cache.read_text())
        except Exception:
            blob = {}
    fetched = blob.get("fetched", 0)
    scores: dict[str, float] = blob.get("scores", {}) if (time.time() - fetched) < EPSS_TTL else {}
    if not scores:
        fetched = time.time()
    out = {v: float(scores[v]) for v in cves if v in scores}
    need = [v for v in cves if v not in out]
    for i in range(0, len(need), 80):
        batch = need[i:i + 80]
        try:
            data = await c.providers.http_json(f"{EPSS_URL}?cve={','.join(batch)}", timeout=60)
        except Exception as exc:
            c.runner.event("intel", f"EPSS lookup failed for {len(batch)} CVEs: {exc}", "warn")
            continue
        for r in (data or {}).get("data", []):
            try:
                out[r["cve"]] = scores[r["cve"]] = float(r["epss"])
            except (KeyError, TypeError, ValueError):
                pass
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"fetched": fetched, "scores": scores}))
    except Exception:
        pass
    return out


# ---- NVD enrichment: CVSS, CWE and affected-version verification ----------------------
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_INTERVAL_NOKEY = 6.5      # NVD allows ~5 requests / 30s without a key
NVD_INTERVAL_KEY = 0.7        # ~50 / 30s with a free key
NVD_MAX_LOOKUPS = 120         # uncached lookups per scan (cached CVEs are free); the rest fill in next run
NVD_TTL = 14 * 86400          # a published CVE record barely changes, so cache it for a fortnight


def _ver(s: str | None):
    """A comparable version object: packaging.Version if it parses, else a numeric tuple, else None."""
    s = (s or "").strip()
    if not s or s in ("*", "-"):
        return None
    try:
        from packaging.version import Version
        return Version(s)
    except Exception:
        nums = re.findall(r"\d+", s)
        return tuple(int(n) for n in nums) if nums else None


def _version_in_range(running_cpe: str, ranges: list[dict]) -> str | None:
    """Compare the running CPE's version against a CVE's affected ranges, but only ranges for the SAME
    product (same CPE vendor:product) — a version number is meaningless across products. 'in' if it
    falls in a vulnerable range, 'out' if clearly outside every same-product range, None if undecidable."""
    rparts = running_cpe.split(":")
    if len(rparts) < 6:
        return None
    r_vendor, r_product, version = rparts[3], rparts[4], rparts[5]
    v = _ver(version)
    if v is None or not ranges:
        return None
    saw_decidable = False
    for r in ranges:
        cparts = (r.get("cpe") or "").split(":")
        if len(cparts) < 6 or cparts[4] != r_product or cparts[3] != r_vendor:
            continue                          # different product: not comparable by version
        si, se = _ver(r.get("startInc")), _ver(r.get("startExc"))
        ei, ee = _ver(r.get("endInc")), _ver(r.get("endExc"))
        bounds = [si, se, ei, ee]
        if not any(x is not None for x in bounds):
            exact = _ver(cparts[5]) if len(cparts) > 5 else None
            if exact is None:
                continue                      # version '*' CPE: can't use version to decide
            saw_decidable = True
            if type(exact) is type(v) and exact == v:
                return "in"
            continue
        ok, comparable = True, True
        try:
            if si is not None and not (type(si) is type(v) and v >= si):
                ok = False
            if se is not None and not (type(se) is type(v) and v > se):
                ok = False
            if ei is not None and not (type(ei) is type(v) and v <= ei):
                ok = False
            if ee is not None and not (type(ee) is type(v) and v < ee):
                ok = False
        except TypeError:
            comparable = False
        if not comparable:
            continue
        saw_decidable = True
        if ok:
            return "in"
    return "out" if saw_decidable else None


def _parse_nvd(cve_obj: dict) -> dict:
    metrics = cve_obj.get("metrics", {}) or {}
    cvss = severity = vector = None
    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(mk) or []
        if arr:
            d = arr[0].get("cvssData", {}) or {}
            cvss = d.get("baseScore")
            severity = (arr[0].get("baseSeverity") or d.get("baseSeverity") or "").upper() or None
            vector = d.get("vectorString")
            break
    cwes: list[str] = []
    for w in cve_obj.get("weaknesses", []) or []:
        for desc in w.get("description", []) or []:
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    ranges: list[dict] = []
    for cfg in cve_obj.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                ranges.append({"cpe": m.get("criteria", ""),
                               "startInc": m.get("versionStartIncluding"), "startExc": m.get("versionStartExcluding"),
                               "endInc": m.get("versionEndIncluding"), "endExc": m.get("versionEndExcluding")})
    return {"cvss": cvss, "severity": severity, "vector": vector, "cwes": cwes[:4],
            "published": (cve_obj.get("published") or "")[:10], "ranges": ranges[:40]}


async def _nvd(c: Ctx, cves: list[str]) -> dict[str, dict]:
    """CVSS, CWE and affected-version ranges per CVE from the NVD 2.0 API, cached per-CVE on disk.
    Only the actionable CVEs are enriched, so the per-scan request count stays small."""
    cache_dir = c.state.cfg.data_dir / "cache" / "nvd"
    cache_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, dict] = {}
    pending: list[str] = []
    for v in cves:
        f = cache_dir / f"{v}.json"
        if f.exists() and time.time() - f.stat().st_mtime < NVD_TTL:
            try:
                out[v] = json.loads(f.read_text())
                continue
            except Exception:
                pass
        pending.append(v)
    key = c.secrets.get("nvd")
    headers = {"apiKey": key} if key else None
    interval = NVD_INTERVAL_KEY if key else NVD_INTERVAL_NOKEY
    for i, v in enumerate(pending[:NVD_MAX_LOOKUPS]):
        if i:
            await asyncio.sleep(interval)
        try:
            data = await c.providers.http_json(f"{NVD_URL}?cveId={v}", headers=headers, timeout=40) or {}
        except Exception as exc:
            c.runner.event("intel", f"NVD lookup for {v} failed: {exc}", "warn")
            continue
        vulns = data.get("vulnerabilities") or []
        parsed = _parse_nvd(vulns[0]["cve"]) if vulns and vulns[0].get("cve") else \
            {"cvss": None, "severity": None, "vector": None, "cwes": [], "published": "", "ranges": []}
        out[v] = parsed
        try:
            (cache_dir / f"{v}.json").write_text(json.dumps(parsed))
        except Exception:
            pass
    if len(pending) > NVD_MAX_LOOKUPS:
        c.runner.event("intel", f"NVD: enriched {NVD_MAX_LOOKUPS} CVEs this scan; "
                                f"{len(pending) - NVD_MAX_LOOKUPS} more will fill in on the next run.", "warn")
    return out


def _cvss_tail(v: str, nvd: dict) -> str:
    """' · CVSS 9.8 (CRITICAL) · CWE-787' from enrichment, or '' if unknown."""
    e = nvd.get(v) or {}
    bits = []
    if e.get("cvss") is not None:
        sev = f" ({e['severity']})" if e.get("severity") else ""
        bits.append(f"CVSS {e['cvss']}{sev}")
    if e.get("cwes"):
        bits.append(", ".join(e["cwes"][:2]))
    return (" · " + " · ".join(bits)) if bits else ""


def _cpe_version(cpe: str) -> str:
    parts = cpe.split(":")
    return parts[5] if len(parts) > 5 else ""


async def st_intel(c: Ctx) -> dict:
    ips = _own_ips(c)
    cpef = c.run_dir / "tech" / "cpes.json"
    if not ips and not cpef.exists():
        raise StageSkip("no public IPs of yours known (CDN and shared-platform IPs are excluded)")
    targets = sorted(ips)[:400]
    sem = asyncio.Semaphore(5)
    per_ip: dict[str, dict] = {}

    async def idb(ip: str) -> None:
        async with sem:
            try:
                d = await c.providers.http_json(f"https://internetdb.shodan.io/{ip}", timeout=30) or {}
            except Exception as exc:
                if _http_code(exc) != 404:
                    c.runner.event("intel", f"InternetDB {ip}: {exc}", "warn")
                d = {}
            per_ip[ip] = {"ports": d.get("ports") or [], "cpes": d.get("cpes") or [], "vulns": set(d.get("vulns") or []),
                          "products": []}
    await asyncio.gather(*(idb(ip) for ip in targets))
    shodan_key = c.secrets.get("shodan")
    used_shodan = 0
    if shodan_key and c.settings.shodan_lookups:
        # host lookups are free on a free account; 1 request/second
        for ip in [ip for ip in targets if per_ip[ip]["ports"]][:100]:
            try:
                d = await c.providers.http_json(f"https://api.shodan.io/shodan/host/{ip}?key={urllib.parse.quote(shodan_key)}",
                                                timeout=30) or {}
                used_shodan += 1
                per_ip[ip]["vulns"] |= set((d.get("vulns") or []) if isinstance(d.get("vulns"), list) else (d.get("vulns") or {}).keys())
                per_ip[ip]["products"] = sorted({f"{x.get('product')} {x.get('version') or ''}".strip()
                                                 for x in d.get("data", []) if x.get("product")})[:10]
            except Exception as exc:
                if _http_code(exc) == 401:
                    c.runner.event("intel", "Shodan rejected the key; continuing with InternetDB only.", "warn")
                    break
            await asyncio.sleep(1.1)
    netlas = c.run_dir / "intel" / "netlas_cves.json"
    if netlas.exists():
        for ip, cves in json.loads(netlas.read_text()).items():
            if ip in per_ip:
                per_ip[ip]["vulns"] |= set(cves)
    # software versions fingerprinted on your web pages -> CVEs via Shodan's free CVEDB
    tech_cves: dict[str, dict[str, set[str]]] = {}
    if cpef.exists():
        host_cpes = json.loads(cpef.read_text() or "{}")
        by_cpe = await cves_for_cpes(c, sorted({x for v in host_cpes.values() for x in v}))
        for h, cps in host_cpes.items():
            for cp in cps:
                if by_cpe.get(cp):
                    tech_cves.setdefault(h, {})[cp] = set(by_cpe[cp])
    cve_re = re.compile(r"^CVE-\d{4}-\d{4,}$")
    all_cves = sorted({v for d in per_ip.values() for v in d["vulns"] if cve_re.match(v)} |
                      {v for m in tech_cves.values() for s in m.values() for v in s if cve_re.match(v)})
    kev = await _kev(c) if all_cves else {}
    epss = await _epss(c, all_cves) if all_cves else {}
    # enrich the CVEs that actually matter (KEV or likely-exploited) with CVSS / CWE / affected-version
    # ranges from NVD, so the findings carry authoritative scores and can be version-checked.
    actionable = sorted({v for v in all_cves if v in kev or epss.get(v, 0) >= EPSS_LIKELY})
    nvd = await _nvd(c, actionable) if actionable else {}
    counts = {"ips_checked": len(targets), "shodan_lookups": used_shodan, "cves": len(all_cves),
              "kev": sum(1 for v in all_cves if v in kev), "epss_likely": sum(1 for v in all_cves if v not in kev and epss.get(v, 0) >= EPSS_LIKELY),
              "nvd_enriched": sum(1 for v in actionable if nvd.get(v, {}).get("cvss") is not None)}
    report = {}
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "intel-cve")
            for ip, d in per_ip.items():
                hosts = ips.get(ip, [])
                where = ", ".join(hosts[:3]) or ip
                cves = sorted(v for v in d["vulns"] if v in all_cves)
                if not cves:
                    continue
                report[ip] = {"hosts": hosts, "cves": [{"cve": v, "kev": v in kev, "epss": epss.get(v),
                                                        "cvss": (nvd.get(v) or {}).get("cvss")} for v in cves],
                              "products": d["products"], "cpes": d["cpes"]}
                rest = []
                for v in cves:
                    if v in kev:
                        k = kev[v]
                        rw = " · used in ransomware" if str(k.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
                        _finding(db, c.scan_id, "vulns", "high",
                                 f"Known-exploited vulnerability reported (CISA KEV, unverified version match): {v}", where,
                                 "intel-cve", (f"{ip} · {k.get('vendorProject', '')} {k.get('product', '')}: "
                                               f"{k.get('vulnerabilityName', '')}{rw}{_cvss_tail(v, nvd)}")[:400], efile="intel/cves.json")
                    elif epss.get(v, 0) >= EPSS_LIKELY:
                        _finding(db, c.scan_id, "vulns", "medium",
                                 f"Likely-exploited vulnerability reported (EPSS {epss[v]:.0%}, unverified): {v}", where,
                                 "intel-cve", f"{ip}{_cvss_tail(v, nvd)}", efile="intel/cves.json")
                    else:
                        rest.append(v)
                if rest:
                    _finding(db, c.scan_id, "vulns", "info",
                             f"{len(rest)} CVE{'s' if len(rest) != 1 else ''} suggested by service banners (low exploit likelihood)",
                             where, "intel-cve", f"{ip}: " + ", ".join(rest[:20]), efile="intel/cves.json")
            for h, by in tech_cves.items():
                for cp, cves in by.items():
                    product = " ".join(cp.split(":")[3:6])
                    running = _cpe_version(cp)
                    rest = []
                    for v in sorted(cves):
                        verdict = _version_in_range(cp, (nvd.get(v) or {}).get("ranges", [])) if running else None
                        vtag = {"in": f" · running {running} is in the affected range",
                                "out": f" · running {running} appears outside the affected ranges"}.get(verdict, "")
                        if v in kev:
                            # a version that matches the affected range turns a fingerprint guess into a confirmed hit
                            conf = "version confirmed in affected range" if verdict == "in" else "version from page fingerprint, unverified"
                            _finding(db, c.scan_id, "vulns", "high",
                                     f"Known-exploited vulnerability for {product} (CISA KEV, {conf}): {v}",
                                     h, "intel-cve", (f"{kev[v].get('vulnerabilityName', '')}{_cvss_tail(v, nvd)}{vtag}")[:300] or None, efile="intel/cves.json")
                        elif epss.get(v, 0) >= EPSS_LIKELY:
                            _finding(db, c.scan_id, "vulns", "medium",
                                     f"Likely-exploited vulnerability for {product} (EPSS {epss[v]:.0%}, version from page fingerprint): {v}",
                                     h, "intel-cve", f"{cp}{_cvss_tail(v, nvd)}{vtag}", efile="intel/cves.json")
                        else:
                            rest.append(v)
                    if rest:
                        _finding(db, c.scan_id, "vulns", "info",
                                 f"{len(rest)} CVE{'s' if len(rest) != 1 else ''} listed for {product} (low exploit likelihood)",
                                 h, "intel-cve", ", ".join(rest[:20]), efile="intel/cves.json")
                report.setdefault("by_host", {})[h] = {cp: sorted(v) for cp, v in by.items()}
    finally:
        db.close()
    counts["software_versions_checked"] = sum(len(v) for v in tech_cves.values())
    c.file("intel/cves.json").write_text(json.dumps(report, indent=2))
    return counts


# ---- exposure feeds: LeakIX and Netlas (free keys) ------------------------------------

LEAK_SEV = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}


async def st_feeds(c: Ctx) -> dict:
    leakix, netlas = c.secrets.get("leakix"), c.secrets.get("netlas")
    if not leakix and not netlas:
        raise StageSkip("no LeakIX or Netlas key saved (both have free tiers)")
    counts = {"leakix_leaks": 0, "leakix_services": 0, "netlas_records": 0, "netlas_requests": 0, "hosts_not_in_scope": 0}
    unknown: dict[str, set[str]] = {}
    db = c.db()
    try:
        _clear(db, c.scan_id, "leakix")
        _clear(db, c.scan_id, "netlas")
    finally:
        db.close()
    raw: dict[str, object] = {}
    if leakix:
        for d in c.roots:
            try:
                data = await c.providers.http_json(f"https://leakix.net/domain/{urllib.parse.quote(d)}",
                                                   headers={"api-key": leakix, "Accept": "application/json"}, timeout=60) or {}
            except Exception as exc:
                code = _http_code(exc)
                if code == 404:
                    data = {}
                else:
                    c.runner.event("feeds", f"LeakIX {d}: {exc}" + (" (daily free quota used up?)" if code == 429 else ""), "warn")
                    continue
            raw[f"leakix:{d}"] = data
            services = (data.get("Services") or data.get("services") or []) if isinstance(data, dict) else []
            leaks = (data.get("Leaks") or data.get("leaks") or []) if isinstance(data, dict) else []
            counts["leakix_services"] += len(services)
            db = c.db()
            try:
                with db.tx():
                    for ev in services + leaks:
                        host = str(ev.get("host") or "").lower().rstrip(".")
                        if host and _under(host, c.roots) and host not in c.all_hosts:
                            unknown.setdefault(host, set()).add("LeakIX")
                    for ev in leaks:
                        host = str(ev.get("host") or ev.get("ip") or d).lower()
                        if host not in c.all_hosts and not _under(host, c.roots) and host != str(ev.get("ip")):
                            continue
                        leak = ev.get("leak") or {}
                        sev = LEAK_SEV.get(str(leak.get("severity") or "").lower(), "medium")
                        counts["leakix_leaks"] += 1
                        _finding(db, c.scan_id, "exposure", sev,
                                 f"LeakIX reports an exposed {ev.get('event_source') or 'service'} ({leak.get('type') or 'leak'})",
                                 host, "leakix", f"{ev.get('ip', '')}:{ev.get('port', '')} {str(ev.get('summary') or '')[:200]}".strip(), efile="intel/feeds_raw.json")
            finally:
                db.close()
            await asyncio.sleep(1.5)
    netlas_cves: dict[str, list[str]] = {}
    if netlas:
        budget = int(c.options.get("netlas_max_requests", 5))
        for d in c.roots:
            for page in range(budget):
                if counts["netlas_requests"] >= budget:
                    break
                q = urllib.parse.quote(f"host:*.{d} OR host:{d}")
                try:
                    data = await c.providers.http_json(f"https://app.netlas.io/api/responses/?q={q}&start={page * 20}",
                                                       headers={"X-API-Key": netlas}, timeout=60) or {}
                except Exception as exc:
                    code = _http_code(exc)
                    c.runner.event("feeds", f"Netlas: {exc}" + (" (daily free quota used up?)" if code in (402, 429) else ""), "warn")
                    break
                counts["netlas_requests"] += 1
                items = data.get("items") or []
                raw[f"netlas:{d}:{page}"] = data
                for it in items:
                    x = it.get("data") or {}
                    counts["netlas_records"] += 1
                    host, ip = str(x.get("host") or "").lower(), str(x.get("ip") or "")
                    if host and _under(host, c.roots) and host not in c.all_hosts:
                        unknown.setdefault(host, set()).add("Netlas")
                    for cv in x.get("cve") or []:
                        name = cv.get("name") if isinstance(cv, dict) else cv
                        if ip and name:
                            netlas_cves.setdefault(ip, []).append(str(name))
                if len(items) < 20:
                    break
                await asyncio.sleep(1.0)
    c.file("intel/netlas_cves.json").write_text(json.dumps({k: sorted(set(v)) for k, v in netlas_cves.items()}, indent=2))
    c.file("intel/feeds_raw.json").write_text(json.dumps(raw, indent=1, default=str)[:20_000_000])
    db = c.db()
    try:
        with db.tx():
            for h, srcs in sorted(unknown.items())[:300]:
                _finding(db, c.scan_id, "surface", "low", "Host seen by exposure feeds but not in scan scope", h,
                         "leakix" if "LeakIX" in srcs else "netlas", ", ".join(sorted(srcs)), efile="intel/feeds_raw.json")
    finally:
        db.close()
    counts["hosts_not_in_scope"] = len(unknown)
    return counts


# ---- openSquat: newly registered lookalike domains (free community feed) --------------

def parse_opensquat(data) -> list[dict]:
    rows = data if isinstance(data, list) else (data.get("results") or data.get("domains") or []) if isinstance(data, dict) else []
    out = []
    for r in rows:
        if isinstance(r, str):
            out.append({"domain": r.lower().strip(), "keyword": "", "confidence": ""})
        elif isinstance(r, dict) and (r.get("domain") or r.get("name")):
            out.append({"domain": str(r.get("domain") or r.get("name")).lower().strip(), "keyword": str(r.get("keyword") or ""),
                        "confidence": str(r.get("confidence") or r.get("level") or "")})
    return [r for r in out if "." in r["domain"]]


async def st_squat(c: Ctx) -> dict:
    brands = sorted({r.split(".")[0] for r in c.roots if len(r.split(".")[0]) >= 3})
    if not brands:
        raise StageSkip("root domains too short to use as keywords")
    kw = c.file("squat/keywords.txt")
    kw.write_text("\n".join(brands) + "\n")
    out = c.file("squat/opensquat.json")
    _rotate(out)
    argv = ["opensquat", "-k", str(kw), "-o", str(out), "-t", "json", "-c", str(int(c.options.get("opensquat_confidence", 1)))]
    env = {}
    if c.options.get("opensquat_portcheck"):
        argv.append("--portcheck")
        c.runner.event("squat", "Port check is ON: openSquat will connect to suspected lookalike domains on 80/443. Those are "
                                "someone else's servers (possibly an attacker's) and will see this machine's IP.", "warn")
    if c.options.get("opensquat_premium") and c.secrets.get("opensquat"):
        argv.append("--premium")
        env["OPENSQUAT_API_KEY"] = c.secrets["opensquat"]
    await c.runner.run("squat", argv, c.timeout("squat", 20), env=env, cwd=c.file("squat/work/.keep").parent)
    rows = [r for r in parse_opensquat(_load_json_any(out)) if not _under(r["domain"], c.roots)]
    db = c.db()
    try:
        known = {m.group(1) for r in db.all("SELECT title FROM findings WHERE scan_id = ? AND source_tool = 'dnstwist'", c.scan_id)
                 for m in [re.search(r": (\S+)$", r["title"])] if m}
        with db.tx():
            _clear(db, c.scan_id, "opensquat")
            new = 0
            for r in rows[:300]:
                if r["domain"] in known:
                    continue
                root = next((x for x in c.roots if x.split(".")[0] in r["domain"]), c.roots[0])
                sev, note = lookalike_severity(root, r["domain"], "")
                sev = "low" if sev == "medium" and not note else sev
                _finding(db, c.scan_id, "brand", sev, f"Newly registered lookalike{note}: {r['domain']}", root, "opensquat",
                         f"keyword {r['keyword']}" + (f", confidence {r['confidence']}" if r["confidence"] else ""), efile="squat/opensquat.json")
                new += 1
    finally:
        db.close()
    return {"keywords": len(brands), "matches": len(rows), "new_vs_dnstwist": new,
            "port_check": bool(c.options.get("opensquat_portcheck"))}


# ---- urlscan.io: pages already seen in the wild (search only) --------------------------

async def st_urlscan(c: Ctx) -> dict:
    key = c.secrets.get("urlscan")
    headers = {"API-Key": key} if key else {}
    counts = {"searches": 0, "pages_on_your_domains": 0, "hosts_not_in_scope": 0, "live_lookalikes": 0}
    seen_hosts: set[str] = set()
    raw = {}

    async def search(q: str, size: int = 100) -> list[dict]:
        if counts["searches"] >= 60:
            return []
        try:
            data = await c.providers.http_json(f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(q)}&size={size}",
                                               headers=headers, timeout=60) or {}
        except Exception as exc:
            code = _http_code(exc)
            c.runner.event("urlscan", f"urlscan search '{q}': {exc}" + (" (rate limit; a free key raises it)" if code == 429 else ""),
                           "warn")
            return []
        finally:
            counts["searches"] += 1
            await asyncio.sleep(1.0 if key else 2.5)
        raw[q] = data
        return data.get("results") or []

    for d in c.roots:
        for r in await search(f"page.domain:{d}"):
            h = str((r.get("page") or {}).get("domain") or "").lower()
            counts["pages_on_your_domains"] += 1
            if h and _under(h, c.roots):
                seen_hosts.add(h)
    db = c.db()
    try:
        look = []
        for r in db.all("SELECT title, host, source_tool FROM findings WHERE scan_id = ? AND area = 'brand'", c.scan_id):
            m = re.search(r": (\S+)$", r["title"])
            if m and m.group(1) not in look:
                look.append(m.group(1))
    finally:
        db.close()
    hits = []
    for dom in look[:40]:
        res = await search(f"page.domain:{dom}", size=5)
        if res:
            r0 = res[0]
            hits.append((dom, str((r0.get("task") or {}).get("time") or "")[:10], r0.get("result") or "",
                         str((r0.get("page") or {}).get("title") or "")[:80]))
    outside = sorted(seen_hosts - c.all_hosts)
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "urlscan")
            for h in outside[:300]:
                _finding(db, c.scan_id, "surface", "low", "Host seen on urlscan.io but not in scan scope", h, "urlscan", efile="urlscan/search.json")
            for dom, when, link, title in hits:
                counts["live_lookalikes"] += 1
                _finding(db, c.scan_id, "brand", "medium", f"Lookalike domain has pages on urlscan.io: {dom}", dom, "urlscan",
                         f"last seen {when}" + (f" · '{title}'" if title else "") + (f" · {link.replace('/api/v1/result/', '/result/')}"
                                                                                       if link else ""), efile="urlscan/search.json")
    finally:
        db.close()
    counts["hosts_not_in_scope"] = len(outside)
    c.file("urlscan/search.json").write_text(json.dumps(raw, indent=1)[:10_000_000])
    return counts


# ---- SpiderFoot sidecar, passive use case only ------------------------------------------

SF_HOST_TYPES = {"INTERNET_NAME", "AFFILIATE_INTERNET_NAME", "DOMAIN_NAME", "CO_HOSTED_SITE"}
SF_FINDING_TYPES = {
    "LEAKSITE_CONTENT": ("medium", "Content mentioning you on a leak/paste site"),
    "LEAKSITE_URL": ("medium", "Your data referenced on a leak/paste site"),
    "EMAILADDR_COMPROMISED": ("medium", "Compromised email address"),
    "PASSWORD_COMPROMISED": ("high", "Compromised password reported"),
    "MALICIOUS_INTERNET_NAME": ("high", "Host flagged as malicious by a threat feed"),
    "MALICIOUS_IPADDR": ("high", "IP flagged as malicious by a threat feed"),
    "BLACKLISTED_INTERNET_NAME": ("medium", "Host on a blocklist"),
    "BLACKLISTED_IPADDR": ("medium", "IP on a blocklist"),
    "CLOUD_STORAGE_BUCKET_OPEN": ("high", "Open cloud storage bucket"),
    "PUBLIC_CODE_REPO": ("info", "Public code repository"),
    "SIMILARDOMAIN": ("low", "Similar domain"),
}


async def st_spiderfoot(c: Ctx) -> dict:
    base = c.settings.spiderfoot_url.rstrip("/")
    hdr = {"Accept": "application/json"}
    try:
        await c.providers.http_json(f"{base}/ping", headers=hdr, timeout=10)
    except Exception as exc:
        raise StageSkip(f"SpiderFoot sidecar not reachable at {base} ({type(exc).__name__}). "
                        "Start it with: docker compose --profile spiderfoot up -d")
    usecase = c.options.get("spiderfoot_usecase", "passive")
    if usecase not in ("passive", "footprint", "investigate", "all"):
        usecase = "passive"
    if usecase != "passive":
        c.runner.event("spiderfoot", f"SpiderFoot use case is '{usecase}', not passive: some modules will contact your hosts "
                                     "directly (and 'all' includes port scanning and brute-force modules).", "warn")
    ids = []
    for d in c.roots:
        form = urllib.parse.urlencode({"scanname": f"outsider-{c.scan_id}-{d}", "scantarget": d, "usecase": usecase,
                                       "modulelist": "", "typelist": ""}).encode()
        res = await c.providers.http_json(f"{base}/startscan", data=form,
                                          headers=hdr | {"Content-Type": "application/x-www-form-urlencoded"}, timeout=60)
        if not (isinstance(res, list) and len(res) > 1 and str(res[0]).upper() == "SUCCESS"):
            raise StageFailed(f"SpiderFoot refused the scan for {d}: {str(res)[:200]}")
        ids.append(str(res[1]))
        c.runner.event("spiderfoot", f"SpiderFoot passive scan started for {d} (id {res[1]}).")
    deadline = time.monotonic() + c.timeout("spiderfoot", 120) - 120
    pending = set(ids)
    while pending and time.monotonic() < deadline:
        await c.runner.wait_while_paused()
        if c.runner.cancelled:
            for sid in pending:
                try:
                    await c.providers.http_json(f"{base}/stopscan?id={sid}", headers=hdr, timeout=20)
                except Exception:
                    pass
            raise StageFailed("cancelled")
        for sid in list(pending):
            try:
                st = await c.providers.http_json(f"{base}/scanstatus?id={sid}", headers=hdr, timeout=20)
                status = str(st[5]).upper() if isinstance(st, list) and len(st) > 5 else ""
            except Exception:
                status = ""
            if status in ("FINISHED", "ABORTED", "ERROR-FAILED"):
                pending.discard(sid)
        if pending:
            await asyncio.sleep(30)
    if pending:
        c.runner.event("spiderfoot", f"{len(pending)} SpiderFoot scan(s) still running at the time limit; importing what's there.", "warn")
    events = await c.providers.http_json(f"{base}/scanexportjsonmulti?ids={','.join(ids)}", headers=hdr, timeout=120) or []
    c.file("spiderfoot/events.json").write_text(json.dumps(events, indent=1)[:50_000_000])
    new_hosts, counts = set(), {"events": len(events), "new_hosts": 0, "findings": 0}
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "spiderfoot")
            done = set()
            for e in events:
                et, data = str(e.get("event_type") or e.get("type") or ""), str(e.get("data") or "")
                if e.get("false_positive"):
                    continue
                if et in SF_HOST_TYPES:
                    h = data.lower().rstrip(".")
                    if _under(h, c.roots) and h not in c.all_hosts:
                        new_hosts.add(h)
                elif et in SF_FINDING_TYPES and (et, data) not in done and len(done) < 500:
                    done.add((et, data))
                    sev, title = SF_FINDING_TYPES[et]
                    host = str(e.get("source_data") or "")[:200] if _under(str(e.get("source_data") or "x.invalid"), c.roots) else None
                    _finding(db, c.scan_id, "intel", sev, f"SpiderFoot: {title}", host, "spiderfoot", data[:300], efile="spiderfoot/events.json")
                    counts["findings"] += 1
            for h in sorted(new_hosts)[:300]:
                _finding(db, c.scan_id, "surface", "low", "Host found by SpiderFoot but not in scan scope", h, "spiderfoot", efile="spiderfoot/events.json")
    finally:
        db.close()
    counts["new_hosts"] = len(new_hosts)
    return counts


# ---- technology fingerprints (Wappalyzer rules, community fork) -------------------------

WAPPALYZER_DIRS = [Path(os.environ.get("ASM_WAPPALYZER_DIR", "/opt/wappalyzer"))]
CVEDB_URL = "https://cvedb.shodan.io/cves"


def _find_tech_dir() -> Path | None:
    for base in WAPPALYZER_DIRS:
        if not base.exists():
            continue
        if (base / "a.json").exists():
            return base
        for p in sorted(base.rglob("technologies")):
            if (p / "a.json").exists() or any(p.glob("*.json")):
                return p
    return None


def _pattern(raw) -> list[tuple[re.Pattern, str | None]]:
    r"""Wappalyzer pattern 'regex\;version:\1\;confidence:50' -> (compiled regex, version template)."""
    out = []
    for item in (raw if isinstance(raw, list) else [raw]):
        if not isinstance(item, str):
            continue
        parts = item.split("\\;")
        version = next((p[8:] for p in parts[1:] if p.startswith("version:")), None)
        try:
            out.append((re.compile(parts[0], re.I), version))
        except re.error:
            continue
    return out


def load_fingerprints(tech_dir: Path) -> dict[str, dict]:
    techs: dict[str, dict] = {}
    for f in sorted(tech_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(errors="replace"))
        except json.JSONDecodeError:
            continue
        for name, t in data.items():
            if not isinstance(t, dict):
                continue
            techs[name] = {
                "headers": {k.lower(): _pattern(v) for k, v in (t.get("headers") or {}).items()},
                "cookies": {k.lower(): _pattern(v) for k, v in (t.get("cookies") or {}).items()},
                "meta": {k.lower(): _pattern(v) for k, v in (t.get("meta") or {}).items()},
                "html": _pattern(t.get("html") or []),
                "scriptSrc": _pattern(t.get("scriptSrc") or t.get("scripts") or []),
                "url": _pattern(t.get("url") or []),
                "implies": [i.split("\\;")[0] for i in (t.get("implies") if isinstance(t.get("implies"), list)
                                                         else [t["implies"]] if t.get("implies") else [])],
                "cpe": t.get("cpe"),
            }
    return techs


def _version(tpl: str | None, m: re.Match) -> str:
    if not tpl:
        return ""
    def sub(mm: re.Match) -> str:
        i = int(mm.group(1))
        try:
            return m.group(i) or ""
        except IndexError:
            return ""
    v = re.sub(r"\\(\d)", sub, tpl)
    if "?" in v:                     # ternary "\\1?a:b" after substitution: "x?a:b" / "?a:b"
        cond, _, rest = v.partition("?")
        a, _, b = rest.partition(":")
        v = a if cond else b
    v = v.strip()
    return v if re.fullmatch(r"[\w.\-+]{1,30}", v) else ""


def fingerprint(page: dict, techs: dict[str, dict]) -> dict[str, str]:
    """Technology name -> version ('' if unknown) for one fetched page."""
    body = page.get("body") or ""
    headers = {k.lower(): str(v) for k, v in (page.get("headers") or {}).items()}
    cookies = {c.lower() for c in page.get("cookies") or []}
    metas: dict[str, str] = {}
    for m in re.finditer(r"<meta\b[^>]*>", body[:200_000], re.I):
        tag = m.group(0)
        n = re.search(r"""(?:name|property)\s*=\s*["']([^"']+)""", tag, re.I)
        c = re.search(r"""content\s*=\s*["']([^"']*)""", tag, re.I)
        if n and c:
            metas[n.group(1).lower()] = c.group(1)
    scripts = re.findall(r"""<script[^>]+src\s*=\s*["']([^"']+)""", body[:300_000], re.I)
    html = body[:300_000]
    found: dict[str, str] = {}

    def hit(name: str, pats, text: str) -> None:
        for rx, tpl in pats:
            m = rx.search(text)
            if m:
                v = _version(tpl, m)
                if name not in found or (v and not found[name]):
                    found[name] = v
                return

    for name, t in techs.items():
        for h, pats in t["headers"].items():
            if h in headers:
                hit(name, pats or [(re.compile(""), None)], headers[h])
        for ck, pats in t["cookies"].items():
            if ck in cookies:
                found.setdefault(name, "")
        for mk, pats in t["meta"].items():
            if mk in metas:
                hit(name, pats, metas[mk])
        if t["scriptSrc"]:
            for s in scripts:
                hit(name, t["scriptSrc"], s)
        if t["html"]:
            hit(name, t["html"], html)
        if t["url"]:
            hit(name, t["url"], page.get("url") or "")
    # implied technologies (WordPress -> PHP, ...)
    queue = list(found)
    while queue:
        for imp in techs.get(queue.pop(), {}).get("implies", []):
            if imp in techs and imp not in found:
                found[imp] = ""
                queue.append(imp)
    return found


def versioned_cpe(cpe: str | None, version: str) -> str | None:
    if not cpe or not version:
        return None
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    parts[5] = version
    return ":".join(parts)


async def st_tech(c: Ctx) -> dict:
    tech_dir = _find_tech_dir()
    if not tech_dir:
        raise StageSkip("Wappalyzer fingerprints aren't installed in this image (rebuild the container)")
    techs = load_fingerprints(tech_dir)
    db = c.db()
    try:
        rows = db.all("SELECT host, web_url FROM assets WHERE scan_id = ? AND is_live = 1 AND web_url IS NOT NULL", c.scan_id)
    finally:
        db.close()
    from .pipeline import _valid_web_url
    # a malformed stored address (seen from an early BBOT 3 parse) falls back to https://host/
    targets = [(r["host"], r["web_url"] if _valid_web_url(r["web_url"]) else f"https://{r['host']}/")
               for r in rows if r["host"] in c.light_hosts][:300]
    if not targets:
        raise StageSkip("no live web hosts")
    c.runner.event("tech", f"Fetching the front page of {len(targets)} live hosts (one ordinary request each) and matching "
                           f"{len(techs)} Wappalyzer fingerprints.")
    sem = asyncio.Semaphore(8)
    results: dict[str, dict[str, str]] = {}
    failed: list[str] = []

    async def one(host: str, url: str) -> None:
        async with sem:
            await c.runner.wait_while_paused()
            if c.runner.cancelled:
                return
            try:
                page = await c.providers.http_page(url, timeout=15)
                if page:
                    results[host] = fingerprint(page, techs)
            except Exception as exc:             # one odd page never fails the stage
                failed.append(host)
                c.runner.event("tech", f"{host}: couldn't fingerprint ({type(exc).__name__}: {str(exc)[:120]})", "warn")
    await asyncio.gather(*(one(h, u) for h, u in targets))
    cpes: dict[str, list[str]] = {}
    db = c.db()
    try:
        with db.tx():
            for host, found in results.items():
                _upsert_asset(db, c.scan_id, host, tech=[f"{n} {v}".strip() for n, v in found.items()])
                for n, v in found.items():
                    cp = versioned_cpe(techs.get(n, {}).get("cpe"), v)
                    if cp:
                        cpes.setdefault(host, []).append(cp)
    finally:
        db.close()
    c.file("tech/fingerprints.json").write_text(json.dumps(results, indent=2))
    c.file("tech/cpes.json").write_text(json.dumps(cpes, indent=2))
    return {"hosts_fetched": len(results), "hosts_failed": len(failed), "technologies": len({n for f in results.values() for n in f}),
            "with_versions": len({f"{n} {v}" for f in results.values() for n, v in f.items() if v}),
            "cpes": len({x for v in cpes.values() for x in v})}


async def cves_for_cpes(c: Ctx, cpes: list[str]) -> dict[str, list[str]]:
    """CVE IDs per CPE from Shodan's free CVEDB (no key)."""
    out: dict[str, list[str]] = {}
    for cp in cpes[:100]:
        try:
            data = await c.providers.http_json(f"{CVEDB_URL}?cpe23={urllib.parse.quote(cp)}&limit=200", timeout=30) or {}
        except Exception as exc:
            if _http_code(exc) != 404:
                c.runner.event("intel", f"CVEDB lookup for {cp}: {exc}", "warn")
            continue
        ids = [str(x.get("cve_id") or x.get("cve") or "") for x in data.get("cves", []) if isinstance(x, dict)]
        out[cp] = [i for i in ids if i.startswith("CVE-")]
        await asyncio.sleep(0.3)
    return out


# ---- dnsx: full DNS record snapshot (DNS only) -------------------------------------------

DNS_TYPES = ("a", "aaaa", "cname", "mx", "ns", "txt", "caa")


def parse_dnsx(text: str) -> dict[str, dict[str, list[str]]]:
    out: dict[str, dict[str, list[str]]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(r.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        rec = out.setdefault(host, {})
        for t in DNS_TYPES:
            vals = r.get(t) or []
            if isinstance(vals, (str, dict)):
                vals = [vals]
            for v in vals:
                if isinstance(v, dict):         # some dnsx versions emit CAA as objects
                    v = " ".join(str(x) for x in v.values())
                v = str(v).strip().rstrip(".")
                if v and v not in rec.setdefault(t.upper(), []):
                    rec[t.upper()].append(v)
    return out


DNS_BRUTE_WORDS = (
    "www api dev staging stage test qa uat prod preprod demo beta alpha sandbox admin portal app apps web mail smtp "
    "imap pop webmail mx mx1 mx2 ns ns1 ns2 dns vpn remote gateway gw proxy cdn static assets img images media files "
    "download downloads docs doc wiki blog shop store cart checkout pay payment payments billing invoice support help "
    "status monitor monitoring metrics grafana kibana prometheus jenkins ci cd git gitlab github jira confluence "
    "dashboard console manage internal intranet extranet corp office hr finance legal m mobile auth login sso idp "
    "oauth accounts account id identity secure vault secrets config api1 api2 api-dev api-staging v1 v2 v3 graphql ws "
    "socket live events data db database sql mysql postgres redis cache queue mq kafka s3 backup backups old legacy "
    "new beta2 edge origin lb loadbalancer k8s kube cluster node1 node2 registry harbor nexus artifactory email "
    "newsletter crm erp analytics tracking pixel tag cms wp wordpress drupal partner partners vendor vendors client "
    "clients customer customers public private test1 test2 demo1 uat1 training lab labs research"
).split()


async def st_dns(c: Ctx) -> dict:
    hosts = sorted(c.all_hosts | set(c.roots))
    if not hosts:
        raise StageSkip("no hosts")
    f = c.file("dns/hosts.txt")
    f.write_text("\n".join(hosts) + "\n")
    out = c.file("dns/dnsx.jsonl")
    _rotate(out)
    await c.runner.run("dns", ["dnsx", "-l", str(f), *[f"-{t}" for t in DNS_TYPES], "-resp", "-json", "-silent",
                               "-t", "20", "-rl", "100", "-duc", "-o", str(out)], c.timeout("dns", 15))
    recs = parse_dnsx(out.read_text(errors="replace") if out.exists() else "")
    import ipaddress
    private = []
    db = c.db()
    try:
        with db.tx():
            db.run("DELETE FROM dns_records WHERE scan_id = ?", c.scan_id)
            _clear(db, c.scan_id, "dnsx")
            for host, rr in recs.items():
                for t, vals in rr.items():
                    for v in vals:
                        db.run("INSERT OR IGNORE INTO dns_records (scan_id, host, rtype, value) VALUES (?, ?, ?, ?)",
                               c.scan_id, host, t, v[:1000])
                bad = []
                for ip in rr.get("A", []) + rr.get("AAAA", []):
                    try:
                        a = ipaddress.ip_address(ip)
                        if a.is_private or a.is_loopback or a.is_link_local:
                            bad.append(ip)
                    except ValueError:
                        pass
                if bad:
                    private.append(host)
                    _finding(db, c.scan_id, "exposure", "low", "Public DNS name resolves to a private/internal address",
                             host, "dnsx", ", ".join(bad[:5]), efile="dns/dnsx.jsonl")
    finally:
        db.close()
    counts = {"hosts": len(recs), "records": sum(len(v) for r in recs.values() for v in r.values()),
              "cnames": sum(1 for r in recs.values() if r.get("CNAME")), "private_addresses": len(private),
              "brute_new_hosts": 0, "ptr_names": 0, "cohosted_found": 0}
    if c.options.get("reverse_dns", True):
        counts["ptr_names"], counts["cohosted_found"] = await _reverse_dns(c)
    if c.options.get("dns_bruteforce"):
        counts["brute_new_hosts"] = await _dns_brute(c, set(c.all_hosts))
    return counts


def parse_dnsx_ptr(text: str) -> dict[str, list[str]]:
    """dnsx -ptr -json: {ip: [names]}."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = str(r.get("host") or r.get("ip") or "").strip()
        names = r.get("ptr") or r.get("a") or []
        if isinstance(names, str):
            names = [names]
        if ip:
            for n in names:
                n = str(n).strip().rstrip(".").lower()
                if n and n not in out.setdefault(ip, []):
                    out[ip].append(n)
    return out


async def _reverse_dns(c: Ctx) -> tuple[int, int]:
    """PTR lookups on your own public IPs (not CDN/shared): finds co-hosted names discovery may have missed."""
    ips = sorted(_own_ips(c))
    if not ips:
        return 0, 0
    f = c.file("dns/own_ips.txt")
    f.write_text("\n".join(ips) + "\n")
    out = c.file("dns/ptr.jsonl")
    _rotate(out)
    try:
        await c.runner.run("dns", ["dnsx", "-l", str(f), "-ptr", "-resp", "-json", "-silent", "-t", "20", "-rl", "100",
                                   "-duc", "-o", str(out)], c.timeout("dns", 15))
    except StageFailed as exc:
        c.runner.event("dns", f"reverse DNS failed: {exc}", "warn")
        return 0, 0
    ptr = parse_dnsx_ptr(out.read_text(errors="replace") if out.exists() else "")
    names = {n for v in ptr.values() for n in v}
    known = {h.lower() for h in c.all_hosts}
    cohosted = 0
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "ptr")
            for ip, ns in ptr.items():
                for n in ns:
                    db.run("INSERT OR IGNORE INTO dns_records (scan_id, host, rtype, value) VALUES (?, ?, 'PTR', ?)",
                           c.scan_id, ip, n[:1000])
                new = [n for n in ns if _under(n, c.roots) and n not in known]
                for n in new:
                    cohosted += 1
                    _finding(db, c.scan_id, "surface", "low", "Co-hosted name found by reverse DNS (not in discovery)",
                             n, "ptr", f"shares {ip}", efile="dns/ptr.jsonl")
    finally:
        db.close()
    return len(names), cohosted


async def _dns_brute(c: Ctx, known: set[str]) -> int:
    """Opt-in subdomain brute: resolve a wordlist against each root. Active — many queries to the target's DNS."""
    c.runner.event("dns", f"ACTIVE: brute-forcing {len(DNS_BRUTE_WORDS)} subdomain names against your DNS for each root "
                          f"domain ({len(c.roots)} roots). This is a lot of DNS queries from this machine's IP.", "warn")
    wl = c.file("dns/wordlist.txt")
    wl.write_text("\n".join(DNS_BRUTE_WORDS) + "\n")
    new = 0
    db = c.db()
    try:
        for root in c.roots:
            out = c.file(f"dns/brute_{root}.jsonl")
            _rotate(out)
            try:
                await c.runner.run("dns", ["dnsx", "-d", root, "-w", str(wl), "-a", "-cname", "-resp", "-json",
                                           "-silent", "-t", "40", "-rl", "500", "-duc", "-o", str(out)], c.timeout("dns", 15))
            except StageFailed as exc:
                c.runner.event("dns", f"brute of {root} failed: {exc}", "warn")
                continue
            recs = parse_dnsx(out.read_text(errors="replace") if out.exists() else "")
            with db.tx():
                for host, rr in recs.items():
                    host = host.lower().rstrip(".")
                    if not _under(host, c.roots):
                        continue
                    for t, vals in rr.items():
                        for v in vals:
                            db.run("INSERT OR IGNORE INTO dns_records (scan_id, host, rtype, value) VALUES (?, ?, ?, ?)",
                                   c.scan_id, host, t, v[:1000])
                    if host not in known:
                        new += 1
                        _finding(db, c.scan_id, "surface", "low", "Subdomain found by DNS brute-force (not in discovery)",
                                 host, "dnsx", ", ".join(rr.get("A", []) + rr.get("CNAME", []))[:200] or None, efile=f"dns/brute_{root}.jsonl")
    finally:
        db.close()
    return new


# ---- naabu: opt-in active port confirmation (TCP connect, low rate) --------------------

TOP_100_PORTS = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199,
                 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
                 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
                 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
                 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
                 49156, 49157]


def parse_naabu(text: str) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip, port = str(r.get("ip") or r.get("host") or ""), r.get("port")
            if isinstance(port, dict):
                port = port.get("Port") or port.get("port")
        else:
            ip, _, port = line.rpartition(":")
        try:
            out.setdefault(ip, set()).add(int(port))
        except (TypeError, ValueError):
            pass
    return out


async def st_port_check(c: Ctx) -> dict:
    ips = _own_ips(c)
    if not ips:
        raise StageSkip("no public IPs of yours known (CDN and shared-platform IPs are never scanned)")
    db = c.db()
    try:
        reported: dict[str, set[int]] = {}
        for r in db.all("SELECT ips, ports FROM assets WHERE scan_id = ?", c.scan_id):
            for ip in json.loads(r["ips"]):
                if ip in ips:
                    reported.setdefault(ip, set()).update(int(p) for p in json.loads(r["ports"]))
    finally:
        db.close()
    targets = sorted(ips)[:256]
    ports = sorted(set(TOP_100_PORTS) | {p for s in reported.values() for p in s if 0 < p < 65536})
    c.runner.event("port_check", f"ACTIVE: TCP connect checks on {len(ports)} ports across {len(targets)} of your own IPs "
                                 "(~100 packets/second). CDN edges and shared third-party platforms are excluded.", "warn")
    f = c.file("services/port_check_ips.txt")
    f.write_text("\n".join(targets) + "\n")
    out = c.file("services/naabu.jsonl")
    _rotate(out)
    await c.runner.run("port_check", ["naabu", "-list", str(f), "-p", ",".join(map(str, ports)), "-s", "c", "-rate", "100",
                                      "-c", "25", "-retries", "1", "-timeout", "1500", "-json", "-silent", "-duc", "-o", str(out)],
                       c.timeout("port_check", 30))
    found = parse_naabu(out.read_text(errors="replace") if out.exists() else "")
    from .pipeline import RISKY_PORTS
    counts = {"ips_checked": len(targets), "ports_per_ip": len(ports), "confirmed_open": 0, "not_in_shodan": 0,
              "shodan_but_closed": 0, "new_risky": 0}
    report = {}
    db = c.db()
    try:
        with db.tx():
            _clear(db, c.scan_id, "naabu")
            for ip in targets:
                open_now, rep = found.get(ip, set()), reported.get(ip, set())
                counts["confirmed_open"] += len(open_now)
                new, stale = open_now - rep, rep - open_now
                counts["not_in_shodan"] += len(new)
                counts["shodan_but_closed"] += len(stale)
                report[ip] = {"open": sorted(open_now), "new": sorted(new), "closed_since_shodan": sorted(stale)}
                hosts = ips.get(ip, [])
                for h in hosts or [ip]:
                    row = db.one("SELECT ports_confirmed FROM assets WHERE scan_id = ? AND host = ?", c.scan_id, h)
                    if row is not None:
                        db.run("UPDATE assets SET ports_confirmed = ? WHERE scan_id = ? AND host = ?",
                               json.dumps(sorted(open_now)), c.scan_id, h)
                where = ", ".join(hosts[:3]) or ip
                for p in sorted(new):
                    if p in RISKY_PORTS:
                        sev, label = RISKY_PORTS[p]
                        counts["new_risky"] += 1
                        _finding(db, c.scan_id, "exposure", sev, f"{label} exposed on port {p} (confirmed, not in Shodan's data)",
                                 where, "naabu", f"{ip}:{p}", efile="services/port_check.json")
                if new:
                    _finding(db, c.scan_id, "exposure", "info", f"{len(new)} open port{'s' if len(new) != 1 else ''} not in Shodan's data",
                             where, "naabu", f"{ip}: " + ", ".join(map(str, sorted(new))), efile="services/port_check.json")
                if stale:
                    _finding(db, c.scan_id, "exposure", "info",
                             f"{len(stale)} port{'s' if len(stale) != 1 else ''} Shodan lists as open are closed now",
                             where, "naabu", f"{ip}: " + ", ".join(map(str, sorted(stale))), efile="services/port_check.json")
    finally:
        db.close()
    c.file("services/port_check.json").write_text(json.dumps(report, indent=2))
    return counts
