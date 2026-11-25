"""Stage D1: passive discovery of subdomains and related-domain suggestions.

Nothing here contacts the target's own servers. Sources: BBOT's passive modules
(third-party datasets), certificate transparency (crt.sh), DNS lookups through
resolvers, and optionally WhoisXML. Results become scope_items for you to review.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets as pysecrets
import socket
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .db import DB, now


# --- SSRF guard for outbound page fetches ------------------------------------
def _resolved_ips_public(host: str) -> bool:
    """True only if the host resolves and every resolved address is a global (public) IP.
    Blocks fetches/redirects to loopback, link-local (incl. the 169.254.169.254 cloud-metadata
    address), private and reserved ranges. urllib re-resolves at connect time, so this is not by
    itself a full DNS-rebinding defence; it does stop a scanned target redirecting us to an
    internal address, which is the realistic vector here (self-host)."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    seen = False
    for info in infos:
        seen = True
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return False
        except ValueError:
            return False
    return seen


class _PublicOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to http(s) targets that resolve entirely to public IPs."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme not in ("http", "https") or not _resolved_ips_public(parts.hostname or ""):
            raise urllib.error.URLError(f"blocked redirect to non-public or non-http target: {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(_PublicOnlyRedirectHandler())
from .domains import is_third_party, registrable_domain, shares_brand, under
from .runner import ACTIVE, Runner, StageCancelled, StageFailed
from .scope import ScopeError, host_of, normalise_domain
from .secrets_store import SecretStore
from .settings_model import Settings

SOURCES = ("certificates", "dns_infra", "whois", "affiliates")
# BBOT 3 risk flags to exclude on every run (BBOT 2's "aggressive"/"deadly" no longer exist)
BBOT_EXCLUDE_FLAGS = ["invasive", "loud", "download", "web-heavy", "web-paramminer", "iis-shortnames"]
MAX_CANDIDATES = 5000
RESOLVE_CONCURRENCY = 40
CRT_BACKOFF_S = 3.0

# Our secret name -> prefix of BBOT module names that take that service's API key.
# Actual module names are read from the installed BBOT at runtime, because they change between
# releases (e.g. BBOT 3 replaced "censys" with "censys_ip"), and BBOT refuses to start if its
# config names a module that doesn't exist.
BBOT_KEY_PREFIXES = {
    "shodan": "shodan", "censys": "censys", "securitytrails": "securitytrails",
    "virustotal": "virustotal", "chaos": "chaos", "github": "github",
}


def bbot_key_modules() -> dict[str, list[str]]:
    """Map our secret names to installed BBOT modules that take an API key.

    A module qualifies if its own file mentions api_key, or if it inherits from a BBOT template
    class (bbot/modules/templates/*.py) that does, e.g. github_codesearch(github) or
    virustotal(subdomain_enum_apikey). Read from the installed package so renames don't break it.
    """
    import importlib.util
    import re as _re
    try:
        spec = importlib.util.find_spec("bbot")
    except (ImportError, ValueError):
        spec = None
    if not spec or not spec.origin:
        return {}
    mods_dir = Path(spec.origin).parent / "modules"
    class_re = _re.compile(r"^class\s+(\w+)\s*\(([^)]*)\)", _re.M)

    keyed_templates: set[str] = set()
    for p in sorted((mods_dir / "templates").glob("*.py")):
        try:
            src = p.read_text(errors="replace")
        except OSError:
            continue
        if "api_key" in src:
            keyed_templates.update(m.group(1) for m in class_re.finditer(src))
            keyed_templates.add(p.stem)

    found: dict[str, list[str]] = {}
    for p in sorted(mods_dir.glob("*.py")):
        name = p.stem
        if name.startswith("_") or name == "base":
            continue
        try:
            src = p.read_text(errors="replace")
        except OSError:
            continue
        bases = {b.strip().split(".")[-1] for m in class_re.finditer(src) for b in m.group(2).split(",")}
        if "api_key" not in src and not (bases & keyed_templates):
            continue
        for secret, prefix in BBOT_KEY_PREFIXES.items():
            if name.startswith(prefix):
                found.setdefault(secret, []).append(name)
    return found


# ---- providers (real network vs test doubles) ------------------------------

class Providers:
    """Network access used by discovery. Tests substitute a fake."""

    def __init__(self, user_agent: str):
        self.ua = user_agent
        self._resolver = None

    def _r(self):
        if self._resolver is None:
            import dns.asyncresolver  # provided by dnspython (a BBOT dependency)
            r = dns.asyncresolver.Resolver()
            r.lifetime = 6.0
            r.timeout = 3.0
            self._resolver = r
        return self._resolver

    async def records(self, name: str, rtype: str) -> list[str]:
        import dns.exception
        import dns.resolver
        try:
            ans = await self._r().resolve(name, rtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer):
            return []
        except Exception:
            return []
        out = []
        for rr in ans:
            if rtype == "MX":
                out.append(str(rr.exchange).rstrip(".").lower())
            elif rtype in ("NS", "CNAME"):
                out.append(str(rr.target).rstrip(".").lower())
            elif rtype == "TXT":
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            else:
                out.append(rr.to_text())
        return out

    async def resolve(self, name: str) -> dict | None:
        """CNAME chain + IPs, or None if the name doesn't exist."""
        import dns.exception
        import dns.resolver
        cnames: list[str] = []
        ips: list[str] = []
        try:
            for rtype in ("A", "AAAA"):
                ans = await self._r().resolve(name, rtype, raise_on_no_answer=False)
                if ans.rrset is not None:
                    ips += [rr.to_text() for rr in ans.rrset]
                for rrset in ans.response.answer:
                    if rrset.rdtype == 5:  # CNAME
                        cnames += [str(rr.target).rstrip(".").lower() for rr in rrset]
        except dns.resolver.NXDOMAIN:
            return None
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return {"cname": [], "ips": [], "error": "lookup failed"}
        return {"cname": list(dict.fromkeys(cnames)), "ips": sorted(set(ips))}

    async def http_json(self, url: str, headers: dict | None = None, data: bytes | None = None,
                        timeout: int = 60) -> Any:
        def go():
            req = urllib.request.Request(url, data=data, headers={"User-Agent": self.ua, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace") or "null")
        return await asyncio.to_thread(go)


    async def http_page(self, url: str, timeout: int = 15, max_bytes: int = 512 * 1024) -> dict | None:
        """One ordinary GET (redirects followed): status, lower-cased headers, Set-Cookie names, body text, final URL."""
        def go():
            parts = urllib.parse.urlsplit(url)
            if parts.scheme not in ("http", "https") or not _resolved_ips_public(parts.hostname or ""):
                return None     # SSRF guard: only fetch public http(s) hosts
            try:
                req = urllib.request.Request(url, headers={"User-Agent": self.ua, "Accept": "text/html,*/*;q=0.8"})
                r = _SAFE_OPENER.open(req, timeout=timeout)
            except urllib.error.HTTPError as e:
                r = e
            except Exception:
                return None
            with r:
                body = r.read(max_bytes).decode("utf-8", "replace")
                hdrs: dict[str, str] = {}
                for k, v in r.headers.items():
                    k = k.lower()
                    hdrs[k] = f"{hdrs[k]}, {v}" if k in hdrs and k != "set-cookie" else v
                cookies = [c.split("=", 1)[0].strip() for c in r.headers.get_all("Set-Cookie") or []]
                return {"status": getattr(r, "status", None) or r.getcode(), "headers": hdrs, "cookies": cookies,
                        "body": body, "url": r.geturl()}
        return await asyncio.to_thread(go)


# ---- candidate collection ------------------------------------------------

@dataclass
class Cand:
    value: str
    kind: str                       # subdomain | related
    sources: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)
    grp: str | None = None
    third_party: bool = False

    def add(self, source: str, reason: str) -> None:
        self.sources.add(source)
        if reason not in self.reasons and len(self.reasons) < 6:
            self.reasons.append(reason)


class Collector:
    def __init__(self, target: str, roots: list[str], providers_list: list[str]):
        self.target = target
        self.roots = roots
        self.third = providers_list
        self.c: dict[str, Cand] = {}

    def add(self, name: str, source: str, reason: str) -> None:
        try:
            host = normalise_domain(host_of(name).lstrip("*.").lstrip("."))
        except ScopeError:
            return
        if len(self.c) >= MAX_CANDIDATES and host not in self.c:
            return
        if any(under(host, r) for r in self.roots):
            kind = "subdomain"
            value = host
        else:
            kind = "related"
            value = registrable_domain(host)
            if any(under(value, r) for r in self.roots):
                return
        cand = self.c.setdefault(value, Cand(value, kind))
        cand.add(source, reason)
        if kind == "related" and is_third_party(value, self.third):
            cand.third_party = True


def related_confidence(sources: set[str]) -> str:
    if "certificates" in sources or len(sources - {"subdomain-enum"}) >= 2:
        return "high"
    if sources & {"dns_infra", "whois"}:
        return "medium"
    return "low"


# ---- the stage -------------------------------------------------------------

def _write_bbot_config(store: SecretStore, user_agent: str) -> list[str]:
    """BBOT reads API keys from ~/.config/bbot/bbot.yml. Written fresh, mode 600, each run,
    inside the container's home (not the data volume). Values never appear on a command line."""
    import yaml
    modules: dict[str, dict] = {}
    for name, mods in bbot_key_modules().items():
        value = store.get(name)
        if value:
            for m in mods:
                modules[m] = {"api_key": value}
    cfg = {"modules": modules, "web": {"user_agent": user_agent}}
    path = Path(os.environ.get("HOME", "/home/asm")) / ".config" / "bbot" / "bbot.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        yaml.safe_dump(cfg, fh)
    os.replace(tmp, path)
    return sorted(modules)


def _bbot_name(run_dir: Path) -> str:
    base = run_dir / "bbot"
    n = 1
    while (base / f"discovery_{n}").exists():
        n += 1
    return f"discovery_{n}"


def parse_bbot_events(path: Path):
    """Yield (event dict) from BBOT's NDJSON output, skipping bad lines."""
    if not path.exists():
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


async def run_discovery(state, scan_id: str, sources: set[str], expand: str | None = None,
                        providers: Providers | None = None, use_bbot: bool = True) -> None:
    db = state.db()
    try:
        scan = db.one("SELECT * FROM scans WHERE id = ?", scan_id)
        settings = Settings.model_validate(db.get_setting("app", {}))
        store = SecretStore(db, state.master_key)
        secret_values = store.all_values()
        roots = [r["value"] for r in db.all(
            "SELECT value FROM scope_items WHERE scan_id = ? AND kind IN ('root') OR "
            "(scan_id = ? AND kind = 'related' AND decision = 'included')", scan_id, scan_id)]
        whois_key = store.get("whoisxml") if "whois" in sources else None
        keyed_modules = _write_bbot_config(store, settings.user_agent) if use_bbot else []
    finally:
        db.close()

    target = expand or scan["root_domain"]
    run_dir = Path(scan["run_dir"])
    providers = providers or Providers(settings.user_agent)
    runner = Runner(state.cfg.db_path, scan_id, run_dir, secret_values)
    ACTIVE[scan_id] = runner
    stage = "discovery"
    _set_scan(state, scan_id, "discovering")
    runner.set_stage(stage, "running")
    runner.event(stage, f"Passive discovery for {target} (sources: {', '.join(sorted(sources)) or 'subdomains only'})")
    if use_bbot:
        runner.event(stage, "BBOT API keys configured for: " + (", ".join(keyed_modules) or "none (add keys in Settings)"))
    col = Collector(target, sorted(set(roots + [target])), settings.third_party_providers)
    timeout = settings.stage_timeout_minutes.get("discovery", 90) * 60

    try:
        # 1. BBOT passive subdomain enumeration (third-party datasets only)
        if use_bbot:
            targets_file = run_dir / "scope" / f"discovery_target_{target}.txt"
            targets_file.write_text(target + "\n")
            name = _bbot_name(run_dir)
            argv = ["bbot", "-t", str(targets_file), "-p", "subdomain-enum", "-rf", "passive",
                    "-ef", *BBOT_EXCLUDE_FLAGS, "-em", "portscan", "-om", "json",
                    "-o", str(run_dir / "bbot"), "-n", name, "-y", "--no-deps", "--no-color"]
            try:
                rc = await runner.run(stage, argv, timeout, line_filter=_bbot_line_filter)
                if rc != 0:
                    runner.event(stage, f"BBOT exited with code {rc}; continuing with other sources.", "warn")
            except StageFailed as exc:
                runner.event(stage, f"BBOT did not complete ({exc}); continuing with other sources.", "warn")
            for ev in parse_bbot_events(run_dir / "bbot" / name / "output.json"):
                if ev.get("type") != "DNS_NAME":
                    continue
                host = str(ev.get("data", ""))
                tags = ev.get("tags") or []
                module = ev.get("module", "bbot")
                if "affiliate" in tags and not under(host, target):
                    if "affiliates" in sources:
                        col.add(host, "affiliates", f"BBOT affiliate via {module}")
                else:
                    col.add(host, "subdomain-enum", f"found by {module}")

        # 2. Certificate transparency: subdomains always; other names on the same certs if enabled
        await _cert_transparency(runner, providers, col, target, "certificates" in sources)

        # 3. Shared DNS infrastructure (MX, NS, SPF includes)
        if "dns_infra" in sources:
            await _dns_infra(runner, providers, col, target, settings.third_party_providers)

        # 4. WHOIS / reverse WHOIS
        if "whois" in sources:
            if whois_key:
                await _whois(runner, providers, col, target, whois_key)
            else:
                runner.event(stage, "Registration details (WHOIS) skipped: no WhoisXML key saved.", "warn")

        # 5. Resolve and group subdomains
        await _group_subdomains(runner, providers, col, target, settings.third_party_providers)

        # 6. Store
        counts = _store(state, scan_id, col)
        runner.event(stage, f"Discovery complete: {counts['subdomain']} subdomains, {counts['related']} related-domain suggestions.")
        runner.set_stage(stage, "done", summary=json.dumps(counts))
        _set_scan(state, scan_id, "awaiting_scope")
    except StageCancelled:
        runner.event(stage, "Discovery cancelled.", "warn")
        runner.set_stage(stage, "cancelled")
        _set_scan(state, scan_id, "draft")
    except Exception as exc:  # report, never crash the server
        runner.event(stage, f"Discovery failed: {type(exc).__name__}: {exc}", "error")
        runner.set_stage(stage, "failed")
        _set_scan(state, scan_id, "draft")
    finally:
        ACTIVE.pop(scan_id, None)


def _bbot_line_filter(line: str) -> bool:
    return any(t in line for t in ("[INFO]", "[WARN]", "[ERRR]", "[SUCC]", "[CRIT]", "Traceback", "Error"))


def _set_scan(state, scan_id: str, status: str) -> None:
    db = state.db()
    try:
        db.run("UPDATE scans SET status = ? WHERE id = ?", status, scan_id)
    finally:
        db.close()


async def _cert_transparency(runner, providers, col: Collector, target: str, related: bool) -> None:
    url = "https://crt.sh/?q=" + urllib.parse.quote(f"%.{target}") + "&output=json"
    data = None
    for attempt in range(3):
        try:
            data = await providers.http_json(url, timeout=90)
            break
        except Exception as exc:
            runner.event("discovery", f"crt.sh attempt {attempt + 1} failed: {exc}", "warn")
            await asyncio.sleep(CRT_BACKOFF_S * (attempt + 1))
    if not isinstance(data, list):
        runner.event("discovery", "Certificate transparency unavailable this run (crt.sh did not respond).", "warn")
        return
    n_sub, n_rel = 0, 0
    for entry in data[:20000]:
        names = [n.strip().lower() for n in str(entry.get("name_value", "")).split("\n") if n.strip()]
        anchor = next((n for n in names if under(n.lstrip("*."), target)), target)
        for n in names:
            if under(n.lstrip("*."), target):
                col.add(n, "subdomain-enum", "certificate transparency")
                n_sub += 1
            elif related:
                col.add(n, "certificates", f"same certificate as {anchor.lstrip('*.')}")
                n_rel += 1
    runner.event("discovery", f"Certificate transparency: {len(data)} certificates, {n_sub} subdomain names, {n_rel} other names.")


async def _dns_infra(runner, providers, col: Collector, target: str, third: list[str]) -> None:
    mx = await providers.records(target, "MX")
    ns = await providers.records(target, "NS")
    txt = await providers.records(target, "TXT")
    includes = []
    for t in txt:
        if t.lower().startswith("v=spf1"):
            includes += [p.split(":", 1)[1] for p in t.split() if p.lower().startswith(("include:", "redirect=")) and ":" in p]
            includes += [p.split("=", 1)[1] for p in t.split() if p.lower().startswith("redirect=")]
    found = 0
    for label, hosts in (("MX", mx), ("NS", ns), ("SPF include", includes)):
        for h in hosts:
            h = h.strip().rstrip(".").lower()
            if not h or under(h, target) or is_third_party(h, third):
                continue
            if shares_brand(h, target):
                col.add(h, "dns_infra", f"same {label}: {h}")
            else:
                # MX/NS/SPF names without the organisation's brand are almost always vendors
                col.add(h, "dns_vendor", f"same {label}: {h} (likely a vendor)")
            found += 1
    runner.event("discovery", f"DNS infrastructure: {len(mx)} MX, {len(ns)} NS, {len(includes)} SPF includes; {found} non-provider names.")


async def _whois(runner, providers, col: Collector, target: str, key: str) -> None:
    try:
        w = await providers.http_json(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService?" + urllib.parse.urlencode(
                {"apiKey": key, "domainName": target, "outputFormat": "JSON"}), timeout=60)
        rec = (w or {}).get("WhoisRecord", {})
        org = ((rec.get("registrant") or {}).get("organization")
               or (rec.get("registryData", {}).get("registrant") or {}).get("organization") or "").strip()
        if not org or any(p in org.lower() for p in ("privacy", "redacted", "proxy", "withheld", "not disclosed")):
            runner.event("discovery", "WHOIS: registrant organisation is private or missing; reverse lookup skipped.", "warn")
            return
        body = json.dumps({"apiKey": key, "searchType": "current", "mode": "purchase",
                           "basicSearchTerms": {"include": [org]}}).encode()
        r = await providers.http_json("https://reverse-whois.whoisxmlapi.com/api/v2",
                                      headers={"Content-Type": "application/json"}, data=body, timeout=90)
        domains = (r or {}).get("domainsList", [])[:500]
        for d in domains:
            col.add(d, "whois", f"registered to {org}")
        runner.event("discovery", f"Reverse WHOIS for '{org}': {len(domains)} domains.")
    except Exception as exc:
        runner.event("discovery", f"WHOIS lookup failed: {exc}", "warn")


async def _group_subdomains(runner, providers, col: Collector, target: str, third: list[str]) -> None:
    subs = [c for c in col.c.values() if c.kind == "subdomain"]
    col.add(target, "subdomain-enum", "the domain you entered")
    root_cand = col.c.get(target)
    if root_cand and root_cand not in subs:
        subs.append(root_cand)
    runner.event("discovery", f"Resolving {len(subs)} names (DNS only)…")

    # Probe a few random names: CDN-backed wildcards (CloudFront etc.) rotate addresses between queries
    wildcard_ips: set[str] = set()
    for _ in range(3):
        wc = await providers.resolve(f"asm-wc-{pysecrets.token_hex(6)}.{target}")
        if wc and wc.get("ips"):
            wildcard_ips |= set(wc["ips"])
    if wildcard_ips:
        runner.event("discovery", f"Wildcard DNS detected for *.{target}: any name resolves. Names with no other evidence "
                                  "are listed under 'Wildcard' and left unticked.", "warn")

    sem = asyncio.Semaphore(RESOLVE_CONCURRENCY)

    async def one(c: Cand):
        async with sem:
            res = await providers.resolve(c.value)
        if res is None or (not res.get("ips") and not res.get("cname")):
            c.grp = "no_dns"
        elif any(is_third_party(cn, third) for cn in res.get("cname", [])):
            c.grp = "third_party"
            c.add(next(iter(c.sources)), f"CNAME to {res['cname'][-1]}")
        elif wildcard_ips and set(res.get("ips", [])) <= wildcard_ips and c.value != target:
            if _has_ct_evidence(c):
                c.grp = "resolves"
                c.add(next(iter(c.sources)), "has its own certificate (domain also has wildcard DNS)")
            else:
                c.grp = "wildcard"
                c.add(next(iter(c.sources)), "answers only like a random name would (wildcard DNS)")
        else:
            c.grp = "resolves"

    await asyncio.gather(*(one(c) for c in subs))
    n_wild = sum(1 for c in subs if c.grp == "wildcard")
    if n_wild:
        runner.event("discovery", f"{n_wild} names look like wildcard answers only; review them under 'Wildcard'.")


CT_MODULES = {"crt", "crt_db", "certspotter", "censys_dns"}


def _has_ct_evidence(c: Cand) -> bool:
    """A specific (non-wildcard) certificate was issued for this exact name."""
    return any(r == "certificate transparency" or (r.startswith("found by ") and r[9:] in CT_MODULES) for r in c.reasons)


def _store(state, scan_id: str, col: Collector) -> dict:
    db = state.db()
    counts = {"subdomain": 0, "related": 0}
    try:
        with db.tx():
            # older versions collapsed wildcard answers into one "*.domain" entry
            db.run("DELETE FROM scope_items WHERE scan_id = ? AND kind = 'subdomain' AND value LIKE '*.%'", scan_id)
            for c in col.c.values():
                if c.kind == "subdomain":
                    decision = "included" if c.grp != "wildcard" else "suggested"
                    conf = "high" if c.grp in ("resolves", "third_party") else "medium"
                else:
                    decision = "excluded" if c.third_party else "suggested"
                    conf = related_confidence(c.sources)
                existing = db.one("SELECT sources, reasons, decided_at FROM scope_items WHERE scan_id = ? AND value = ?",
                                  scan_id, c.value)
                if existing:
                    srcs = sorted(set(json.loads(existing["sources"])) | c.sources)
                    reasons = list(dict.fromkeys(json.loads(existing["reasons"]) + c.reasons))[:6]
                    db.run("UPDATE scope_items SET sources = ?, reasons = ?, grp = COALESCE(?, grp), "
                           "confidence = CASE WHEN kind = 'root' THEN confidence ELSE ? END, third_party = ? "
                           "WHERE scan_id = ? AND value = ?",
                           json.dumps(srcs), json.dumps(reasons), c.grp,
                           conf if c.kind == "subdomain" else related_confidence(set(srcs)),
                           int(c.third_party), scan_id, c.value)
                else:
                    db.run("INSERT INTO scope_items (scan_id, value, kind, grp, sources, reasons, confidence, decision, third_party) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           scan_id, c.value, c.kind, c.grp, json.dumps(sorted(c.sources)), json.dumps(c.reasons),
                           conf, decision, int(c.third_party))
                counts[c.kind] += 1
    finally:
        db.close()
    return counts
