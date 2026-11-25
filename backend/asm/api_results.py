"""Milestone 5 routes: results overview (RAG, metric cards with trend, top risks), assets, findings with
analyst status, unknown-host triage, and a read-only browser of the run folder.

Everything here is computed from the database at request time, so a finding marked as a false positive or a
triage decision changes the RAG and the counts straight away.
"""
from __future__ import annotations

import json
import mimetypes
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from .db import DB, now
from .surface import AGENT_TAGS, classify_host, dedup_tech, is_agent_surface
from .graph import build_graph, graph_summary, to_payload
from .attackpaths import simulate
from . import report_refs as refs
from .evidence import build_evidence
from . import eol as eolmod

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_TECH_VER_RE = re.compile(r"[\s:]+v?\d[\w.\-]*$", re.I)


def _tech_name(s: str) -> str:
    """Canonical technology name: strip an inline version (space- or colon-separated) and keep the full
    product name. 'Okta 7.51.0' -> 'Okta'; 'jquery:3.6.1' -> 'jquery'; 'AWS CloudFront' -> unchanged."""
    base = _TECH_VER_RE.sub("", s or "").strip()
    return base or (s or "").strip()


# Canonical display casing for technologies the fingerprinters only ever emit lower-case. Keyed by the
# lower-cased name; anything not listed falls back to a gentle title-case (see _tech_display).
_TECH_CANON = {
    "framer sites": "Framer Sites", "framer": "Framer", "adobe fonts": "Adobe Fonts",
    "cloudflare browser insights": "Cloudflare Browser Insights", "corebook": "Corebook",
    "express": "Express", "google sign-in": "Google Sign-In", "apple sign-in": "Apple Sign-In",
    "onetrust": "OneTrust", "recaptcha": "reCAPTCHA", "wordpress block editor": "WordPress Block Editor",
    "wordpress": "WordPress", "youtube": "YouTube", "cdnjs": "cdnjs", "c3.js": "C3.js",
    "requirejs": "RequireJS", "typekit": "Typekit", "readme": "ReadMe", "node.js": "Node.js",
    "next.js": "Next.js", "php": "PHP", "mysql": "MySQL", "nginx": "Nginx", "jquery": "jQuery",
    "jquery migrate": "jQuery Migrate", "react": "React", "vue.js": "Vue.js", "angular": "Angular",
    "webpack": "Webpack", "bootstrap": "Bootstrap", "bynder": "Bynder", "ahoy": "Ahoy",
    "stimulus": "Stimulus", "contentful": "Contentful", "envoy": "Envoy", "render": "Render",
}
# brand tokens that keep their own casing inside the title-case fallback
_TECH_CASE_FIX = {"js": "js", "css": "CSS", "api": "API", "aws": "AWS", "sdk": "SDK", "ui": "UI"}


def _tech_display(name: str) -> str:
    """Pretty display name: explicit canonical map first, else capitalise each word of an all-lower-case
    name (leaving names that already carry capitals, acronyms and dotted tokens like 'C3.js' untouched)."""
    key = (name or "").lower()
    if key in _TECH_CANON:
        return _TECH_CANON[key]
    if name and name == name.lower():
        out = []
        for w in name.split(" "):
            if not w:
                out.append(w)
            elif w in _TECH_CASE_FIX:
                out.append(_TECH_CASE_FIX[w])
            elif "." in w or any(ch.isdigit() for ch in w):
                out.append(w)                      # 'c3.js', 'web3' -> leave as-is
            else:
                out.append(w[:1].upper() + w[1:])
        return " ".join(out)
    return name

FINDING_STATUSES = ("observation", "verified", "false_positive")
TRIAGE_DECISIONS = {
    "ours_unrecorded": "Ours, not in the CMDB",
    "third_party_ours": "Ours, run by a vendor",
    "should_not_exist": "Shouldn't exist (decommission)",
    "not_ours": "Not ours (wrong match)",
    "investigating": "Investigating",
}
KNOWN_DECISIONS = {"ours_unrecorded", "third_party_ours", "not_ours", "should_not_exist"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
VCONF_ORDER = ("confirmed", "probable", "unconfirmed")
VCONF_RANK = {"confirmed": 0, "probable": 1, "unconfirmed": 2}


def version_confidence(title: str, area: str) -> str | None:
    """Triage axis for version-based CVE findings: did we CONFIRM the running version is in the CVE's
    affected range (act now), merely FINGERPRINT a version (probable — verify the exact build), or have
    no version at all (unconfirmed — fingerprint it first). None for non-vuln findings."""
    if area != "vulns":
        return None
    t = (title or "").lower()
    if "version confirmed in affected range" in t:
        return "confirmed"
    if "version from page fingerprint" in t or re.search(r"\bfor [a-z].*\d+\.\d", t):
        return "probable"
    return "unconfirmed"
RISKY_TOOLS = ("internetdb", "internetdb-extra", "naabu")
TAKEOVER_TOOLS = ("bbot:baddns", "baddns-live", "dnsreaper")
SCREENSHOT_EXT = (".png", ".jpg", ".jpeg", ".webp")
TEXT_EXT = {".txt", ".log", ".json", ".yaml", ".yml", ".csv", ".tsv", ".md", ".xml", ".nmap", ".gnmap", ".conf", ""}
MAX_PREVIEW = 2 * 1024 * 1024
INSTANCES_RE = re.compile(r"\s*\(\d+ instances\)$")


LOOKALIKE_RE = re.compile(r"^(Registered lookalike[^:]*): \S+$")


def suggest_triage(a, has_takeover: bool) -> dict:
    """A best-guess triage classification for an undecided host, from the scan's own evidence, with a
    confidence level and the plain-English reasons behind it. The analyst confirms or overrides — nothing
    here is applied automatically. `a` is the asset row (or None if the host produced no asset)."""
    if has_takeover:
        return {"decision": "investigating", "confidence": "medium",
                "reasons": ["dangling DNS record (possible takeover) — confirm before keeping or removing"]}
    if a is None:
        return {"decision": "investigating", "confidence": "low", "reasons": ["no asset details were collected for this host"]}
    ips = json.loads(a["ips"] or "[]")
    if not ips:
        return {"decision": "should_not_exist", "confidence": "low",
                "reasons": ["doesn't resolve to any IP — likely a stale DNS record"]}
    live = bool(a["is_live"])
    cdn = bool(a["cdn"])
    third = bool(a["third_party"])
    edge = json.loads(a["edge"] or "{}")
    tls = json.loads(a["tls"] or "{}")
    provider = edge.get("cdn") or edge.get("cloud") or edge.get("waf")
    status = a["http_status"]
    if cdn or third or provider:
        reasons = []
        if provider:
            reasons.append(f"fronted/hosted by {provider}")
        elif cdn:
            reasons.append("sits behind a CDN/WAF edge")
        else:
            reasons.append("resolves onto third-party / SaaS infrastructure")
        return {"decision": "third_party_ours", "confidence": "high" if provider else "medium", "reasons": reasons}
    cn = str(tls.get("subject_cn") or "")
    wildcard = cn.startswith("*.")
    has_cert = bool(tls) and not tls.get("mismatched") and not tls.get("self_signed") and not tls.get("expired")
    if live and wildcard:
        return {"decision": "ours_unrecorded", "confidence": "high",
                "reasons": ["presents your wildcard certificate", f"live{f' ({status})' if status else ''} on your own infrastructure"]}
    if live and has_cert:
        return {"decision": "ours_unrecorded", "confidence": "medium",
                "reasons": ["presents a valid TLS certificate for itself", f"live{f' ({status})' if status else ''}"]}
    if live:
        return {"decision": "ours_unrecorded", "confidence": "medium",
                "reasons": [f"live{f' ({status})' if status else ''} on your own infrastructure"]}
    return {"decision": "investigating", "confidence": "low", "reasons": ["resolves but serves no live web page"]}


def group_title(title: str) -> str:
    """The issue a finding belongs to, so one problem on 17 hosts (or 9 lookalike domains) groups together:
    'CSP Header Not Set (3 instances)' -> 'CSP Header Not Set';
    BBOT's 'Dangling CNAME, possible takeover (...). Confidence: [MEDIUM] Signature: ...' -> the part before 'Confidence';
    'Registered lookalike with mail servers (look-alike characters): m1ro.com' -> without the domain."""
    t = INSTANCES_RE.sub("", title)
    t = t.split(" Confidence: [", 1)[0].rstrip(" .")
    m = LOOKALIKE_RE.match(t)
    return m.group(1) if m else t


def scan_row(db: DB, sid: str):
    return db.one("SELECT * FROM scans WHERE id = ?", sid)


def _harvested_emails(run_dir) -> list[dict]:
    """Emails BBOT extracted (EMAIL_ADDRESS events), deduped. Read-time from the run folder."""
    from pathlib import Path as _P
    base = _P(run_dir) / "bbot"
    if not base.exists():
        return []
    seen: dict[str, dict] = {}
    for oj in base.glob("*/output.json"):
        try:
            for line in oj.read_text(encoding="utf-8", errors="replace").splitlines():
                if '"EMAIL_ADDRESS"' not in line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("type") != "EMAIL_ADDRESS":
                    continue
                email = str(ev.get("data") or "").strip().lower()
                if "@" not in email:
                    continue
                e = seen.setdefault(email, {"email": email, "host": ev.get("host"), "sources": set()})
                if ev.get("module"):
                    e["sources"].add(str(ev["module"]))
        except Exception:
            continue
    return sorted(({"email": e["email"], "host": e["host"], "sources": sorted(e["sources"])} for e in seen.values()),
                  key=lambda x: x["email"])


def _email_breaches(obj) -> list[str]:
    """Breach names from an XposedOrNot check-email response, whatever nesting it uses."""
    if not isinstance(obj, dict) or obj.get("Error"):
        return []
    out: list[str] = []
    b = obj.get("breaches")
    if isinstance(b, list):
        for item in b:
            if isinstance(item, list):
                out += [str(x) for x in item]
            elif isinstance(item, str):
                out.append(item)
    return out


def _xon_check_emails(emails: list[str]) -> list[dict]:
    """On-demand per-email breach check via XposedOrNot (free, rate-limited). Best-effort."""
    import time as _t
    import urllib.parse as _up
    import urllib.request as _ur
    out = []
    for em in emails:
        res = {"email": em, "breaches": [], "ok": True}
        try:
            url = "https://api.xposedornot.com/v1/check-email/" + _up.quote(em)
            req = _ur.Request(url, headers={"User-Agent": "outsider-asm/1.0", "Accept": "application/json"})
            with _ur.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode("utf-8", "replace") or "null")
            res["breaches"] = _email_breaches(data)
        except Exception as exc:
            res["ok"] = False
            res["error"] = str(exc)[:120]
        out.append(res)
        _t.sleep(0.6)      # stay under the 2/sec cap
    return out


def _host_eq(a: str, b: str) -> bool:
    a, b = (a or '').lower().strip('.'), (b or '').lower().strip('.')
    return bool(a) and (a == b or a.endswith('.' + b) or b.endswith('.' + a))


def _tls_expiry(tls: dict) -> str | None:
    v = tls.get("not_after")
    return str(v)[:10] if v else None


def _screenshots(run_dir: Path) -> dict[str, str]:
    """host -> screenshot path (relative to the run folder). gowitness names files like http---host-443-.jpeg."""
    out: dict[str, tuple[int, str]] = {}
    base = run_dir / "bbot"
    if not base.exists():
        return {}
    for f in base.rglob("*"):
        if f.suffix.lower() not in SCREENSHOT_EXT or "screenshots" not in f.parts:
            continue
        m = re.match(r"^(https?)---(.+)-(\d{1,5})-(.*)$", f.stem)
        if not m:
            continue
        # prefer HTTPS, then the front page over deeper pages (gowitness also shoots paths like ...-443-pricing-)
        rank = (0 if m.group(1) == "https" else 2) + (0 if m.group(4).strip("-") == "" else 1)
        host = m.group(2)
        if host not in out or rank < out[host][0]:
            out[host] = (rank, str(f.relative_to(run_dir)))
    return {h: p for h, (_, p) in out.items()}


def _tech_detail(run_dir: Path) -> dict[str, list[dict]]:
    """host -> [{name, version, cpe, cve_url}]. Versions come from the fingerprinter (tech/fingerprints.json,
    name -> version) which is authoritative; CPE strings (tech/cpes.json) are merged in where present.
    assets.tech only keeps product names, so this is where real version numbers surface."""
    def _load(p):
        try:
            return json.loads((run_dir / "tech" / p).read_text())
        except Exception:
            return {}
    fp = _load("fingerprints.json")
    cp = _load("cpes.json")
    # host -> {name_lower: (version, cpe)} from CPEs
    cpe_by_host: dict[str, dict[str, tuple]] = {}
    for host, cpes in (cp.items() if isinstance(cp, dict) else []):
        m: dict[str, tuple] = {}
        for cpe in cpes or []:
            parts = str(cpe).split(":")
            if len(parts) < 6:
                continue
            vendor, product, version = parts[3], parts[4], parts[5]
            name = product if product not in ("*", "-", "") else vendor
            ver = version if version not in ("*", "-", "") else None
            if name:
                m[name.lower()] = (ver, str(cpe))
        cpe_by_host[host] = m
    out: dict[str, list[dict]] = {}
    for host, techs in (fp.items() if isinstance(fp, dict) else []):
        if not isinstance(techs, dict):
            continue
        cmap = cpe_by_host.get(host, {})
        seen: set[str] = set()
        items: list[dict] = []
        for name, ver in techs.items():
            key = (name or "").lower()
            if not name or key in seen:
                continue
            seen.add(key)
            cver, cpe = cmap.get(key, (None, None))
            version = (ver or None) or cver
            items.append({"name": name, "version": version, "cpe": cpe,
                          "cve_url": refs.tech_cve_url(name, version) if version else None})
        # CPE-detected components the fingerprinter missed entirely
        for key, (cver, cpe) in cmap.items():
            if key in seen:
                continue
            seen.add(key)
            nm = cpe.split(":")[4] if cpe and len(cpe.split(":")) > 4 and cpe.split(":")[4] not in ("*", "-") else key
            items.append({"name": nm, "version": cver, "cpe": cpe,
                          "cve_url": refs.tech_cve_url(nm, cver) if cver else None})
        if items:
            out[host] = items
    return out


def compute_ips(db: DB, sid: str) -> list[dict]:
    """IP-centric inventory: per public IP, the hosts on it, its netblock/ASN, ports, technologies, PTR names,
    whether it's a shared platform, and how many hosts share it (blast radius)."""
    import ipaddress
    assets = db.all("SELECT host, ips, ports, ports_confirmed, tech, cdn, third_party, is_live FROM assets WHERE scan_id = ?", sid)
    # netblocks from the asn findings (subnet in the title/host)
    nets = []
    for r in db.all("SELECT host, title FROM findings WHERE scan_id = ? AND source_tool = 'asn'", sid):
        try:
            net = ipaddress.ip_network(r["host"], strict=False)
        except ValueError:
            continue
        kind = "own" if "org-owned" in r["title"] else "shared"
        label = r["title"].split("(", 1)[-1].rstrip(")") if "(" in r["title"] else ""
        nets.append((net, kind, label))
    ptr: dict[str, list[str]] = {}
    for r in db.all("SELECT host, value FROM dns_records WHERE scan_id = ? AND rtype = 'PTR'", sid):
        ptr.setdefault(r["host"], []).append(r["value"])

    def is_pub(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast)
        except ValueError:
            return False

    by_ip: dict[str, dict] = {}
    for a in assets:
        for ip in json.loads(a["ips"] or "[]"):
            if not is_pub(ip):
                continue
            e = by_ip.setdefault(ip, {"ip": ip, "hosts": [], "ports": set(), "ports_confirmed": set(), "tech": [],
                                      "shared": False, "live": False})
            e["hosts"].append(a["host"])
            e["ports"].update(int(p) for p in json.loads(a["ports"] or "[]"))
            if a["ports_confirmed"]:
                e["ports_confirmed"].update(int(p) for p in json.loads(a["ports_confirmed"]))
            e["tech"] += json.loads(a["tech"] or "[]")
            e["shared"] = e["shared"] or bool(a["cdn"]) or bool(a["third_party"])
            e["live"] = e["live"] or bool(a["is_live"])
    out = []
    for ip, e in by_ip.items():
        netblock = asn = owner = None
        best = None
        for net, kind, label in nets:
            if ipaddress.ip_address(ip) in net and (best is None or net.prefixlen > best.prefixlen):
                best, netblock, owner = net, str(net), label
                m = re.search(r"AS(\d+)", label)
                asn = m.group(1) if m else None
                e["net_kind"] = kind
        out.append({
            "ip": ip, "hosts": sorted(e["hosts"]), "host_count": len(e["hosts"]),
            "ports": sorted(e["ports"]), "ports_confirmed": sorted(e["ports_confirmed"]),
            "tech": dedup_tech(e["tech"]), "shared": e["shared"], "live": e["live"],
            "netblock": netblock, "asn": asn, "owner": owner, "net_kind": e.get("net_kind"),
            "ptr": sorted(ptr.get(ip, [])),
            "agent_hosts": sorted(h for h in e["hosts"] if is_agent_surface(h)),
        })
    # your own IPs first (not shared), then by blast radius
    out.sort(key=lambda r: (r["shared"], -r["host_count"], r["ip"]))
    return out


def _previous_scan(db: DB, scan) -> str | None:
    # the most recent earlier scan of the same domain that has results (rowid breaks ties within a second)
    row = db.one("SELECT s.id FROM scans s JOIN metrics m ON m.scan_id = s.id WHERE s.root_domain = ? "
                 "AND s.rowid < (SELECT rowid FROM scans WHERE id = ?) ORDER BY s.rowid DESC LIMIT 1",
                 scan["root_domain"], scan["id"])
    return row["id"] if row else None


def compute_overview(db: DB, sid: str) -> dict:
    """Headline RAG with its reasons, the metric values, and top risks. False positives don't count."""
    scan = scan_row(db, sid)
    stages = {r["stage_key"]: r for r in db.all("SELECT stage_key, status, summary FROM stages WHERE scan_id = ?", sid)}
    summ = lambda k: json.loads(stages[k]["summary"] or "{}") if k in stages else {}
    ran = lambda k: k in stages and stages[k]["status"] == "done"
    f = [dict(r) for r in db.all("SELECT * FROM findings WHERE scan_id = ? AND status != 'false_positive'", sid)]
    assets = db.all("SELECT * FROM assets WHERE scan_id = ?", sid)
    triage = {r["host"]: r["decision"] for r in db.all("SELECT host, decision FROM triage WHERE scan_id = ?", sid)}
    in_scope = {r["value"] for r in db.all("SELECT value FROM scope_items WHERE scan_id = ? AND kind IN ('root','subdomain') "
                                           "AND decision = 'included' AND value NOT LIKE '*.%'", sid)}
    in_scope.add(scan["root_domain"])

    def count(pred) -> int:
        return sum(1 for x in f if pred(x))

    # one per host: BBOT's baddns and dnsReaper often flag the same name; dnsReaper's "unlikely" ones don't count
    takeover = len({x["host"] for x in f if x["source_tool"] in TAKEOVER_TOOLS and x["severity"] != "low"})
    kev = len({x["title"].rsplit(" ", 1)[-1] for x in f if x["source_tool"] == "intel-cve" and x["severity"] == "high"})  # distinct CVEs
    epss = count(lambda x: x["source_tool"] == "intel-cve" and x["severity"] == "medium")
    spf_broken = count(lambda x: x["area"] == "email" and x["title"].startswith("SPF needs"))
    live_lookalikes = count(lambda x: x["source_tool"] == "urlscan" and x["area"] == "brand")
    leaks = count(lambda x: x["source_tool"] in ("leakix", "spiderfoot") and x["severity"] in ("critical", "high"))
    risky = count(lambda x: x["source_tool"] in RISKY_TOOLS and x["severity"] in ("critical", "high", "medium"))
    expired = count(lambda x: x["area"] == "tls" and x["title"].startswith("Expired"))
    expiring = count(lambda x: x["area"] == "tls" and "expires within 30 days" in x["title"])
    zap_high = count(lambda x: x["source_tool"] == "zap" and x["severity"] in ("critical", "high"))
    zap_med = count(lambda x: x["source_tool"] == "zap" and x["severity"] == "medium")
    dmarc = len({x["host"] for x in f if x["area"] == "email" and
                 (x["title"].startswith("No DMARC record") or "p=none" in x["title"] or "quarantine, not reject" in x["title"])})
    unknown_hosts = [a["host"] for a in assets if a["host"] in in_scope and not a["in_cmdb"] and triage.get(a["host"]) not in KNOWN_DECISIONS]
    own_ips = {ip for a in assets if not a["cdn"] and not a["third_party"] for ip in json.loads(a["ips"])}
    open_ports = summ("ports").get("open_ports", 0) + summ("cloud").get("open_ports", 0)
    lookalike_mx = count(lambda x: x["area"] == "brand" and x["severity"] in ("medium", "high"))
    sev = {s: count(lambda x, s=s: x["severity"] == s) for s in SEV_ORDER}
    vuln_matrix = {c: {s: 0 for s in SEV_ORDER} for c in VCONF_ORDER}
    for x in f:
        vc = version_confidence(x["title"], x["area"])
        if vc:
            vuln_matrix[vc][x["severity"]] += 1
    vuln_act_now = vuln_matrix["confirmed"]["critical"] + vuln_matrix["confirmed"]["high"]
    # AI-agent / MCP surface: live hosts whose name marks them as agent, MCP, model or digital-twin infrastructure
    agent_hosts = sorted({a["host"] for a in assets if a["is_live"] and is_agent_surface(a["host"])})
    own_netblocks = summ("bbot_light").get("own_netblocks", 0)
    all_netblocks = summ("bbot_light").get("netblocks", 0)
    # deduped technology breakdown (BBOT double-counts by case: Amazon/amazon, HSTS/hsts)
    tech_counter: dict[str, dict] = {}        # case-insensitive name -> {name, count}
    for a in assets:
        seen: set[str] = set()
        for t in json.loads(a["tech"] or "[]"):
            name = _tech_name(t)
            key = name.lower()
            if not name or key in seen:
                continue
            seen.add(key)
            e = tech_counter.setdefault(key, {"name": name, "count": 0})
            e["count"] += 1
            if name != e["name"] and any(c.isupper() for c in name) and not any(c.isupper() for c in e["name"]):
                e["name"] = name                  # prefer a properly-cased variant
    tech_top = sorted(tech_counter.values(), key=lambda e: (-e["count"], e["name"].lower()))

    F = lambda **kw: {"tab": "findings", "filter": kw}
    reasons = []
    def reason(level, n, text, link):
        if n:
            reasons.append({"level": level, "count": n, "text": text, "link": link})
    reason("red", risky, f"{risky} risky service{'s' if risky != 1 else ''} exposed (RDP, databases, SSH…)", F(tool="internetdb"))
    reason("red", takeover, f"{takeover} dangling DNS record{'s' if takeover != 1 else ''} (possible subdomain takeover)", F(tool="takeover"))
    reason("red", leaks, f"{leaks} high-severity leak{'s' if leaks != 1 else ''} reported by LeakIX / SpiderFoot", F(severity="high", q="LeakIX"))
    reason("red", expired, f"{expired} expired certificate{'s' if expired != 1 else ''}", F(area="tls", q="Expired"))
    reason("red", zap_high, f"{zap_high} high-risk web alert{'s' if zap_high != 1 else ''} from ZAP", F(tool="zap", severity="high"))
    reason("amber", len(unknown_hosts), f"{len(unknown_hosts)} host{'s' if len(unknown_hosts) != 1 else ''} not in the CMDB and not yet triaged",
           {"tab": "triage", "filter": {"decision": "undecided"}})
    reason("amber", kev, f"{kev} known-exploited CVE{'s' if kev != 1 else ''} (CISA KEV) matched to your service versions: verify",
           F(tool="intel-cve", severity="high"))
    reason("amber", spf_broken, f"{spf_broken} domain{'s' if spf_broken != 1 else ''} with SPF over the 10-lookup limit", F(area="email", q="SPF needs"))
    reason("amber", live_lookalikes, f"{live_lookalikes} lookalike domain{'s' if live_lookalikes != 1 else ''} with live pages (phishing risk)",
           F(tool="urlscan"))
    reason("amber", dmarc, f"{dmarc} domain{'s' if dmarc != 1 else ''} without DMARC reject", F(area="email"))
    reason("amber", zap_med, f"{zap_med} medium web alerts from ZAP", F(tool="zap", severity="medium"))
    reason("amber", expiring, f"{expiring} certificate{'s' if expiring != 1 else ''} expiring within 30 days", F(area="tls", q="expires within"))
    reason("amber", len(agent_hosts), f"{len(agent_hosts)} AI-agent / MCP host{'s' if len(agent_hosts) != 1 else ''} exposed (review auth and rate limits)",
           {"tab": "assets", "filter": {"tag": "agent"}})
    rag = "red" if any(r["level"] == "red" for r in reasons) else "amber" if reasons else "green"
    not_collected = []
    if not ran("hibp"):
        not_collected.append("breach exposure (XposedOrNot / HIBP)")
    not_collected.append("readable storage buckets and leaked secrets (no stage collects these yet)")

    values = {
        "hosts_in_scope": len(in_scope),
        "live_web_hosts": sum(1 for a in assets if a["is_live"]),
        "unknown_hosts": len(unknown_hosts),
        "takeover_risks": takeover,
        "risky_services": risky,
        "open_ports": open_ports,
        "own_public_ips": len(own_ips),
        "high_findings": sev["critical"] + sev["high"],
        "medium_findings": sev["medium"],
        "expiring_certs": expiring + expired,
        "lookalikes_with_mail": lookalike_mx,
        "historical_urls": summ("gau").get("historical_urls", 0),
        "kev_cves": kev,
        "likely_exploited": epss,
        "agent_surface": len(agent_hosts),
        "netblocks_own": own_netblocks,
        "netblocks_all": all_netblocks,
        "dmarc_missing": dmarc,
        "lookalikes_with_mx": lookalike_mx,
    }
    groups: dict[tuple, dict] = {}
    for x in f:
        if x["severity"] not in ("critical", "high", "medium"):
            continue
        k = (x["severity"], group_title(x["title"]))
        g = groups.setdefault(k, {"severity": x["severity"], "title": k[1], "area": x["area"],
                                  "tool": x["source_tool"], "hosts": set(), "fid": x["id"]})
        g["fid"] = min(g["fid"], x["id"])            # a representative finding so the UI can open its detail pane
        if x["host"]:
            g["hosts"].add(x["host"])
    risk_weight = lambda g: (SEV_ORDER[g["severity"]], -(10 if g["tool"] in TAKEOVER_TOOLS + RISKY_TOOLS else 0), -len(g["hosts"]))
    top = sorted(groups.values(), key=risk_weight)[:6]
    top = [{**g, "hosts": sorted(g["hosts"]), "link": F(q=g["title"], severity=g["severity"])} for g in top]
    failed_stages = sorted(k for k, r in stages.items() if r["status"] == "failed")
    partial = bool(failed_stages) or scan["status"] == "completed_with_errors"
    return {"rag": rag, "reasons": reasons, "values": values, "top_risks": top, "not_collected": not_collected,
            "partial": partial, "failed_stages": failed_stages,
            "severity": sev, "status": scan["status"], "finished_at": scan["finished_at"],
            "tech": [{"name": _tech_display(e["name"]), "count": e["count"]} for e in tech_top], "agent_hosts": agent_hosts,
            "vuln_matrix": {"matrix": vuln_matrix, "order": list(VCONF_ORDER), "act_now": vuln_act_now}}


CARDS = [
    ("hosts_in_scope", "Hosts in scope", "neutral", {"tab": "assets", "filter": {}}),
    ("live_web_hosts", "Live web hosts", "neutral", {"tab": "assets", "filter": {"live": True}}),
    ("unknown_hosts", "Unknown hosts", "lower", {"tab": "triage", "filter": {"decision": "undecided"}}),
    ("takeover_risks", "Takeover risks", "lower", {"tab": "findings", "filter": {"tool": "takeover"}}),
    ("kev_cves", "Known-exploited CVEs (to verify)", "lower", {"tab": "findings", "filter": {"tool": "intel-cve", "severity": "high"}}),
    ("agent_surface", "AI-agent / MCP surface", "neutral", {"tab": "assets", "filter": {"tag": "agent"}}),
    ("risky_services", "Risky services", "lower", {"tab": "findings", "filter": {"tool": "internetdb"}}),
    ("high_findings", "High / critical", "lower", {"tab": "findings", "filter": {"severity": "high"}}),
    ("medium_findings", "Medium", "lower", {"tab": "findings", "filter": {"severity": "medium"}}),
    ("expiring_certs", "Certificates expired or expiring", "lower", {"tab": "findings", "filter": {"area": "tls", "q": "xpir"}}),
    ("open_ports", "Open ports (yours)", "lower", {"tab": "assets", "filter": {"ports": True}}),
    ("own_public_ips", "Your public IPs", "neutral", {"tab": "assets", "filter": {}}),
    ("lookalikes_with_mail", "Lookalikes worth watching", "lower", {"tab": "findings", "filter": {"area": "brand", "severity": "medium"}}),
    ("dmarc_missing", "Domains without DMARC reject", "lower", {"tab": "findings", "filter": {"area": "email"}}),
    ("netblocks_own", "Netblocks to check (org-owned)", "lower", {"tab": "findings", "filter": {"tool": "asn", "q": "org-owned"}}),
    ("historical_urls", "Historical URLs", "neutral", {"tab": "files", "filter": {"path": "urls"}}),
]


def _ident(title: str) -> str:
    t = INSTANCES_RE.sub("", title)
    return t.split(" Confidence: [", 1)[0].rstrip(" .")


def compute_changes(db: DB, sid: str, against: str) -> dict:
    """What changed between two scans: hosts, live hosts, open ports, findings (false positives ignored) and RAG."""
    def snap(x: str):
        assets = {a["host"]: a for a in db.all("SELECT * FROM assets WHERE scan_id = ?", x)}
        fs = {}
        for r in db.all("SELECT area, severity, title, host, source_tool FROM findings WHERE scan_id = ? AND status != 'false_positive'", x):
            k = (r["area"], _ident(r["title"]), r["host"] or "")
            if k not in fs or SEV_ORDER[r["severity"]] < SEV_ORDER[fs[k]["severity"]]:
                fs[k] = dict(r)
        ports = {(h, p) for h, a in assets.items() if not a["cdn"] for p in json.loads(a["ports"])}
        return assets, fs, ports

    a_new, f_new, p_new = snap(sid)
    a_old, f_old, p_old = snap(against)
    live_new = {h for h, a in a_new.items() if a["is_live"]}
    live_old = {h for h, a in a_old.items() if a["is_live"]}
    row = lambda r: {"area": r["area"], "severity": r["severity"], "title": r["title"], "host": r["host"], "tool": r["source_tool"]}
    sevkey = lambda r: (SEV_ORDER[r["severity"]], r["title"], r["host"] or "")
    new_f = sorted((row(f_new[k]) for k in f_new.keys() - f_old.keys()), key=sevkey)
    resolved = sorted((row(f_old[k]) for k in f_old.keys() - f_new.keys()), key=sevkey)
    changed = sorted(({**row(f_new[k]), "was": f_old[k]["severity"]} for k in f_new.keys() & f_old.keys()
                      if f_new[k]["severity"] != f_old[k]["severity"]), key=sevkey)
    o_new, o_old = compute_overview(db, sid), compute_overview(db, against)
    hosts_added, hosts_removed = sorted(a_new.keys() - a_old.keys()), sorted(a_old.keys() - a_new.keys())
    opened = [{"host": h, "port": p} for h, p in sorted(p_new - p_old)]
    closed = [{"host": h, "port": p} for h, p in sorted(p_old - p_new)]
    deltas = {k: {"before": o_old["values"].get(k), "after": v} for k, v in o_new["values"].items() if o_old["values"].get(k) != v}

    headline = []
    if o_new["rag"] != o_old["rag"]:
        headline.append(f"Overall status moved from {o_old['rag'].upper()} to {o_new['rag'].upper()}.")
    hi_new = sum(1 for r in new_f if r["severity"] in ("critical", "high"))
    hi_res = sum(1 for r in resolved if r["severity"] in ("critical", "high"))
    if new_f or resolved:
        headline.append(f"{len(new_f)} new finding{'s' if len(new_f) != 1 else ''} ({hi_new} high) and {len(resolved)} resolved ({hi_res} high).")
    if hosts_added or hosts_removed:
        headline.append(f"{len(hosts_added)} host{'s' if len(hosts_added) != 1 else ''} appeared and {len(hosts_removed)} disappeared.")
    dns_old = {(r["host"], r["rtype"], r["value"]) for r in db.all("SELECT host, rtype, value FROM dns_records WHERE scan_id = ?", against)}
    dns_new = {(r["host"], r["rtype"], r["value"]) for r in db.all("SELECT host, rtype, value FROM dns_records WHERE scan_id = ?", sid)}
    dns_changes = []
    if dns_old and dns_new:      # only when both scans took a DNS snapshot
        common = {h for h, _, _ in dns_old} & {h for h, _, _ in dns_new}
        for h, t, v in sorted(dns_new - dns_old):
            if h in common:
                dns_changes.append({"host": h, "type": t, "value": v, "change": "added"})
        for h, t, v in sorted(dns_old - dns_new):
            if h in common:
                dns_changes.append({"host": h, "type": t, "value": v, "change": "removed"})
        moved = {(c["host"]) for c in dns_changes if c["type"] == "CNAME"}
        if moved:
            headline.append(f"{len(moved)} host{'s' if len(moved) != 1 else ''} changed CNAME target (check for new providers or takeovers).")
        elif dns_changes:
            headline.append(f"{len(dns_changes)} DNS record change{'s' if len(dns_changes) != 1 else ''} on existing hosts.")
    if opened or closed:
        headline.append(f"{len(opened)} port{'s' if len(opened) != 1 else ''} newly open, {len(closed)} closed.")
    if not headline:
        headline.append("No material change since the previous scan.")
    prev = scan_row(db, against)
    return {
        "against": {"id": against, "finished_at": prev["finished_at"] if prev else None, "rag": o_old["rag"]},
        "rag": {"before": o_old["rag"], "after": o_new["rag"]}, "headline": headline,
        "hosts": {"added": hosts_added, "removed": hosts_removed},
        "live": {"added": sorted(live_new - live_old), "removed": sorted(live_old - live_new)},
        "ports": {"opened": opened, "closed": closed},
        "findings": {"new": new_f, "resolved": resolved, "changed": changed},
        "dns": dns_changes,
        "metrics": deltas,
    }


def routes(state) -> list[Route]:
    from .app import err

    def _run_dir(scan) -> Path:
        base = state.cfg.runs_dir.resolve()
        d = (state.cfg.runs_dir / Path(scan["run_dir"]).name).resolve()
        if base not in d.parents:
            raise PermissionError("run folder outside the data folder")
        return d

    async def overview(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            cur = compute_overview(db, sid)
            prev_id = _previous_scan(db, scan)
            prev = compute_overview(db, prev_id) if prev_id else None
            prev_scan = scan_row(db, prev_id) if prev_id else None
        finally:
            db.close()
        cards = []
        for key, label, better, link in CARDS:
            v = cur["values"][key]
            p = prev["values"][key] if prev else None
            trend = None
            if p is not None and p != v:
                trend = "better" if (better == "lower" and v < p) else "worse" if better == "lower" else "changed"
            cards.append({"key": key, "label": label, "value": v, "previous": p, "trend": trend, "link": link})
        return JSONResponse({**cur, "cards": cards,
                             "previous": {"id": prev_id, "rag": prev["rag"], "finished_at": prev_scan["finished_at"]} if prev else None})

    async def graph_view(request: Request) -> Response:
        sid = request.path_params["id"]
        full = request.query_params.get("full") == "1"
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            g = build_graph(db, sid)
            body = {"summary": graph_summary(g)}
            if full:
                body["graph"] = to_payload(g)
        finally:
            db.close()
        return JSONResponse(body)

    async def attack_paths(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            out = simulate(db, sid)
        finally:
            db.close()
        # attach canonical reference URLs so the UI links MITRE techniques and category framing
        # without constructing any URL itself
        for p in out.get("paths", []):
            p["framing"] = refs.path_framing(p.get("category", ""), p.get("likelihood", ""))
            p["tag_refs"] = refs.agent_tag_refs(p.get("agent_tags", []))
            p["mitre_links"] = refs.mitre_links(p.get("mitre", []))
            for step in p.get("steps", []):
                step["mitre_links"] = refs.mitre_links(step.get("mitre", []))
        return JSONResponse(out)

    async def finding_detail(request: Request) -> Response:
        """One finding, expanded into everything the detail pane needs: the grouped siblings (the same
        issue on other hosts), curated what/why/fix guidance, every authoritative reference as a ready
        link (NIST/CWE/OWASP/CVE/KEV/EPSS — all built backend-side), and a pointer to the raw tool
        output in the run folder. No URL is constructed in the browser."""
        sid = request.path_params["id"]
        fid = request.path_params["fid"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            row = db.one("SELECT * FROM findings WHERE scan_id = ? AND id = ?", sid, fid)
            if not row:
                return err(404, "finding not found")
            siblings = db.all("SELECT id, severity, title, host, source_tool, evidence_ref, status FROM findings "
                              "WHERE scan_id = ? AND status != 'false_positive'", sid)
        finally:
            db.close()
        group = group_title(row["title"])
        members = [dict(r) for r in siblings if group_title(r["title"]) == group]
        if not members:                                  # the finding itself may be a false positive
            members = [{"id": row["id"], "severity": row["severity"], "title": row["title"],
                        "host": row["host"], "source_tool": row["source_tool"], "evidence_ref": row["evidence_ref"]}]
        hosts = sorted({m["host"] for m in members if m["host"]})
        cves = sorted({c.upper() for m in members for c in CVE_RE.findall(f"{m['title']} {m.get('evidence_ref') or ''}")})
        kev = any("CISA KEV" in m["title"] or "known-exploited" in m["title"].lower() for m in members)
        epss = any("EPSS" in m["title"] or "likely-exploited" in m["title"].lower() for m in members)
        guide = refs.guidance_for(group, row["area"], row["source_tool"])
        references = refs.finding_references(guide, cves=cves, kev=kev, epss=epss)
        # raw-output pointer: prefer the exact artifact file the pipeline recorded for this finding
        # (verified to exist); else the tool's run-folder subdir; else the run-folder root.
        run_dir = None
        try:
            run_dir = _run_dir(scan)
        except Exception:
            run_dir = None
        efile = row["evidence_file"] if "evidence_file" in row.keys() else None
        raw_file = ""
        if efile and run_dir is not None:
            try:
                if (run_dir / efile).is_file():
                    raw_file = efile
            except Exception:
                raw_file = ""
        hint = refs.raw_dir_hint(row["source_tool"])
        if raw_file:                                  # browse the artifact's own folder by default
            hint = str(Path(raw_file).parent) if "/" in raw_file else ""
        elif hint and run_dir is not None:
            try:
                if not (run_dir / hint).is_dir():
                    hint = ""
            except Exception:
                hint = ""
        else:
            hint = ""
        return JSONResponse({
            "id": row["id"], "group": group, "area": row["area"], "severity": row["severity"],
            "title": row["title"], "tool": row["source_tool"], "host": row["host"],
            "evidence_ref": row["evidence_ref"], "status": row["status"],
            "hosts": hosts, "cves": cves, "kev": kev, "epss": epss,
            "guidance": {"what": guide.get("what", ""), "why": guide.get("why", ""), "fix": guide.get("fix", "")},
            "references": references,
            "raw": {"evidence": row["evidence_ref"], "tool": row["source_tool"], "files_path": hint, "file": raw_file or None},
            "version_confidence": version_confidence(row["title"], row["area"]),
            "evidence": build_evidence(dict(row), run_dir),
            "members": [{"id": m["id"], "severity": m["severity"], "title": m["title"],
                         "host": m["host"], "evidence_ref": m.get("evidence_ref")} for m in members],
        })

    async def ips_view(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            rows = compute_ips(db, sid)
        finally:
            db.close()
        own = [r for r in rows if not r["shared"]]
        return JSONResponse({"ips": rows, "summary": {"total": len(rows), "own": len(own),
                             "shared": len(rows) - len(own), "multi_host": sum(1 for r in rows if r["host_count"] > 1)}})

    async def assets(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            rows = db.all("SELECT * FROM assets WHERE scan_id = ? ORDER BY host", sid)
            fcount: dict[str, dict[str, int]] = {}
            for r in db.all("SELECT host, severity, COUNT(*) AS n FROM findings WHERE scan_id = ? AND status != 'false_positive' "
                            "GROUP BY host, severity", sid):
                fcount.setdefault(r["host"], {})[r["severity"]] = r["n"]
            triage = {r["host"]: r["decision"] for r in db.all("SELECT host, decision FROM triage WHERE scan_id = ?", sid)}
            marks = ",".join("?" * len(TAKEOVER_TOOLS))
            takeover = {r["host"] for r in db.all(
                f"SELECT DISTINCT host FROM findings WHERE scan_id = ? AND source_tool IN ({marks}) AND severity != 'low'", sid, *TAKEOVER_TOOLS)}
            risky = {}
            for r in db.all("SELECT host, evidence_ref FROM findings WHERE scan_id = ? AND source_tool IN ('internetdb','internetdb-extra','naabu')", sid):
                port = str(r["evidence_ref"] or "").rsplit(":", 1)[-1]
                if port.isdigit():
                    for h in str(r["host"] or "").split(", "):
                        risky.setdefault(h, set()).add(int(port))
        finally:
            db.close()
        run = _run_dir(scan)
        shots = _screenshots(run)
        techd = _tech_detail(run)
        out = []
        for a in rows:
            tls = json.loads(a["tls"] or "{}")
            out.append({
                "host": a["host"], "ips": json.loads(a["ips"]), "is_live": bool(a["is_live"]), "web_url": a["web_url"],
                "http_status": a["http_status"], "tech": dedup_tech(json.loads(a["tech"])), "ports": json.loads(a["ports"]),
                "tags": classify_host(a["host"]),
                "risky_ports": sorted(risky.get(a["host"], [])), "in_cmdb": bool(a["in_cmdb"]), "cdn": bool(a["cdn"]),
                "third_party": bool(a["third_party"]), "tls_expiry": _tls_expiry(tls), "tls_version": tls.get("tls_version"),
                "tls_flags": [k for k in ("expired", "self_signed", "mismatched") if tls.get(k)],
                "findings": fcount.get(a["host"], {}), "triage": triage.get(a["host"]), "screenshot": shots.get(a["host"]),
                "edge": json.loads(a["edge"] or "{}"), "found_by": json.loads(a["found_by"] or "[]"),
                "ports_confirmed": json.loads(a["ports_confirmed"]) if a["ports_confirmed"] is not None else None,
                "suggestion": suggest_triage(a, a["host"] in takeover),
                "tech_detail": techd.get(a["host"], []),
            })
        return JSONResponse({"assets": out, "decisions": TRIAGE_DECISIONS})

    async def findings(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            rows = db.all("SELECT id, area, severity, title, host, source_tool, evidence_ref, status, note, status_at "
                          "FROM findings WHERE scan_id = ?", sid)
        finally:
            db.close()
        out = [{**dict(r), "group": group_title(r["title"]), "version_confidence": version_confidence(r["title"], r["area"])} for r in rows]
        out.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["area"], x["group"], x["host"] or ""))
        return JSONResponse({"findings": out, "statuses": FINDING_STATUSES})

    async def findings_patch(request: Request) -> Response:
        sid = request.path_params["id"]
        try:
            data = json.loads(await request.body() or b"{}")
        except json.JSONDecodeError:
            return err(400, "invalid JSON")
        ids = data.get("ids")
        status = data.get("status")
        note = data.get("note")
        if not isinstance(ids, list) or not ids or len(ids) > 5000 or not all(isinstance(i, int) for i in ids):
            return err(422, "ids must be a non-empty list of finding ids")
        if status is not None and status not in FINDING_STATUSES:
            return err(422, f"status must be one of {', '.join(FINDING_STATUSES)}")
        if note is not None and (not isinstance(note, str) or len(note) > 2000):
            return err(422, "note must be text up to 2000 characters")
        if status is None and note is None:
            return err(422, "nothing to change")
        db = state.db()
        try:
            marks = ",".join("?" * len(ids))
            with db.tx():
                if status is not None:
                    db.run(f"UPDATE findings SET status = ?, status_at = ? WHERE scan_id = ? AND id IN ({marks})", status, now(), sid, *ids)
                if note is not None:
                    db.run(f"UPDATE findings SET note = ? WHERE scan_id = ? AND id IN ({marks})", note.strip() or None, sid, *ids)
            n = db.one(f"SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND id IN ({marks})", sid, *ids)["n"]
        finally:
            db.close()
        return JSONResponse({"updated": n})

    async def triage_list(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            items = {r["value"]: r for r in db.all("SELECT value, grp, sources, reasons FROM scope_items WHERE scan_id = ? "
                                                    "AND kind IN ('root','subdomain') AND decision = 'included' AND value NOT LIKE '*.%'", sid)}
            assets = {r["host"]: r for r in db.all("SELECT * FROM assets WHERE scan_id = ?", sid)}
            decisions = {r["host"]: r for r in db.all("SELECT * FROM triage WHERE scan_id = ?", sid)}
            fcount: dict[str, int] = {}
            for r in db.all("SELECT host, COUNT(*) AS n FROM findings WHERE scan_id = ? AND status != 'false_positive' "
                            "AND severity IN ('critical','high','medium') GROUP BY host", sid):
                fcount[r["host"]] = r["n"]
            marks = ",".join("?" * len(TAKEOVER_TOOLS))
            takeover = {r["host"] for r in db.all(
                f"SELECT DISTINCT host FROM findings WHERE scan_id = ? AND source_tool IN ({marks}) AND severity != 'low'", sid, *TAKEOVER_TOOLS)}
        finally:
            db.close()
        hosts = sorted(set(items) | {scan["root_domain"]})
        out = []
        for h in hosts:
            a = assets.get(h)
            if a and a["in_cmdb"]:
                continue
            it = items.get(h)
            d = decisions.get(h)
            out.append({
                "host": h, "group": it["grp"] if it else "root", "reasons": json.loads(it["reasons"]) if it else [],
                "is_live": bool(a and a["is_live"]), "http_status": a["http_status"] if a else None,
                "ips": json.loads(a["ips"])[:6] if a else [], "third_party": bool(a and a["third_party"]),
                "cdn": bool(a and a["cdn"]), "issues": fcount.get(h, 0),
                "decision": d["decision"] if d else None, "note": d["note"] if d else None, "decided_at": d["decided_at"] if d else None,
                "suggestion": suggest_triage(a, h in takeover),
            })
        return JSONResponse({"hosts": out, "decisions": TRIAGE_DECISIONS})

    async def triage_put(request: Request) -> Response:
        sid = request.path_params["id"]
        try:
            data = json.loads(await request.body() or b"{}")
        except json.JSONDecodeError:
            return err(400, "invalid JSON")
        hosts = data.get("hosts")
        if not isinstance(hosts, list) or not hosts or len(hosts) > 5000 or not all(isinstance(h, str) for h in hosts):
            return err(422, "hosts must be a non-empty list")
        has_decision, has_note = "decision" in data, "note" in data
        decision, note = data.get("decision"), data.get("note")
        if has_decision and decision is not None and decision not in TRIAGE_DECISIONS:
            return err(422, "unknown decision")
        if has_note and note is not None and (not isinstance(note, str) or len(note) > 2000):
            return err(422, "note must be text up to 2000 characters")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            allowed = {r["value"] for r in db.all("SELECT value FROM scope_items WHERE scan_id = ? AND kind IN ('root','subdomain')", sid)}
            allowed.add(scan["root_domain"])
            bad = [h for h in hosts if h not in allowed]
            if bad:
                return err(422, f"not in this scan's scope: {', '.join(bad[:5])}")
            with db.tx():
                for h in hosts:
                    cur = db.one("SELECT decision, note FROM triage WHERE scan_id = ? AND host = ?", sid, h)
                    dec = decision if has_decision else (cur["decision"] if cur else None)
                    nt = (note.strip() or None) if has_note and note is not None else (None if has_note else (cur["note"] if cur else None))
                    db.run("INSERT INTO triage (scan_id, host, decision, note, decided_at) VALUES (?, ?, ?, ?, ?) "
                           "ON CONFLICT(scan_id, host) DO UPDATE SET decision = excluded.decision, note = excluded.note, "
                           "decided_at = excluded.decided_at", sid, h, dec, nt, now())
        finally:
            db.close()
        return JSONResponse({"updated": len(hosts)})

    async def triage_cmdb(request: Request) -> Response:
        """Record hosts as known assets in the CMDB (and mark them so in this scan)."""
        sid = request.path_params["id"]
        try:
            data = json.loads(await request.body() or b"{}")
        except json.JSONDecodeError:
            return err(400, "invalid JSON")
        hosts = data.get("hosts")
        if not isinstance(hosts, list) or not hosts or len(hosts) > 5000 or not all(isinstance(h, str) for h in hosts):
            return err(422, "hosts must be a non-empty list")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            allowed = {r["value"] for r in db.all("SELECT value FROM scope_items WHERE scan_id = ? AND kind IN ('root','subdomain')", sid)}
            allowed.add(scan["root_domain"])
            hosts = [h for h in hosts if h in allowed]
            with db.tx():
                for h in hosts:
                    db.run("INSERT INTO cmdb_entries (value, kind, imported_at) VALUES (?, 'host', ?) ON CONFLICT(value) DO NOTHING", h, now())
                    db.run("UPDATE assets SET in_cmdb = 1 WHERE scan_id = ? AND host = ?", sid, h)
        finally:
            db.close()
        return JSONResponse({"added": len(hosts)})

    def _safe_path(scan, rel: str) -> Path:
        root = _run_dir(scan)
        rel = (rel or "").lstrip("/")
        if "\x00" in rel or any(part == ".." for part in Path(rel).parts):
            raise PermissionError("bad path")
        p = (root / rel).resolve()
        if p != root and root not in p.parents:
            raise PermissionError("outside the run folder")
        return p

    async def files_list(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
        finally:
            db.close()
        if not scan:
            return err(404, "scan not found")
        try:
            p = _safe_path(scan, request.query_params.get("path", ""))
        except PermissionError as e:
            return err(403, str(e))
        if not p.exists():
            return err(404, "not found")
        if not p.is_dir():
            return err(400, "not a folder")
        root = _run_dir(scan)
        entries = []
        for c in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            if c.is_symlink():
                continue
            st = c.stat()
            entries.append({"name": c.name, "path": str(c.relative_to(root)), "dir": c.is_dir(), "size": st.st_size if c.is_file() else None,
                            "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds"),
                            "children": sum(1 for _ in c.iterdir()) if c.is_dir() else None})
        return JSONResponse({"path": str(p.relative_to(root)) if p != root else "", "entries": entries})

    async def files_raw(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
        finally:
            db.close()
        if not scan:
            return err(404, "scan not found")
        try:
            p = _safe_path(scan, request.query_params.get("path", ""))
        except PermissionError as e:
            return err(403, str(e))
        if not p.is_file() or p.is_symlink():
            return err(404, "not found")
        ext = p.suffix.lower()
        download = request.query_params.get("download") == "1"
        headers = {"X-Content-Type-Options": "nosniff",
                   # tool output can contain hostile content from scanned sites: never let it run in this origin
                   "Content-Security-Policy": "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'"}
        if ext in SCREENSHOT_EXT and not download:
            return FileResponse(p, media_type=mimetypes.types_map.get(ext, "image/jpeg"), headers=headers)
        if ext in TEXT_EXT and not download:
            if p.stat().st_size > MAX_PREVIEW:
                return err(413, "too large to preview; download it instead")
            return Response(p.read_bytes(), media_type="text/plain; charset=utf-8", headers=headers)
        # anything else (HTML reports, archives…) downloads as an attachment, never renders here
        return FileResponse(p, media_type="application/octet-stream", filename=p.name,
                            headers={**headers, "Content-Disposition": f'attachment; filename="{p.name}"'})

    async def history(request: Request) -> Response:
        """RAG and a few headline numbers for every scan that has results (Home page)."""
        db = state.db()
        try:
            ids = [r["scan_id"] for r in db.all("SELECT scan_id FROM metrics")]
            out = {}
            for sid in ids:
                try:
                    o = compute_overview(db, sid)
                except Exception:
                    continue
                out[sid] = {"rag": o["rag"], "values": o["values"], "severity": o["severity"]}
        finally:
            db.close()
        return JSONResponse({"scans": out})

    async def changes(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            options = [dict(r) for r in db.all(
                "SELECT s.id, s.finished_at, s.status FROM scans s JOIN metrics m ON m.scan_id = s.id "
                "WHERE s.root_domain = ? AND s.id != ? ORDER BY s.rowid DESC", scan["root_domain"], sid)]
            against = request.query_params.get("against") or _previous_scan(db, scan)
            if against and against not in {o["id"] for o in options}:
                return err(422, "can only compare with another finished scan of the same domain")
            if not against:
                return JSONResponse({"against": None, "options": options})
            out = compute_changes(db, sid, against)
        finally:
            db.close()
        return JSONResponse(out | {"options": options})

    async def search(request: Request) -> Response:
        sid = request.path_params["id"]
        q = (request.query_params.get("q") or "").strip().lower()
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            if len(q) < 2:
                return JSONResponse({"q": q, "hosts": [], "ips": [], "findings": []})
            assets = db.all("SELECT host, ips, is_live FROM assets WHERE scan_id = ?", sid)
            hosts, ipset = [], {}
            for a in assets:
                ips = json.loads(a["ips"] or "[]")
                if q in a["host"].lower():
                    hosts.append({"host": a["host"], "live": bool(a["is_live"]),
                                  "agent": is_agent_surface(a["host"])})
                for ip in ips:
                    if q in ip.lower():
                        ipset.setdefault(ip, {"ip": ip, "hosts": []})["hosts"].append(a["host"])
            hosts.sort(key=lambda h: (not h["live"], h["host"]))
            ips = sorted(ipset.values(), key=lambda e: (-len(e["hosts"]), e["ip"]))
            fseen, findings = set(), []
            for r in db.all("SELECT area, severity, title, host, source_tool FROM findings "
                            "WHERE scan_id = ? AND status != 'false_positive'", sid):
                g = group_title(r["title"])
                if q in g.lower() or q in (r["host"] or "").lower():
                    key = (r["severity"], g)
                    if key in fseen:
                        continue
                    fseen.add(key)
                    findings.append({"severity": r["severity"], "group": g, "area": r["area"], "host": r["host"]})
            findings.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["group"]))
        finally:
            db.close()
        return JSONResponse({"q": q, "hosts": hosts[:8], "ips": ips[:8], "findings": findings[:8],
                             "more": {"hosts": max(0, len(hosts) - 8), "ips": max(0, len(ips) - 8), "findings": max(0, len(findings) - 8)}})

    async def report_preview(request: Request) -> Response:
        from . import reports
        sid = request.path_params["id"]
        kind = request.query_params.get("kind", "board")
        against = request.query_params.get("against") or None
        if kind not in reports.REPORT_KINDS:
            return err(422, f"unknown report kind: {kind}")
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            body = reports.preview(db, sid, kind, against, data_dir=state.cfg.data_dir)
        finally:
            db.close()
        return JSONResponse({**body, "kinds": [{"kind": k, "title": reports.KIND_TITLES[k]} for k in reports.REPORT_KINDS]})

    async def report_build(request: Request) -> Response:
        from . import reports
        sid = request.path_params["id"]
        kind = request.query_params.get("kind", "board")
        redacted = request.query_params.get("redacted") in ("1", "true", "yes")
        against = request.query_params.get("against") or None
        if kind not in reports.REPORT_KINDS:
            return err(422, f"unknown report kind: {kind}")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            out_dir = _run_dir(scan) / "reports"
            try:
                path = reports.build(db, sid, kind, redacted=redacted, against=against, out_dir=out_dir,
                                     data_dir=state.cfg.data_dir)
            except reports.ReportError as e:
                return err(503, str(e))
        finally:
            db.close()
        media = "application/zip" if kind == "share-zip" else "application/pdf"
        disposition = "attachment" if kind == "share-zip" else "inline"
        return FileResponse(path, media_type=media, filename=path.name,
                            content_disposition_type=disposition)

    async def tech_eol(request: Request) -> Response:
        from starlette.concurrency import run_in_threadpool
        name = request.query_params.get("name", "")
        version = request.query_params.get("version") or None
        if not name:
            return err(400, "name required")
        res = await run_in_threadpool(eolmod.assess, state.cfg.data_dir, name, version)
        return JSONResponse(res)

    async def emails_view(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            flagged = db.one("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND source_tool IN ('xposedornot', 'hibp')", sid)["n"] > 0
        finally:
            db.close()
        emails = _harvested_emails(_run_dir(scan))
        return JSONResponse({"emails": emails, "count": len(emails), "flagged": bool(flagged)})

    async def emails_check(request: Request) -> Response:
        from starlette.concurrency import run_in_threadpool
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
        finally:
            db.close()
        if not scan:
            return err(404, "scan not found")
        emails = [e["email"] for e in _harvested_emails(_run_dir(scan))][:20]   # cap for the daily rate limit
        if not emails:
            return JSONResponse({"results": [], "checked": 0, "note": "no emails harvested"})
        results = await run_in_threadpool(_xon_check_emails, emails)
        exposed = sum(1 for r in results if r.get("breaches"))
        return JSONResponse({"results": results, "checked": len(emails), "exposed": exposed})

    async def dns_view(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            if not scan_row(db, sid):
                return err(404, "scan not found")
            rows = db.all("SELECT host, rtype, value FROM dns_records WHERE scan_id = ? ORDER BY host, rtype, value", sid)
        finally:
            db.close()
        recs = [dict(r) for r in rows]
        types: dict[str, int] = {}
        for r in recs:
            types[r["rtype"]] = types.get(r["rtype"], 0) + 1
        return JSONResponse({"records": recs, "types": types, "total": len(recs),
                             "hosts": sorted({r["host"] for r in recs})})

    async def endpoints_view(request: Request) -> Response:
        sid = request.path_params["id"]
        host = request.query_params.get("host")
        db = state.db()
        try:
            scan = scan_row(db, sid)
        finally:
            db.close()
        if not scan:
            return err(404, "scan not found")
        from urllib.parse import urlsplit
        run_dir = _run_dir(scan)
        sources = [("interesting", "urls/interesting.txt"),
                   ("url", "urls/historical.txt"), ("url", "urls/gau_inscope.txt")]
        by_host: dict[str, dict] = {}
        total = 0
        for kind, rel in sources:
            p = run_dir / rel
            if not p.exists():
                continue
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            for u in lines:
                u = u.strip()
                if not u.startswith("http"):
                    continue
                try:
                    h = (urlsplit(u).hostname or "").lower()
                except Exception:
                    continue
                if not h:
                    continue
                if host and not _host_eq(h, host):
                    continue
                d = by_host.setdefault(h, {"interesting": [], "urls": [], "_seen": set()})
                if u in d["_seen"]:
                    continue
                d["_seen"].add(u)
                total += 1
                (d["interesting"] if kind == "interesting" else d["urls"]).append(u)
                if total > 60000:
                    break
        # ZAP's spider surfaces deep endpoints (exposed backups, admin paths, .git/.env) that gau/BBOT miss.
        zpath = run_dir / "zap" / "zap-estate.json"
        if zpath.exists():
            _SENS = re.compile(r"\.(sql|bak|backup|old|csv|xls[xm]?|zip|tar|gz|tgz|7z|env|git|pem|key|p12|pfx|log|dump|sqlite)(\?|$)"
                               r"|/(admin|backup|private|internal|secret|config|\.git|\.env|\.svn|phpinfo)", re.I)
            try:
                z = json.loads(zpath.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                z = None
            for site in ((z or {}).get("site") or []):
                for al in site.get("alerts", []) or []:
                    for ins in al.get("instances", []) or []:
                        u = (ins.get("uri") or "").strip()
                        if not u.startswith("http"):
                            continue
                        try:
                            h = (urlsplit(u).hostname or "").lower()
                        except Exception:
                            continue
                        if not h or (host and not _host_eq(h, host)):
                            continue
                        d = by_host.setdefault(h, {"interesting": [], "urls": [], "_seen": set()})
                        if u in d["_seen"]:
                            continue
                        d["_seen"].add(u)
                        total += 1
                        (d["interesting"] if _SENS.search(u) else d["urls"]).append(u)
        if host:
            d = by_host.get(host.lower()) or next((v for k, v in by_host.items() if _host_eq(k, host)), {"interesting": [], "urls": []})
            return JSONResponse({"host": host,
                                 "interesting": d["interesting"][:200], "urls": d["urls"][:500],
                                 "counts": {"interesting": len(d["interesting"]), "urls": len(d["urls"])}})
        summary = [{"host": h, "total": len(v["interesting"]) + len(v["urls"]), "interesting": len(v["interesting"])}
                   for h, v in by_host.items()]
        summary.sort(key=lambda x: -x["total"])
        return JSONResponse({"hosts": summary[:500], "total": total})

    return [

        Route("/api/scans/{id:str}/search", search, methods=["GET"]),
        Route("/api/tech/eol", tech_eol, methods=["GET"]),
        Route("/api/scans/{id:str}/emails", emails_view, methods=["GET"]),
        Route("/api/scans/{id:str}/emails/check", emails_check, methods=["POST"]),
        Route("/api/scans/{id:str}/dns", dns_view, methods=["GET"]),
        Route("/api/scans/{id:str}/endpoints", endpoints_view, methods=["GET"]),
        Route("/api/scans/{id:str}/report/preview", report_preview, methods=["GET"]),
        Route("/api/scans/{id:str}/report", report_build, methods=["GET"]),
        Route("/api/scans/{id:str}/changes", changes, methods=["GET"]),
        Route("/api/scans/{id:str}/overview", overview, methods=["GET"]),
        Route("/api/scans/{id:str}/assets", assets, methods=["GET"]),
        Route("/api/scans/{id:str}/ips", ips_view, methods=["GET"]),
        Route("/api/scans/{id:str}/graph", graph_view, methods=["GET"]),
        Route("/api/scans/{id:str}/attack-paths", attack_paths, methods=["GET"]),
        Route("/api/scans/{id:str}/findings", findings, methods=["GET"]),
        Route("/api/scans/{id:str}/findings", findings_patch, methods=["PATCH"]),
        Route("/api/scans/{id:str}/findings/{fid:int}", finding_detail, methods=["GET"]),
        Route("/api/scans/{id:str}/triage", triage_list, methods=["GET"]),
        Route("/api/scans/{id:str}/triage", triage_put, methods=["PUT"]),
        Route("/api/scans/{id:str}/triage/cmdb", triage_cmdb, methods=["POST"]),
        Route("/api/scans/{id:str}/files", files_list, methods=["GET"]),
        Route("/api/scans/{id:str}/files/raw", files_raw, methods=["GET"]),
        Route("/api/history", history, methods=["GET"]),
    ]
