"""Milestone 6: the comprehensive master report.

One end-to-end technical report, assembled from the database at request time and rendered to PDF with
Typst (baked into the image). It carries embedded evidence plus run-folder pointers, authoritative deep
links (NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK, CWE, OWASP Top 10, NIST SP 800-53), curated remediation
guidance per finding class, and full kill-chain attack paths.

Two outputs:
  master      The full report (optionally redacted).
  share-zip   The redacted report + a README, zipped for sending outside the team.

Redaction replaces host names and IPs with stable pseudonyms (asset-01, ip-07). Severities, CVE ids,
counts, MITRE ids, control mappings and recommendations are kept — they carry the message.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import tempfile
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .db import DB
from .api_results import (
    SEV_ORDER, compute_overview, compute_changes, group_title, scan_row, _previous_scan,
)
from .graph import build_graph, graph_summary
from .attackpaths import simulate, CATEGORIES
from . import report_refs as kb

REPORT_KINDS = ("master", "share-zip")
KIND_TITLES = {"master": "Comprehensive report", "share-zip": "Redacted share pack"}
RAG_WORD = {"red": "RED", "amber": "AMBER", "green": "GREEN"}
RAG_RGB = {"red": "#c0392b", "amber": "#c87f0a", "green": "#1e8449"}
SEV_RGB = {"critical": "#7b241c", "high": "#c0392b", "medium": "#c87f0a", "low": "#2471a3", "info": "#566573"}
AREA_LABEL = {
    "tls": "TLS / certificates", "email": "Email authentication", "brand": "Brand / lookalikes",
    "web": "Web application", "dns": "DNS", "exposure": "Exposed services", "vulns": "Vulnerabilities",
    "leak": "Leaks", "surface": "Attack surface", "intel": "Threat intel",
}
LIK_WORD = {"observed": "Observed", "plausible": "Plausible", "theoretical": "Theoretical"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
EPSS_RE = re.compile(r"EPSS\s+(\d+)%", re.I)
# where each tool's raw artifacts live in the run folder (shown in the Files tab)
TOOL_FOLDER = {
    "zap": "zap/", "tlsx": "tls/", "testssl": "tls/", "intel-cve": "services/", "internetdb": "services/",
    "internetdb-extra": "services/", "naabu": "services/", "checkdmarc": "email/", "dns-email": "email/",
    "dnsreaper": "bbot/", "bbot:baddns": "bbot/", "baddns-live": "bbot/", "urlscan": "lookalikes/",
    "dnstwist": "lookalikes/", "opensquat": "lookalikes/", "leakix": "services/", "spiderfoot": "services/",
    "gau": "urls/", "cloudlist": "cloud/", "asn": "services/", "hibp": "hibp/",
}


# --------------------------------------------------------------------------- redaction

class Redactor:
    def __init__(self, on: bool):
        self.on = on
        self._host: dict[str, str] = {}
        self._ip: dict[str, str] = {}
        self._email: dict[str, str] = {}
        self._ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        self._ip6_re = re.compile(r"(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}", re.I)
        self._email_re = re.compile(r"[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}", re.I)
        self._host_re = re.compile(r"\b(?:[a-z0-9_-]+\.)+[a-z]{2,}\b", re.I)

    def host(self, h):
        if not h:
            return h or ""
        if not self.on:
            return h
        if h not in self._host:
            self._host[h] = f"asset-{len(self._host) + 1:02d}"
        return self._host[h]

    def ip(self, v):
        if not v:
            return v or ""
        if not self.on:
            return v
        if v not in self._ip:
            self._ip[v] = f"ip-{len(self._ip) + 1:02d}"
        return self._ip[v]

    def email(self, v):
        if not v:
            return v or ""
        if not self.on:
            return v
        if v not in self._email:
            self._email[v] = f"email-{len(self._email) + 1:02d}"
        return self._email[v]

    def _sub_ip6(self, m):
        tok = m.group(0)
        try:
            if ipaddress.ip_address(tok).version != 6:
                return tok
        except ValueError:
            return tok
        return self.ip(tok)

    def text(self, s):
        if not s or not self.on:
            return s or ""
        # order matters: whole emails first (so a domain isn't half-redacted), then IPv4, IPv6, hosts
        s = self._email_re.sub(lambda m: self.email(m.group(0)), s)
        s = self._ip_re.sub(lambda m: self.ip(m.group(0)), s)
        s = self._ip6_re.sub(self._sub_ip6, s)
        s = self._host_re.sub(lambda m: self.host(m.group(0)), s)
        return s

    def hosts(self, hs):
        return [self.host(h) for h in hs]


# --------------------------------------------------------------------------- data

def _split_hosts(h) -> list[str]:
    return [x.strip() for x in (h or "").split(",") if x.strip()]


def _load_kev_cache(data_dir) -> dict:
    if not data_dir:
        return {}
    p = Path(data_dir) / "cache" / "kev.json"
    try:
        raw = json.loads(p.read_text())
        return {v["cveID"]: v for v in raw.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return {}


def _load_nvd(data_dir, cve: str) -> dict:
    if not data_dir:
        return {}
    try:
        return json.loads((Path(data_dir) / "cache" / "nvd" / f"{cve}.json").read_text())
    except Exception:
        return {}


def _cve_register(findings: list[dict], kev_cache: dict, data_dir=None) -> dict:
    """CVE -> {hosts, kev, epss, product, vuln_name, kev_meta, cvss, severity, cwes}."""
    reg: dict[str, dict] = {}
    for f in findings:
        if f["source_tool"] != "intel-cve":
            continue
        title = f["title"]
        epss_m = EPSS_RE.search(title)
        kev_in_title = "CISA KEV" in title
        ev = f.get("evidence_ref") or ""
        product = vuln = ""
        if "·" in ev:                       # "ip · vendor product: vulnName"
            tail = ev.split("·", 1)[1]
            if ":" in tail:
                product, vuln = tail.split(":", 1)
            else:
                product = tail
        for cve in CVE_RE.findall(title) + CVE_RE.findall(ev):
            cve = cve.upper()
            r = reg.setdefault(cve, {"cve": cve, "hosts": set(), "kev": False, "epss": None,
                                     "product": "", "vuln_name": "", "kev_meta": None,
                                     "cvss": None, "severity": None, "cwes": []})
            r["hosts"].update(_split_hosts(f["host"]))
            r["kev"] = r["kev"] or kev_in_title
            if epss_m and r["epss"] is None:
                r["epss"] = int(epss_m.group(1)) / 100
            if product.strip() and not r["product"]:
                r["product"] = product.strip()
            if vuln.strip() and not r["vuln_name"]:
                # the evidence may carry a trailing " · CVSS …/CWE …" tail — keep only the vuln name
                r["vuln_name"] = vuln.split(" · CVSS")[0].replace(" · used in ransomware", "").strip()
            k = kev_cache.get(cve)
            if k:
                r["kev"] = True
                r["kev_meta"] = k
                r["product"] = r["product"] or f"{k.get('vendorProject','')} {k.get('product','')}".strip()
                r["vuln_name"] = r["vuln_name"] or k.get("vulnerabilityName", "")
    for cve, r in reg.items():                 # authoritative CVSS / CWE from the cached NVD record
        e = _load_nvd(data_dir, cve)
        if e:
            r["cvss"], r["severity"], r["cwes"] = e.get("cvss"), e.get("severity"), e.get("cwes", [])
    return reg


def collect(db: DB, sid: str, against: str | None = None, data_dir=None) -> dict:
    scan = scan_row(db, sid)
    if not scan:
        raise KeyError(sid)
    overview = compute_overview(db, sid)
    prev_id = against or _previous_scan(db, scan)
    changes = compute_changes(db, sid, prev_id) if prev_id else None
    try:
        paths = simulate(db, sid)
    except Exception:
        paths = {"paths": [], "summary": {"total": 0, "agent_related": 0, "by_category": {}, "by_agent_tag": {}}}
    try:
        gsummary = graph_summary(build_graph(db, sid))
    except Exception:
        gsummary = {"nodes": {}, "edges": 0}
    findings = [dict(r) for r in db.all(
        "SELECT area, severity, title, host, source_tool, evidence_ref, status, note "
        "FROM findings WHERE scan_id = ? AND status != 'false_positive'", sid)]
    for x in findings:
        x["group"] = group_title(x["title"])
    assets = [dict(r) for r in db.all(
        "SELECT host, is_live, ips, tech, tls, ports, ports_confirmed, cdn, third_party, http_status, web_url "
        "FROM assets WHERE scan_id = ?", sid)]
    assets_by_host = {a["host"]: a for a in assets}
    dns = {}
    for r in db.all("SELECT host, rtype, value FROM dns_records WHERE scan_id = ?", sid):
        dns.setdefault((r["host"], r["rtype"]), []).append(r["value"])
    stages = [dict(r) for r in db.all("SELECT stage_key, status FROM stages WHERE scan_id = ?", sid)]
    kev_cache = _load_kev_cache(data_dir)
    cves = _cve_register(findings, kev_cache, data_dir)
    email = sorted((x for x in findings if x["area"] == "email"),
                   key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["host"] or ""))
    brand = sorted((x for x in findings if x["area"] == "brand"),
                   key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
    return {
        "scan": dict(scan), "overview": overview, "changes": changes, "paths": paths, "graph": gsummary,
        "findings": findings, "assets": assets, "assets_by_host": assets_by_host, "dns": dns,
        "stages": stages, "cves": cves, "agent_hosts": overview.get("agent_hosts", []),
        "email": email, "brand": brand, "generated_at": datetime.now(timezone.utc),
    }


def preview(db: DB, sid: str, kind: str, against: str | None = None, data_dir=None) -> dict:
    d = collect(db, sid, against, data_dir)
    ov, ch = d["overview"], d["changes"]
    scan = d["scan"]
    mats = [x for x in d["findings"] if x["severity"] in ("critical", "high", "medium")]
    kev_n = sum(1 for c in d["cves"].values() if c["kev"])
    sections = [
        f"Executive summary — status {RAG_WORD[ov['rag']]}, {len(ov['reasons'])} reason(s)",
        f"What changed: {ch['headline'][0] if ch else 'first scan, no baseline'}",
        f"Detailed findings: {len(mats)} material (with evidence, references and remediation)",
        f"CVE register: {len(d['cves'])} CVEs ({kev_n} on CISA KEV) with NVD / KEV / EPSS links",
        f"Attack paths: {d['paths']['summary']['total']} full kill-chains ({d['paths']['summary']['agent_related']} agent-related)",
        f"AI-agent / MCP surface: {len(d['agent_hosts'])} hosts",
        "Appendices: asset inventory, email & brand, evidence index, framework coverage (NIST/OWASP/MITRE)",
    ]
    return {
        "kind": kind, "title": KIND_TITLES[kind], "root_domain": scan["root_domain"],
        "finished_at": scan["finished_at"], "rag": ov["rag"],
        "against": {"id": ch["against"]["id"], "finished_at": ch["against"]["finished_at"]} if ch else None,
        "sections": sections, "redacted_by_default": kind == "share-zip",
    }


# --------------------------------------------------------------------------- Typst helpers

def _s(v) -> str:
    s = "" if v is None else str(v)
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")
    return f'"{s}"'


def _sml(v) -> str:
    """String literal preserving newlines (for raw code blocks)."""
    s = "" if v is None else str(v)
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "\\n")
    return f'"{s}"'


def _t(v) -> str:
    return "#" + _s(v)


_MARKUP_SPECIAL = re.compile(r"([#*_`$\\@<>\[\]])")


def _em(s) -> str:
    return _MARKUP_SPECIAL.sub(r"\\\1", str(s or ""))


def _lnk(url: str, label: str) -> str:
    """A Typst link expression for use inside a content block: #link("url")[label]."""
    return f'#link({_s(url)})[{_em(label)}]'


def _code(text: str) -> str:
    """A monospace evidence block."""
    if not text.strip():
        return ""
    return f'#block(width: 100%, fill: rgb("#f4f6f8"), inset: 7pt, radius: 3pt, breakable: true)[#raw(block: true, {_sml(text)})]\n'


def _chips(items) -> str:
    if not items:
        return ""
    return "#stack(dir: ltr, spacing: 5pt, " + " ".join(f'chip({_s(x)}),' for x in items) + ")\n"


# --------------------------------------------------------------------------- preamble & shared blocks

def _preamble(d: dict, redacted: bool) -> str:
    rag = d["overview"]["rag"]
    accent = RAG_RGB.get(rag, "#2c3e50")
    fin = (d["scan"]["finished_at"] or "")[:16].replace("T", " ")
    gen = d["generated_at"].strftime("%Y-%m-%d %H:%M UTC")
    sub = f"{d['scan']['root_domain']} · scan finished {fin} · generated {gen}" + (" · REDACTED" if redacted else "")
    return f"""#set document(title: "External Attack Surface Report — {_em(d['scan']['root_domain'])}", author: "Outsider ASM")
#set page(paper: "a4", margin: (x: 2cm, y: 2.2cm), numbering: "1 / 1", number-align: center,
  footer: context [
    #set text(size: 8pt, fill: rgb("#7f8c8d"))
    #line(length: 100%, stroke: 0.5pt + rgb("#dfe4ea"))
    #v(2pt)
    #grid(columns: (1fr, 1fr),
      align(left)[Outsider ASM · 88Zero Labs], align(right)[Confidential · page #counter(page).display()])
  ])
#set text(font: ("Liberation Sans", "DejaVu Sans"), size: 9.7pt, fill: rgb("#2c3e50"))
#set par(justify: true, leading: 0.62em)
#show link: it => text(fill: rgb("#1f6feb"))[#underline(it)]
#show heading.where(level: 1): it => block(above: 1.2em, below: 0.6em)[#set text(size: 15pt, fill: rgb("{accent}")); #counter(heading).display() #h(4pt) #it.body]
#show heading.where(level: 2): it => block(above: 0.9em, below: 0.35em)[#set text(size: 12pt, fill: rgb("#2c3e50")); #it.body]
#show heading.where(level: 3): it => block(above: 0.6em, below: 0.25em)[#set text(size: 10.5pt, fill: rgb("#34495e")); #it.body]
#let sev_badge(sev, rgbhex) = box(fill: rgb(rgbhex), inset: (x: 5pt, y: 2pt), radius: 2pt)[#text(fill: white, size: 8pt, weight: "bold")[#upper(sev)]]
#let chip(s) = box(fill: rgb("#eef2f7"), inset: (x: 5pt, y: 2pt), radius: 3pt)[#text(size: 8pt, fill: rgb("#34495e"))[#s]]

// ---- cover ----
#v(3cm)
#align(center)[
  #text(size: 26pt, weight: "bold", fill: rgb("{accent}"))[External Attack Surface Report]
  #v(6pt)
  #text(size: 16pt)[{_em(d['scan']['root_domain'])}]
  #v(2pt)
  #text(size: 10pt, fill: rgb("#7f8c8d"))[{_em(sub)}]
  #v(10pt)
  #box(fill: rgb("{accent}1a"), stroke: 1pt + rgb("{accent}"), inset: 10pt, radius: 4pt)[
    #text(size: 15pt, weight: "bold", fill: rgb("{accent}"))[Overall exposure: {RAG_WORD[rag]}]
  ]
]
#v(1fr)
#align(center)[#text(size: 8.5pt, fill: rgb("#95a5a6"))[Prepared with Outsider ASM. Passive and light-touch collection unless an active stage was explicitly authorised. #linebreak() This report is confidential and intended only for the named organisation.]]
#pagebreak()

// ---- contents ----
#outline(title: "Contents", depth: 2, indent: auto)
#pagebreak()
#set heading(numbering: "1.1")
"""


def _rag_box(d: dict, R: Redactor) -> str:
    ov = d["overview"]
    rag = ov["rag"]
    hexc = RAG_RGB[rag]
    lines = "".join(f'[#text(size: 9pt)[• {_t(R.text(r["text"]))}]],\n' for r in ov["reasons"][:10]) \
        or '[#text(size: 9pt, fill: rgb("#1e8449"))[No material issues outstanding.]],'
    return f"""#block(width: 100%, fill: rgb("{hexc}1a"), stroke: (left: 3pt + rgb("{hexc}")), inset: 10pt, radius: 3pt)[
  #text(size: 13pt, weight: "bold", fill: rgb("{hexc}"))[Overall status: {RAG_WORD[rag]}]
  #v(4pt)
  #stack(spacing: 4pt, {lines})
]
#v(8pt)
"""


def _metric_grid(d: dict, R: Redactor) -> str:
    values = d["overview"]["values"]
    deltas = (d["changes"] or {}).get("metrics", {})
    rows = [
        ("hosts_in_scope", "Hosts in scope"), ("live_web_hosts", "Live web hosts"),
        ("agent_surface", "AI-agent / MCP surface"), ("high_findings", "High / critical findings"),
        ("medium_findings", "Medium findings"), ("takeover_risks", "Takeover risks"),
        ("risky_services", "Risky services"), ("kev_cves", "Known-exploited CVEs"),
        ("dmarc_missing", "Domains w/o DMARC reject"), ("expiring_certs", "Certs expired / expiring"),
        ("open_ports", "Open ports (yours)"), ("own_public_ips", "Your public IPs"),
    ]
    cells = []
    for key, label in rows:
        v = values.get(key, 0)
        dmeta = deltas.get(key)
        arrow = ""
        if dmeta and dmeta.get("before") is not None:
            diff = (dmeta["after"] or 0) - (dmeta["before"] or 0)
            if diff > 0:
                arrow = f' #text(size:8pt, fill: rgb("#c0392b"))[(+{diff})]'
            elif diff < 0:
                arrow = f' #text(size:8pt, fill: rgb("#1e8449"))[({diff})]'
        cells.append(f'box(width: 100%, fill: rgb("#f7f9fb"), inset: 8pt, radius: 3pt)['
                     f'#text(size: 17pt, weight: "bold")[{v}]{arrow} #linebreak() '
                     f'#text(size: 8pt, fill: rgb("#7f8c8d"))[{_em(label)}]],')
    return f'#grid(columns: (1fr, 1fr, 1fr), gutter: 6pt, {" ".join(cells)})\n#v(6pt)\n'


# --------------------------------------------------------------------------- evidence extraction

def _evidence_lines(g: dict, d: dict, R: Redactor) -> list[str]:
    """Structured, embeddable evidence for a grouped finding."""
    out: list[str] = []
    hosts = sorted(g["hosts"])
    tool = g["tool"]
    area = g["area"]
    abh = d["assets_by_host"]
    if tool == "intel-cve":
        for cve, r in sorted(d["cves"].items()):
            if not (r["hosts"] & set(hosts)):
                continue
            tag = "KEV" if r["kev"] else (f"EPSS {int(r['epss']*100)}%" if r["epss"] else "banner")
            prod = f" — {r['product'].strip()}" if r["product"].strip() else ""
            out.append(f"{cve}  [{tag}]{prod}")
    elif "takeover" in g["group"].lower() or tool in ("dnsreaper", "bbot:baddns", "baddns-live"):
        for h in hosts:
            cname = d["dns"].get((h, "CNAME"))
            tgt = cname[0] if cname else None
            if not tgt:
                m = re.search(r"\bto\s+([a-z0-9.-]+\.[a-z]{2,})", g["group"], re.I)
                tgt = m.group(1) if m else "(target in finding title)"
            out.append(f"{R.host(h)}  CNAME →  {R.text(tgt)}")
    elif area == "tls":
        for h in hosts[:12]:
            a = abh.get(h)
            tls = {}
            try:
                tls = json.loads(a["tls"]) if a and a["tls"] else {}
            except Exception:
                tls = {}
            na = str(tls.get("not_after", ""))[:10]
            iss = tls.get("issuer") or tls.get("issuer_cn") or ""
            out.append(f"{R.host(h)}  expires {na or '?'}  issuer {iss or '?'}")
    elif area == "email":
        for h in hosts[:8]:
            rec = g.get("ev") or ""
            out.append(f"{R.host(h)}  {R.text(rec) if rec else '(record in finding detail)'}")
    elif tool in ("internetdb", "internetdb-extra", "naabu") or area == "exposure":
        for h in hosts[:12]:
            a = abh.get(h)
            try:
                ports = json.loads(a["ports"]) if a and a["ports"] else []
            except Exception:
                ports = []
            out.append(f"{R.host(h)}  open ports: {', '.join(str(p) for p in ports) or '(see services/)'}")
    else:
        ev = g.get("ev")
        if ev:
            out.append(R.text(str(ev)))
    return out[:14]


def _run_ref(tool: str) -> str:
    return TOOL_FOLDER.get(tool, "report/")


# --------------------------------------------------------------------------- sections

def _sec_exec(d: dict, R: Redactor) -> str:
    ov, ch = d["overview"], d["changes"]
    out = ["= Executive summary\n", _rag_box(d, R)]
    # posture statement
    rag = ov["rag"]
    posture = {
        "red": "The external attack surface has at least one issue that warrants prompt action.",
        "amber": "The external attack surface has issues that should be scheduled and tracked, but none rated critical in this scan.",
        "green": "No material external exposure was identified in this scan.",
    }[rag]
    out.append(f'{posture} The sections below give the full evidence, authoritative references and remediation for each item, '
               f'then the modelled attack paths and supporting appendices.\n\n')
    out.append("== What changed since the last scan\n")
    if ch:
        for line in ch["headline"]:
            out.append(f'{_t(R.text(line))}\n\n')
    else:
        out.append("This is the first scan on record; there is no previous baseline to compare against.\n\n")
    out.append("== Top risks\n")
    top = ov["top_risks"]
    if top:
        cells = ['[*Sev*], [*Issue*], [*Area*], [*Hosts*],']
        for gp in top:
            hs = R.hosts(gp.get("hosts", []))
            shown = ", ".join(hs[:5]) + (f" +{len(hs) - 5}" if len(hs) > 5 else "")
            cells.append(f'[#sev_badge({_s(gp["severity"])}, {_s(SEV_RGB.get(gp["severity"], "#566573"))})], '
                         f'[{_t(R.text(gp["title"]))}], [{_t(AREA_LABEL.get(gp["area"], gp["area"]))}], '
                         f'[#text(size: 8pt)[{_t(shown or "—")}]],')
        out.append(f'#table(columns: (auto, 1.7fr, 0.9fr, 1.2fr), stroke: 0.5pt + rgb("#dfe4ea"), inset: 6pt, '
                   f'align: (horizon, left, left, left), {" ".join(cells)})\n#v(4pt)\n')
    else:
        out.append('#text(fill: rgb("#7f8c8d"))[No critical, high or medium issues to list.]\n')
    out.append("== Posture at a glance\n")
    out.append(_metric_grid(d, R))
    return "".join(out)


def _sec_scope(d: dict, R: Redactor) -> str:
    ov = d["overview"]
    scan = d["scan"]
    done = [s["stage_key"] for s in d["stages"] if s["status"] == "done"]
    out = ["= Scope & methodology\n"]
    out.append(f'*Target:* {_t(scan["root_domain"])}  ·  *Scan window finished:* {_t((scan["finished_at"] or "")[:16].replace("T"," "))}\n\n')
    out.append(f'Outsider ASM enumerates the organisation\'s internet-facing estate from the outside and reasons over what it finds. '
               f'Collection is passive and light-touch by default; active stages only run when explicitly authorised. '
               f'This scan covered {ov["values"]["hosts_in_scope"]} in-scope host(s), of which {ov["values"]["live_web_hosts"]} were live, '
               f'across {ov["values"]["own_public_ips"]} of your public IP(s).\n\n')
    out.append("== Stages run\n")
    out.append(_chips([group_title(s).replace("_", " ") for s in done]) or "No stages recorded.\n")
    out.append("\n== Data sources\n")
    out.append("Shodan InternetDB, CISA KEV, FIRST EPSS, Certificate Transparency, BBOT (passive modules), dnsx, tlsx, "
               "checkdmarc, dnsReaper / baddns, dnstwist / openSquat, urlscan.io, and — where enabled — LeakIX, Netlas, "
               "SpiderFoot and cloudlist. Active web testing (ZAP) and active scanning run only when authorised.\n\n")
    if ov.get("not_collected"):
        out.append("== Not collected\n")
        out.append(f'#text(size: 9pt, fill: rgb("#7f8c8d"))[{_t("; ".join(ov["not_collected"]))}]\n\n')
    out.append('#block(fill: rgb("#eef2f7"), inset: 9pt, radius: 3pt)[#text(size: 8.5pt, fill: rgb("#34495e"))'
               '[*A note on confidence.* CVE matches are derived from version banners and page fingerprints and are '
               'marked unverified — confirm the running version before treating a CVE as present. Attack paths are a '
               'defensive model reasoned from collected exposure: nothing in this assessment sent attack traffic or '
               'attempted exploitation.]]\n')
    return "".join(out)


def _sec_findings(d: dict, R: Redactor) -> str:
    mats = [x for x in d["findings"] if x["severity"] in ("critical", "high", "medium")]
    groups: dict[tuple, dict] = {}
    for x in mats:
        k = (x["severity"], x["area"], x["group"])
        g = groups.setdefault(k, {"severity": x["severity"], "area": x["area"], "group": x["group"],
                                  "tool": x["source_tool"], "hosts": set(), "ev": x.get("evidence_ref")})
        if x["host"]:
            g["hosts"].update(_split_hosts(x["host"]))
    order = sorted(groups.values(), key=lambda g: (SEV_ORDER.get(g["severity"], 9), g["area"], g["group"]))
    out = ["= Detailed findings\n",
           f'{len(order)} distinct issue(s) across {sum(len(g["hosts"]) for g in order)} host-instance(s), '
           f'critical/high/medium, false positives excluded. Each entry carries embedded evidence, a run-folder '
           f'pointer, authoritative references and remediation.\n\n']
    cur = None
    n = 0
    for g in order:
        if g["severity"] != cur:
            cur = g["severity"]
            out.append(f'== {cur.capitalize()} severity\n')
        n += 1
        gd = kb.guidance_for(g["group"], g["area"], g["tool"])
        hosts = sorted(R.hosts(g["hosts"]))
        shown = ", ".join(hosts[:30]) + (f" … (+{len(hosts) - 30})" if len(hosts) > 30 else "")
        tooln = {"zap": "OWASP ZAP", "intel-cve": "KEV/EPSS intel", "internetdb": "Shodan InternetDB",
                 "baddns-live": "baddns", "bbot:baddns": "BBOT baddns"}.get(g["tool"], g["tool"])
        out.append(f'=== {_em(g["group"])}\n')
        out.append(f'#sev_badge({_s(g["severity"])}, {_s(SEV_RGB.get(g["severity"], "#566573"))}) '
                   f'#chip({_s(AREA_LABEL.get(g["area"], g["area"]))}) #chip({_s(tooln)}) '
                   f'#chip({_s(f"{len(hosts)} host(s)")})\n#v(3pt)\n')
        if gd.get("what"):
            out.append(f'*What it is.* {_t(gd["what"])}\n\n')
        if gd.get("why"):
            out.append(f'*Why it matters.* {_t(gd["why"])}\n\n')
        out.append(f'*Affected.* #text(size: 8.5pt)[{_t(shown or "—")}]\n\n')
        ev = _evidence_lines(g, d, R)
        if ev:
            out.append("*Evidence.*\n")
            out.append(_code("\n".join(ev)))
        out.append(f'#text(size: 8.5pt, fill: rgb("#7f8c8d"))[Raw artifacts: run folder #raw({_s(_run_ref(g["tool"]))}) (Files tab).]\n\n')
        # references
        refs = []
        if g["tool"] == "intel-cve":
            for cve in sorted({c for c in d["cves"] if d["cves"][c]["hosts"] & g["hosts"]})[:8]:
                refs.append(_lnk(kb.nvd_url(cve), cve))
        for cwe in gd.get("cwe", []):
            num = str(cwe).upper().replace("CWE-", "")
            refs.append(_lnk(kb.cwe_url(num), f"CWE-{num}"))
        if gd.get("owasp"):
            title, url = kb.owasp_url(gd["owasp"])
            refs.append(_lnk(url, title))
        for label, url in gd.get("refs", []):
            refs.append(_lnk(url, label))
        if refs:
            out.append("*References.* " + "  ·  ".join(refs) + "\n\n")
        # NIST controls
        if gd.get("nist"):
            ctl = []
            for cid in gd["nist"]:
                cid2, title, url = kb.nist_control(cid)
                ctl.append(_lnk(url, f"{cid2} {title}".strip()))
            out.append("*NIST SP 800-53.* " + "  ·  ".join(ctl) + "\n\n")
        if gd.get("fix"):
            out.append(f'#block(fill: rgb("#eafaf1"), inset: 7pt, radius: 3pt)[#text(size: 9pt)[*Remediation.* {_t(gd["fix"])}]]\n\n')
    if not order:
        out.append('#text(fill: rgb("#1e8449"))[No material findings.]\n')
    return "".join(out)


def _sec_attack_paths(d: dict, R: Redactor) -> str:
    ap = d["paths"]
    out = ["= Attack paths\n",
           '#block(fill: rgb("#eef2f7"), inset: 9pt, radius: 3pt)[#text(size: 9pt, fill: rgb("#34495e"))'
           '[*Defensive model.* Every path is reasoned from exposure already collected. Nothing here sent traffic or '
           'attempted anything. Likelihood — observed / plausible / theoretical — states how much evidence supports the chain.]]\n#v(6pt)\n']
    s = ap["summary"]
    if s.get("by_category"):
        cells = ['[*Category*], [*Paths*],']
        for c in CATEGORIES:
            nn = s["by_category"].get(c, 0)
            if nn:
                cells.append(f'[{_t(c)}], [{nn}],')
        out.append(f'#table(columns: (1fr, auto), stroke: 0.5pt + rgb("#dfe4ea"), inset: 5pt, {" ".join(cells)})\n#v(4pt)\n')
    for i, p in enumerate(ap["paths"][:24], 1):
        sevhex = SEV_RGB.get(p["severity"], "#566573")
        cat = p["category"]
        pre, impact, cat_refs = kb.PATH_CATEGORY.get(cat, ("", "", []))
        out.append(f'== {i}. {_em(R.text(p["title"]))}\n')
        out.append(f'#sev_badge({_s(p["severity"])}, {_s(sevhex)}) '
                   f'#chip({_s(LIK_WORD.get(p["likelihood"], p["likelihood"]))}) #chip({_s(cat)})\n#v(3pt)\n')
        if pre:
            out.append(f'*Preconditions.* {_t(pre)}\n\n')
        if p.get("nodes"):
            out.append(f'*Assets involved.* #text(size: 8.5pt)[{_t(", ".join(R.hosts(p["nodes"][:12])))}]\n\n')
        out.append("*Kill chain.*\n")
        for j, st in enumerate(p["steps"], 1):
            mitre = "  ".join(_lnk(kb.mitre_url(m), m) for m in st.get("mitre", []))
            tags = " ".join(f'#chip({_s(t)})' for t in st.get("agent_tags", []))
            evtxt = ""
            if st.get("evidence"):
                ev_items = "; ".join(f"{k}={R.text(str(v))}" for k, v in st["evidence"].items())
                evtxt = f' #text(size: 8pt, fill: rgb("#7f8c8d"))[— evidence: {_t(ev_items)}]'
            out.append(f'{j}. {_t(R.text(st["description"]))} {mitre} {tags}{evtxt}\n')
        out.append("\n")
        out.append(f'*Likelihood.* {_t(kb.LIKELIHOOD_REASON.get(p["likelihood"], ""))}\n\n')
        if impact:
            out.append(f'*Business impact.* {_t(impact)}\n\n')
        reduce_refs = "  ·  ".join(_lnk(u, l) for l, u in cat_refs)
        out.append(f'#block(fill: rgb("#eafaf1"), inset: 7pt, radius: 3pt)[#text(size: 9pt)[*Reduce it.* {_t(R.text(p["recommendation"]))}'
                   + (f' #linebreak() References: {reduce_refs}' if reduce_refs else "") + ']]\n\n')
    if not ap["paths"]:
        out.append("No attack paths were modelled from the current exposure.\n")
    return "".join(out)


def _sec_appendices(d: dict, R: Redactor) -> str:
    out = ["= Appendix A — CVE register\n"]
    if d["cves"]:
        cells = ['[*CVE*], [*CVSS*], [*Exploitation*], [*Product*], [*Hosts*], [*Links*],']
        for cve, r in sorted(d["cves"].items(),
                             key=lambda kv: (not kv[1]["kev"], -(kv[1]["epss"] or 0), -(kv[1].get("cvss") or 0), kv[0])):
            exploit = "CISA KEV" if r["kev"] else (f'EPSS {int(r["epss"]*100)}%' if (r["epss"] or 0) >= 0.10 else "banner")
            cvss = f'{r["cvss"]}' + (f' {r["severity"][:4]}' if r.get("severity") else "") if r.get("cvss") is not None else "—"
            hs = R.hosts(sorted(r["hosts"]))
            links = _lnk(kb.nvd_url(cve), "NVD")
            if r["kev"]:
                links += "  " + _lnk(kb.KEV_CATALOG_URL, "KEV")
            cells.append(f'[#raw({_s(cve)})], [{_t(cvss)}], [{_t(exploit)}], [#text(size:8pt)[{_t(R.text(r["product"]) or "—")}]], '
                         f'[#text(size:8pt)[{_t(", ".join(hs[:4]) + (" …" if len(hs) > 4 else "") or "—")}]], [#text(size:8pt)[{links}]],')
        out.append(f'#table(columns: (auto, auto, auto, 1.3fr, 1.2fr, auto), stroke: 0.5pt + rgb("#dfe4ea"), inset: 5pt, '
                   f'align: (left, left, left, left, left, left), {" ".join(cells)})\n')
        if any(r["kev"] and r["kev_meta"] for r in d["cves"].values()):
            out.append("\n== KEV catalogue detail\n")
            for cve, r in sorted(d["cves"].items()):
                k = r["kev_meta"]
                if not (r["kev"] and k):
                    continue
                rw = " · known ransomware use" if str(k.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
                out.append(f'• #raw({_s(cve)}) — {_t(k.get("vulnerabilityName",""))}. Added {_t(k.get("dateAdded","?"))}, '
                           f'remediate by {_t(k.get("dueDate","?"))}{_em(rw)}.\n\n')
    else:
        out.append("No CVEs were matched to service versions in this scan.\n")

    # Appendix B — asset inventory
    out.append("= Appendix B — asset inventory\n")
    live = [a for a in d["assets"] if a["is_live"]]
    cells = ['[*Host*], [*Live*], [*CDN/3P*], [*Status*], [*Technologies*],']
    for a in sorted(live, key=lambda a: a["host"])[:80]:
        try:
            tech = ", ".join(json.loads(a["tech"] or "[]")[:6])
        except Exception:
            tech = ""
        tag = "CDN" if a["cdn"] else ("3P" if a["third_party"] else "own")
        cells.append(f'[#text(size:8pt)[{_t(R.host(a["host"]))}]], [{"✓" if a["is_live"] else ""}], [{_t(tag)}], '
                     f'[{_t(a["http_status"] or "")}], [#text(size:8pt)[{_t(R.text(tech))}]],')
    out.append(f'#table(columns: (1.6fr, auto, auto, auto, 1.8fr), stroke: 0.5pt + rgb("#dfe4ea"), inset: 4pt, {" ".join(cells)})\n')
    if len(live) > 80:
        out.append(f'#text(size: 8pt, fill: rgb("#7f8c8d"))[… and {len(live) - 80} more live host(s); see the Assets tab.]\n')

    # Appendix C — AI-agent surface
    out.append("= Appendix C — AI-agent & MCP surface\n")
    if d["agent_hosts"]:
        out.append(f'{len(d["agent_hosts"])} live host(s) match agent / MCP / model / digital-twin naming. '
                   f'Each should enforce consistent authentication, per-caller tool authorisation and rate limits.\n\n')
        out.append(_chips(R.hosts(d["agent_hosts"])))
    else:
        out.append("No hosts matched the agent / MCP naming patterns.\n")

    # Appendix D — email & brand
    out.append("\n= Appendix D — email & brand\n")
    if d["email"]:
        out.append("== Email authentication\n")
        cells = ['[*Sev*], [*Issue*], [*Domain*],']
        for x in d["email"]:
            cells.append(f'[#sev_badge({_s(x["severity"])}, {_s(SEV_RGB.get(x["severity"], "#566573"))})], '
                         f'[{_t(R.text(group_title(x["title"])))}], [#text(size:8pt)[{_t(R.host(x["host"]))}]],')
        out.append(f'#table(columns: (auto, 2fr, 1.1fr), stroke: 0.5pt + rgb("#dfe4ea"), inset: 5pt, {" ".join(cells)})\n')
    if d["brand"]:
        out.append("== Lookalike & brand domains\n")
        cells = ['[*Sev*], [*What was seen*], [*Domain*],']
        for x in d["brand"][:40]:
            dom = x["title"].rsplit(": ", 1)[-1] if ": " in x["title"] else x["host"]
            cells.append(f'[#sev_badge({_s(x["severity"])}, {_s(SEV_RGB.get(x["severity"], "#566573"))})], '
                         f'[{_t(R.text(group_title(x["title"])))}], [#text(size:8pt)[{_t(R.text(dom))}]],')
        out.append(f'#table(columns: (auto, 2fr, 1.1fr), stroke: 0.5pt + rgb("#dfe4ea"), inset: 5pt, {" ".join(cells)})\n')
    if not d["email"] and not d["brand"]:
        out.append("No email-authentication or lookalike issues were found.\n")

    # Appendix E — framework coverage
    out.append("\n= Appendix E — framework coverage\n")
    nist_seen: dict[str, str] = {}
    owasp_seen: set[str] = set()
    for x in d["findings"]:
        if x["severity"] not in ("critical", "high", "medium"):
            continue
        gd = kb.guidance_for(x["group"], x["area"], x["source_tool"])
        for cid in gd.get("nist", []):
            cid2, title, _ = kb.nist_control(cid)
            nist_seen[cid2] = title
        if gd.get("owasp"):
            owasp_seen.add(gd["owasp"])
    mitre_seen = sorted({m for p in d["paths"]["paths"] for m in p.get("mitre", [])})
    out.append("== NIST SP 800-53 controls implicated\n")
    if nist_seen:
        items = [_lnk(kb.nist_control(c)[2], f"{c} {t}") for c, t in sorted(nist_seen.items())]
        out.append("  ·  ".join(items) + "\n\n")
    else:
        out.append("None mapped.\n\n")
    out.append("== OWASP Top 10 (2021) categories implicated\n")
    if owasp_seen:
        out.append("  ·  ".join(_lnk(kb.owasp_url(c)[1], kb.owasp_url(c)[0]) for c in sorted(owasp_seen)) + "\n\n")
    else:
        out.append("None mapped.\n\n")
    out.append("== MITRE ATT&CK techniques referenced\n")
    if mitre_seen:
        out.append("  ·  ".join(_lnk(kb.mitre_url(m), m) for m in mitre_seen) + "\n")
    else:
        out.append("None referenced.\n")

    # Appendix F — evidence index
    out.append("\n= Appendix F — evidence index\n")
    out.append("Where to find the raw artifacts behind each tool's findings, in the scan's run folder (Files tab).\n\n")
    tools = sorted({x["source_tool"] for x in d["findings"] if x["severity"] in ("critical", "high", "medium")})
    cells = ['[*Tool*], [*Run-folder location*],']
    for t in tools:
        cells.append(f'[{_t(t)}], [#raw({_s(_run_ref(t))})],')
    if tools:
        out.append(f'#table(columns: (1fr, 1fr), stroke: 0.5pt + rgb("#dfe4ea"), inset: 5pt, {" ".join(cells)})\n')
    return "".join(out)


def master_typ(d: dict, R: Redactor) -> str:
    parts = [
        _preamble(d, R.on),
        _sec_exec(d, R),
        _sec_scope(d, R),
        _sec_findings(d, R),
        _sec_attack_paths(d, R),
        _sec_appendices(d, R),
    ]
    return "".join(parts)


# --------------------------------------------------------------------------- render

class ReportError(RuntimeError):
    pass


def _typst_bin() -> str:
    exe = shutil.which("typst")
    if not exe:
        raise ReportError("typst is not installed in this image; cannot render PDF")
    return exe


def render_pdf(typ_source: str, out_pdf: Path) -> Path:
    exe = _typst_bin()
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "report.typ"
        src.write_text(typ_source, encoding="utf-8")
        proc = subprocess.run([exe, "compile", "--root", tmp, str(src), str(out_pdf)],
                              capture_output=True, text=True, timeout=180)
        if proc.returncode != 0 or not out_pdf.exists():
            raise ReportError(f"typst compile failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return out_pdf


def build(db: DB, sid: str, kind: str, redacted: bool = False, against: str | None = None,
          out_dir: Path | None = None, data_dir=None) -> Path:
    if kind not in REPORT_KINDS:
        raise ReportError(f"unknown report kind: {kind}")
    d = collect(db, sid, against, data_dir)
    out_dir = out_dir or Path(tempfile.mkdtemp())
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = d["generated_at"].strftime("%Y%m%d-%H%M")
    base = re.sub(r"[^a-z0-9.-]+", "-", d["scan"]["root_domain"].lower())
    if kind == "share-zip":
        return _share_zip(d, out_dir, base, stamp)
    R = Redactor(redacted)
    typ = master_typ(d, R)
    suffix = "-redacted" if redacted else ""
    pdf = out_dir / f"{base}-report{suffix}-{stamp}.pdf"
    render_pdf(typ, pdf)
    return pdf


def _share_zip(d, out_dir, base, stamp) -> Path:
    R = Redactor(True)
    tmp = Path(tempfile.mkdtemp())
    report = tmp / "attack-surface-report.pdf"
    render_pdf(master_typ(d, R), report)
    readme = tmp / "README.txt"
    readme.write_text(
        "Outsider ASM — redacted share pack\n"
        f"Target: {d['scan']['root_domain']}\n"
        f"Scan finished: {d['scan']['finished_at']}\n"
        f"Generated: {d['generated_at'].strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        "Host names and IP addresses are replaced with stable pseudonyms (asset-01, ip-07).\n"
        "CVE ids, severities, counts, MITRE/NIST/OWASP mappings and recommendations are unchanged.\n"
        "The attack paths are a defensive model: no traffic was sent and nothing was attempted.\n",
        encoding="utf-8")
    zpath = out_dir / f"{base}-share-pack-{stamp}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(report, "attack-surface-report.pdf")
        z.write(readme, "README.txt")
    shutil.rmtree(tmp, ignore_errors=True)
    return zpath
