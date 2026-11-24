"""Structured, location-bearing evidence for a finding, reconstructed from the raw tool output in the
run folder.

The findings table only stores a thin `evidence_ref` (a plugin id like ``zap:10055``, a category, or
nothing). The real "where is this and what exactly is wrong" lives one directory away in the tool's
own output. This module reads that output and returns ONE generic shape the detail pane renders the
same way for every tool::

    {
      "location":  "https://www.miro.com",             # WHERE the issue is
      "locator":   "response header Content-Security-Policy",  # WHICH part (optional)
      "observed":  "default-src 'unsafe-inline' ...",   # the literal proof (optional)
      "fields":    [{"label": "...", "value": "..."}],  # structured key facts
      "instances": [{"location","locator","observed"}], # multi-location issues (ZAP etc.)
      "fix":       "...",                               # tool-supplied remediation (optional)
      "raw_file":  "zap/zap-estate.json",               # pointer (the detail route resolves it)
      "source":    "zap",
    }

Everything is pure stdlib and defensive: a missing or corrupt file yields ``{}`` so the detail route
falls back to its existing behaviour. Nothing here is fetched; it only reads files already on disk.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# a hostname/domain token, used to pull the look-alike domain out of a finding title
_DOMAIN_RE = re.compile(r"\b((?:xn--[a-z0-9-]+|[a-z0-9-]+)(?:\.[a-z0-9-]+)+)\b", re.I)


def _clean(s) -> str:
    if not s:
        return ""
    s = _TAG_RE.sub(" ", str(s))
    return _WS_RE.sub(" ", s).strip()


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _read_jsonl(p: Path) -> list:
    out = []
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        return []
    return out


def _host_matches(a: str, b: str) -> bool:
    a, b = (a or "").lower().strip("."), (b or "").lower().strip(".")
    return bool(a) and bool(b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


# --------------------------------------------------------------------------- per-tool mappers
# Each returns a dict (the shape above, minus raw_file/source which build_evidence fills) or {}.

def _zap(finding: Mapping, run_dir: Path) -> dict:
    ref = str(finding.get("evidence_ref") or "")
    pid = ref.split(":", 1)[1].strip() if ":" in ref else ref.strip()
    host = finding.get("host") or ""
    data = _read_json(run_dir / "zap" / "zap-estate.json")
    if not data:
        return {}
    sites = data.get("site") or data.get("sites") or []
    if isinstance(sites, dict):
        sites = [sites]
    alert = None
    # prefer the alert on the finding's own host; fall back to the first matching plugin anywhere
    for prefer_host in (True, False):
        for site in sites:
            if prefer_host and not _host_matches(site.get("@host", ""), host):
                continue
            for al in site.get("alerts", []) or []:
                if str(al.get("pluginid") or al.get("pluginId") or "") == pid:
                    alert = al
                    break
            if alert:
                break
        if alert:
            break
    if not alert:
        return {}
    instances = []
    for inst in alert.get("instances", []) or []:
        param = _clean(inst.get("param"))
        loc = inst.get("uri") or inst.get("nodeName") or host
        locator = f"parameter {param}" if param else (inst.get("method") or "")
        observed = _clean(inst.get("evidence")) or _clean(inst.get("attack"))
        instances.append({
            "location": loc, "locator": _clean(locator),
            "observed": observed, "detail": _clean(inst.get("otherinfo")),
        })
    first = instances[0] if instances else {}
    fields = []
    if alert.get("confidence"):
        fields.append({"label": "Confidence", "value": _clean(alert.get("riskdesc") or alert.get("confidence"))})
    if alert.get("count"):
        fields.append({"label": "Instances", "value": str(alert.get("count"))})
    if alert.get("cweid") and str(alert["cweid"]) not in ("", "-1"):
        fields.append({"label": "CWE", "value": f"CWE-{alert['cweid']}"})
    return {
        "location": first.get("location", host), "locator": first.get("locator", ""),
        "observed": first.get("observed", ""), "detail": _clean(alert.get("otherinfo")),
        "fields": fields, "instances": instances, "fix": _clean(alert.get("solution")),
    }


def _email(finding: Mapping, run_dir: Path) -> dict:
    host = (finding.get("host") or "").lower()
    data = _read_json(run_dir / "email" / "posture.json")
    if not isinstance(data, list):
        return {}
    rec = next((r for r in data if _host_matches(r.get("domain", ""), host)), None)
    if rec is None and data:
        rec = data[0]
    if not rec:
        return {}
    title = (finding.get("title") or "").lower()
    fields = []
    if rec.get("spf") is not None:
        fields.append({"label": "SPF", "value": _clean(rec["spf"]) or "(none)"})
    if rec.get("dmarc") is not None:
        fields.append({"label": "DMARC", "value": _clean(rec["dmarc"]) or "(none)"})
    if rec.get("dmarc_policy"):
        fields.append({"label": "DMARC policy", "value": str(rec["dmarc_policy"])})
    if rec.get("mta_sts") is not None:
        fields.append({"label": "MTA-STS", "value": "present" if rec["mta_sts"] else "absent"})
    if rec.get("mx"):
        mx = rec["mx"]
        fields.append({"label": "MX", "value": ", ".join(mx) if isinstance(mx, list) else _clean(mx)})
    # the observed string is the record the finding is actually about
    if "dmarc" in title:
        observed = _clean(rec.get("dmarc")) or "(no DMARC record)"
    elif "spf" in title:
        observed = _clean(rec.get("spf")) or "(no SPF record)"
    elif "mta" in title:
        observed = "MTA-STS absent" if not rec.get("mta_sts") else "MTA-STS present"
    else:
        observed = _clean(rec.get("dmarc")) or _clean(rec.get("spf"))
    return {"location": rec.get("domain", host), "locator": "email DNS records",
            "observed": observed, "fields": fields}


def _tlsx(finding: Mapping, run_dir: Path) -> dict:
    host = finding.get("host") or ""
    for rec in _read_jsonl(run_dir / "tls" / "tlsx.json"):
        if _host_matches(rec.get("host", ""), host):
            fields = []
            for label, key in (("Subject CN", "subject_cn"), ("Issuer", "issuer_cn"),
                               ("Expires", "not_after"), ("TLS version", "tls_version"),
                               ("Cipher", "cipher")):
                v = rec.get(key)
                if v:
                    fields.append({"label": label, "value": str(v)[:19] if key == "not_after" else _clean(v)})
            flags = [k for k in ("expired", "self_signed", "mismatched", "revoked") if rec.get(k)]
            if flags:
                fields.append({"label": "Flags", "value": ", ".join(flags)})
            san = rec.get("subject_an")
            observed = _clean(rec.get("cipher")) or _clean(rec.get("subject_cn"))
            port = rec.get("port") or "443"
            return {"location": f"{rec.get('host', host)}:{port}", "locator": "TLS certificate",
                    "observed": observed, "fields": fields,
                    "detail": ("SANs: " + ", ".join(san[:8])) if isinstance(san, list) and san else ""}
    return {}


def _testssl(finding: Mapping, run_dir: Path) -> dict:
    host = finding.get("host") or ""
    d = run_dir / "tls" / "testssl"
    if not d.is_dir():
        return {}
    cand = None
    for f in d.glob("*.json"):
        if _host_matches(f.stem, host):
            cand = f
            break
    if cand is None:
        return {}
    arr = _read_json(cand)
    if not isinstance(arr, list):
        return {}
    bad = [r for r in arr if str(r.get("severity", "")).upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]
    instances = [{"location": f"{r.get('ip', host)}:{r.get('port', '443')}",
                  "locator": _clean(r.get("id")), "observed": _clean(r.get("finding")),
                  "detail": str(r.get("severity", ""))} for r in bad[:25]]
    first = instances[0] if instances else {}
    return {"location": first.get("location", f"{host}:443"), "locator": first.get("locator", ""),
            "observed": first.get("observed", ""), "instances": instances,
            "fields": [{"label": "Checks flagged", "value": str(len(bad))}] if bad else []}


def _lookalike(finding: Mapping, run_dir: Path) -> dict:
    title = finding.get("title") or ""
    # the look-alike domain is the last domain token in the title
    doms = _DOMAIN_RE.findall(title)
    target = doms[-1].lower() if doms else (finding.get("evidence_ref") or "").lower()
    d = run_dir / "lookalikes"
    if not d.is_dir():
        return {}
    for f in d.glob("*.json"):
        for rec in (_read_json(f) or []):
            if (rec.get("domain") or "").lower() == target and rec.get("fuzzer") != "*original":
                fields = [{"label": "Look-alike domain", "value": rec["domain"]},
                          {"label": "Technique", "value": _clean(rec.get("fuzzer"))}]
                for label, key in (("A records", "dns_a"), ("MX", "dns_mx"), ("NS", "dns_ns")):
                    v = rec.get(key)
                    if v:
                        v = v if isinstance(v, list) else [str(v)]
                        fields.append({"label": label, "value": ", ".join(str(x) for x in v[:6])})
                has_mx = bool(rec.get("dns_mx"))
                return {"location": rec["domain"], "locator": "registered look-alike",
                        "observed": rec["domain"] + (" (has mail servers)" if has_mx else ""),
                        "fields": fields}
    return {}


def _intel_cve(finding: Mapping, run_dir: Path) -> dict:
    data = _read_json(run_dir / "intel" / "cves.json")
    if not isinstance(data, dict):
        return {}
    ref = f"{finding.get('host', '')} {finding.get('evidence_ref', '')}"
    ip = next((t for t in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", ref) if t in data), None)
    if ip is None:
        ip = next((k for k in data if _host_matches(k, finding.get("host", ""))), None)
    if ip is None or ip not in data:
        return {}
    rec = data[ip]
    cves = rec.get("cves", []) or []
    fields = [{"label": "Host IP", "value": ip}]
    if rec.get("hosts"):
        fields.append({"label": "Serves", "value": ", ".join(rec["hosts"][:6])})
    if rec.get("products"):
        prods = rec["products"]
        fields.append({"label": "Products", "value": ", ".join(prods[:6]) if isinstance(prods, list) else _clean(prods)})
    instances = [{"location": ip, "locator": c.get("cve", ""),
                  "observed": (("KEV " if c.get("kev") else "") + (f"EPSS {c['epss']:.2f}" if c.get("epss") is not None else "")).strip() or c.get("cve", ""),
                  "detail": "known-exploited" if c.get("kev") else ""} for c in cves]
    out = {"location": ip, "locator": f"{len(cves)} CVE(s)", "observed": ", ".join(c.get("cve", "") for c in cves[:5]),
           "fields": fields, "instances": instances}
    host = (finding.get("host") or "").strip()
    if host and host not in ip:
        out["host"] = host
    return out


def _port(finding: Mapping, run_dir: Path) -> dict:
    ref = _clean(finding.get("evidence_ref"))
    loc = ref if ref else finding.get("host", "")
    pc = _read_json(run_dir / "services" / "port_check.json")
    fields = []
    if isinstance(pc, list):
        for r in pc:
            if _host_matches(r.get("host", ""), finding.get("host", "")) and r.get("service"):
                fields.append({"label": "Service", "value": _clean(r.get("service"))})
                break
    out = {"location": loc, "locator": "open port", "observed": ref, "fields": fields}
    host = (finding.get("host") or "").strip()
    if host and host not in loc:          # the resolved host this IP:port belongs to
        out["host"] = host
    return out


def _bbot(finding: Mapping, run_dir: Path) -> dict:
    ref = _clean(finding.get("evidence_ref"))
    if not ref:
        return {}
    return {"location": ref, "locator": "discovered by BBOT",
            "observed": "", "fields": []}


def _dnsx(finding: Mapping, run_dir: Path) -> dict:
    ref = _clean(finding.get("evidence_ref"))
    if not ref:
        return {}
    ips = [x.strip() for x in ref.split(",") if x.strip()]
    return {"location": finding.get("host", ""), "locator": "resolves to",
            "observed": ", ".join(ips[:8]),
            "fields": [{"label": "Resolved IPs", "value": ", ".join(ips)}]}


def _urlscan(finding: Mapping, run_dir: Path) -> dict:
    host = finding.get("host") or ""
    data = _read_json(run_dir / "urlscan" / "search.json")
    if not isinstance(data, dict):
        return {}
    results = None
    for key, val in data.items():
        dom = key.split(":", 1)[1] if ":" in key else key
        if _host_matches(dom, host) and isinstance(val, dict) and val.get("results"):
            results = val["results"]
            break
    if not results:
        return {}
    res = results[0]
    task = res.get("task", {}) or {}
    page = res.get("page", {}) or {}
    uuid = task.get("uuid") or ""
    fields = []
    for label, v in (("Page URL", task.get("url") or page.get("url")),
                     ("Resolved IP", page.get("ip")), ("Server", page.get("server")),
                     ("Country", page.get("country"))):
        if v:
            fields.append({"label": label, "value": _clean(v)})
    if uuid:
        fields.append({"label": "Screenshot", "value": f"https://urlscan.io/screenshots/{uuid}.png"})
    return {"location": _clean(task.get("url") or page.get("url") or host),
            "locator": "urlscan.io capture", "observed": _clean(page.get("ip") or ""),
            "fields": fields}


# source_tool prefix -> mapper
_MAPPERS = {
    "zap": _zap,
    "checkdmarc": _email, "dns-email": _email,
    "tlsx": _tlsx, "testssl": _testssl,
    "dnstwist": _lookalike,
    "intel-cve": _intel_cve,
    "naabu": _port, "internetdb": _port, "internetdb-extra": _port,
    "dnsx": _dnsx, "ptr": _dnsx,
    "urlscan": _urlscan,
}


def build_evidence(finding: Mapping, run_dir) -> dict:
    """Return the structured evidence object for one finding, or {} when nothing can be reconstructed.

    `finding` is a sqlite row / mapping with at least title, host, source_tool, evidence_ref.
    `run_dir` is the scan's run folder (a Path, or None)."""
    if run_dir is None:
        return {}
    run_dir = Path(run_dir)
    tool = (finding.get("source_tool") or "")
    base = tool.split(":", 1)[0]
    fn = _MAPPERS.get(tool) or _MAPPERS.get(base)
    if fn is None and (base.startswith("bbot") or base.startswith("baddns")):
        fn = _bbot
    if fn is None:
        return {}
    try:
        ev = fn(finding, run_dir) or {}
    except Exception:
        return {}
    if not ev:
        return {}
    ev.setdefault("source", tool)
    # prune empty keys so the frontend can test presence simply
    return {k: v for k, v in ev.items() if v not in ("", None, [], {})}


def evidence_summary(finding: Mapping, run_dir) -> str:
    """A compact one-line evidence string (location + short proof) for the list view / exports."""
    ev = build_evidence(finding, run_dir)
    if not ev:
        return str(finding.get("evidence_ref") or "")
    loc = ev.get("location", "")
    obs = ev.get("observed", "")
    if obs and len(obs) > 70:
        obs = obs[:67] + "…"
    return f"{loc} — {obs}" if (loc and obs) else (loc or obs or str(finding.get("evidence_ref") or ""))
