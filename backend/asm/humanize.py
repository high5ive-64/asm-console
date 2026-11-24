"""Turn raw tool output into short, plain-English activity lines for the UI.

humanize(stage, level, message) returns a readable line, or None for noise that the
readable view should hide (the raw view still shows everything). Lines that look like
progress updates carry a "progress key" so the UI can replace the previous one instead
of stacking hundreds of near-identical lines.
"""
from __future__ import annotations

import json
import re

# BBOT event types -> words
EVENT_WORDS = {
    "DNS_NAME": "host names", "URL": "web pages", "TECHNOLOGY": "technologies", "FINDING": "findings",
    "VULNERABILITY": "vulnerabilities", "WEBSCREENSHOT": "screenshots", "IP_ADDRESS": "IP addresses",
    "EMAIL_ADDRESS": "email addresses", "STORAGE_BUCKET": "storage buckets", "SOCIAL": "social profiles",
    "ASN": "networks (ASNs)", "AZURE_TENANT": "Azure tenants", "OPEN_TCP_PORT": "open ports",
    "CODE_REPOSITORY": "code repositories",
}
HIDE_EVENT_TYPES = {"SCAN", "ORG_STUB", "HTTP_RESPONSE", "DNS_NAME_UNRESOLVED", "URL_UNVERIFIED", "RAW_TEXT"}

# BBOT module -> what it's doing, for "Modules running" lines
MODULE_WORDS = {
    "baddns": "checking for takeovers", "dnsresolve": "resolving names", "http": "visiting web pages",
    "gowitness": "taking screenshots", "sslcert": "reading certificates", "robots": "reading robots.txt",
    "securitytxt": "reading security.txt", "excavate": "reading page content", "speculate": "inferring hosts",
    "crt": "querying certificate logs", "crt_db": "querying certificate logs", "certspotter": "querying certificate logs",
    "dnscaa": "reading CAA records", "dnsbimi": "reading BIMI records", "dnstlsrpt": "reading TLS-RPT records",
    "shodan_idb": "querying Shodan", "shodan_dns": "querying Shodan", "virustotal": "querying VirusTotal",
    "securitytrails": "querying SecurityTrails", "wayback": "querying the Wayback Machine", "otx": "querying AlienVault OTX",
    "urlscan": "querying urlscan.io", "cloudcheck": "identifying cloud providers", "social": "spotting social profiles",
    "asn": "looking up networks", "azure_tenant": "checking Microsoft tenant", "python": "processing results",
}
TOOL_INTRO = {
    "zap.sh": "Starting ZAP (headless) with the passive-only plan",
    "tlsx": "Running one TLS handshake per host",
    "smap": "Looking up open ports in Shodan's InternetDB (no packets sent to your hosts)",
    "gau": "Fetching archived URLs from the Wayback Machine, Common Crawl, OTX and urlscan",
    "uro": "De-duplicating archived URLs",
    "dnstwist": "Generating lookalike domains and checking which are registered",
    "dig": "DNS lookup",
    "typst": "Building the PDF",
    "cdncheck": "Matching IPs against published CDN, WAF and cloud ranges (offline)",
    "dnsreaper": "Checking names against dnsReaper's takeover signatures (DNS only)",
    "checkdmarc": "Parsing SPF, DMARC, MTA-STS, TLS-RPT and BIMI records",
    "testssl.sh": "Reviewing TLS configuration with testssl.sh",
    "opensquat": "Searching today's newly registered domains for your brand",
    "cloudlist": "Listing assets from your cloud accounts (read-only)",
}
BBOT_PASS = {"light": "web pass", "dnsonly": "takeover checks"}


def _pass(name: str) -> str:
    return "discovery" if name.startswith("discovery") else BBOT_PASS.get(name, name)

RE_PROGRESS = re.compile(r"Events produced so far: (.*)$")
RE_RUNNING = re.compile(r"Modules running \(incoming:processing:outgoing\) (.*)$")
RE_MOD = re.compile(r"([\w.]+)\(([\d,]+):([\d,]+):([\d,]+)\)")
RE_COUNT = re.compile(r"([A-Z_]+): (\d{1,3}(?:,\d{3})+|\d+)")
RE_FINDING = re.compile(r"^\[(FINDING|VULNERABILITY)\]\s+(.*)$")
RE_SEV = re.compile(r"Severity: \[(\w+)\]")
RE_PASSNAME = re.compile(r"\]\s*([\w.-]+): (?:Events produced|Modules running|No events)")


def _n(s: str) -> int:
    return int(s.replace(",", ""))


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}"


def humanize(stage: str | None, level: str, msg: str) -> dict | None:
    """Return {"text": str, "kind": "info|good|warn|bad|progress|step", "key": progress-key|None} or None to hide."""
    m = msg.strip()
    if not m:
        return None

    # our own messages are already readable
    if level in ("info", "warn", "error"):
        if m.startswith("Stage started: "):
            return {"text": m.replace("Stage started: ", "Started: "), "kind": "step", "key": None}
        if m.startswith("Stage complete: "):
            return {"text": "Finished: " + m[len("Stage complete: "):].replace(", ", " · "), "kind": "good", "key": None}
        return {"text": m, "kind": {"warn": "warn", "error": "bad"}.get(level, "info"), "key": None}

    if level == "cmd":
        argv = m[2:].split() if m.startswith("$ ") else m.split()
        tool = argv[0] if argv else ""
        if tool == "bbot":
            name = argv[argv.index("-n") + 1] if "-n" in argv else ""
            if "--dry-run" in argv:
                return {"text": "Checking which BBOT modules would load (dry run)", "kind": "step", "key": None}
            if name.startswith("discovery"):
                return {"text": "Starting BBOT passive discovery (third-party data sources only)", "kind": "step", "key": None}
            return {"text": f"Starting BBOT {BBOT_PASS.get(name, name)}", "kind": "step", "key": None}
        if tool in TOOL_INTRO:
            return {"text": TOOL_INTRO[tool], "kind": "step", "key": None}
        return None

    # ---- raw tool output ("log") ----
    # BBOT progress counters
    pm = RE_PROGRESS.search(m)
    if pm:
        pas = RE_PASSNAME.search(m)
        hide = HIDE_EVENT_TYPES | ({"OPEN_TCP_PORT"} if stage == "bbot_light" else set())   # assumed 80/443 there
        counts = [(t, _n(v)) for t, v in RE_COUNT.findall(re.sub(r"\([^)]*\)", "", pm.group(1)))
                  if t not in hide and t in EVENT_WORDS]
        if not counts:
            return None
        text = "Found so far: " + " · ".join(_plural(v, EVENT_WORDS[t]) for t, v in counts)
        return {"text": text, "kind": "progress", "key": f"found:{pas.group(1) if pas else ''}"}
    rm = RE_RUNNING.search(m)
    if rm:
        pas = RE_PASSNAME.search(m)
        parts = []
        for mod, inc, proc, _out in RE_MOD.findall(rm.group(1)):
            what = MODULE_WORDS.get(mod, mod)
            active, queued = _n(proc), _n(inc)
            if not active and not queued:
                continue
            parts.append(f"{what} ({active} active" + (f", {queued:,} queued)" if queued else ")"))
        if not parts:
            return None
        return {"text": "Working: " + " · ".join(parts), "kind": "progress", "key": f"working:{pas.group(1) if pas else ''}"}
    if "No events in queue" in m:
        return None

    fm = RE_FINDING.match(m)
    if fm:
        body = fm.group(2)
        sev = (RE_SEV.search(body).group(1) if RE_SEV.search(body) else "").upper()
        desc = re.sub(r"Severity: \[\w+\]\s*Confidence: \[\w+\]\s*", "", body).split("\t")[0].strip()
        desc = re.sub(r"\s*Confidence: \[\w+\].*$", "", desc)
        kind = "bad" if sev in ("HIGH", "CRITICAL") else "warn" if sev in ("MEDIUM", "LOW") else "info"
        return {"text": f"Finding{f' ({sev.lower()})' if sev else ''}: {desc[:220]}", "kind": kind, "key": None}

    # BBOT lifecycle
    if (w := re.search(r"Encountered domain with wildcard DNS \((\w+)\): (\S+)", m)):
        return {"text": f"{w.group(2)} answers any name (wildcard DNS); matching names are treated with care", "kind": "info", "key": None}
    if (w := re.search(r"Scan (\S+) completed in (.+?) with status", m)):
        return {"text": f"BBOT {_pass(w.group(1))} finished in {w.group(2)}", "kind": "good", "key": None}
    if (w := re.search(r"Starting scan (\S+)", m)):
        return {"text": f"BBOT {_pass(w.group(1))} running", "kind": "step", "key": None}
    if (w := re.search(r"Loaded (\d+)/(\d+) scan modules \((.*)\)", m)):
        mods = [x for x in w.group(3).split(",") if x]
        return {"text": f"Loaded {len(mods)} BBOT module{'' if len(mods) == 1 else 's'}: {', '.join(mods)}", "kind": "info", "key": None}
    if re.search(r"Loaded \d+/\d+ (internal|output) modules", m):
        return None
    if (w := re.search(r"Setup soft-failed for (\w+): No API key set", m)):
        return None  # expected for sources without keys; the discovery log lists which keys are configured
    if (w := re.search(r"Setup soft-failed for (\w+): (.*)", m)):
        return {"text": f"{w.group(1)} unavailable: {w.group(2)[:160]}", "kind": "warn", "key": None}
    if (w := re.search(r"(\w+): API is ready", m)):
        return {"text": f"{w.group(1)} API key works", "kind": "good", "key": None}
    if (w := re.search(r"Setup succeeded for (\d+)/(\d+) modules", m)):
        return {"text": f"BBOT: {w.group(1)} of {w.group(2)} modules ready", "kind": "info", "key": None}
    if "Finishing scan" in m:
        return {"text": "Wrapping up and writing results", "kind": "info", "key": None}
    if "Stderr for run_live" in m and "gowitness" in m:
        return {"text": "Screenshot tool reported a problem (see raw log)", "kind": "warn", "key": "gowitness-err"}
    if (w := re.search(r"Could not find config option \"([^\"]+)\"", m)):
        return {"text": f"BBOT rejected a setting: {w.group(1)}", "kind": "bad", "key": None}

    # ZAP automation framework
    if (w := re.match(r"Job (\w[\w-]*) requesting URL (\S+)", m)):
        return {"text": f"{'Spider' if w.group(1) == 'spider' else 'Browser crawl'}: visiting {w.group(2)}", "kind": "progress",
                "key": f"zap-visit:{w.group(1)}"}
    if (w := re.match(r"Job (\w[\w-]*) error accessing URL (\S+) status code returned : (\d+)", m)):
        return {"text": f"{w.group(2)} answered {w.group(3)}; nothing to crawl there", "kind": "info", "key": None}
    if (w := re.match(r"Job (\w[\w-]*) found ([\d,]+) URLs", m)):
        return {"text": f"{'Spider' if w.group(1) == 'spider' else 'Browser crawl'} found {w.group(2)} URLs", "kind": "info", "key": None}
    if (w := re.match(r"Job (\w[\w-]*) started", m)):
        names = {"spider": "Spidering", "spiderAjax": "Crawling with headless Firefox", "passiveScan-wait": "Waiting for passive checks to finish",
                 "report": "Writing the report"}
        return {"text": names.get(w.group(1), f"ZAP job {w.group(1)} started"), "kind": "step", "key": None}
    if re.match(r"Job (\w[\w-]*) (set|finished|requesting|adding|context)", m) or m.startswith(("Automation plan", "Found Java")):
        if "Automation plan succeeded" in m:
            return {"text": "ZAP plan finished", "kind": "good", "key": None}
        if "Automation plan failures" in m or "Automation plan warnings" in m:
            return {"text": m[:200], "kind": "warn", "key": None}
        return None

    # tlsx JSON lines
    if m.startswith("{") and '"tls_version"' in m:
        try:
            r = json.loads(m)
        except json.JSONDecodeError:
            return None
        bits = [f"TLS {str(r.get('tls_version', '')).replace('tls1', '1.').replace('tls', '')}".strip()]
        if r.get("not_after"):
            bits.append(f"certificate valid to {str(r['not_after'])[:10]}")
        flags = [f for f, k in (("EXPIRED", "expired"), ("self-signed", "self_signed"), ("name mismatch", "mismatched")) if r.get(k)]
        kind = "bad" if r.get("expired") else "warn" if flags else "info"
        return {"text": f"{r.get('host')}: " + " · ".join(bits + flags), "kind": kind, "key": None}

    # smap / InternetDB
    if (w := re.search(r"InternetDB returned HTTP 404 for ([\d.:a-f]+)", m)):
        return {"text": f"No Shodan data for {w.group(1).rstrip(':')}", "kind": "info", "key": None}

    # BBOT banner/tables/event echo and other noise
    if re.match(r"^\s*(\||\+|_|\\|/|BIGHUGE|www\.blacklantern)", m) or re.match(r"^\[(INFO|SUCC)\] (asn|aggregate|output\.\w+):", m) \
            or re.match(r"^\[[A-Z_]+\]\s", m) and not m.startswith(("[WARN]", "[ERRR]", "[CRIT]")) or "Reading targets from" in m:
        return None
    if m.startswith(("[ERRR]", "[CRIT]")) or re.search(r"\b(error|failed|exception)\b", m, re.I):
        return {"text": re.sub(r"^\[\w+\]\s*", "", m)[:240], "kind": "bad", "key": None}
    if m.startswith("[WARN]"):
        return {"text": m[7:].strip()[:240], "kind": "warn", "key": None}
    return None
