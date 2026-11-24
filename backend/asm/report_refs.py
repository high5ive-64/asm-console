"""Security knowledge base for the comprehensive report: authoritative reference links, framework
mappings (CWE, OWASP Top 10 2021, MITRE ATT&CK, NIST SP 800-53 r5) and curated remediation guidance
per finding class.

Kept separate from the Typst assembly so the mappings can be reviewed and unit-tested on their own.
Nothing here is fetched at runtime; the URLs are deterministic deep links an analyst can open.
"""
from __future__ import annotations

import re
from urllib.parse import quote

# --------------------------------------------------------------------------- reference URLs

def nvd_url(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"

KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_URL = "https://www.first.org/epss/"

def mitre_url(tid: str) -> str:
    """T1190 -> technique page; T1584.001 -> sub-technique page."""
    tid = tid.strip().upper()
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"

def cwe_url(n: int | str) -> str:
    n = str(n).upper().replace("CWE-", "")
    return f"https://cwe.mitre.org/data/definitions/{n}.html"

# OWASP Top 10 2021 categories -> (title, url)
OWASP_2021 = {
    "A01": ("A01:2021 Broken Access Control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02": ("A02:2021 Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A03": ("A03:2021 Injection", "https://owasp.org/Top10/A03_2021-Injection/"),
    "A04": ("A04:2021 Insecure Design", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    "A05": ("A05:2021 Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A06": ("A06:2021 Vulnerable and Outdated Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "A07": ("A07:2021 Identification and Authentication Failures", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    "A08": ("A08:2021 Software and Data Integrity Failures", "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    "A09": ("A09:2021 Security Logging and Monitoring Failures", "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    "A10": ("A10:2021 Server-Side Request Forgery (SSRF)", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
}

def owasp_url(code: str) -> tuple[str, str]:
    return OWASP_2021.get(code, (code, "https://owasp.org/Top10/"))

# NIST SP 800-53 r5 controls -> (title, url). csf.tools hosts a stable browsable mirror per control.
_NIST = {
    "AC-3": "Access Enforcement", "AC-4": "Information Flow Enforcement", "AC-6": "Least Privilege",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "CA-7": "Continuous Monitoring", "CA-8": "Penetration Testing",
    "CM-6": "Configuration Settings", "CM-7": "Least Functionality", "CM-8": "System Component Inventory",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management", "IA-9": "Service Identification and Authentication",
    "PM-5": "System Inventory", "RA-5": "Vulnerability Monitoring and Scanning",
    "SA-9": "External System Services", "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity", "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection", "SC-17": "Public Key Infrastructure Certificates",
    "SC-18": "Mobile Code", "SC-20": "Secure Name/Address Resolution Service (Authoritative Source)",
    "SC-23": "Session Authenticity", "SI-2": "Flaw Remediation", "SI-4": "System Monitoring",
    "SI-8": "Spam Protection", "SI-10": "Information Input Validation",
}

def nist_control(cid: str) -> tuple[str, str, str]:
    """-> (id, title, url)."""
    cid = cid.upper()
    title = _NIST.get(cid, "")
    fam = cid.split("-")[0].lower()
    url = f"https://csf.tools/reference/nist-sp-800-53/r5/{fam}/{cid.lower()}/"
    return cid, title, url


# --------------------------------------------------------------------------- finding guidance

# Each entry: matched by a regex on the grouped finding title. Fields:
#   what  - one line: what the finding is
#   why   - why it matters (impact / attacker value)
#   fix   - concrete remediation
#   cwe   - list of CWE ids
#   owasp - OWASP Top 10 code (A0x) or None
#   nist  - list of NIST 800-53 control ids
#   refs  - list of (label, url) authoritative references
_GUIDE: list[tuple[re.Pattern, dict]] = []

def _g(pattern: str, **kw):
    _GUIDE.append((re.compile(pattern, re.I), kw))

_g(r"known-exploited vulnerability|CISA KEV",
   what="A service or product version on this asset matches a CVE on CISA's Known Exploited Vulnerabilities (KEV) catalogue — a vulnerability with confirmed in-the-wild exploitation.",
   why="KEV entries are actively exploited now, not theoretically. If the version match is real, this is a direct, high-probability breach entry point.",
   fix="Confirm the running version (the match is from a banner/fingerprint and is unverified), then patch or remove the affected service to at least the fixed version. Treat KEV items inside the CISA due-date window as emergency change.",
   cwe=[], owasp="A06", nist=["RA-5", "SI-2", "CM-8"],
   refs=[("CISA KEV catalogue", KEV_CATALOG_URL)])

_g(r"likely-exploited vulnerability|EPSS",
   what="A CVE with a high EPSS score (FIRST's model-estimated probability of exploitation in the next 30 days) matches a version banner on this asset.",
   why="High EPSS means exploitation is probable even though it is not yet on the KEV list. Worth remediating ahead of the long tail of low-EPSS CVEs.",
   fix="Verify the version, prioritise patching above routine CVEs, and monitor whether the CVE is later added to KEV.",
   cwe=[], owasp="A06", nist=["RA-5", "SI-2"],
   refs=[("FIRST EPSS", EPSS_URL)])

_g(r"CVE.* suggested by service banners|low exploit likelihood",
   what="Service banners/fingerprints suggest CVEs with low current exploitation likelihood.",
   why="Lower priority than KEV/EPSS items, but still part of the patch backlog and useful for version hygiene.",
   fix="Fold into routine patch management; verify versions before acting as banners are often inaccurate.",
   cwe=[], owasp="A06", nist=["RA-5", "SI-2"], refs=[])

_g(r"dangling|takeover|CNAME",
   what="A DNS record (usually a CNAME) points at a third-party service target that is no longer claimed, so an attacker can register the target and serve content under your name.",
   why="Subdomain takeover gives an attacker a trusted hostname: phishing, cookie theft on the parent domain, OAuth redirect abuse, and — for an AI-agent estate — a trusted source an agent may ingest as instructions.",
   fix="Remove the dangling DNS record, or re-claim the target at the provider. Add dangling-record detection to DNS change control.",
   cwe=["CWE-350"], owasp="A05", nist=["CM-8", "SC-7", "SC-20"],
   refs=[("OWASP: Subdomain takeover", "https://owasp.org/www-community/attacks/Subdomain_takeover")])

_g(r"no dmarc|dmarc record: the domain can be spoofed",
   what="The domain publishes no DMARC record, so receivers have no policy telling them to reject spoofed mail.",
   why="Anyone can send email as the domain. This is the first enabler of brand-impersonation phishing against staff, customers and suppliers.",
   fix="Publish DMARC at p=none to observe, then move to p=quarantine and p=reject once SPF and DKIM alignment are confirmed. Pair with a monitored rua/ruf address.",
   cwe=["CWE-290"], owasp="A07", nist=["SC-8", "SI-8", "SC-20"],
   refs=[("RFC 7489 (DMARC)", "https://datatracker.ietf.org/doc/html/rfc7489"), ("M3AAWG DMARC guidance", "https://www.m3aawg.org/")])

_g(r"p=none|quarantine, not reject|dmarc policy",
   what="A DMARC record exists but is set to p=none or p=quarantine rather than p=reject, so spoofed mail is still delivered or only foldered.",
   why="A non-reject policy leaves the domain practically spoofable; p=none provides reporting only, no enforcement.",
   fix="After confirming SPF/DKIM alignment for all legitimate senders, raise the policy to p=reject (pct=100).",
   cwe=["CWE-290"], owasp="A07", nist=["SC-8", "SI-8"],
   refs=[("RFC 7489 (DMARC)", "https://datatracker.ietf.org/doc/html/rfc7489")])

_g(r"spf",
   what="The domain's SPF record is broken or exceeds the 10 DNS-lookup limit, so SPF evaluation may fail (permerror) for legitimate senders.",
   why="A failing SPF weakens DMARC enforcement and can cause legitimate mail to be rejected while still leaving room for spoofing.",
   fix="Flatten or consolidate includes to stay under 10 lookups; remove unused senders; validate with an SPF checker.",
   cwe=["CWE-290"], owasp="A07", nist=["SC-8", "SI-8"],
   refs=[("RFC 7208 (SPF)", "https://datatracker.ietf.org/doc/html/rfc7208")])

_g(r"lookalike|look-alike|typosquat|homograph",
   what="A registered domain visually or phonetically imitates the brand (typo, homoglyph or added word).",
   why="Lookalikes are staged for phishing and business-email-compromise. A lookalike with live mail servers or a live page is an imminent concern.",
   fix="Monitor and, where justified, file UDRP/takedown. Pre-emptively register high-risk permutations. Ensure DMARC p=reject limits exact-domain spoofing so attackers must fall back to lookalikes you can watch.",
   cwe=["CWE-290"], owasp="A07", nist=["SI-8", "SI-4"],
   refs=[("APWG eCrime resources", "https://apwg.org/")])

_g(r"expired certificate|expired tls",
   what="A TLS certificate in use has passed its notAfter date.",
   why="Browsers and clients reject expired certificates, breaking service and training users to click through security warnings.",
   fix="Renew and automate renewal (ACME). Alert well before expiry.",
   cwe=["CWE-298", "CWE-324"], owasp="A02", nist=["SC-12", "SC-17"],
   refs=[("Mozilla TLS guidance", "https://wiki.mozilla.org/Security/Server_Side_TLS")])

_g(r"expires within|expiring",
   what="A TLS certificate will expire within 30 days.",
   why="Impending outage and the same click-through risk as an expired certificate if renewal is missed.",
   fix="Renew now and automate renewal; add expiry monitoring to the certificate inventory.",
   cwe=["CWE-298"], owasp="A02", nist=["SC-12", "SC-17"],
   refs=[("Mozilla TLS guidance", "https://wiki.mozilla.org/Security/Server_Side_TLS")])

_g(r"legacy protocol|tls1|sslv|self-signed|mismatched|weak cipher",
   what="The TLS endpoint negotiates a legacy protocol/cipher, or presents a self-signed or mismatched certificate.",
   why="Legacy TLS (<=1.1) and weak ciphers are susceptible to downgrade and interception; self-signed/mismatched certs undermine trust and enable MITM.",
   fix="Disable TLS 1.0/1.1 and weak ciphers, prefer TLS 1.2+ with modern suites, and present a correctly-chained certificate from a trusted CA.",
   cwe=["CWE-326", "CWE-327"], owasp="A02", nist=["SC-8", "SC-13"],
   refs=[("Mozilla SSL Config Generator", "https://ssl-config.mozilla.org/")])

_g(r"api key in url|information disclosure|sensitive.*query string|secret",
   what="A secret (API key, token or credential) was observed in a URL / query string or otherwise disclosed.",
   why="Secrets in URLs leak into logs, referrer headers, browser history and proxy caches, and are often valid for direct API access.",
   fix="Rotate the exposed secret immediately, move secrets to headers or a server-side store, and scrub them from logs and historical URLs.",
   cwe=["CWE-598", "CWE-200"], owasp="A01", nist=["AC-3", "IA-5", "AU-6"],
   refs=[("CWE-598", cwe_url(598))])

_g(r"content security policy|\bcsp\b",
   what="No Content-Security-Policy header is set on the response.",
   why="CSP is the main defence-in-depth control against cross-site scripting and data injection; without it, an XSS flaw has no secondary containment.",
   fix="Define and roll out a restrictive CSP (start report-only), eliminating inline script where possible.",
   cwe=["CWE-693"], owasp="A05", nist=["SC-18", "SI-10"],
   refs=[("MDN: CSP", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP")])

_g(r"hsts|strict-transport|missing.*header|x-frame|clickjack|cookie",
   what="A security-hardening response header (HSTS, X-Frame-Options/frame-ancestors, cookie flags, etc.) is missing or weak.",
   why="Missing hardening headers leave the app exposed to downgrade, clickjacking or cookie theft that a correct header would prevent.",
   fix="Add the missing headers: HSTS with a long max-age, frame-ancestors/X-Frame-Options, and Secure/HttpOnly/SameSite cookie flags.",
   cwe=["CWE-693", "CWE-1021"], owasp="A05", nist=["SC-8", "SC-23"],
   refs=[("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/")])

_g(r"\bxss\b|cross-site scripting",
   what="A reflected or stored cross-site scripting condition was reported.",
   why="XSS lets an attacker run script in a victim's session: session theft, action-on-behalf, and credential capture.",
   fix="Context-aware output encoding, input validation, and a strong CSP as defence-in-depth.",
   cwe=["CWE-79"], owasp="A03", nist=["SI-10"],
   refs=[("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")])

_g(r"sql injection|sqli",
   what="A SQL injection condition was reported.",
   why="SQLi can expose or modify the entire database and sometimes gain code execution.",
   fix="Use parameterised queries / prepared statements everywhere; apply least-privilege database accounts.",
   cwe=["CWE-89"], owasp="A03", nist=["SI-10", "AC-6"],
   refs=[("OWASP SQL Injection Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")])

_g(r"ssrf|server-side request forgery|svg|transform|convert",
   what="A server-side request forgery condition, or a transform/convert service (image/SVG/document rendering) prone to SSRF, was identified.",
   why="SSRF lets an attacker make the server fetch internal URLs — cloud metadata (IMDS), internal admin panels, and east-west services — a classic pivot to cloud credential theft.",
   fix="Block requests to link-local/metadata and RFC1918 ranges, enforce an allowlist of fetchable destinations, require IMDSv2, and isolate transform workers.",
   cwe=["CWE-918"], owasp="A10", nist=["SC-7", "AC-4"],
   refs=[("OWASP SSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html")])

_g(r"rdp|database|mysql|postgres|mongo|redis|elastic|ssh|exposed service|risky service|open port",
   what="A sensitive service (remote access, database or admin protocol) is reachable from the internet.",
   why="Internet-exposed management and data services are prime targets for credential-stuffing, known-exploit and ransomware intrusion.",
   fix="Put the service behind a VPN/ZTNA or IP allowlist, disable internet exposure, and ensure strong authentication and patching.",
   cwe=["CWE-284"], owasp="A05", nist=["SC-7", "CM-7", "AC-3"],
   refs=[("CISA: reduce internet-exposed management interfaces", "https://www.cisa.gov/news-events/directives/bod-23-02-mitigating-risk-internet-exposed-management-interfaces")])

_g(r"leak|breach|credential|exposed on",
   what="Leaked data, exposed storage or credentials attributable to the organisation were reported by an intelligence source.",
   why="Leaked credentials and exposed stores are directly usable for account takeover and data access.",
   fix="Validate the leak, rotate any exposed credentials, lock down exposed storage, and enforce MFA on affected accounts.",
   cwe=["CWE-200"], owasp="A01", nist=["AC-3", "IA-5", "SI-4"], refs=[])

_g(r"not in the cmdb|unknown host|not yet triaged|shadow",
   what="A live host in scope is not recorded in the asset inventory / CMDB and has not been triaged.",
   why="Unmanaged ('shadow') assets are unpatched and unmonitored by definition — the attack surface you don't know you have.",
   fix="Triage ownership, add to the CMDB, and bring under standard monitoring and patching — or decommission if it should not exist.",
   cwe=[], owasp="A05", nist=["CM-8", "PM-5"], refs=[])

_g(r"agent|mcp|digital-twin|model context",
   what="An AI-agent / MCP / model-serving endpoint is exposed, with authentication that is missing or inconsistent across regions.",
   why="Agent and MCP endpoints expose tools and data to callers. Inconsistent or missing auth enables prompt injection, tool poisoning, confused-deputy abuse and excessive-agency actions under a trusted identity.",
   fix="Enforce consistent authentication on every region/replica, apply per-caller tool authorisation (e.g. Okta Cross-App-Access), rate-limit, and treat any ingested external content as untrusted input.",
   cwe=["CWE-284", "CWE-862"], owasp="A01", nist=["AC-3", "AC-6", "IA-9", "AC-4"],
   refs=[("OWASP Top 10 for LLM Applications", "https://genai.owasp.org/llm-top-10/"),
         ("MITRE ATLAS", "https://atlas.mitre.org/")])


def guidance_for(group: str, area: str = "", tool: str = "") -> dict:
    for rx, data in _GUIDE:
        if rx.search(group or ""):
            return data
    # area fallback
    fallbacks = {
        "tls": ["SC-8", "SC-13"], "email": ["SC-8", "SI-8"], "vulns": ["RA-5", "SI-2"],
        "web": ["SI-10", "SC-7"], "exposure": ["SC-7", "CM-7"], "brand": ["SI-8"],
        "surface": ["CM-8", "PM-5"], "dns": ["SC-20", "CM-8"],
    }
    return {"what": "", "why": "", "fix": "", "cwe": [], "owasp": None,
            "nist": fallbacks.get(area, []), "refs": []}


# --------------------------------------------------------------------------- attack-path framing

# category -> (precondition, business impact, extra references)
PATH_CATEGORY = {
    "agent-abuse": (
        "An AI-agent / MCP endpoint is reachable, and its authentication is missing or inconsistent, or it ingests content from a source an attacker can influence.",
        "An attacker acts through a trusted agent identity: data exfiltration via agent tools, actions taken on behalf of the organisation, and lateral movement into systems the agent can reach.",
        [("OWASP LLM Top 10", "https://genai.owasp.org/llm-top-10/"), ("MITRE ATLAS", "https://atlas.mitre.org/")]),
    "breach": (
        "An exposed service carries a known-exploited or likely-exploited vulnerability, or a weak authentication boundary.",
        "Initial access to the environment, from which an attacker can escalate and move laterally toward sensitive data.",
        [("CISA KEV catalogue", KEV_CATALOG_URL)]),
    "exfiltration": (
        "A path exists from an external entry point to data or credentials — directly disclosed, or reachable via SSRF / over-privileged service.",
        "Loss of confidential data or credentials, with regulatory, contractual and reputational consequences.",
        [("OWASP SSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html")]),
    "lateral": (
        "Shared hosting, shared certificates or co-located services let an attacker pivot from one compromised asset to others.",
        "A single compromise widens into many: the blast radius of one foothold is amplified across co-hosted or cert-sharing assets.",
        [("MITRE ATT&CK: Lateral Movement", "https://attack.mitre.org/tactics/TA0008/")]),
    "phishing": (
        "The domain is spoofable (no DMARC reject) or a lookalike is registered, giving an attacker a credible sender or site.",
        "Credential theft and business-email-compromise against staff, customers and suppliers; a lookalike can also feed poisoned content to agents.",
        [("APWG", "https://apwg.org/")]),
    "ddos": (
        "An origin is reachable directly, bypassing the CDN/WAF that is meant to front it.",
        "Volumetric or application-layer denial of service against the unprotected origin, and WAF bypass for other attacks.",
        [("CISA DDoS guidance", "https://www.cisa.gov/news-events/news/understanding-and-responding-distributed-denial-service-attacks")]),
}

LIKELIHOOD_REASON = {
    "observed": "The enabling weakness was directly observed in this scan's evidence.",
    "plausible": "The enabling weaknesses were observed individually; the chain is a realistic composition of them.",
    "theoretical": "The components exist but the full chain was not directly evidenced; treated as a pattern to watch.",
}


# --------------------------------------------------------------------------- API surface for the UI
# The UI must never construct reference URLs itself (they drift and get guessed wrong). These helpers
# are the single source of truth: every URL the detail pane links to is built here from the canonical
# builders above, so changing a reference scheme (e.g. the NIST mirror) is a one-line change.

def mitre_links(ids: list[str]) -> list[dict]:
    """ATT&CK technique ids -> [{id, url}] for clickable chips in the kill chain."""
    out, seen = [], set()
    for t in ids or []:
        t = t.strip().upper()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append({"id": t, "url": mitre_url(t)})
    return out


def finding_references(guidance: dict, cves: list[str] | None = None,
                       kev: bool = False, epss: bool = False) -> list[dict]:
    """Every authoritative link for a finding, as [{label, url, kind}] with kind in
    {cve, kev, epss, nist, cwe, owasp, ref}. Deduped by URL, ordered most-specific first."""
    out: list[dict] = []
    seen: set[str] = set()

    def add(label: str, url: str | None, kind: str):
        if url and url not in seen:
            seen.add(url)
            out.append({"label": label, "url": url, "kind": kind})

    for cve in cves or []:
        add(cve.upper(), nvd_url(cve), "cve")
    if kev:
        add("CISA KEV catalogue", KEV_CATALOG_URL, "kev")
    if epss:
        add("FIRST EPSS", EPSS_URL, "epss")
    for cid in guidance.get("nist", []) or []:
        _id, title, url = nist_control(cid)
        add(f"NIST {_id}" + (f": {title}" if title else ""), url, "nist")
    for c in guidance.get("cwe", []) or []:
        add(str(c).upper(), cwe_url(c), "cwe")
    if guidance.get("owasp"):
        label, url = owasp_url(guidance["owasp"])
        add(label, url, "owasp")
    for ref in guidance.get("refs", []) or []:
        add(ref[0], ref[1], "ref")
    return out


def path_framing(category: str, likelihood: str) -> dict:
    """Category precondition / business impact / extra references + why this likelihood, for a path."""
    pre, impact, refs = PATH_CATEGORY.get(category, ("", "", []))
    return {"precondition": pre, "impact": impact,
            "references": [{"label": l, "url": u} for l, u in refs],
            "likelihood_reason": LIKELIHOOD_REASON.get(likelihood, "")}


# Agentic/LLM risk tags on attack-path steps -> one authoritative reference each. Kept here (never in
# the UI, which must not construct URLs) so the canonical set lives server-side. Deep per-risk slugs on
# genai.owasp.org have churned between the 2023 and 2025 lists, so we link the stable catalogue index
# and name the specific risk in the label; unknown tags get no link.
_LLM_TOP10 = "https://genai.owasp.org/llm-top-10/"
_ATLAS = "https://atlas.mitre.org/"
AGENT_TAG_REF = {
    "prompt-injection":          ("OWASP LLM Top 10 - Prompt injection", _LLM_TOP10),
    "excessive-agency":          ("OWASP LLM Top 10 - Excessive agency", _LLM_TOP10),
    "sensitive-info-disclosure": ("OWASP LLM Top 10 - Sensitive information disclosure", _LLM_TOP10),
    "tool-poisoning":            ("MITRE ATLAS - AI attack techniques", _ATLAS),
    "confused-deputy":           ("MITRE ATLAS - AI attack techniques", _ATLAS),
}

def agent_tag_refs(tags: list[str]) -> list[dict]:
    """[{tag, label, url}] for each agent-risk tag we have a canonical reference for; others omitted."""
    out: list[dict] = []
    for t in tags or []:
        ref = AGENT_TAG_REF.get(t)
        if ref:
            out.append({"tag": t, "label": ref[0], "url": ref[1]})
    return out


# source_tool -> most likely run-folder subdirectory holding its raw output. Only a hint: the detail
# route verifies the directory exists before linking, and falls back to the run-folder root otherwise,
# so a "View raw output" link is never a dead end.
_RAW_DIR_EXACT = {
    "zap": "zap", "gowitness": "bbot", "asn": "bbot",
    "internetdb": "services", "internetdb-extra": "services", "naabu": "services",
    "dnsreaper": "takeover",
    "intel-cve": "intel", "leakix": "intel", "netlas": "intel", "spiderfoot": "spiderfoot",
    "urlscan": "urlscan", "opensquat": "squat", "hibp": "hibp",
    "checkdmarc": "email", "dnstwist": "lookalikes",
    "testssl": "tls", "tlsx": "tls", "cloudlist": "cloud", "dnsx": "dns", "ptr": "dns",
}

def raw_dir_hint(tool: str) -> str:
    t = (tool or "").split(":", 1)[0]
    if t.startswith("bbot") or t.startswith("baddns"):
        return "bbot"
    return _RAW_DIR_EXACT.get(t, "")


def tech_cve_url(product: str, version: str | None = None) -> str:
    """Deterministic NVD keyword-search deep link for a detected component (and version when known).
    Passive fingerprinting gives no CPE-accurate CVE list, so this is the analyst pivot, built here
    so the UI never constructs it."""
    q = (product or "").strip()
    if version:
        q = f"{q} {version}".strip()
    return ("https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview"
            "&search_type=all&query=" + quote(q))
