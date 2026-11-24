"""Theoretical attack-path simulation, focused on AI-agent exposure.

This is a DEFENSIVE prioritisation aid. It reasons over exposure the scan already collected — it never sends traffic
and never attempts anything. Each path is a chain of steps an attacker *could* take, every step tied to a concrete
finding or asset, mapped to MITRE ATT&CK and to the agent-threat taxonomy (prompt injection, tool poisoning,
excessive agency, confused deputy, sensitive-information disclosure). Paths are ranked by impact, how directly the
scan evidences them, and how far they reach.

Nothing here asserts a system is exploitable. "observed" means the enabling weakness was seen in the data;
"plausible" means a strong signal was seen; "theoretical" means the shape is present but unconfirmed.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from .db import DB
from .graph import Graph, build_graph, co_hosting, shared_certs
from .surface import classify_host, is_agent_surface

# impact and likelihood weights for ranking
_SEV_W = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_LIK_W = {"observed": 3, "plausible": 2, "theoretical": 1}
CATEGORIES = ("agent-abuse", "breach", "exfiltration", "lateral", "phishing", "ddos")


def _step(technique: str, mitre: list[str], agent: list[str], desc: str, evidence: dict | None = None) -> dict:
    return {"technique": technique, "mitre": mitre, "agent_tags": agent, "description": desc, "evidence": evidence or {}}


def _path(pid: str, title: str, category: str, severity: str, likelihood: str, steps: list[dict],
          nodes: list[str], recommendation: str) -> dict:
    score = _SEV_W.get(severity, 2) * _LIK_W.get(likelihood, 1) * (1 + min(len(nodes), 20) / 20)
    mitre = sorted({m for s in steps for m in s["mitre"]})
    agent = sorted({t for s in steps for t in s["agent_tags"]})
    return {"id": pid, "title": title, "category": category, "severity": severity, "likelihood": likelihood,
            "steps": steps, "nodes": nodes, "mitre": mitre, "agent_tags": agent, "recommendation": recommendation,
            "score": round(score, 2)}


def _findings(db: DB, sid: str) -> list[dict]:
    return [dict(r) for r in db.all(
        "SELECT id, area, severity, title, host, source_tool, evidence_ref FROM findings "
        "WHERE scan_id = ? AND status != 'false_positive'", sid)]


# ---- scenario evaluators ----------------------------------------------------------------

def _mcp_inconsistent_auth(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    """Agent/MCP endpoints that are open, or protected in one region but not another."""
    hosts = [n for n in g.of_kind("host") if n.attrs.get("agent") and n.attrs.get("http_status")]
    # group by service name (the first label), so digital-twin-mcp.eu01 and .us01 land together
    fam: dict[str, list] = defaultdict(list)
    for n in hosts:
        fam[n.label.split(".", 1)[0]].append(n)
    out = []
    for svc, group in fam.items():
        statuses = {n.label: n.attrs["http_status"] for n in group}
        protected = {h for h, s in statuses.items() if s in (401, 403)}
        open_live = {h for h, s in statuses.items() if s == 200}
        redirect = {h for h, s in statuses.items() if s in (301, 302, 307, 308)}
        if protected and (open_live or redirect):
            weak = sorted(open_live | redirect)
            steps = [
                _step("Enumerate the agent/MCP endpoints", ["T1133", "T1590"], [],
                      f"The '{svc}' service is published across regions; at least one requires auth and at least one does not.",
                      {"hosts": sorted(statuses)}),
                _step("Reach the endpoint that doesn't challenge for auth", ["T1133"], ["confused-deputy"],
                      f"{', '.join(weak)} answer {sorted({statuses[h] for h in weak})} where a sibling returns 401/403.",
                      {"hosts": weak}),
                _step("Invoke MCP tools / agent actions without authorisation", ["T1213", "T1559"],
                      ["excessive-agency", "sensitive-info-disclosure"],
                      "An unauthenticated MCP/agent surface exposes whatever tools and data the agent can reach."),
            ]
            out.append(_path(f"mcp-inconsistent-{svc}", f"Inconsistent auth on the '{svc}' agent/MCP service",
                             "agent-abuse", "high", "plausible", steps, weak + sorted(protected),
                             "Confirm every regional instance enforces the same authentication and authorisation, and that "
                             "the MCP server validates the caller's identity and tool scope (Okta XAA / Cross-App Access)."))
        elif open_live:
            weak = sorted(open_live)
            steps = [
                _step("Discover the agent/MCP endpoint", ["T1590", "T1133"], [], f"'{svc}' answers 200 with no auth challenge.",
                      {"hosts": weak}),
                _step("Invoke tools / read context without authorisation", ["T1213"],
                      ["excessive-agency", "sensitive-info-disclosure", "tool-poisoning"],
                      "An open MCP/agent endpoint can be driven directly, or seeded with poisoned tool definitions."),
            ]
            out.append(_path(f"mcp-open-{svc}", f"Open agent/MCP endpoint: {svc}", "agent-abuse", "high", "plausible",
                             steps, weak, "Put the endpoint behind authentication and verify tool-call authorisation per caller."))
    return out


def _ssrf_transform(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    """File/transform services are classic SSRF pivots into cloud metadata and internal services."""
    hosts = [n for n in g.of_kind("host") if "transform" in n.attrs.get("tags", []) and n.attrs.get("live")]
    if not hosts:
        return []
    names = sorted(h.label for h in hosts)[:10]
    steps = [
        _step("Identify a file/transform service", ["T1595"], [],
              f"{len(hosts)} host(s) look like fetch/convert/render services (e.g. {names[0]}).", {"hosts": names}),
        _step("Supply a URL that points inward (SSRF)", ["T1190"], ["tool-poisoning"],
              "Transform services that fetch a user-supplied URL can be steered at internal addresses or 169.254.169.254."),
        _step("Read cloud instance-metadata / internal services", ["T1552.005"], ["sensitive-info-disclosure"],
              "SSRF to the metadata endpoint can yield cloud credentials; to internal hosts, unintended data."),
        _step("Exfiltrate data or pivot with the stolen role", ["T1567", "T1078.004"], [],
              "Credentials or data reached this way leave over ordinary web traffic."),
    ]
    return [_path("ssrf-transform", "SSRF via a file/transform service into cloud metadata", "exfiltration", "high",
                  "theoretical", steps, names,
                  "Confirm these services disallow user-controlled fetch targets, block link-local/metadata ranges, and run "
                  "with IMDSv2 and a minimal instance role.")]


def _kev_breach(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    kev = [x for x in f if x["source_tool"] == "intel-cve" and x["severity"] == "high"]
    out = []
    for x in kev[:12]:
        cve = re.search(r"CVE-\d{4}-\d+", x["title"])
        host = x["host"] or ""
        nbrs = co_hosting_for(g, host)
        steps = [
            _step("Match an exposed service to a known-exploited CVE", ["T1595", "T1592"], [],
                  f"{x['title']}", {"host": host, "finding_id": x["id"]}),
            _step("Exploit the public-facing service", ["T1190", "T1210"], [],
                  f"{cve.group(0) if cve else 'The CVE'} is on CISA's Known-Exploited list (verify the version match first)."),
        ]
        if nbrs:
            steps.append(_step("Move laterally to co-hosted services", ["T1021"], ["confused-deputy"],
                               f"{host} shares infrastructure with {len(nbrs)} other host(s).", {"hosts": nbrs[:10]}))
        out.append(_path(f"kev-{x['id']}", f"Known-exploited CVE as a breach entry point ({host})", "breach", "high",
                         "observed", steps, [host] + nbrs[:10],
                         "Verify the running version, patch or virtually-patch, and confirm the host is segmented from the rest."))
    return out


def co_hosting_for(g: Graph, host: str) -> list[str]:
    hid = f"host:{host}"
    if hid not in g.nodes:
        return []
    out = set()
    for ipn in g.neighbours(hid, "resolves_to"):
        if ipn.attrs.get("shared"):
            continue
        for h in g.neighbours(ipn.id, "resolves_to", incoming=True):
            if h.label != host:
                out.add(h.label)
    return sorted(out)


def _takeover_agent(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    tk = [x for x in f if x["source_tool"] in ("bbot:baddns", "baddns-live", "dnsreaper") and x["severity"] != "low"]
    out = []
    for x in tk[:12]:
        host = x["host"] or ""
        agenty = is_agent_surface(host) or "api" in classify_host(host)
        steps = [
            _step("Find a dangling DNS record", ["T1590.002"], [], f"{x['title']}", {"host": host, "finding_id": x["id"]}),
            _step("Claim the abandoned target and serve content from a trusted name", ["T1584.001", "T1656"],
                  ["confused-deputy"], f"{host} resolves to an unclaimed third-party target an attacker can register."),
        ]
        if agenty:
            steps.append(_step("Feed attacker content to agents/clients that trust the domain", ["T1659"],
                               ["prompt-injection", "confused-deputy"],
                               "Content served from a trusted subdomain can be ingested by an agent as instructions."))
        out.append(_path(f"takeover-{x['id']}", f"Subdomain takeover of a trusted name ({host})",
                         "agent-abuse" if agenty else "phishing", "high", "observed", steps, [host],
                         "Remove the dangling record or reclaim the target; agents should not treat subdomain content as trusted input."))
    return out


def _phish_to_agent(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    dmarc = [x for x in f if x["area"] == "email" and
             (x["title"].startswith("No DMARC") or "p=none" in x["title"] or "quarantine, not reject" in x["title"])]
    look_mx = [x for x in f if x["area"] == "brand" and x["severity"] in ("medium", "high") and "mail server" in x["title"].lower()]
    if not dmarc and not look_mx:
        return []
    steps = []
    if dmarc:
        steps.append(_step("Spoof a domain that doesn't enforce DMARC", ["T1656", "T1585.002"], [],
                            f"{dmarc[0]['title']}", {"host": dmarc[0]["host"], "finding_id": dmarc[0]["id"]}))
    if look_mx:
        dom = look_mx[0]["title"].rsplit(": ", 1)[-1]
        steps.append(_step("Or send from a registered lookalike with live mail", ["T1583.001"], [],
                            f"Lookalike with mail servers: {dom}", {"finding_id": look_mx[0]["id"]}))
    steps.append(_step("Deliver a phishing payload to staff or to an AI mail/agent workflow", ["T1566", "T1598"],
                       ["prompt-injection", "excessive-agency"],
                       "If an AI agent reads inbound mail, crafted content becomes injected instructions it may act on."))
    sev = "high" if dmarc and any(x["severity"] == "high" for x in dmarc) else "medium"
    return [_path("phish-agent", "Email spoofing / lookalike into a phishing or agent-injection attack", "phishing", sev,
                  "observed", steps, [x["host"] for x in dmarc[:5] if x["host"]],
                  "Set DMARC to p=reject on all sending domains; monitor the lookalikes; sandbox any agent that ingests email "
                  "and never let it act on unverified message content.")]


def _direct_ddos(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    direct = [n for n in g.of_kind("host") if n.attrs.get("live") and not n.attrs.get("cdn")
              and any(not ipn.attrs.get("shared") for ipn in g.neighbours(n.id, "resolves_to"))]
    if len(direct) < 1:
        return []
    names = sorted(n.label for n in direct)[:15]
    agent = [n for n in direct if n.attrs.get("agent")]
    steps = [
        _step("Identify origins reachable without the CDN/WAF", ["T1595"], [],
              f"{len(direct)} live host(s) answer on your own IPs, outside a CDN.", {"hosts": names}),
        _step("Exhaust the origin directly", ["T1498", "T1499"], [],
              "Traffic aimed at the origin bypasses CDN absorption and rate limiting."),
    ]
    if agent:
        steps.append(_step("Prefer expensive agent/inference endpoints", ["T1499.003"], ["excessive-agency"],
                           f"{len(agent)} of these are agent/model endpoints, where each request is costly.",
                           {"hosts": sorted(n.label for n in agent)}))
    return [_path("ddos-direct", "Direct-to-origin denial of service", "ddos", "medium", "plausible", steps, names,
                  "Force all traffic through the CDN/WAF, keep origin IPs private, and rate-limit agent/inference endpoints.")]


def _leaked_secret(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    rx = re.compile(r"\b(api[ _-]?key|secret|token|credential|password|bearer|aws_|private key)\b", re.I)
    leaks = [x for x in f if rx.search(x["title"]) and x["area"] not in ("email",)]
    out = []
    for x in leaks[:8]:
        steps = [
            _step("Harvest a leaked secret from exposed content", ["T1552.001"], ["sensitive-info-disclosure"],
                  f"{x['title']}", {"host": x["host"], "finding_id": x["id"]}),
            _step("Use the secret against the API it unlocks", ["T1078", "T1071"], ["excessive-agency"],
                  "A leaked key or token can be replayed directly against the service."),
            _step("Read or exfiltrate data within the key's scope", ["T1567"], [],
                  "Impact is bounded by the key's permissions — often broad for agent/service keys."),
        ]
        out.append(_path(f"secret-{x['id']}", f"Leaked secret reused against its API ({x['host'] or 'web content'})",
                         "exfiltration", "high", "observed" if "url" in x["title"].lower() else "plausible", steps,
                         [x["host"]] if x["host"] else [],
                         "Rotate the exposed credential, remove it from client-reachable content, and scope agent/service keys tightly."))
    return out


def _blast_radius(db: DB, sid: str, g: Graph, f: list[dict]) -> list[dict]:
    out = []
    for c in shared_certs(g)[:3]:
        if c["host_count"] < 3:
            continue
        steps = [
            _step("Obtain one private key shared across many hosts", ["T1552.004"], [],
                  f"{c['host_count']} hosts present the same certificate ({c['cert']}).", {"hosts": c["hosts"][:15]}),
            _step("Impersonate or intercept any of them", ["T1557", "T1656"], ["confused-deputy"],
                  "A single leaked key compromises every host that shares the certificate at once."),
        ]
        out.append(_path(f"cert-{c['cert']}", f"Shared certificate as a single point of failure ({c['cert']})",
                         "lateral", "medium", "theoretical", steps, c["hosts"][:15],
                         "Prefer per-service certificates (or tightly-scoped wildcards) so one key leak isn't estate-wide."))
    for ch in co_hosting(g)[:2]:
        if ch["host_count"] < 3:
            continue
        steps = [
            _step("Compromise one origin that serves several names", ["T1190"], [],
                  f"{ch['ip']} carries {ch['host_count']} hosts.", {"hosts": ch["hosts"][:15]}),
            _step("Reach every co-hosted service from that foothold", ["T1021"], ["confused-deputy"],
                  "Co-hosted services share a trust and network boundary."),
        ]
        out.append(_path(f"cohost-{ch['ip']}", f"Co-hosted origin blast radius ({ch['ip']})", "lateral", "medium",
                         "theoretical", steps, ch["hosts"][:15],
                         "Separate high-value and agent services onto their own origins and segment east-west traffic."))
    return out


SCENARIOS = [_mcp_inconsistent_auth, _ssrf_transform, _kev_breach, _takeover_agent, _phish_to_agent, _direct_ddos,
             _leaked_secret, _blast_radius]


def simulate(db: DB, sid: str) -> dict:
    g = build_graph(db, sid)
    f = _findings(db, sid)
    paths: list[dict] = []
    for scenario in SCENARIOS:
        try:
            paths += scenario(db, sid, g, f)
        except Exception:                 # one scenario must never break the rest
            continue
    paths.sort(key=lambda p: -p["score"])
    by_cat: dict[str, int] = {c: 0 for c in CATEGORIES}
    by_agent: dict[str, int] = {}
    for p in paths:
        by_cat[p["category"]] = by_cat.get(p["category"], 0) + 1
        for t in p["agent_tags"]:
            by_agent[t] = by_agent.get(t, 0) + 1
    agent_paths = sum(1 for p in paths if p["category"] == "agent-abuse" or p["agent_tags"])
    return {"paths": paths, "summary": {"total": len(paths), "agent_related": agent_paths,
            "by_category": by_cat, "by_agent_tag": by_agent,
            "top_severity": paths[0]["severity"] if paths else None}}
