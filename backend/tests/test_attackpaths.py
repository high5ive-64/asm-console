"""Phase 3/4: the asset graph and the AI-agent attack-path simulation."""
import json

from test_pipeline import ready_scan, tools  # noqa: F401


def _seed(db, sid):
    def asset(host, ips, status=200, tech=None, tls=None, cdn=0, third=0, live=1, ports="[443, 80]"):
        db.run("INSERT INTO assets (scan_id,host,ips,in_cmdb,is_live,web_url,tech,tls,ports,cdn,third_party,http_status,edge,found_by,ports_confirmed) "
               "VALUES (?,?,?,0,?,?,?,?,?,?,?,?,'{}','[]',NULL)",
               sid, host, json.dumps(ips), live, f"https://{host}/", json.dumps(tech or []), json.dumps(tls or {}), ports, cdn, third, status)

    def finding(area, sev, title, host, tool):
        db.run("INSERT INTO findings (scan_id,area,severity,title,host,source_tool,status) VALUES (?,?,?,?,?,?,'observation')",
               sid, area, sev, title, host, tool)

    wildcard = {"subject_cn": "*.acme.com", "not_after": "2027-01-01T00:00:00Z"}
    asset("acme.com", ["93.184.216.10"], tech=["Amazon", "amazon", "Envoy"], tls=wildcard)
    asset("www.acme.com", ["93.184.216.10"], tls=wildcard)
    asset("api.acme.com", ["93.184.216.10"], tls=wildcard)                       # shared cert + co-hosted own IP
    asset("mcp.acme.com", ["45.33.32.5"], status=200, tls=wildcard)             # open MCP endpoint
    asset("digital-twin-mcp.eu01.acme.com", ["45.33.32.6"], status=401)         # protected
    asset("digital-twin-mcp.us01.acme.com", ["45.33.32.7"], status=301)         # inconsistent (not protected)
    asset("svg-convert.acme.com", ["45.33.32.8"], status=200)                   # SSRF-prone transform
    asset("cdn-host.acme.com", ["104.16.0.1"], cdn=1)                            # behind CDN -> not a DDoS origin

    finding("vulns", "high", "Known-exploited vulnerability reported (CISA KEV, unverified version match): CVE-2023-4448", "api.acme.com", "intel-cve")
    finding("exposure", "medium", "Dangling CNAME to sites.framer.app, possible takeover", "pulse.acme.com", "baddns-live")
    finding("email", "high", "No DMARC record: the domain can be spoofed", "acme.com", "checkdmarc")
    finding("brand", "medium", "Registered lookalike with mail servers: acme-login.com", "acme.com", "dnstwist")
    finding("web", "high", "Information disclosure: API key in URL query string", "api.acme.com", "bbot:excavate")
    finding("surface", "low", "Netblock worth checking as org-owned: 93.184.216.0/24 (AS64500 ACME-NET)", "93.184.216.0/24", "asn")
    finding("surface", "info", "Netblock on a shared platform: 104.16.0.0/16 (AS13335 CLOUDFLARENET)", "104.16.0.0/16", "asn")
    # a takeover host that resolves (so it exists as a node)
    asset("pulse.acme.com", ["45.33.32.9"], status=302)


def test_graph_build_and_questions(authed, tools):
    from asm.app import state
    from asm.graph import build_graph, shared_certs, co_hosting, blast_radius
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        _seed(db, sid)
        g = build_graph(db, sid)
    finally:
        db.close()
    assert len(g.of_kind("host")) >= 8 and len(g.of_kind("netblock")) == 2
    # shared wildcard cert across acme.com/www/api
    sc = shared_certs(g)
    assert any(c["cert"] == "*.acme.com" and c["host_count"] >= 3 for c in sc)
    # co-hosting on the own IP 93.184.216.10
    ch = co_hosting(g)
    assert any(c["ip"] == "93.184.216.10" and c["host_count"] >= 3 for c in ch)
    # the cloudflare IP is shared, so it is not counted as co-hosting
    assert not any(c["ip"] == "104.16.0.1" for c in ch)
    br = blast_radius(g, "93.184.216.10")
    assert br["host_count"] >= 3 and br["netblock"] and "ACME-NET" in br["netblock"]


def test_attack_paths(authed, tools):
    from asm.app import state
    from asm.attackpaths import simulate
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        _seed(db, sid)
        out = simulate(db, sid)
    finally:
        db.close()
    paths = out["paths"]
    ids = {p["id"] for p in paths}
    cats = {p["category"] for p in paths}
    # the signature AI-agent scenarios fire
    assert any(p["id"].startswith("mcp-inconsistent") for p in paths), ids
    assert "mcp-open-mcp" in ids
    assert "ssrf-transform" in ids
    assert any(p["id"].startswith("kev-") for p in paths)
    assert any(p["id"].startswith("takeover-") for p in paths)
    assert "phish-agent" in ids
    assert "ddos-direct" in ids
    assert any(p["id"].startswith("secret-") for p in paths)
    assert any(p["id"].startswith("cert-") or p["id"].startswith("cohost-") for p in paths)
    assert {"agent-abuse", "exfiltration", "breach", "phishing", "ddos"} <= cats
    # every path carries evidence, MITRE ids and a recommendation; steps reference findings/hosts
    for p in paths:
        assert p["steps"] and p["mitre"] and p["recommendation"]
        assert p["severity"] in ("critical", "high", "medium", "low")
        assert p["likelihood"] in ("observed", "plausible", "theoretical")
    # ranked by score, agent-related paths counted, prompt-injection surfaced somewhere
    assert all(paths[i]["score"] >= paths[i + 1]["score"] for i in range(len(paths) - 1))
    assert out["summary"]["agent_related"] >= 3
    assert "prompt-injection" in out["summary"]["by_agent_tag"] or "excessive-agency" in out["summary"]["by_agent_tag"]
    # the DDoS path excludes the CDN-fronted host
    ddos = next(p for p in paths if p["id"] == "ddos-direct")
    assert "cdn-host.acme.com" not in ddos["nodes"]


def test_graph_and_paths_endpoints(authed, tools):
    from asm.app import state
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        _seed(db, sid)
    finally:
        db.close()
    g = client.get(f"/api/scans/{sid}/graph").json()
    assert g["summary"]["nodes"]["host"] >= 8 and g["summary"]["shared_certs"]
    full = client.get(f"/api/scans/{sid}/graph?full=1").json()
    assert full["graph"]["nodes"] and full["graph"]["edges"]
    ap = client.get(f"/api/scans/{sid}/attack-paths").json()
    assert ap["summary"]["total"] >= 6 and ap["paths"][0]["score"] > 0
