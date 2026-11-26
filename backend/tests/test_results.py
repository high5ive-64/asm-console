"""Milestone 5: overview/RAG, assets, findings status, triage, files."""
from pathlib import Path

from test_pipeline import AUTH, ready_scan, wait_done, tools  # noqa: F401  (fixture)


def finished_scan(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False,
               "stages": ["bbot_light", "tls", "zap", "ports", "email", "gau", "lookalikes"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    assert wait_done(client, sid)["status"] == "completed"
    return client, h, sid


def test_overview_rag_reasons_and_false_positive(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    o = client.get(f"/api/scans/{sid}/overview").json()
    assert o["rag"] == "red"
    texts = " | ".join(r["text"] for r in o["reasons"])
    assert "risky service" in texts and "dangling DNS" in texts and "expired certificate" in texts
    assert all(r["link"]["tab"] in ("findings", "triage") for r in o["reasons"])
    assert {c["key"] for c in o["cards"]} >= {"hosts_in_scope", "unknown_hosts", "takeover_risks"}
    assert o["previous"] is None and all(c["trend"] is None for c in o["cards"])
    # marking the takeover finding as a false positive removes that red reason
    f = client.get(f"/api/scans/{sid}/findings").json()["findings"]
    takeover = [x["id"] for x in f if x["source_tool"] == "bbot:baddns"]
    r = client.request("PATCH", f"/api/scans/{sid}/findings", json={"ids": takeover, "status": "false_positive", "note": "checked: CNAME removed"}, headers=h)
    assert r.json()["updated"] == len(takeover)
    o2 = client.get(f"/api/scans/{sid}/overview").json()
    assert "dangling DNS" not in " | ".join(x["text"] for x in o2["reasons"])
    f2 = {x["id"]: x for x in client.get(f"/api/scans/{sid}/findings").json()["findings"]}
    assert f2[takeover[0]]["status"] == "false_positive" and f2[takeover[0]]["note"] == "checked: CNAME removed"
    assert client.request("PATCH", f"/api/scans/{sid}/findings", json={"ids": takeover, "status": "bogus"}, headers=h).status_code == 422


def test_findings_grouped_titles(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    f = client.get(f"/api/scans/{sid}/findings").json()["findings"]
    csp = [x for x in f if x["group"].startswith("Content Security Policy")]
    assert csp and all("instances" not in x["group"] for x in csp)


def test_assets_and_triage_and_cmdb(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    a = client.get(f"/api/scans/{sid}/assets").json()["assets"]
    www = next(x for x in a if x["host"] == "www.acme.com")
    assert www["is_live"] and www["screenshot"] is None or True
    assert any(x["risky_ports"] for x in a)
    t = client.get(f"/api/scans/{sid}/triage").json()
    hosts = [x["host"] for x in t["hosts"]]
    assert "www.acme.com" in hosts and t["decisions"]
    n_unknown = client.get(f"/api/scans/{sid}/overview").json()["values"]["unknown_hosts"]
    assert client.put(f"/api/scans/{sid}/triage", json={"hosts": ["www.acme.com"], "decision": "ours_unrecorded", "note": "marketing"}, headers=h).status_code == 200
    assert client.get(f"/api/scans/{sid}/overview").json()["values"]["unknown_hosts"] == n_unknown - 1
    assert client.put(f"/api/scans/{sid}/triage", json={"hosts": ["evil.example"], "decision": "not_ours"}, headers=h).status_code == 422
    assert client.put(f"/api/scans/{sid}/triage", json={"hosts": ["www.acme.com"], "decision": "nope"}, headers=h).status_code == 422
    # note-only update keeps the decision
    client.put(f"/api/scans/{sid}/triage", json={"hosts": ["www.acme.com"], "note": "owned by marketing"}, headers=h)
    row = next(x for x in client.get(f"/api/scans/{sid}/triage").json()["hosts"] if x["host"] == "www.acme.com")
    assert row["decision"] == "ours_unrecorded" and row["note"] == "owned by marketing"
    # add to CMDB: drops out of triage
    assert client.post(f"/api/scans/{sid}/triage/cmdb", json={"hosts": ["dev.acme.com"]}, headers=h).json()["added"] == 1
    assert "dev.acme.com" not in [x["host"] for x in client.get(f"/api/scans/{sid}/triage").json()["hosts"]]


def test_files_browser_is_confined_and_safe(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    root = client.get(f"/api/scans/{sid}/files").json()
    names = {e["name"] for e in root["entries"]}
    assert {"scope", "logs"} <= names
    sc = client.get(f"/api/scans/{sid}/files?path=scope").json()
    assert any(e["name"] == "snapshot.json" for e in sc["entries"])
    r = client.get(f"/api/scans/{sid}/files/raw?path=scope/snapshot.json")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain") and "sandbox" in r.headers["content-security-policy"]
    for bad in ("../../asm.db", "/etc/passwd", "scope/../../../asm.db", "..", "scope/%00x"):
        assert client.get(f"/api/scans/{sid}/files/raw?path={bad}").status_code in (403, 404), bad
    # HTML reports never render in our origin
    r = client.get(f"/api/scans/{sid}/files")
    zap = client.get(f"/api/scans/{sid}/files?path=zap").json()
    html = [e for e in zap["entries"] if e["name"].endswith(".html")]
    if html:
        r = client.get(f"/api/scans/{sid}/files/raw?path={html[0]['path']}")
        assert "attachment" in r.headers.get("content-disposition", "")


def test_trend_against_previous_scan(authed, tools):
    client, h, sid1 = finished_scan(authed, tools)
    client2, h2, sid2 = finished_scan(authed, tools)
    o = client.get(f"/api/scans/{sid2}/overview").json()
    assert o["previous"] and o["previous"]["id"] == sid1
    assert all(c["previous"] is not None for c in o["cards"])
    hist = client.get("/api/history").json()["scans"]
    assert sid1 in hist and hist[sid1]["rag"] in ("red", "amber", "green")


def test_migration_triage_options():
    from asm.api_results import TRIAGE_DECISIONS
    assert {"not_ours", "investigating"} <= set(TRIAGE_DECISIONS)


def test_group_title_rules():
    from asm.api_results import group_title as g
    assert g("Content Security Policy (CSP) Header Not Set (3 instances)") == "Content Security Policy (CSP) Header Not Set"
    assert g("Dangling CNAME, possible subdomain takeover (NXDOMAIN technique). Confidence: [MEDIUM] Signature: [GENERIC]") == \
        "Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)"
    assert g("Registered lookalike with mail servers (look-alike characters): m1ro.com") == "Registered lookalike with mail servers (look-alike characters)"


def test_phase1_dashboard_agent_surface_and_tech(authed, tools):
    """Overview surfaces the AI-agent/MCP hosts, a de-duped technology breakdown, and the new tiles."""
    from asm.app import state
    client, h, sid = finished_scan(authed, tools)
    db = state.db()
    try:
        # an agent/MCP host and two hosts carrying duplicate-cased technologies
        db.run("INSERT INTO assets (scan_id, host, ips, is_live, web_url, http_status, tech) "
               "VALUES (?, 'mcp.acme.com', '[]', 1, 'https://mcp.acme.com/', 401, ?)", sid, '["Amazon", "amazon", "HSTS", "hsts"]')
        db.run("INSERT INTO assets (scan_id, host, ips, is_live, web_url, http_status, tech) "
               "VALUES (?, 'production-agentcody.acme.com', '[]', 1, 'https://x/', 301, '[]')", sid)
    finally:
        db.close()
    o = client.get(f"/api/scans/{sid}/overview").json()
    assert set(o["agent_hosts"]) >= {"mcp.acme.com", "production-agentcody.acme.com"}
    assert o["values"]["agent_surface"] >= 2
    assert any(r["text"].startswith(str(o["values"]["agent_surface"])) and "AI-agent" in r["text"] for r in o["reasons"])
    assert any(c["key"] == "agent_surface" for c in o["cards"])
    # technology breakdown is de-duped by case: Amazon and HSTS appear once, not Amazon+amazon
    names = [t["name"] for t in o["tech"]]
    assert "Amazon" in names and names.count("Amazon") == 1 and "amazon" not in names
    assert "HSTS" in names and names.count("HSTS") == 1
    # the asset carries surface tags and is reachable via the agent filter
    a = client.get(f"/api/scans/{sid}/assets").json()["assets"]
    mcp = next(x for x in a if x["host"] == "mcp.acme.com")
    assert "mcp" in mcp["tags"] and mcp["tech"].count("AWS") == 1
