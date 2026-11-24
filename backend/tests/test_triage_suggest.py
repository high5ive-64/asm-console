"""Auto-triage suggestions: each undecided host gets a best-guess category + confidence + reasons from
the scan's own evidence. Nothing is applied automatically; the analyst confirms or overrides."""
import json
from test_pipeline import ready_scan, tools  # noqa: F401
from asm.api_results import suggest_triage


class Row(dict):
    """stand-in for a sqlite Row that supports ['col'] access"""


def asset(**kw):
    base = {"ips": "[]", "is_live": 0, "cdn": 0, "third_party": 0, "edge": "{}", "tls": "{}", "http_status": None}
    base.update(kw)
    return Row(base)


def test_suggest_cdn_host_is_vendor_high():
    a = asset(ips='["104.16.0.1"]', is_live=1, cdn=1, edge='{"cdn": "Cloudflare"}', http_status=200)
    s = suggest_triage(a, False)
    assert s["decision"] == "third_party_ours" and s["confidence"] == "high"
    assert any("Cloudflare" in r for r in s["reasons"])


def test_suggest_wildcard_cert_live_is_ours_high():
    a = asset(ips='["93.184.216.10"]', is_live=1, tls='{"subject_cn": "*.acme.com"}', http_status=200)
    s = suggest_triage(a, False)
    assert s["decision"] == "ours_unrecorded" and s["confidence"] == "high"


def test_suggest_live_own_cert_is_ours_medium():
    a = asset(ips='["93.184.216.11"]', is_live=1, tls='{"subject_cn": "app.acme.com"}', http_status=200)
    s = suggest_triage(a, False)
    assert s["decision"] == "ours_unrecorded" and s["confidence"] == "medium"


def test_suggest_non_resolving_is_decommission_low():
    s = suggest_triage(asset(ips="[]"), False)
    assert s["decision"] == "should_not_exist" and s["confidence"] == "low"


def test_suggest_takeover_is_investigating():
    a = asset(ips='["45.33.32.9"]', is_live=1)
    s = suggest_triage(a, True)
    assert s["decision"] == "investigating" and "dangling" in s["reasons"][0].lower()


def test_suggest_no_asset_is_investigating_low():
    s = suggest_triage(None, False)
    assert s["decision"] == "investigating" and s["confidence"] == "low"


def test_triage_endpoint_includes_suggestion(authed, tools):
    from asm.app import state
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        scan = db.one("SELECT root_domain FROM scans WHERE id = ?", sid)
        root = scan["root_domain"]
        # a host in scope with a CDN asset
        db.run("INSERT INTO scope_items (scan_id, kind, value, grp, sources, reasons, decision, third_party) "
               "VALUES (?, 'subdomain', ?, 'web', '[]', '[]', 'included', 0)", sid, f"zz-tri-cdn.{root}")
        db.run("INSERT INTO assets (scan_id,host,ips,in_cmdb,is_live,web_url,tech,tls,ports,cdn,third_party,http_status,edge,found_by,ports_confirmed) "
               "VALUES (?,?,?,0,1,?, '[]','{}','[443]',1,0,200,?, '[]',NULL)",
               sid, f"zz-tri-cdn.{root}", json.dumps(["104.16.0.1"]), f"https://zz-tri-cdn.{root}/", json.dumps({"cdn": "Cloudflare"}))
    finally:
        db.close()
    r = client.get(f"/api/scans/{sid}/triage", headers=h)
    assert r.status_code == 200, r.text
    hosts = {x["host"]: x for x in r.json()["hosts"]}
    sug = hosts[f"zz-tri-cdn.{root}"]["suggestion"]
    assert sug["decision"] == "third_party_ours" and sug["confidence"] == "high"
    assert sug["reasons"]
