"""Milestone 6: the comprehensive master report — knowledge base, data assembly, Typst generation,
evidence/CVE register, redaction, and routes. The real `typst compile` runs only inside the image, so
the build route is asserted to degrade to a clean 503 when the binary is absent (CI) or return a PDF
when present.
"""
import json
import shutil

from asm.app import state
from asm import reports, report_refs as kb
from asm.reports import Redactor, _s, _sml, _t

from test_pipeline import AUTH, ready_scan, wait_done, tools  # noqa: F401
from test_results import finished_scan  # noqa: F401


# --------------------------------------------------------------------------- knowledge base

def test_reference_url_builders():
    assert kb.nvd_url("cve-2023-4448") == "https://nvd.nist.gov/vuln/detail/CVE-2023-4448"
    assert kb.mitre_url("T1190") == "https://attack.mitre.org/techniques/T1190/"
    assert kb.mitre_url("T1584.001") == "https://attack.mitre.org/techniques/T1584/001/"
    assert kb.cwe_url(79).endswith("/79.html")
    assert kb.owasp_url("A10")[1].startswith("https://owasp.org/Top10/A10")
    cid, title, url = kb.nist_control("SC-7")
    assert cid == "SC-7" and "Boundary" in title and "sc-7" in url


def test_guidance_mapping():
    g = kb.guidance_for("Dangling CNAME, possible subdomain takeover", "dns", "baddns-live")
    assert "CM-8" in g["nist"] and g["fix"] and g["why"]
    g2 = kb.guidance_for("No DMARC record: the domain can be spoofed", "email", "checkdmarc")
    assert g2["owasp"] == "A07"
    g3 = kb.guidance_for("Exposed agent endpoint", "exposure", "")
    assert "AC-6" in g3["nist"] and "IA-9" in g3["nist"]
    # fallback by area
    gf = kb.guidance_for("something unmapped", "tls", "tlsx")
    assert gf["nist"] == ["SC-8", "SC-13"]


# --------------------------------------------------------------------------- redaction / escaping

def test_redactor_deterministic():
    on = Redactor(True)
    assert on.host("www.acme.com") == "asset-01" and on.host("www.acme.com") == "asset-01"
    assert on.ip("1.2.3.4") == "ip-01"
    assert "acme.com" not in on.text("see www.acme.com on 1.2.3.4")
    assert Redactor(False).host("www.acme.com") == "www.acme.com"


def test_escaping():
    assert _s('a"b') == '"a\\"b"'
    assert _sml("a\nb") == '"a\\nb"'      # newlines preserved for raw blocks
    assert _t("x").startswith("#")


# --------------------------------------------------------------------------- data

def test_collect_shape(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    db = state.db()
    try:
        d = reports.collect(db, sid)
    finally:
        db.close()
    assert d["overview"]["rag"] == "red"
    assert set(d) >= {"overview", "changes", "paths", "graph", "findings", "cves", "assets_by_host", "dns", "email", "brand", "agent_hosts"}


def test_master_source_has_all_sections(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    db = state.db()
    try:
        d = reports.collect(db, sid)
    finally:
        db.close()
    src = reports.master_typ(d, Redactor(False))
    assert src.startswith("#set document")
    for marker in ["Executive summary", "Scope & methodology", "Detailed findings", "Attack paths",
                   "Appendix A", "Appendix F", "NIST SP 800-53", "Remediation", "Defensive model"]:
        assert marker in src, marker
    # at least one real reference link and one MITRE/NIST link
    assert "nist-sp-800-53" in src
    assert "attack.mitre.org" in src or "cwe.mitre.org" in src


def test_redaction_masks_master(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    db = state.db()
    try:
        d = reports.collect(db, sid)
    finally:
        db.close()
    plain = reports.master_typ(d, Redactor(False))
    red = reports.master_typ(d, Redactor(True))
    assert "www.acme.com" in plain and "www.acme.com" not in red and "asset-01" in red


def test_cve_register_from_injected_kev(authed, tools, tmp_path):
    client, h, sid = finished_scan(authed, tools)
    db = state.db()
    try:
        # inject a KEV + EPSS CVE finding and a matching KEV cache
        with db.tx():
            db.run("INSERT INTO findings (scan_id, area, severity, title, host, source_tool, evidence_ref, status) "
                   "VALUES (?, 'vulns', 'high', ?, 'api.acme.com', 'intel-cve', ?, 'observation')",
                   sid, "Known-exploited vulnerability reported (CISA KEV, unverified version match): CVE-2023-4448",
                   "93.184.216.34 · Example Corp WidgetServer: Memory corruption")
        cache = state.cfg.data_dir / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "kev.json").write_text(json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2023-4448", "vendorProject": "Example", "product": "WidgetServer",
             "vulnerabilityName": "Memory corruption", "dateAdded": "2023-09-01", "dueDate": "2023-09-22",
             "knownRansomwareCampaignUse": "Known"}]}))
        d = reports.collect(db, sid, data_dir=state.cfg.data_dir)
    finally:
        db.close()
    assert "CVE-2023-4448" in d["cves"]
    rec = d["cves"]["CVE-2023-4448"]
    assert rec["kev"] and rec["kev_meta"]["dueDate"] == "2023-09-22"
    src = reports.master_typ(d, Redactor(False))
    assert "CVE-2023-4448" in src and "nvd.nist.gov/vuln/detail/CVE-2023-4448" in src
    assert "KEV catalogue detail" in src and "ransomware" in src.lower()


# --------------------------------------------------------------------------- routes

def test_report_preview_route(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    for kind in reports.REPORT_KINDS:
        r = client.get(f"/api/scans/{sid}/report/preview?kind={kind}")
        assert r.status_code == 200, (kind, r.text)
        body = r.json()
        assert body["kind"] == kind and body["sections"] and body["root_domain"] == "acme.com"
        assert {k["kind"] for k in body["kinds"]} == set(reports.REPORT_KINDS)
    assert client.get(f"/api/scans/{sid}/report/preview?kind=bogus").status_code == 422
    assert client.get(f"/api/scans/{sid}/report/preview?kind=share-zip").json()["redacted_by_default"] is True


def test_report_build_route(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    r = client.get(f"/api/scans/{sid}/report?kind=master")
    if shutil.which("typst"):
        assert r.status_code == 200 and r.content[:5] == b"%PDF-"
        assert r.headers["content-type"].startswith("application/pdf")
    else:
        assert r.status_code == 503 and "typst" in r.text.lower()
    assert client.get(f"/api/scans/{sid}/report?kind=bogus").status_code == 422
    assert client.get("/api/scans/nope/report?kind=master").status_code == 404


def test_build_rejects_unknown_kind(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    db = state.db()
    try:
        raised = False
        try:
            reports.build(db, sid, "nonsense")
        except reports.ReportError:
            raised = True
        assert raised
    finally:
        db.close()


# --------------------------------------------------------------------------- global search (unchanged endpoint)

def test_search_hosts_ips_findings(authed, tools):
    client, h, sid = finished_scan(authed, tools)
    r = client.get(f"/api/scans/{sid}/search?q=acme").json()
    assert any(x["host"].endswith("acme.com") for x in r["hosts"])
    assert all("group" in f and "severity" in f for f in r["findings"])
    assert client.get(f"/api/scans/{sid}/search?q=a").json() == {"q": "a", "hosts": [], "ips": [], "findings": []}
    assert client.get(f"/api/scans/{sid}/search?q=certificate").json()["findings"]
    assert client.get("/api/scans/nope/search?q=acme").status_code == 404
