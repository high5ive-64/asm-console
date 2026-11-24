"""Finding-detail endpoint and attack-path reference enrichment.

The point of both: the browser never builds a reference URL itself. These tests pin that the backend
returns ready, canonical links (NIST via csf.tools, CWE/OWASP/NVD, MITRE ATT&CK) plus a raw-output
pointer, so the detail pane only has to render them.
"""
import json

from test_pipeline import ready_scan, tools  # noqa: F401
from asm import report_refs as refs


def test_reference_builders_are_canonical():
    # NIST comes from the backend's chosen mirror (csf.tools), not a guessed CSRC anchor
    _id, title, url = refs.nist_control("ac-3")
    assert _id == "AC-3" and url == "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-3/"
    assert refs.cwe_url("CWE-918") == "https://cwe.mitre.org/data/definitions/918.html"
    assert refs.mitre_url("T1584.001") == "https://attack.mitre.org/techniques/T1584/001/"
    assert refs.owasp_url("A10")[1].startswith("https://owasp.org/Top10/A10")


def test_finding_references_dedupe_and_kinds():
    guide = refs.guidance_for("Dangling CNAME, possible takeover")
    out = refs.finding_references(guide, cves=["cve-2023-4448"], kev=True)
    kinds = {r["kind"] for r in out}
    assert {"cve", "kev", "nist", "cwe"} <= kinds
    assert out[0]["kind"] == "cve" and out[0]["url"].endswith("CVE-2023-4448")
    assert any(r["url"] == "https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-20/" for r in out)
    # every URL is unique (dedupe holds)
    urls = [r["url"] for r in out]
    assert len(urls) == len(set(urls))


def test_raw_dir_hint_covers_extended_tools():
    # the folder fallback (used when a finding has no recorded evidence_file) is sensible per tool
    assert refs.raw_dir_hint("intel-cve") == "intel"
    assert refs.raw_dir_hint("testssl") == "tls"
    assert refs.raw_dir_hint("tlsx") == "tls"
    assert refs.raw_dir_hint("urlscan") == "urlscan"
    assert refs.raw_dir_hint("opensquat") == "squat"
    assert refs.raw_dir_hint("dnstwist") == "lookalikes"
    assert refs.raw_dir_hint("naabu") == "services"
    assert refs.raw_dir_hint("cloudlist") == "cloud"
    assert refs.raw_dir_hint("ptr") == "dns"
    assert refs.raw_dir_hint("bbot:baddns") == "bbot"      # prefix rule
    assert refs.raw_dir_hint("baddns-live") == "bbot"
    assert refs.raw_dir_hint("something-unknown") == ""    # safe default


def test_mitre_links_and_path_framing():
    links = refs.mitre_links(["T1190", "T1584.001", "T1190"])
    assert links == [
        {"id": "T1190", "url": "https://attack.mitre.org/techniques/T1190/"},
        {"id": "T1584.001", "url": "https://attack.mitre.org/techniques/T1584/001/"},
    ]
    fr = refs.path_framing("agent-abuse", "observed")
    assert "agent" in fr["precondition"].lower() and fr["likelihood_reason"]
    assert any(r["url"] for r in fr["references"])


def _seed_one(db, sid):
    db.run("INSERT INTO assets (scan_id,host,ips,in_cmdb,is_live,web_url,tech,tls,ports,cdn,third_party,http_status,edge,found_by,ports_confirmed) "
           "VALUES (?,?,?,0,1,?,?, '{}', '[443]',0,0,200,'{}','[]',NULL)",
           sid, "svg-convert.acme.com", json.dumps(["45.33.32.8"]), "https://svg-convert.acme.com/", json.dumps(["Node.js"]))
    db.run("INSERT INTO findings (scan_id,area,severity,title,host,source_tool,evidence_ref,status) "
           "VALUES (?,?,?,?,?,?,?, 'observation')",
           sid, "web", "high", "Known-exploited vulnerability reported (CISA KEV, unverified version match): CVE-2023-4448",
           "svg-convert.acme.com", "intel-cve", "45.33.32.8 · Adobe ColdFusion: Access Control Bypass · CVSS 7.8/CWE-284")
    return db.one("SELECT id FROM findings WHERE scan_id = ?", sid)["id"]


def test_finding_detail_endpoint(authed, tools):
    from asm.app import state
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        fid = _seed_one(db, sid)
    finally:
        db.close()
    r = client.get(f"/api/scans/{sid}/findings/{fid}", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["group"] and body["severity"] == "high"
    assert body["cves"] == ["CVE-2023-4448"] and body["kev"] is True
    # guidance is populated from the KEV rule
    assert body["guidance"]["fix"]
    refs_by_kind = {x["kind"] for x in body["references"]}
    assert {"cve", "kev", "nist"} <= refs_by_kind
    assert any(x["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-4448" for x in body["references"])
    assert all(x["url"].startswith("http") for x in body["references"])
    # raw pointer present (files_path may be "" when the run folder has no matching subdir in tests)
    assert body["raw"]["evidence"].startswith("45.33.32.8 ·")
    assert "files_path" in body["raw"]


def test_finding_detail_404(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    assert client.get(f"/api/scans/{sid}/findings/999999", headers=h).status_code == 404


def test_finding_detail_raw_file_resolves_to_artifact(authed, tools):
    """When the pipeline recorded a per-finding evidence_file that exists in the run folder, the detail
    route points raw.file at that exact artifact and raw.files_path at its folder."""
    from asm.app import state
    from pathlib import Path
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        scan = db.one("SELECT run_dir FROM scans WHERE id = ?", sid)
        run_dir = state.cfg.runs_dir / Path(scan["run_dir"]).name
        (run_dir / "email").mkdir(parents=True, exist_ok=True)
        (run_dir / "email" / "posture.json").write_text('{"miro.com": {"dmarc": null}}')
        db.run("INSERT INTO findings (scan_id,area,severity,title,host,source_tool,evidence_ref,evidence_file,status) "
               "VALUES (?,?,?,?,?,?,?,?, 'observation')",
               sid, "email", "high", "No DMARC record: the domain can be spoofed", "acme.com",
               "dns-email", "acme.com", "email/posture.json")
        fid = db.one("SELECT id FROM findings WHERE scan_id = ? ORDER BY id DESC LIMIT 1", sid)["id"]
    finally:
        db.close()
    body = client.get(f"/api/scans/{sid}/findings/{fid}", headers=h).json()
    assert body["raw"]["file"] == "email/posture.json"
    assert body["raw"]["files_path"] == "email"


def test_finding_detail_raw_file_absent_when_artifact_missing(authed, tools):
    """A recorded evidence_file that doesn't exist on disk must not produce a dead link."""
    from asm.app import state
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        db.run("INSERT INTO findings (scan_id,area,severity,title,host,source_tool,evidence_ref,evidence_file,status) "
               "VALUES (?,?,?,?,?,?,?,?, 'observation')",
               sid, "email", "high", "No DMARC record: the domain can be spoofed", "acme.com",
               "dns-email", "acme.com", "email/nope.json")
        fid = db.one("SELECT id FROM findings WHERE scan_id = ? ORDER BY id DESC LIMIT 1", sid)["id"]
    finally:
        db.close()
    body = client.get(f"/api/scans/{sid}/findings/{fid}", headers=h).json()
    assert body["raw"]["file"] is None


def test_attack_paths_carry_reference_links(authed, tools):
    from asm.app import state
    from test_attackpaths import _seed
    client, h, sid = ready_scan(authed, tools)
    db = state.db()
    try:
        _seed(db, sid)
    finally:
        db.close()
    r = client.get(f"/api/scans/{sid}/attack-paths", headers=h)
    assert r.status_code == 200, r.text
    paths = r.json()["paths"]
    assert paths, "expected at least one simulated path"
    for p in paths:
        assert "framing" in p and "likelihood_reason" in p["framing"]
        assert "mitre_links" in p
        for link in p["mitre_links"]:
            assert link["url"].startswith("https://attack.mitre.org/techniques/")
        for step in p["steps"]:
            assert "mitre_links" in step
