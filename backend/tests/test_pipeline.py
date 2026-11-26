from pathlib import Path
"""Milestone 4: authorisation gate, options, the full pipeline with fake tool binaries, cancel/resume/retry."""
import json
import os
import stat
import textwrap

import pytest

from asgi_client import pump
from test_discovery import DNS, FakeProviders, by_value

FAKE_TOOLS = {
    "bbot": r'''
        import json, os, sys
        a = sys.argv[1:]
        home = os.environ["HOME"]
        open(os.path.join(home, "bbot_calls.log"), "a").write(" ".join(a) + "\n")
        if os.path.exists(os.path.join(home, "BBOT_ERROR")):
            print('[ERRR] Could not find config option "x.y"'); sys.exit(1)
        mi = a.index("-m") + 1
        mods = []
        for tok in a[mi:]:
            if tok.startswith("-"): break
            mods.append(tok)
        if os.path.exists(os.path.join(home, "LOAD_FORBIDDEN")): mods.append("nuclei")
        # BBOT refuses to start when a module name is unknown, reporting the first bad one at a time.
        for bad in ("zzbad", "zzbad2"):
            if bad in mods:
                print(f'[ERRR] Could not find scan module "{bad}". Did you mean "portscan"?'); sys.exit(1)
        print(f"[INFO] Loaded {len(mods)}/{len(mods)} scan modules ({','.join(mods)})")
        if "--dry-run" in a: sys.exit(0)
        if "zzidle" in mods:                      # simulate a wedged module: write partial output, then
            import time as _t                     # emit only idle heartbeats and never finish
            o = a[a.index("-o") + 1]; nm = a[a.index("-n") + 1]; dd = os.path.join(o, nm); os.makedirs(dd, exist_ok=True)
            open(os.path.join(dd, "output.json"), "w").write(json.dumps({"type": "DNS_NAME", "data": "idle.acme.com", "host": "idle.acme.com"}) + "\n")
            for _ in range(100):
                print("[INFO] active: No events in queue (0 processed in the past 15 seconds)", flush=True); _t.sleep(0.2)
            sys.exit(0)
        out = a[a.index("-o") + 1]; name = a[a.index("-n") + 1]
        hosts = [h.strip() for h in open(a[a.index("-t") + 1]) if h.strip()]
        d = os.path.join(out, name); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "output.json"), "w") as f:
            for h in hosts:
                f.write(json.dumps({"type": "DNS_NAME", "data": h, "host": h, "resolved_hosts": ["93.184.216.34"] if "cdn" not in h else ["104.16.0.1"], "tags": ["cdn-cloudflare"] if "cdn" in h else []}) + "\n")
                if name == "light":
                    # BBOT 3 format: structured values live in "data_json"
                    f.write(json.dumps({"type": "URL", "data_json": {"url": f"https://{h}/", "hash": {}}, "host": h}) + "\n")
                    f.write(json.dumps({"type": "URL", "data_json": {"url": f"https://{h}/login"}, "host": h}) + "\n")
                    f.write(json.dumps({"type": "TECHNOLOGY", "data_json": {"technology": "nginx", "host": h}, "host": h}) + "\n")
            f.write(json.dumps({"type": "URL", "data": "https://evil.example/", "host": "evil.example"}) + "\n")
            if name == "light" and "asn" in mods:
                f.write(json.dumps({"type": "ASN", "host": "93.184.216.34", "data_json": {"asn": "16509", "subnet": "93.184.216.0/24", "name": "AMAZON-02", "description": "Amazon.com, Inc."}}) + "\n")
                f.write(json.dumps({"type": "ASN", "host": "198.51.100.1", "data_json": {"asn": "64500", "subnet": "198.51.100.0/24", "name": "ACME-NET", "description": "Acme Corp"}}) + "\n")
            if name == "dnsonly":
                f.write(json.dumps({"type": "FINDING", "host": hosts[0], "module": "baddns", "data_json": {"severity": "MEDIUM", "description": "Dangling CNAME, possible subdomain takeover"}}) + "\n")
            if name == "baddns":
                f.write(json.dumps({"type": "FINDING", "host": hosts[0], "module": "baddns", "data_json": {"severity": "HIGH", "description": "Dangling CNAME to sites.framer.app, possible takeover"}}) + "\n")
            if name == "active":
                f.write(json.dumps({"type": "VULNERABILITY", "host": hosts[0], "module": "nuclei", "data_json": {"severity": "HIGH", "description": "Exposed .env file", "url": f"https://{hosts[0]}/.env"}}) + "\n")
        if name == "light" and os.path.exists(os.path.join(home, "BBOT_HANG")):
            import time
            secs = int(open(os.path.join(home, "BBOT_HANG")).read() or 30)
            for i in range(secs):
                print(f"[INFO] light: Modules running (incoming:processing:outgoing) http({secs - i}:2:0), gowitness({i}:1:0)", flush=True)
                print(f"[INFO] light: Events produced so far: DNS_NAME: {10 + i}, URL: {4 * i}, TECHNOLOGY: {i}", flush=True)
                time.sleep(1)
        os.makedirs(os.path.join(d, "gowitness", "screenshots"), exist_ok=True)
        open(os.path.join(d, "gowitness", "screenshots", "http---a-443-.jpeg"), "wb").write(b"jpg")
        print("[SUCC] done")
    ''',
    "zap.sh": r'''
        import json, sys, yaml, os, time
        a = sys.argv[1:]
        plan = yaml.safe_load(open(a[a.index("-autorun") + 1]))
        assert {j["type"] for j in plan["jobs"]} <= {"spider", "spiderAjax", "activeScan", "passiveScan-wait", "report"}
        active = any(j["type"] == "activeScan" for j in plan["jobs"])
        sl = os.path.join(os.environ["HOME"], "ZAP_SLEEP")
        if os.path.exists(sl): time.sleep(float(open(sl).read()))
        rep = next(j["parameters"] for j in plan["jobs"] if j["type"] == "report" and j["parameters"]["reportFile"].endswith(".json"))
        base_alerts = [{"name": "Content Security Policy (CSP) Header Not Set", "riskdesc": "Medium (High)", "count": "3", "pluginid": "10038"}]
        if active: base_alerts.append({"name": "SQL Injection", "riskdesc": "High (Medium)", "count": "1", "pluginid": "40018"})
        sites = [{"@name": u, "alerts": list(base_alerts)} for ctx in plan["env"]["contexts"] for u in ctx["urls"]]
        sites.append({"@name": "https://fonts.googleapis.com", "alerts": [{"name": "x", "riskdesc": "Low (Low)", "count": "1"}]})
        json.dump({"site": sites}, open(os.path.join(rep["reportDir"], rep["reportFile"]), "w"))
        print("Job report finished")
    ''',
    "tlsx": r'''
        import json, sys
        a = sys.argv[1:]
        out = a[a.index("-o") + 1]
        hosts = [h.strip() for h in open(a[a.index("-l") + 1]) if h.strip()]
        with open(out, "w") as f:
            for i, h in enumerate(hosts):
                f.write(json.dumps({"host": h, "tls_version": "tls11" if i == 0 else "tls13", "not_after": "2020-01-01T00:00:00Z" if i == 1 else "2099-01-01T00:00:00Z", "expired": i == 1, "self_signed": False, "mismatched": False}) + "\n")
    ''',
    "smap": r'''
        import sys
        a = sys.argv[1:]
        ips = [l.strip() for l in open(a[a.index("-iL") + 1]) if l.strip()]
        assert "-oP" not in a
        with open(a[a.index("-oN") + 1], "w") as f:      # nmap normal format, as real smap writes it
            f.write("# Nmap 7.99 scan initiated\n")
            for i, ip in enumerate(ips):
                f.write(f"Nmap scan report for host{i}.acme.com ({ip})\nHost is up.\n\nPORT     STATE SERVICE\n"
                        f"443/tcp  open  https?\n3389/tcp open  ms-wbt-server?\n\n")
    ''',
    "gau": r'''
        import sys
        a = sys.argv[1:]
        open(a[a.index("--o") + 1], "w").write("https://www.acme.com/api/v1/x\nhttps://www.acme.com/about\nhttps://notacme.com/admin\nhttps://www.acme.com/.env\n")
    ''',
    "uro": r'''
        import sys
        a = sys.argv[1:]
        open(a[a.index("-o") + 1], "w").write("".join(sorted(set(open(a[a.index("-i") + 1]).readlines()))))
    ''',
    "dnstwist": r'''
        import json, sys
        d = sys.argv[-1]
        print(json.dumps([{"fuzzer": "*original", "domain": d}, {"fuzzer": "omission", "domain": "acm.com", "dns_mx": ["mx.acm.com"]}, {"fuzzer": "tld-swap", "domain": "acme.net"}]))
    ''',
}


class PipelineProviders(FakeProviders):
    async def records(self, name, rtype):
        table = {("acme.com", "MX"): ["mx1.acme.com"], ("acme.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
                 ("_dmarc.acme.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:x@acme.com"]}
        return table.get((name, rtype), [])

    async def http_json(self, url, headers=None, data=None, timeout=60):
        if "breacheddomain" in url:
            assert headers["hibp-api-key"] == "HIBPKEY-1234567"
            return {"alice": ["Adobe"], "bob": ["LinkedIn", "Adobe"]}
        return await super().http_json(url, headers, data, timeout)


@pytest.fixture
def tools(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"; bindir.mkdir()
    import sys
    for name, src in FAKE_TOOLS.items():
        p = bindir / name
        p.write_text(f"#!{sys.executable}\n" + textwrap.dedent(src))
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    import asm.discovery
    monkeypatch.setattr(asm.discovery, "bbot_key_modules", lambda: {})
    return tmp_path


AUTH = {"approved_by": "Jane CISO", "role": "CISO", "approved_on": "2026-11-18", "scope_reference": "TKT-1",
        "soc_notified": True, "soc_contact": "soc@acme.com", "source_ip": "198.51.100.10",
        "test_window": "2026-11-18 09:00-17:00", "attested": True}


def ready_scan(authed, tools, extra_dns=None):
    client, h, tmp = authed
    from asm.app import state
    dns = {**DNS, **(extra_dns or {})}
    state.providers = PipelineProviders(dns=dns)
    state.use_bbot = False                      # discovery from fakes only
    sid = client.post("/api/scans", json={"root_domain": "acme.com"}, headers=h).json()["id"]
    client.post(f"/api/scans/{sid}/discover", json={"sources": []}, headers=h)
    assert pump(client, lambda: client.get(f"/api/scans/{sid}").json()["status"] == "awaiting_scope")
    client.request("PATCH", f"/api/scans/{sid}/scope", json={"exclude_add": ["pay.acme.com"], "add": ["cdn.acme.com"]}, headers=h)
    assert client.post(f"/api/scans/{sid}/scope/confirm", headers=h).status_code == 200
    state.use_bbot = True
    return client, h, sid


def wait_done(client, sid, timeout=40):
    assert pump(client, lambda: client.get(f"/api/scans/{sid}").json()["status"] in
                ("completed", "completed_with_errors", "failed", "cancelled"), timeout=timeout)
    return client.get(f"/api/scans/{sid}/stages").json()


def test_start_requires_scope_and_authorisation(authed, tools):
    client, h, tmp = authed
    sid = client.post("/api/scans", json={"root_domain": "acme.com"}, headers=h).json()["id"]
    assert client.post(f"/api/scans/{sid}/start", headers=h).status_code == 409
    assert client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h).status_code == 409   # scope not confirmed
    client, h, sid = ready_scan(authed, tools)
    r = client.post(f"/api/scans/{sid}/start", headers=h)
    assert r.status_code == 409 and "authorisation" in r.json()["error"]
    bad = {**AUTH, "attested": False}
    r = client.put(f"/api/scans/{sid}/authorisation", json=bad, headers=h)
    assert r.status_code == 422 and any(i["field"] == "attested" for i in r.json()["issues"])
    bad = {**AUTH, "soc_notified": False}
    assert client.put(f"/api/scans/{sid}/authorisation", json=bad, headers=h).status_code == 422
    assert client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h).status_code == 200


def test_options_validation(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    assert client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["portscan"]}, headers=h).status_code == 422
    assert client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "extra_ips": ["10.0.0.1"]}, headers=h).status_code == 422
    assert client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "zap_spider_minutes": 99}, headers=h).status_code == 422
    r = client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["tls", "email"], "extra_ips": ["9.9.9.9"]}, headers=h)
    assert r.status_code == 200
    o = client.get(f"/api/scans/{sid}/options").json()
    assert o["options"]["stages"] == ["tls", "email"] and len(o["stages"]) == 24
    est = client.get(f"/api/scans/{sid}/estimate").json()
    assert set(est["minutes"]) == {"tls", "email", "consolidate"} and est["hosts"] >= 3


def test_full_pipeline(authed, tools):
    client, h, sid = ready_scan(authed, tools, extra_dns={"cdn.acme.com": {"cname": [], "ips": ["104.16.0.1"]}})
    client.put("/api/secrets/hibp", json={"value": "HIBPKEY-1234567"}, headers=h)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "zap", "tls", "ports", "email", "gau", "lookalikes", "hibp", "cloud"],
                                               "extra_ips": ["1.0.0.1"], "zap_max_hosts": 2}, headers=h)
    assert client.post(f"/api/scans/{sid}/start", headers=h).status_code == 202
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    assert st["status"] == "completed", {k: (v["status"], v["summary"]) for k, v in by.items()}
    chosen = {"bbot_light", "zap", "tls", "ports", "email", "gau", "lookalikes", "hibp", "cloud", "consolidate"}
    assert all(by[k]["status"] == "done" for k in chosen), {k: v["status"] for k, v in by.items()}
    assert all(v["status"] == "skipped" for k, v in by.items() if k not in chosen)

    # BBOT: two passes; third-party/no-DNS hosts only ever get baddns
    calls = (tools / "home" / "bbot_calls.log").read_text().splitlines()
    light = [c for c in calls if " -n light " in c and "--dry-run" not in c][0]
    dnsonly = [c for c in calls if " -n dnsonly " in c and "--dry-run" not in c][0]
    assert "-m baddns -ef" in dnsonly and "http" not in dnsonly.split("-ef")[0]
    assert "--strict-scope" in light and "-b " in light and all("--dry-run" in c or "--no-deps" in c for c in calls)
    assert by["bbot_light"]["summary"]["live_hosts"] >= 3 and by["bbot_light"]["summary"]["screenshots"] == 1

    # ZAP: capped at 2 hosts, root first; third-party site ignored
    assert by["zap"]["summary"] == {"sites": 2, "third_party_sites": 1, "alerts": 2}
    plan = (client.get(f"/api/scans/{sid}").json())  # noqa
    # TLS, ports, email, gau, lookalikes, hibp, cloud
    assert by["tls"]["summary"]["expired"] == 1 and by["tls"]["summary"]["legacy_tls"] == 1
    assert by["ports"]["summary"]["risky_services"] >= 1          # 3389 on a non-CDN IP
    assert by["email"]["summary"] == {"domains": 1, "dmarc_reject": 0}
    assert by["gau"]["summary"] == {"historical_urls": 3, "interesting": 2}   # notacme.com dropped
    assert by["lookalikes"]["summary"] == {"registered": 2, "with_mx": 1}
    assert by["hibp"]["summary"] == {"known_breaches": 0, "exposed_accounts": 2, "domains": 1, "sources": ["XposedOrNot", "HIBP"]}
    assert by["cloud"]["summary"]["ips_checked"] == 1

    m = client.get(f"/api/scans/{sid}/metrics").json()["metrics"]
    assert m["surface"]["hosts_in_scope"] >= 5 and m["findings"]["email"]["medium"] == 1
    assert m["findings"]["exposure"]["high"] >= 2      # RDP + takeover
    # nothing from out-of-scope hosts, and the HIBP key never reaches the log
    ev = client.get(f"/api/scans/{sid}/events?after=0").json()["events"]
    assert all("HIBPKEY-1234567" not in e["message"] for e in ev)
    from asm.app import state
    db = state.db()
    try:
        assert not db.one("SELECT 1 FROM assets WHERE scan_id = ? AND host IN ('evil.example','fonts.googleapis.com','pay.acme.com')", sid)
        cdn = db.one("SELECT ports FROM assets WHERE scan_id = ? AND host = 'cdn.acme.com'", sid)
        assert "3389" not in cdn["ports"]                     # CDN IPs aren't checked for exposed services
    finally:
        db.close()
    # scope is locked after the run
    r = client.request("PATCH", f"/api/scans/{sid}/scope", json={"exclude": ["www.acme.com"]}, headers=h)
    assert r.status_code == 409


def test_forbidden_module_in_dry_run_fails_stage(authed, tools, monkeypatch):
    (tools / "home" / "LOAD_FORBIDDEN").write_text("1")
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "email"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    assert st["status"] == "completed_with_errors"
    assert by["bbot_light"]["status"] == "failed" and "forbidden modules: nuclei" in by["bbot_light"]["summary"]["error"]
    assert by["email"]["status"] == "done"            # independent stages still run
    calls = (tools / "home" / "bbot_calls.log").read_text().splitlines()
    assert all("--dry-run" in c for c in calls)        # the real pass never started


def test_cancel_then_resume_and_retry(authed, tools, monkeypatch):
    (tools / "home" / "ZAP_SLEEP").write_text("30")
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "email", "zap", "tls"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    assert pump(client, lambda: any(s["key"] == "zap" and s["status"] == "running"
                                    for s in client.get(f"/api/scans/{sid}/stages").json()["stages"]), timeout=20)
    assert client.post(f"/api/scans/{sid}/cancel", headers=h).status_code == 200
    st = wait_done(client, sid)
    by = {s["key"]: s["status"] for s in st["stages"]}
    assert st["status"] == "cancelled" and by["zap"] == "cancelled" and by["bbot_light"] == "done" and by["tls"] == "done" and by["email"] == "done"   # email ran alongside BBOT
    # retry the cancelled stage quickly
    (tools / "home" / "ZAP_SLEEP").write_text("0")
    assert client.post(f"/api/scans/{sid}/stages/zap/retry", headers=h).status_code == 202
    assert pump(client, lambda: next(s for s in client.get(f"/api/scans/{sid}/stages").json()["stages"] if s["key"] == "zap")["status"] == "done", timeout=20)


def test_interrupted_on_restart(tmp_path):
    from asm.db import DB, migrate
    from asm.pipeline import mark_interrupted
    p = tmp_path / "x.db"; migrate(p)
    db = DB(p)
    db.run("INSERT INTO scans (id, root_domain, status, created_at, run_dir) VALUES ('a','acme.com','running','x','/tmp')")
    db.run("INSERT INTO scans (id, root_domain, status, created_at, run_dir) VALUES ('b','acme.com','discovering','x','/tmp')")
    db.run("INSERT INTO stages (scan_id, stage_key, status) VALUES ('a','zap','running')")
    assert mark_interrupted(db) == 1
    assert db.one("SELECT status FROM scans WHERE id='a'")["status"] == "interrupted"
    assert db.one("SELECT status FROM scans WHERE id='b'")["status"] == "draft"
    assert db.one("SELECT status FROM stages WHERE scan_id='a'")["status"] == "cancelled"
    db.close()


def test_zap_plan_builder_is_passive_and_scoped():
    from asm.pipeline import build_zap_plan, validate_zap_plan, Ctx, StageFailed
    from asm.settings_model import Settings
    import re
    c = Ctx(state=None, scan_id="x", run_dir=__import__("pathlib").Path("/tmp/r"), runner=None, providers=None,
            settings=Settings(), options={"zap_spider_minutes": 2, "zap_ajax_minutes": 1}, roots=["acme.com"],
            light_hosts=["www.acme.com"], dns_hosts=[], exclusions=["pay.acme.com"], secrets={})
    plan = build_zap_plan(c, ["https://www.acme.com"])
    validate_zap_plan(plan)
    inc = plan["env"]["contexts"][0]["includePaths"][0]
    assert re.fullmatch(inc, "https://www.acme.com/login") and not re.fullmatch(inc, "https://www.acme.com.evil.io/")
    assert not re.fullmatch(inc, "https://api.acme.com/")      # exact hosts only, not the whole domain
    plan["jobs"].append({"type": "activeScan"})
    with pytest.raises(StageFailed):
        validate_zap_plan(plan)


def test_resume_after_cancel_runs_only_unfinished(authed, tools):
    (tools / "home" / "ZAP_SLEEP").write_text("30")
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "zap", "email"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    assert pump(client, lambda: any(s["key"] == "zap" and s["status"] == "running"
                                    for s in client.get(f"/api/scans/{sid}/stages").json()["stages"]), timeout=20)
    client.post(f"/api/scans/{sid}/cancel", headers=h)
    wait_done(client, sid)
    n_before = len((tools / "home" / "bbot_calls.log").read_text().splitlines())
    (tools / "home" / "ZAP_SLEEP").write_text("0")
    r = client.post(f"/api/scans/{sid}/start", headers=h)
    assert r.status_code == 202 and r.json()["resumed"] is True
    st = wait_done(client, sid)
    by = {s["key"]: s["status"] for s in st["stages"]}
    assert st["status"] == "completed" and by["zap"] == "done" and by["email"] == "done"
    assert len((tools / "home" / "bbot_calls.log").read_text().splitlines()) == n_before   # BBOT not re-run


def test_bbot_timeout_keeps_partial_results(authed, tools, monkeypatch):
    import asm.pipeline as pl
    monkeypatch.setattr(pl.Ctx, "timeout", lambda self, stage, default: 2 if stage == "bbot_light" else default * 60)
    (tools / "home" / "BBOT_HANG").write_text("30")
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    bb = next(s for s in st["stages"] if s["key"] == "bbot_light")
    assert bb["status"] == "done" and bb["summary"]["live_hosts"] > 0
    calls = (tools / "home" / "bbot_calls.log").read_text()
    light_call = next(l for l in calls.splitlines() if "-n light" in l and "--dry-run" not in l)
    assert "baddns" not in light_call and "-c " not in light_call


def test_bbot_error_fails_stage_and_zap_falls_back_to_tls(authed, tools):
    (tools / "home" / "BBOT_ERROR").write_text("1")
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "tls", "zap"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    assert by["bbot_light"]["status"] == "failed" and "would not start" in by["bbot_light"]["summary"]["error"]
    assert st["status"] == "completed_with_errors"
    assert by["tls"]["status"] == "done"
    assert by["zap"]["status"] == "done", by["zap"]["summary"]
    ev = [e["message"] for e in client.get(f"/api/scans/{sid}/events").json()["events"]]
    assert any("using hosts that answered on TLS" in m for m in ev)


def test_bbot_idle_watchdog_reaps_wedged_pass(authed, tools, monkeypatch):
    """A pass that stops producing events is reaped by the idle watchdog, keeping partial results,
    instead of grinding to the outer time budget."""
    import asm.pipeline as pl
    monkeypatch.setattr(pl, "BBOT_IDLE_TIMEOUT_S", 2)                 # reap after 2s of only heartbeats
    monkeypatch.setattr(pl, "LIGHT_MODULES", pl.LIGHT_MODULES + ["zzidle"])
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "email"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    assert by["bbot_light"]["status"] == "done", by["bbot_light"]["summary"]
    msgs = [e["message"] for e in client.get(f"/api/scans/{sid}/events").json()["events"]]
    assert any("No new activity" in m for m in msgs)                  # the watchdog fired
    assert any("keeping the results gathered so far" in m for m in msgs)


def test_bbot_progress_line_predicate():
    from asm.pipeline import _bbot_progress_line as p
    assert p("[INFO] active: No events in queue (0 processed in the past 15 seconds)") is False
    assert p("[INFO] active: No events in queue (3 processed in the past 15 seconds)") is True   # work happening
    assert p("[INFO] active: Modules running (incoming:processing:outgoing) generic_ssrf(0:1:0)") is False
    assert p("[INFO] active: Events produced so far: FINDING: 26") is False
    assert p("[FINDING] http://x/ reflected parameter") is True
    assert p("[INFO] nuclei: [0:00:10] | Templates: 11330 | Requests: 158") is True


def test_bbot_self_heals_unknown_modules(authed, tools, monkeypatch):
    """Unknown/renamed module names must not kill the pass: each is dropped and the pass loops until clean."""
    import asm.pipeline as pl
    monkeypatch.setattr(pl, "LIGHT_MODULES", pl.LIGHT_MODULES + ["zzbad", "zzbad2"])   # two stale names
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "email"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    assert by["bbot_light"]["status"] == "done", by["bbot_light"]["summary"]
    calls = (tools / "home" / "bbot_calls.log").read_text().splitlines()
    light_dry = [l for l in calls if "-n light" in l and "--dry-run" in l]
    light_real = [l for l in calls if "-n light" in l and "--dry-run" not in l]
    # the loop needed at least three dry runs (both bad, drop one, drop other, clean) and the real
    # pass requested neither stale name
    assert len(light_dry) >= 3
    assert light_real and all("zzbad" not in l for l in light_real)
    ev = [e["message"] for e in client.get(f"/api/scans/{sid}/events").json()["events"]]
    assert any("does not have module" in m and "zzbad" in m and "zzbad2" in m for m in ev)


def test_lookalike_severity():
    from asm.pipeline import lookalike_severity as ls
    assert ls("miro.com", "mira.com", "replacement")[0] == "low"
    assert ls("miro.com", "miro-miro.com", "addition")[0] == "medium"
    assert ls("miro.com", "mirologin.com", "addition")[0] == "medium"
    assert ls("miro.com", "xn--mir-vlz.com", "homoglyph")[0] == "medium"
    assert ls("eventbrite.com", "eventbrlte.com", "replacement")[0] == "medium"


def test_rerun_all_and_retry_turned_off_stage_and_counts(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "tls", "email"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    by = {s["key"]: s["status"] for s in st["stages"]}
    assert by["gau"] == "skipped"
    c = client.get(f"/api/scans/{sid}/counts").json()
    assert c["domains"] == 1 and c["subdomains_in_scope"] > 0 and c["live_hosts"] > 0 and c["web_endpoints"] > 0
    assert c["certificates"] > 0 and c["issues"] == sum(c["issues_by_severity"].values())
    # running a stage that was turned off turns it on
    assert client.post(f"/api/scans/{sid}/stages/gau/retry", headers=h).status_code == 202
    st = wait_done(client, sid)
    assert {s["key"]: s["status"] for s in st["stages"]}["gau"] == "done"
    assert "gau" in client.get(f"/api/scans/{sid}").json()["options"]["stages"]
    # re-run everything that's enabled
    n = len((tools / "home" / "bbot_calls.log").read_text().splitlines())
    r = client.post(f"/api/scans/{sid}/rerun", headers=h)
    assert r.status_code == 202 and set(r.json()["rerunning"]) == {"bbot_light", "tls", "email", "gau", "consolidate"}
    st = wait_done(client, sid)
    assert st["status"] == "completed"
    assert len((tools / "home" / "bbot_calls.log").read_text().splitlines()) > n


def test_bbot_progress_parse():
    from asm.api_run import _bbot_progress
    assert _bbot_progress("x: Events produced so far: DNS_NAME: 1,449, URL: 403, FINDING: 2 (1 LOW, 1 INFO)") == \
        {"DNS_NAME": 1449, "URL": 403, "FINDING": 2}


def test_dry_run_check_with_non_ascii_earlier_log(authed, tools):
    """Regression: the dry-run check sliced characters by a byte offset, so multi-byte text from an
    earlier run (gowitness prints bullets) hid BBOT's 'Loaded ... modules' line."""
    client, h, sid = ready_scan(authed, tools)
    from asm.app import state
    db = state.db()
    run_dir = Path(db.one("SELECT run_dir FROM scans WHERE id = ?", sid)["run_dir"]); db.close()
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs" / "bbot_light.log").write_text("  \u2022 gowitness scan file -f x\n" * 400, encoding="utf-8")
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    bb = next(s for s in st["stages"] if s["key"] == "bbot_light")
    assert bb["status"] == "done", bb["summary"]


def test_counts_survive_second_bbot_pass(authed, tools):
    """The ticker must not drop to 0 when BBOT's DNS-only pass starts reporting its own (smaller) totals."""
    client, h, sid = ready_scan(authed, tools)
    from asm.app import state
    from asm.api_run import live_counts
    from asm.db import now
    db = state.db()
    try:
        db.run("UPDATE scans SET status = 'running' WHERE id = ?", sid)
        db.run("INSERT INTO stages (scan_id, stage_key, status, started_at) VALUES (?, 'bbot_light', 'running', ?)", sid, "2000-01-01T00:00:00+00:00")
        for msg in ("[INFO] light: Events produced so far: DNS_NAME: 300, URL: 250",
                    "[INFO] light: Events produced so far: DNS_NAME: 449, URL: 398, FINDING: 2 (1 LOW, 1 INFO)",
                    "[INFO] dnsonly: Events produced so far: DNS_NAME: 12, SCAN: 1"):
            db.run("INSERT INTO events (scan_id, stage_key, ts, level, message) VALUES (?, 'bbot_light', ?, 'log', ?)", sid, now(), msg)
        c = live_counts(db, sid, db.one("SELECT * FROM scans WHERE id = ?", sid))
    finally:
        db.close()
    assert c["web_endpoints"] == 398 and c["bbot_live"]["DNS_NAME"] == 461


def test_bbot3_output_parsed_and_reuse(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "zap"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    sm = by["bbot_light"]["summary"]
    n_live = sm["live_hosts"]
    assert n_live > 0 and sm["web_endpoints"] == 2 * n_live and sm["technologies"] == n_live and sm["screenshots"] == 1
    assert by["zap"]["status"] == "done", by["zap"]["summary"]
    # re-read saved output without running BBOT again
    calls = len((tools / "home" / "bbot_calls.log").read_text().splitlines())
    r = client.post(f"/api/scans/{sid}/stages/bbot_light/retry?reuse=1", headers=h)
    assert r.status_code == 202 and r.json()["reuse_output"] is True
    st = wait_done(client, sid)
    assert next(s for s in st["stages"] if s["key"] == "bbot_light")["summary"]["web_endpoints"] == 2 * n_live
    assert len((tools / "home" / "bbot_calls.log").read_text().splitlines()) == calls


def test_ev_data_formats():
    from asm.pipeline import ev_data, ev_url
    assert ev_url({"data_json": {"url": "https://a.example/x"}}) == "https://a.example/x"
    assert ev_url({"data_json": "{'url': 'https://a.example/'}"}) == "https://a.example/"
    assert ev_url({"data": "https://b.example/"}) == "https://b.example/"
    assert ev_url({"data": None}) is None and ev_url({}) is None
    assert ev_data({"data": "x.example:443"}) == "x.example:443"


def test_parse_nmap_normal():
    from asm.pipeline import parse_nmap_normal
    text = """# Nmap 7.99 scan initiated Wed Nov 18 18:10:12 2026
Nmap scan report for readmessl.com (104.16.241.118)
Host is up.

PORT     STATE SERVICE      VERSION
80/tcp   open  http?
2052/tcp open  clearvisn?

Nmap scan report for 198.51.100.7
PORT   STATE SERVICE
22/tcp open  ssh
"""
    assert parse_nmap_normal(text) == {"104.16.241.118": [80, 2052], "198.51.100.7": [22]}


def test_shared_infra():
    from asm.pipeline import is_shared_infra
    assert is_shared_infra("certara2.mktoweb.com", ["miro.com"])
    assert not is_shared_infra("api.miro.com", ["miro.com"])
    assert not is_shared_infra(None, ["miro.com"])


def test_stages_run_in_parallel_respecting_dependencies(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "tls", "zap", "ports", "email", "gau", "lookalikes"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    st = wait_done(client, sid)
    assert st["status"] == "completed"
    ev = client.get(f"/api/scans/{sid}/events").json()["events"]
    order = [(e["stage_key"], e["message"].split(":")[0]) for e in ev if e["message"].startswith(("Stage started", "Stage complete"))]
    pos = {k: i for i, k in enumerate(order)}
    # independent stages start before BBOT finishes
    assert pos[("tls", "Stage started")] < pos[("bbot_light", "Stage complete")]
    assert pos[("email", "Stage started")] < pos[("bbot_light", "Stage complete")]
    # dependants wait
    assert pos[("zap", "Stage started")] > pos[("bbot_light", "Stage complete")]
    assert pos[("zap", "Stage started")] > pos[("tls", "Stage complete")]
    assert pos[("ports", "Stage started")] > pos[("bbot_light", "Stage complete")]
    assert pos[("consolidate", "Stage started")] == max(i for (k, kind), i in pos.items() if kind == "Stage started")


def test_humanize_samples():
    from asm.humanize import humanize as hz
    h = hz("bbot_light", "log", "[INFO] light: Events produced so far: DNS_NAME: 1,449, URL: 403, OPEN_TCP_PORT: 377, FINDING: 2 (1 LOW, 1 INFO), SCAN: 1")
    assert h["text"] == "Found so far: 1,449 host names · 403 web pages · 2 findings" and h["key"] == "found:light"
    h = hz("bbot_light", "log", "[INFO] dnsonly: Modules running (incoming:processing:outgoing) baddns(614:8:0), dnsresolve(0:0:0)")
    assert h["text"] == "Working: checking for takeovers (8 active, 614 queued)" and h["kind"] == "progress"
    assert hz("bbot_light", "log", "[INFO] light: No events in queue (0 processed in the past 15 seconds)") is None
    assert hz("zap", "log", "Job spider set context = estate") is None
    assert hz("zap", "log", "Job spider requesting URL https://a.example/")["text"] == "Spider: visiting https://a.example/"
    assert "Finding (medium): Dangling CNAME" in hz("bbot_light", "log", "[FINDING]           \tSeverity: [MEDIUM] Confidence: [MEDIUM] Dangling CNAME, possible takeover\tbaddns\t(x)")["text"]
    assert hz("tls", "log", '{"host":"a.example","tls_version":"tls13","not_after":"2027-01-02T00:00:00Z","mismatched":true}')["text"] == \
        "a.example: TLS 1.3 · certificate valid to 2027-01-02 · name mismatch"
    assert hz("bbot_light", "cmd", "$ bbot -t x -n dnsonly -y")["text"] == "Starting BBOT takeover checks"
    assert hz(None, "info", "Stage complete: a 1, b 2")["text"] == "Finished: a 1 · b 2"


def test_start_keeps_discovery_record(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["email"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    wait_done(client, sid)
    c = client.get(f"/api/scans/{sid}/candidates").json()
    assert c["discovery"] and c["discovery"]["status"] == "done"


def test_zap_plan_one_context_per_host_and_limits():
    from asm.pipeline import build_zap_plan, zap_minutes, Ctx
    from asm.settings_model import Settings
    import re
    c = Ctx(state=None, scan_id="x", run_dir=__import__("pathlib").Path("/tmp/r"), runner=None, providers=None,
            settings=Settings(), options={"zap_spider_minutes": 3, "zap_ajax_minutes": 3}, roots=["acme.com"],
            light_hosts=[], dns_hosts=[], exclusions=[], secrets={})
    targets = [f"https://h{i}.acme.com" for i in range(30)]
    plan = build_zap_plan(c, targets)
    assert len(plan["env"]["contexts"]) == 30
    for ctx, t in zip(plan["env"]["contexts"], targets):
        assert ctx["urls"] == [t] and len(ctx["includePaths"]) == 1
        assert not re.fullmatch(ctx["includePaths"][0], "https://h99.acme.com/")   # never another host
    spiders = [j for j in plan["jobs"] if j["type"] == "spider"]
    assert all(j["parameters"]["maxDepth"] and j["parameters"]["maxChildren"] for j in spiders)
    assert zap_minutes(c, 30) >= 30 * 7.5                                # sized to the plan, not a flat 4 hours


def test_status_rank_and_dead_hosts_skipped():
    from asm.pipeline import status_rank
    assert status_rank(200) < status_rank(401) < status_rank(301) < status_rank(None) < status_rank(403) == status_rank(503)


def test_zap_waits_for_host_choice_then_scans_only_chosen(authed, tools):
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"stages": ["bbot_light", "tls", "zap", "email"], "zap_confirm_targets": True, "zap_active": True, "zap_active_minutes": 5}, headers=h)
    client.post(f"/api/scans/{sid}/start?confirm=active", headers=h)
    stage = lambda k: next(s for s in client.get(f"/api/scans/{sid}/stages").json()["stages"] if s["key"] == k)
    assert pump(client, lambda: stage("zap")["status"] == "waiting", timeout=20)
    assert stage("email")["status"] == "done"                      # other stages carried on
    info = client.get(f"/api/scans/{sid}/zap/targets").json()
    assert info["waiting"] and len(info["candidates"]) >= 2 and info["selected"] == info["recommended"]
    pick = [info["candidates"][-1]["host"]]
    assert client.put(f"/api/scans/{sid}/zap/targets", json={"hosts": ["evil.example"]}, headers=h).status_code == 422
    r = client.post(f"/api/scans/{sid}/zap/confirm", json={"hosts": pick}, headers=h)
    assert r.status_code == 200 and r.json()["confirmed"] == 1
    st = wait_done(client, sid)
    assert st["status"] == "completed" and next(s for s in st["stages"] if s["key"] == "zap")["summary"]["sites"] == 1
    from asm.app import state
    db = state.db()
    run_dir = Path(db.one("SELECT run_dir FROM scans WHERE id = ?", sid)["run_dir"]); db.close()
    plan = __import__("yaml").safe_load((run_dir / "zap" / "plan.yaml").read_text())
    assert [c["urls"][0] for c in plan["env"]["contexts"]] == [info["candidates"][-1]["url"]]


def test_pause_freezes_and_resume_continues(authed, tools):
    (tools / "home" / "ZAP_SLEEP").write_text("4")
    client, h, sid = ready_scan(authed, tools)
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ["bbot_light", "zap"]}, headers=h)
    client.post(f"/api/scans/{sid}/start", headers=h)
    stage = lambda k: next(s for s in client.get(f"/api/scans/{sid}/stages").json()["stages"] if s["key"] == k)
    assert pump(client, lambda: stage("zap")["status"] == "running", timeout=20)
    assert client.post(f"/api/scans/{sid}/pause", headers=h).status_code == 200
    assert client.get(f"/api/scans/{sid}/stages").json()["paused"] is True
    import time as _t
    t0 = _t.time()
    pump(client, lambda: False, timeout=6)                         # ZAP would finish in 4s if it weren't frozen
    assert stage("zap")["status"] == "running"
    assert client.post(f"/api/scans/{sid}/resume", headers=h).status_code == 200
    st = wait_done(client, sid)
    assert st["status"] == "completed" and _t.time() - t0 >= 6
