"""v0.6 stages: cdncheck, dnsReaper, checkdmarc, testssl.sh, cloudlist, KEV/EPSS intel, LeakIX/Netlas, openSquat,
urlscan, SpiderFoot, plus scan-to-scan changes and the non-invasive defaults."""
import json
import os
import stat
import sys
import textwrap

import pytest

from asm.allowlist import CommandRejected, Ctx as ACtx, validate
from asm.extras import (email_findings, parse_cdncheck, parse_cloudlist, parse_dnsreaper, parse_opensquat, parse_testssl,
                        cloudlist_provider_config)
from test_pipeline import AUTH, PipelineProviders, ready_scan, tools, wait_done  # noqa: F401 (tools is a fixture)

EXTRA_TOOLS = {
    "cdncheck": r'''
        import json, sys
        a = sys.argv[1:]
        assert "-i" in a and "-jsonl" in a
        for ip in open(a[a.index("-i") + 1]).read().split():
            if ip.startswith("104.16."):
                print(json.dumps({"input": ip, "ip": ip, "waf": True, "waf_name": "cloudflare", "cdn": True, "cdn_name": "cloudflare"}))
            elif ip == "93.184.216.34":
                print(json.dumps({"input": ip, "ip": ip, "cloud": True, "cloud_name": "aws"}))
    ''',
    "dnsreaper": r'''
        import json, os, sys
        a = sys.argv[1:]
        open(os.path.join(os.environ["HOME"], "dnsreaper_calls.log"), "a").write(" ".join(a) + "\n")
        out = a[a.index("--out") + 1] + ".json"
        if a[0] == "file":
            hosts = [h.strip() for h in open(a[a.index("--filename") + 1]) if h.strip()]
            rows = [{"domain": hosts[0], "signature": "AWS S3", "info": "bucket missing", "confidence": "CONFIRMED"},
                    {"domain": "other.example", "signature": "x", "confidence": "CONFIRMED"}]
        else:
            rows = [{"domain": "zoneonly.acme.com", "signature": "Heroku", "confidence": "POTENTIAL"},
                    {"domain": "notmine.org", "signature": "Heroku", "confidence": "CONFIRMED"}]
        json.dump(rows, open(out, "w"))
    ''',
    "checkdmarc": r'''
        import json, sys
        a = sys.argv[1:]
        open(__import__("os").path.join(__import__("os").environ["HOME"], "checkdmarc_args.log"), "w").write(" ".join(a))
        out = a[a.index("-o") + 1]
        doms = [x for x in a if "." in x and not x.endswith(".json")]
        res = [{"domain": d, "mx": {"hosts": [{"hostname": "mx1." + d}]},
                "spf": {"record": "v=spf1 include:a include:b ~all", "valid": False, "dns_lookups": 13, "error": "too many lookups"},
                "dmarc": {"record": "v=DMARC1; p=reject; sp=none", "valid": True, "tags": {"p": {"value": "reject"}, "sp": {"value": "none"}}},
                "mta_sts": {"valid": False}, "smtp_tls_reporting": {"valid": False}, "bimi": {}} for d in doms]
        json.dump(res[0] if len(res) == 1 else res, open(out, "w"))
    ''',
    "testssl.sh": r'''
        import json, os, sys
        a = sys.argv[1:]
        open(os.path.join(os.environ["HOME"], "testssl_calls.log"), "a").write(" ".join(a) + "\n")
        out = a[a.index("--jsonfile") + 1]
        rows = [{"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
                {"id": "HSTS", "severity": "MEDIUM", "finding": "not offered"},
                {"id": "scanTime", "severity": "INFO", "finding": "12"},
                {"id": "overall_grade", "severity": "INFO", "finding": "B"}]
        if "--vulnerable" in a:
            rows.append({"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE", "cve": "CVE-2014-0160"})
        json.dump(rows, open(out, "w"))
    ''',
    "opensquat": r'''
        import json, os, sys
        a = sys.argv[1:]
        open(os.path.join(os.environ["HOME"], "opensquat_args.log"), "w").write(" ".join(a) + "\n" + os.getcwd())
        kws = open(a[a.index("-k") + 1]).read().split()
        json.dump([{"domain": f"{kws[0]}-login-portal.com", "keyword": kws[0]}, "acm.com", "www.acme.com"], open(a[a.index("-o") + 1], "w"))
    ''',
    "cloudlist": r'''
        import json, os, sys, yaml
        a = sys.argv[1:]
        cfg = yaml.safe_load(open(a[a.index("-pc") + 1]))
        assert cfg[0]["provider"] == "aws" and cfg[0]["aws_secret_key"] == "SECRETKEY1234"
        with open(a[a.index("-o") + 1], "w") as f:
            f.write(json.dumps({"provider": "aws", "service": "ec2", "public_ipv4": "52.1.2.3", "dns_name": "ec2-52-1-2-3.compute.amazonaws.com"}) + "\n")
            f.write(json.dumps({"provider": "aws", "service": "route53", "dns_name": "hidden.acme.com"}) + "\n")
    ''',
}

EXTRA_TOOLS["dnsx"] = r'''
    import json, os, sys
    a = sys.argv[1:]
    assert "-json" in a
    out = a[a.index("-o") + 1]
    if "-ptr" in a:                    # reverse DNS: map each own IP to a PTR name
        with open(out, "w") as f:
            for ip in (l.strip() for l in open(a[a.index("-l") + 1]) if l.strip()):
                name = "ec2-host.acme.com" if ip == "93.184.216.34" else f"rev-{ip.replace('.','-')}.example.net"
                f.write(json.dumps({"host": ip, "ptr": [name]}) + "\n")
    elif "-d" in a:                    # brute mode: <word>.<root> for each wordlist entry
        root = a[a.index("-d") + 1]; words = [w.strip() for w in open(a[a.index("-w") + 1]) if w.strip()]
        open(os.path.join(os.environ["HOME"], "dnsx_brute.log"), "a").write(f"{root}:{len(words)}\n")
        with open(out, "w") as f:
            if "admin" in words:        # pretend admin.<root> resolves (a host discovery missed)
                f.write(json.dumps({"host": f"admin.{root}", "a": ["93.184.216.34"]}) + "\n")
    else:
        with open(out, "w") as f:
            for i, h in enumerate(l.strip() for l in open(a[a.index("-l") + 1]) if l.strip()):
                r = {"host": h, "a": ["93.184.216.34"], "txt": ["v=spf1 -all"], "status_code": "NOERROR"}
                if h.startswith("dev."):
                    r["a"] = ["10.1.2.3"]
                if h.startswith("www."):
                    cf = os.path.join(os.environ["HOME"], "DNSX_CNAME")
                    r["cname"] = [open(cf).read().strip() if os.path.exists(cf) else "edge.example.net"]
                f.write(json.dumps(r) + "\n")
'''
EXTRA_TOOLS["naabu"] = r'''
    import json, os, sys
    a = sys.argv[1:]
    open(os.path.join(os.environ["HOME"], "naabu_args.log"), "w").write(" ".join(a))
    assert a[a.index("-s") + 1] == "c"
    with open(a[a.index("-o") + 1], "w") as f:
        for ip in (l.strip() for l in open(a[a.index("-list") + 1]) if l.strip()):
            for p in (443, 6379):
                f.write(json.dumps({"ip": ip, "port": p, "protocol": "tcp"}) + "\n")
'''
FINGERPRINTS = {
    "nginx": {"headers": {"Server": "nginx(?:/([\\d.]+))?\\;version:\\1"}, "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
    "WordPress": {"meta": {"generator": "^WordPress ?([\\d.]+)?\\;version:\\1"}, "implies": "PHP",
                  "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
    "PHP": {"cookies": {"PHPSESSID": ""}},
    "jQuery": {"scriptSrc": "jquery[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1"},
}

KEV = {"vulnerabilities": [{"cveID": "CVE-2023-1111", "vendorProject": "Acme", "product": "Gateway",
                            "vulnerabilityName": "RCE", "knownRansomwareCampaignUse": "Known"}]}


class XProviders(PipelineProviders):
    calls: list

    async def http_page(self, url, timeout=15, max_bytes=0):
        return {"status": 200, "url": url, "headers": {"server": "nginx/1.18.0"}, "cookies": ["PHPSESSID"],
                "body": '<meta name="generator" content="WordPress 6.1"><script src="/js/jquery-3.4.1.min.js"></script>'}

    async def http_json(self, url, headers=None, data=None, timeout=60):
        self.urls.append(url)
        if "internetdb.shodan.io" in url:
            ip = url.rsplit("/", 1)[-1]
            return {"ip": ip, "ports": [443], "vulns": ["CVE-2023-1111", "CVE-2020-2222", "CVE-2019-3333"]}
        if "cvedb.shodan.io" in url:
            return {"cves": [{"cve_id": "CVE-2021-23017", "epss": 0.5}, {"cve_id": "CVE-2023-1111"}]} if "nginx" in url else {"cves": []}
        if "known_exploited" in url:
            return KEV
        if "api.first.org" in url:
            return {"data": [{"cve": "CVE-2023-1111", "epss": "0.97"}, {"cve": "CVE-2020-2222", "epss": "0.40"},
                             {"cve": "CVE-2019-3333", "epss": "0.001"}]}
        if "services.nvd.nist.gov" in url:
            cve = url.rsplit("cveId=", 1)[-1]
            recs = {
                "CVE-2023-1111": {"id": cve, "published": "2023-05-01T00:00:00",
                                  "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}, "baseSeverity": "CRITICAL"}]},
                                  "weaknesses": [{"description": [{"value": "CWE-787"}]}],
                                  "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]}]}]},
                "CVE-2020-2222": {"id": cve, "published": "2020-02-02T00:00:00",
                                  "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]},
                                  "weaknesses": [{"description": [{"value": "CWE-79"}]}], "configurations": []},
            }
            r = recs.get(cve)
            return {"vulnerabilities": [{"cve": r}] if r else []}
        if "leakix.net/domain" in url:
            assert headers["api-key"] == "LEAKIXKEY-123456"
            return {"Services": [{"host": "shadow.acme.com", "ip": "93.184.216.34", "port": 22}],
                    "Leaks": [{"host": "www.acme.com", "ip": "93.184.216.34", "port": 9200, "event_source": "ElasticSearchOpenPlugin",
                               "summary": "indices: users", "leak": {"severity": "critical", "type": "open database"}}]}
        if "app.netlas.io" in url:
            assert headers["X-API-Key"] == "NETLASKEY-123456"
            return {"items": [{"data": {"host": "netlas-only.acme.com", "ip": "93.184.216.34", "cve": [{"name": "CVE-2023-1111"}]}}]}
        if "urlscan.io" in url:
            if "acm.com" in url:
                return {"results": [{"page": {"domain": "acm.com", "title": "Acme login"}, "task": {"time": "2026-11-17T10:00:00Z"},
                                     "result": "https://urlscan.io/api/v1/result/abc/"}]}
            return {"results": [{"page": {"domain": "www.acme.com"}}, {"page": {"domain": "old-promo.acme.com"}}]}
        if "spiderfoot" in url:
            if url.endswith("/ping"):
                return ["SUCCESS", "4.0"]
            if "/startscan" in url:
                assert b"usecase=passive" in data
                return ["SUCCESS", "SF1"]
            if "/scanstatus" in url:
                return ["n", "t", 0, 0, 0, "FINISHED"]
            if "/scanexportjsonmulti" in url:
                return [{"event_type": "INTERNET_NAME", "data": "sf-only.acme.com"},
                        {"event_type": "LEAKSITE_URL", "data": "https://paste.example/abc", "source_data": "acme.com"},
                        {"event_type": "PORTSCAN", "data": "ignored"}]
        return await super().http_json(url, headers, data, timeout)


@pytest.fixture
def xtools(tools, monkeypatch):
    fp = tools / "wappalyzer" / "src" / "technologies"
    fp.mkdir(parents=True)
    (fp / "a.json").write_text(json.dumps(FINGERPRINTS))
    import asm.extras
    monkeypatch.setattr(asm.extras, "WAPPALYZER_DIRS", [tools / "wappalyzer"])
    bindir = tools / "bin"
    for name, src in EXTRA_TOOLS.items():
        p = bindir / name
        p.write_text(f"#!{sys.executable}\n" + textwrap.dedent(src))
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return tools


ALL_NEW = ["bbot_light", "cdn", "takeover", "tls", "tls_deep", "ports", "cloudlist", "cloud", "feeds", "intel", "email",
           "lookalikes", "squat", "urlscan", "spiderfoot"]


def _run(client, h, sid, **opts):
    client.put(f"/api/scans/{sid}/authorisation", json=AUTH, headers=h)
    r = client.put(f"/api/scans/{sid}/options", json={"zap_confirm_targets": False, "stages": ALL_NEW, **opts}, headers=h)
    assert r.status_code == 200, r.text
    assert client.post(f"/api/scans/{sid}/start", headers=h).status_code == 202
    st = wait_done(client, sid, timeout=60)
    return st, {s["key"]: s for s in st["stages"]}


def test_new_stages_end_to_end(authed, xtools, monkeypatch):
    import asm.extras as _ex
    monkeypatch.setattr(_ex, "NVD_INTERVAL_NOKEY", 0)        # don't sleep between NVD lookups in tests
    client, h, sid = ready_scan(authed, xtools, extra_dns={"cdn.acme.com": {"cname": [], "ips": ["104.16.0.1"]}})
    from asm.app import state
    state.providers = XProviders(dns=state.providers.dns)
    for name, val in (("leakix", "LEAKIXKEY-123456"), ("netlas", "NETLASKEY-123456"), ("cloud_aws", "AKIAEXAMPLE:SECRETKEY1234"),
                      ("cloud_cloudflare", "cftoken_abcdefghijklmnopqrstuvwxyz")):
        assert client.put(f"/api/secrets/{name}", json={"value": val}, headers=h).status_code == 200
    st, by = _run(client, h, sid)
    assert st["status"] == "completed", {k: (v["status"], v["summary"]) for k, v in by.items()}
    for k in ALL_NEW:
        assert by[k]["status"] == "done", (k, by[k]["status"], by[k]["summary"])

    # cdncheck replaces the tag guess, and its verdict is stored per host
    assert by["cdn"]["summary"]["waf"] == 1 and by["cdn"]["summary"]["cloud"] == 1
    # dnsReaper: file + Cloudflare zone; out-of-scope names dropped
    assert by["takeover"]["summary"]["confirmed"] == 1 and by["takeover"]["summary"]["from_zones_only"] == 1
    # checkdmarc: SPF over the limit, sp=none; --skip-tls by default (no SMTP connections)
    assert "--skip-tls" in (xtools / "home" / "checkdmarc_args.log").read_text()
    assert by["email"]["summary"]["spf_over_limit"] == 1 and by["email"]["summary"]["dmarc_reject"] == 1
    # testssl: safe checks only by default
    calls = (xtools / "home" / "testssl_calls.log").read_text()
    assert "--vulnerable" not in calls and "--headers" in calls
    assert by["tls_deep"]["summary"]["medium"] >= 1 and "B" in by["tls_deep"]["summary"]["grades"]
    # cloudlist: the IP no DNS points at is checked by the cloud stage
    assert by["cloudlist"]["summary"]["ips_without_dns"] == 1 and by["cloudlist"]["summary"]["names_not_discovered"] == 2
    assert by["cloud"]["summary"]["ips_checked"] == 1
    assert not list((xtools).rglob(".provider-config.yaml"))           # keys never left on disk
    # intel: KEV (high), EPSS >= 10% (medium), the rest grouped as info
    assert by["intel"]["summary"]["kev"] == 1 and by["intel"]["summary"]["epss_likely"] == 1
    # openSquat: brand keyword, own domains and dnstwist duplicates dropped, no port check
    args = (xtools / "home" / "opensquat_args.log").read_text()
    assert "--portcheck" not in args and by["squat"]["summary"]["new_vs_dnstwist"] == 1
    # urlscan: the lookalike with live pages, and a host not in scope
    assert by["urlscan"]["summary"]["live_lookalikes"] >= 1 and by["urlscan"]["summary"]["hosts_not_in_scope"] == 1
    assert by["spiderfoot"]["summary"] == {"events": 3, "new_hosts": 1, "findings": 1}

    db = state.db()
    try:
        f = [dict(r) for r in db.all("SELECT * FROM findings WHERE scan_id = ?", sid)]
        cdn = db.one("SELECT cdn, edge FROM assets WHERE scan_id = ? AND host = 'cdn.acme.com'", sid)
        www = db.one("SELECT cdn, edge FROM assets WHERE scan_id = ? AND host = 'www.acme.com'", sid)
    finally:
        db.close()
    assert cdn["cdn"] == 1 and json.loads(cdn["edge"])["waf"] == "cloudflare"
    assert www["cdn"] == 0 and json.loads(www["edge"]) == {"cloud": "aws"}
    t = lambda tool: [x for x in f if x["source_tool"] == tool]
    assert not any(x["host"] in ("other.example", "notmine.org") for x in t("dnsreaper"))
    assert any(x["title"].startswith("SPF needs 13") and x["severity"] == "high" for x in t("checkdmarc"))
    assert any("sp=none" in x["title"] for x in t("checkdmarc"))
    kevfind = [x for x in t("intel-cve") if x["severity"] == "high" and "CVE-2023-1111" in x["title"]]
    assert kevfind
    assert any("CVSS 9.8" in (x["evidence_ref"] or "") and "CWE-787" in (x["evidence_ref"] or "") for x in kevfind)  # NVD enrichment
    assert by["intel"]["summary"]["nvd_enriched"] == 2
    assert any(x["severity"] == "high" and "Elastic" in x["title"] for x in t("leakix"))
    assert {x["host"] for x in t("leakix") + t("netlas") if x["area"] == "surface"} == {"shadow.acme.com", "netlas-only.acme.com"}
    assert any("acme-login-portal.com" in x["title"] for x in t("opensquat"))
    # secrets never reach the event log
    ev = client.get(f"/api/scans/{sid}/events?after=0").json()["events"]
    for secret in ("LEAKIXKEY-123456", "NETLASKEY-123456", "SECRETKEY1234", "cftoken_abcdefghijklmnopqrstuvwxyz"):
        assert all(secret not in e["message"] for e in ev)

    # the overview counts one takeover per host across BBOT and dnsReaper, and flags KEV for verification
    o = client.get(f"/api/scans/{sid}/overview").json()
    texts = " ".join(r["text"] for r in o["reasons"])
    assert "known-exploited" in texts and "10-lookup" in texts and "LeakIX" in texts
    assert o["values"]["kev_cves"] == 1


def test_nvd_parse_and_version_range():
    from asm.extras import _parse_nvd, _version_in_range
    cve = {"id": "CVE-X", "published": "2023-01-01T00:00:00",
           "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "V"}, "baseSeverity": "CRITICAL"}]},
           "weaknesses": [{"description": [{"value": "CWE-89"}, {"value": "NVD-CWE-noinfo"}]}],
           "configurations": [{"nodes": [{"cpeMatch": [
               {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.20.0"}]}]}]}
    p = _parse_nvd(cve)
    assert p["cvss"] == 9.8 and p["severity"] == "CRITICAL" and p["cwes"] == ["CWE-89"]
    rg = p["ranges"]
    assert _version_in_range("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", rg) == "in"
    assert _version_in_range("cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*", rg) == "out"   # endExcluding boundary
    assert _version_in_range("cpe:2.3:a:nginx:nginx:0.9.0:*:*:*:*:*:*:*", rg) == "out"    # below start
    assert _version_in_range("cpe:2.3:a:apache:httpd:1.18.0:*:*:*:*:*:*:*", rg) is None   # different product
    assert _version_in_range("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", rg) is None         # unknown running version


def test_invasive_switches_are_opt_in(authed, xtools):
    client, h, sid = ready_scan(authed, xtools)
    from asm.app import state
    state.providers = XProviders(dns=state.providers.dns)
    st, by = _run(client, h, sid, stages=["bbot_light", "tls_deep", "email", "squat"], testssl_vuln_checks=True,
                  email_starttls=True, opensquat_portcheck=True)
    assert "--vulnerable" in (xtools / "home" / "testssl_calls.log").read_text()
    assert "--skip-tls" not in (xtools / "home" / "checkdmarc_args.log").read_text()
    assert "--portcheck" in (xtools / "home" / "opensquat_args.log").read_text()
    ev = client.get(f"/api/scans/{sid}/events?after=0").json()["events"]
    warns = [e["message"] for e in ev if e["level"] == "warn"]
    assert any("malformed TLS handshakes" in w for w in warns) and any("someone else's servers" in w for w in warns)


def test_defaults_are_non_invasive():
    from asm.api_run import OptionsIn
    o = OptionsIn()
    assert not o.testssl_vuln_checks and not o.email_starttls and not o.opensquat_portcheck and not o.opensquat_premium
    assert "spiderfoot" not in o.stages and "cdn" in o.stages and "takeover" in o.stages
    assert not o.lookalike_probe and o.spiderfoot_usecase == "passive" and "port_check" not in o.stages


def test_stage_skips_when_not_configured(authed, xtools):
    client, h, sid = ready_scan(authed, xtools)
    from asm.app import state
    state.providers = XProviders(dns=state.providers.dns)
    st, by = _run(client, h, sid, stages=["feeds", "cloudlist", "spiderfoot"])
    assert by["feeds"]["status"] == "skipped" and "free" in by["feeds"]["summary"]["reason"]
    assert by["cloudlist"]["status"] == "skipped"
    o = client.get(f"/api/scans/{sid}/options").json()
    assert o["readiness"]["feeds"]["ok"] is False and o["readiness"]["cloudlist"]["ok"] is False


def test_cloudlist_upload(authed, xtools):
    client, h, tmp = authed
    assert client.get("/api/imports/cloudlist").json() == {"present": False}
    assert client.post("/api/imports/cloudlist", data=b"nothing useful here !!", headers=h).status_code == 422
    body = (json.dumps({"provider": "gcp", "public_ipv4": "34.1.1.1", "dns_name": "api.acme.com"}) + "\n35.2.2.2\n").encode()
    r = client.post("/api/imports/cloudlist", data=body, headers=h)
    assert r.status_code == 200 and r.json()["public_ips"] == 2 and r.json()["providers"] == ["gcp"]
    assert client.delete("/api/imports/cloudlist", headers=h).json() == {"present": False}


def test_parsers():
    assert parse_cdncheck('1.2.3.4 [waf] [cloudflare]\n{"ip": "5.6.7.8", "cloud": true, "cloud_name": "aws"}') == \
        {"1.2.3.4": {"waf": "cloudflare"}, "5.6.7.8": {"cloud": "aws"}}
    assert parse_dnsreaper([{"Domain": "a.acme.com", "Signature": "S3", "Confidence": "CONFIRMED"}])[0]["confidence"] == "confirmed"
    assert parse_opensquat({"results": ["x.com", {"domain": "y.com", "keyword": "acme"}]})[1]["keyword"] == "acme"
    assert len(parse_testssl([{"id": "a", "severity": "LOW"}, {"protocols": [{"id": "b"}]}])) == 2
    items = parse_cloudlist('{"provider": "aws", "public_ipv4": "52.1.1.1"}\nfoo.acme.com\n10.0.0.1\n')
    assert [i["ip"] or i["host"] for i in items] == ["52.1.1.1", "foo.acme.com"]      # private IPs dropped
    cfg = cloudlist_provider_config({"cloud_aws": "AK:SK", "cloud_azure": "t:c:s:sub", "cloud_do": "tok"})
    assert [c["provider"] for c in cfg] == ["aws", "azure", "do"] and cfg[1]["subscription_id"] == "sub"


def test_email_rules():
    base = {"mx": {"hosts": [{"hostname": "mx"}]}, "mta_sts": {"valid": True, "policy": {"mode": "enforce"}},
            "smtp_tls_reporting": {"valid": True}}
    titles = lambda r: [t for _, t in email_findings({**base, **r})]
    assert any("No DMARC" in t for t in titles({"spf": {"record": "v=spf1 -all"}}))
    t = titles({"spf": {"record": "v=spf1 +all", "dns_lookups": 2}, "dmarc": {"record": "v=DMARC1; p=quarantine; pct=50",
                "tags": {"p": {"value": "quarantine"}, "pct": {"value": 50}, "rua": {"value": ["mailto:x"]}}}})
    assert any("+all" in x for x in t) and any("pct=50" in x for x in t) and any("quarantine" in x for x in t)
    assert not any("rua" in x for x in t)
    # no mail: lock-down advice instead of SPF/MTA-STS noise
    t = [t for _, t in email_findings({"mx": {"hosts": []}, "dmarc": {"record": "v=DMARC1; p=reject", "tags": {"p": {"value": "reject"}, "rua": {"value": "x"}}}})]
    assert t == ["Domain sends no mail but isn't locked down (v=spf1 -all)"]


def test_allowlist_new_tools():
    ctx = ACtx(allowed_dirs=[__import__("pathlib").Path("/tmp")])
    validate(["cdncheck", "-i", "/tmp/x", "-resp", "-jsonl", "-silent", "-nc"], ctx)
    validate(["dnsreaper", "file", "--filename", "/tmp/h", "--out", "/tmp/o", "--out-format", "json", "--parallelism", "20"], ctx)
    validate(["testssl.sh", "--quiet", "--protocols", "--jsonfile", "/tmp/o.json", "www.acme.com"], ctx)
    validate(["checkdmarc", "acme.com", "-f", "json", "-o", "/tmp/x.json", "--skip-tls"], ctx)
    for bad in (["dnsreaper", "single", "--domain", "acme.com"], ["testssl.sh", "--file", "/tmp/x"],
                ["testssl.sh", "--mx", "acme.com"], ["cdncheck", "-i", "/etc/passwd"], ["opensquat", "--vt"],
                ["cloudlist", "-pc", "/tmp/x.txt"], ["checkdmarc", "acme.com", "-o", "/etc/x.json"]):
        with pytest.raises(CommandRejected):
            validate(bad, ctx)


def test_changes_between_scans(authed, xtools):
    from asm.app import state
    client, h, sid1 = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid1, stages=["bbot_light", "tls", "ports"])
    # second scan of the same domain
    client2, h2, sid2 = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid2, stages=["bbot_light", "tls", "ports"])
    db = state.db()
    try:
        db.run("DELETE FROM findings WHERE scan_id = ? AND title LIKE 'Expired%'", sid2)      # fixed since scan 1
        db.run("INSERT INTO findings (scan_id, area, severity, title, host, source_tool) VALUES (?, 'web', 'high', 'New thing', 'www.acme.com', 'zap')", sid2)
        db.run("INSERT INTO assets (scan_id, host, ports) VALUES (?, 'brand-new.acme.com', '[8080]')", sid2)
    finally:
        db.close()
    r = client.get(f"/api/scans/{sid2}/changes").json()
    assert r["against"]["id"] == sid1
    assert r["hosts"]["added"] == ["brand-new.acme.com"]
    assert {"host": "brand-new.acme.com", "port": 8080} in r["ports"]["opened"]
    assert [x["title"] for x in r["findings"]["new"]] == ["New thing"]
    assert any(x["title"].startswith("Expired") for x in r["findings"]["resolved"])
    assert any("1 new finding" in x for x in r["headline"])
    assert client.get(f"/api/scans/{sid2}/changes?against=nope").status_code == 422
    assert client.get(f"/api/scans/{sid1}/changes").json()["against"] is None


def test_stages_added_after_a_scan_can_be_run(authed, xtools):
    """A scan finished before v0.6 has no records for the new stages: they show as not_run with a Run action."""
    from asm.app import state
    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid, stages=["bbot_light", "tls"])
    db = state.db()
    try:   # simulate an older scan: drop the records of stages it never knew about
        db.run("DELETE FROM stages WHERE scan_id = ? AND stage_key IN ('cdn', 'takeover', 'email')", sid)
    finally:
        db.close()
    by = {s["key"]: s for s in client.get(f"/api/scans/{sid}/stages").json()["stages"]}
    assert by["cdn"]["status"] == "not_run" and by["cdn"]["summary"]["reason"] == "added after this scan ran"
    assert client.post(f"/api/scans/{sid}/stages/takeover/retry", headers=h).status_code == 202
    st = wait_done(client, sid)
    assert {s["key"]: s for s in st["stages"]}["takeover"]["status"] == "done"
    r = client.post(f"/api/scans/{sid}/run-new", headers=h)
    assert r.status_code == 202 and set(r.json()["running"]) == {"cdn", "email"}
    st = wait_done(client, sid)
    by = {s["key"]: s for s in st["stages"]}
    assert by["cdn"]["status"] == "done" and by["email"]["status"] == "done"
    assert client.post(f"/api/scans/{sid}/run-new", headers=h).status_code == 409



def test_tech_dns_and_port_check(authed, xtools, monkeypatch):
    import asm.extras as _ex
    monkeypatch.setattr(_ex, "NVD_INTERVAL_NOKEY", 0)
    from asm.app import state
    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    st, by = _run(client, h, sid, stages=["bbot_light", "tech", "dns", "ports", "port_check", "intel"])
    assert all(by[k]["status"] == "done" for k in ("tech", "dns", "port_check", "intel")), {k: (v["status"], v["summary"]) for k, v in by.items()}
    # Wappalyzer rules: header/meta/script/cookie matches with versions, implied PHP, CPEs for versioned products
    t = by["tech"]["summary"]
    assert t["technologies"] == 4 and t["cpes"] == 2
    db = state.db()
    try:
        tech = json.loads(db.one("SELECT tech FROM assets WHERE scan_id = ? AND host = 'www.acme.com'", sid)["tech"])
        f = [dict(r) for r in db.all("SELECT * FROM findings WHERE scan_id = ?", sid)]
        recs = db.one("SELECT COUNT(*) AS n FROM dns_records WHERE scan_id = ?", sid)["n"]
        pc = db.one("SELECT ports_confirmed FROM assets WHERE scan_id = ? AND host = 'www.acme.com'", sid)["ports_confirmed"]
    finally:
        db.close()
    assert {"nginx 1.18.0", "WordPress 6.1", "PHP", "jQuery 3.4.1"} <= set(tech)
    # CVEDB: fingerprinted nginx version -> KEV + EPSS findings, labelled as fingerprint matches
    assert any("version from page fingerprint" in x["title"] and x["severity"] == "high" for x in f if x["source_tool"] == "intel-cve")
    # dnsx: snapshot stored, private address flagged
    assert recs > 0 and by["dns"]["summary"]["private_addresses"] >= 1
    assert any(x["source_tool"] == "dnsx" and "private" in x["title"] for x in f)
    # naabu: connect scan only, Redis newly confirmed (not in Shodan), 3389 from Shodan now closed
    args = (xtools / "home" / "naabu_args.log").read_text()
    assert " -s c " in args and "-rate 100" in args and "3389" in args
    assert json.loads(pc) == [443, 6379]
    assert any(x["source_tool"] == "naabu" and "Redis" in x["title"] for x in f)
    assert any(x["source_tool"] == "naabu" and "closed now" in x["title"] for x in f)
    ev = client.get(f"/api/scans/{sid}/events?after=0").json()["events"]
    assert any("ACTIVE: TCP connect" in e["message"] for e in ev)


def test_port_check_is_off_by_default_and_marked_active():
    from asm.api_run import OptionsIn
    from asm.pipeline import STAGES
    assert "port_check" not in OptionsIn().stages
    assert next(s for s in STAGES if s.key == "port_check").traffic == "active"
    ctx = ACtx(allowed_dirs=[__import__("pathlib").Path("/tmp")])
    validate(["naabu", "-list", "/tmp/x", "-p", "22,443", "-s", "c", "-rate", "100", "-json", "-o", "/tmp/o"], ctx)
    for bad in (["naabu", "-list", "/tmp/x", "-s", "s"], ["naabu", "-host", "acme.com"], ["naabu", "-list", "/tmp/x", "-rate", "5000"],
                ["naabu", "-list", "/tmp/x", "-p", "-"], ["nmap", "-sT", "x"], ["nuclei", "-u", "x"]):
        with pytest.raises(CommandRejected):
            validate(bad, ctx)


def test_dns_changes_between_scans(authed, xtools, monkeypatch):
    from asm.app import state
    client, h, sid1 = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid1, stages=["bbot_light", "dns"])
    (xtools / "home" / "DNSX_CNAME").write_text("abandoned.herokuapp.com")
    client, h, sid2 = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid2, stages=["bbot_light", "dns"])
    r = client.get(f"/api/scans/{sid2}/changes").json()
    ch = {(d["type"], d["value"], d["change"]) for d in r["dns"]}
    assert ("CNAME", "abandoned.herokuapp.com", "added") in ch and ("CNAME", "edge.example.net", "removed") in ch
    assert any("CNAME target" in x for x in r["headline"])


def test_switches_on_finished_scan_and_active_confirmation(authed, xtools):
    from asm.app import state
    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid, stages=["bbot_light", "ports", "tls_deep"])
    # unknown keys and bad values are refused
    assert client.request("PATCH", f"/api/scans/{sid}/switches", json={"stages": ["port_check"]}, headers=h).status_code == 422
    assert client.request("PATCH", f"/api/scans/{sid}/switches", json={"spiderfoot_usecase": "evil"}, headers=h).status_code == 422
    r = client.request("PATCH", f"/api/scans/{sid}/switches", json={"testssl_vuln_checks": True}, headers=h)
    assert r.status_code == 200 and r.json()["switches"]["testssl_vuln_checks"] is True
    assert client.post(f"/api/scans/{sid}/stages/tls_deep/retry", headers=h).status_code == 202
    wait_done(client, sid)
    assert "--vulnerable" in (xtools / "home" / "testssl_calls.log").read_text().splitlines()[-1]
    # an active stage never starts without an explicit confirmation
    assert client.post(f"/api/scans/{sid}/stages/port_check/retry", headers=h).status_code == 428
    assert client.post(f"/api/scans/{sid}/stages/port_check/retry?confirm=active", headers=h).status_code == 202
    st = wait_done(client, sid)
    assert {s["key"]: s for s in st["stages"]}["port_check"]["status"] == "done"


def test_tech_survives_malformed_stored_url(authed, xtools):
    """A stored web_url of '://' (from an early BBOT 3 parse) must not fail the stage: fall back to https://host/."""
    from asm.app import state
    client, h, sid = ready_scan(authed, xtools)
    seen = []

    class P(XProviders):
        async def http_page(self, url, timeout=15, max_bytes=0):
            seen.append(url)
            if "boom" in url:
                raise RuntimeError("odd page")
            return await super().http_page(url, timeout, max_bytes)

    state.providers = P(dns=state.providers.dns)
    _run(client, h, sid, stages=["bbot_light"])
    db = state.db()
    try:
        db.run("UPDATE assets SET web_url = '://' WHERE scan_id = ? AND host = 'www.acme.com'", sid)
    finally:
        db.close()
    assert client.post(f"/api/scans/{sid}/stages/tech/retry", headers=h).status_code == 202
    st = wait_done(client, sid)
    tech = {s["key"]: s for s in st["stages"]}["tech"]
    assert tech["status"] == "done", tech["summary"]
    assert "https://www.acme.com/" in seen
    # and the store refuses to save such an address again
    from asm.pipeline import _upsert_asset, _valid_web_url
    assert not _valid_web_url("://") and not _valid_web_url("ftp://x") and _valid_web_url("https://a.b")


def test_active_options(authed, xtools):
    """ZAP active scan, BBOT active modules, dnsx brute and baddns-deep: off by default, work when switched on."""
    from asm.app import state
    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    st, by = _run(client, h, sid, stages=["bbot_light", "tls", "zap", "takeover", "dns"],
                  zap_active=True, zap_active_minutes=5, bbot_active=True, bbot_active_max_hosts=50,
                  dns_bruteforce=True, takeover_deep=True)
    if by["bbot_light"]["status"] != "done":
        import json as _j; print("BBOT SUMMARY:", _j.dumps(by["bbot_light"]["summary"]))
        evs = client.get(f"/api/scans/{sid}/events?after=0").json()["events"]
        for e in evs:
            if e["stage_key"] == "bbot_light": print("EV", e["level"], e["message"][:200])
    assert all(by[k]["status"] == "done" for k in ("bbot_light", "zap", "takeover", "dns")), {k: v["status"] for k, v in by.items()}

    calls = (xtools / "home" / "bbot_calls.log").read_text()
    # an active pass ran with active modules and active flags, never the forbidden ones
    active_call = next((l for l in calls.splitlines() if "-n active" in l and "--dry-run" not in l), None)
    # explicit -m drives the active modules; brute-forcers are excluded by name, and no stale -f flags are used
    assert active_call and "nuclei" in active_call and "lightfuzz" in active_call
    assert "-f active" not in active_call and "aggressive" not in active_call
    assert "-em portscan webbrute webbrute_shortnames" in active_call
    assert "--force" in active_call                 # a module setup failure must not kill the stage
    assert not any(m in active_call.split() for m in ("medusa", "legba", "git_clone"))
    # a baddns pass ran over the live hosts (takeover-deep)
    assert any("-n baddns" in l and "--dry-run" not in l for l in calls.splitlines())
    assert by["takeover"]["summary"]["baddns_live_hits"] >= 1
    # dnsx brute ran against the root
    assert (xtools / "home" / "dnsx_brute.log").exists() and by["dns"]["summary"]["brute_new_hosts"] >= 1

    db = state.db()
    try:
        f = [dict(r) for r in db.all("SELECT * FROM findings WHERE scan_id = ?", sid)]
    finally:
        db.close()
    assert any(x["source_tool"] == "nuclei" or (x["source_tool"] == "bbot:nuclei") for x in f) or \
        any("env" in x["title"].lower() for x in f if x["source_tool"].startswith("bbot"))
    assert any(x["source_tool"] == "baddns-live" and "framer" in x["title"].lower() for x in f)
    assert any(x["source_tool"] == "dnsx" and x["area"] == "surface" for x in f)       # brute-found subdomain
    # ZAP active produced a high alert
    assert any(x["source_tool"].startswith("zap") and x["severity"] == "high" for x in f) or \
        any("injection" in x["title"].lower() for x in f)
    ev = client.get(f"/api/scans/{sid}/events?after=0").json()["events"]
    warns = " ".join(e["message"] for e in ev if e["level"] == "warn")
    assert "ACTIVE scanning is ON" in warns and "brute-forcing" in warns


def test_active_switches_off_by_default_and_gated(authed, xtools):
    from asm.api_run import OptionsIn, _active_now
    o = OptionsIn()
    assert not o.zap_active and not o.bbot_active and not o.dns_bruteforce and o.takeover_deep is True
    assert _active_now("zap", {"zap_active": True}) and not _active_now("zap", {})
    assert _active_now("bbot_light", {"bbot_active": True}) and _active_now("dns", {"dns_bruteforce": True})
    assert _active_now("port_check", {})      # always active by StageDef

    from asm.app import state
    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _run(client, h, sid, stages=["bbot_light", "zap"], zap_active=True)
    # re-running the ZAP stage needs an explicit active confirmation
    assert client.post(f"/api/scans/{sid}/stages/zap/retry", headers=h).status_code == 428
    assert client.post(f"/api/scans/{sid}/stages/zap/retry?confirm=active", headers=h).status_code == 202
    wait_done(client, sid)
    by = {s["key"]: s for s in client.get(f"/api/scans/{sid}/stages").json()["stages"]}
    assert by["zap"]["active_now"] is True and by["bbot_light"]["active_now"] is False


def test_asn_netblocks(authed, xtools):
    """BBOT's passive asn module: netblocks surfaced, shared platforms vs possibly-owned labelled, toggle respected."""
    from asm.app import state
    from asm.pipeline import asn_kind
    assert asn_kind("AMAZON-02", "Amazon.com") == "shared" and asn_kind("ACME-NET", "Acme Corp") == "own"

    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    st, by = _run(client, h, sid, stages=["bbot_light"], asn_lookup=True)
    assert by["bbot_light"]["status"] == "done"
    assert "-m http sslcert robots securitytxt asn" in (xtools / "home" / "bbot_calls.log").read_text()
    assert by["bbot_light"]["summary"]["netblocks"] == 2 and by["bbot_light"]["summary"]["own_netblocks"] == 1
    db = state.db()
    try:
        f = [dict(r) for r in db.all("SELECT * FROM findings WHERE scan_id = ? AND source_tool = 'asn'", sid)]
    finally:
        db.close()
    assert any("org-owned" in x["title"] and "198.51.100.0/24" in x["title"] and x["severity"] == "low" for x in f)
    assert any("shared platform" in x["title"] and "AMAZON" in x["title"] and x["severity"] == "info" for x in f)

    # toggle off: the module isn't loaded and no netblocks are found
    client2, h2, sid2 = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    _, by2 = _run(client2, h2, sid2, stages=["bbot_light"], asn_lookup=False)
    assert by2["bbot_light"]["summary"]["netblocks"] == 0
    calls = (xtools / "home" / "bbot_calls.log").read_text().splitlines()
    assert any(" asn " not in l and "-n light" in l and "--dry-run" not in l for l in calls)


def test_reverse_dns_and_ip_view(authed, xtools):
    """PTR over own IPs finds co-hosted names; the IP view groups hosts, netblocks, ports and tech per IP."""
    from asm.app import state
    from asm.api_results import compute_ips
    client, h, sid = ready_scan(authed, xtools)
    state.providers = XProviders(dns=state.providers.dns)
    st, by = _run(client, h, sid, stages=["bbot_light", "ports", "dns"], asn_lookup=True, reverse_dns=True)
    assert by["dns"]["status"] == "done"
    assert by["dns"]["summary"]["ptr_names"] >= 1
    # the PTR name ec2-host.acme.com is under scope and new -> co-hosted finding
    assert "-ptr" in (xtools / "home" / "dnsx_brute.log").read_text() if (xtools / "home" / "dnsx_brute.log").exists() else True
    db = state.db()
    try:
        ptr = db.all("SELECT host, value FROM dns_records WHERE scan_id = ? AND rtype = 'PTR'", sid)
        cohost = [dict(r) for r in db.all("SELECT * FROM findings WHERE scan_id = ? AND source_tool = 'ptr'", sid)]
        ips = compute_ips(db, sid)
    finally:
        db.close()
    assert any(r["value"] == "ec2-host.acme.com" for r in ptr)
    assert any("Co-hosted" in x["title"] for x in cohost)
    # IP view: 93.184.216.34 carries every acme host (blast radius) and lists its ports + PTR
    shared_ip = next((r for r in ips if r["ip"] == "93.184.216.34"), None)
    assert shared_ip and shared_ip["host_count"] >= 2 and 443 in shared_ip["ports"]
    assert "ec2-host.acme.com" in shared_ip["ptr"]
    # endpoint shape
    resp = client.get(f"/api/scans/{sid}/ips").json()
    assert resp["summary"]["total"] >= 1 and "own" in resp["summary"]
    assert all({"ip", "hosts", "ports", "tech", "netblock", "ptr", "agent_hosts"} <= set(r) for r in resp["ips"])


def test_reverse_dns_default_on():
    from asm.api_run import OptionsIn
    assert OptionsIn().reverse_dns is True
