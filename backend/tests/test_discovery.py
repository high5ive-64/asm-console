"""Discovery (stage D1) and scope selection, with fake DNS / crt.sh / WhoisXML and a fake bbot binary."""
import json
import os
import stat
import textwrap

from asgi_client import pump

CRT = [
    {"name_value": "www.acme.com\nacme.com"},
    {"name_value": "shop.acme.com\nacme-store.co.uk\nwww.acme-store.co.uk"},
    {"name_value": "*.dev.acme.com"},
    {"name_value": "status.acme.com"},
    {"name_value": "mail.acme.com\nbob@acme.com"},
    {"name_value": "sni.cloudflaressl.com\nacme.com"},
]
DNS = {
    "acme.com": {"cname": [], "ips": ["203.0.113.1"]},
    "www.acme.com": {"cname": [], "ips": ["203.0.113.1"]},
    "shop.acme.com": {"cname": ["acme.myshopify.com"], "ips": ["23.227.38.1"]},
    "dev.acme.com": {"cname": [], "ips": ["203.0.113.9"]},
    "status.acme.com": {"cname": ["acme.statuspage.io"], "ips": ["1.2.3.4"]},
    "mail.acme.com": None,
    "api.acme.com": {"cname": [], "ips": ["203.0.113.20"]},
}
RECORDS = {
    ("acme.com", "MX"): ["mx1.acmemail.net", "aspmx.l.google.com"],
    ("acme.com", "NS"): ["ns1.cloudflare.com", "ns-520.awsdns-01.net", "ns-1773.awsdns-29.co.uk"],
    ("acme.com", "TXT"): ["v=spf1 include:_spf.google.com include:spf.acme-corp.com include:docebosaas.com ~all", "google-site-verification=x"],
}


class FakeProviders:
    def __init__(self, crt=CRT, dns=DNS, wildcard=False, fail_crt=False):
        self.crt, self.dns, self.wildcard, self.fail_crt = crt, dns, wildcard, fail_crt
        self.urls = []

    async def records(self, name, rtype):
        return RECORDS.get((name, rtype), [])

    async def resolve(self, name):
        if name.startswith("asm-wc-"):
            return {"cname": [], "ips": ["198.51.100.7"]} if self.wildcard else None
        if self.wildcard and name not in self.dns:
            return {"cname": [], "ips": ["198.51.100.7"]}
        return self.dns.get(name)

    async def http_json(self, url, headers=None, data=None, timeout=60):
        self.urls.append(url)
        if "crt.sh" in url:
            if self.fail_crt:
                raise OSError("crt.sh down")
            return self.crt
        if "WhoisService" in url:
            return {"WhoisRecord": {"registrant": {"organization": "Acme Holdings Ltd"}}}
        if "reverse-whois" in url:
            return {"domainsList": ["acme-holdings.com", "acme.com", "acmeplc.co.uk"]}
        raise AssertionError(url)


def setup(authed, providers, use_bbot=False):
    client, h, tmp = authed
    from asm.app import state
    state.providers = providers
    state.use_bbot = use_bbot
    sid = client.post("/api/scans", json={"root_domain": "acme.com"}, headers=h).json()["id"]
    return client, h, sid


def discover(client, h, sid, sources, expand=None):
    body = {"sources": sources}
    if expand:
        body["expand"] = expand
    r = client.post(f"/api/scans/{sid}/discover", json=body, headers=h)
    assert r.status_code == 202, r.text
    assert pump(client, lambda: client.get(f"/api/scans/{sid}").json()["status"] in ("awaiting_scope", "draft"))
    return client.get(f"/api/scans/{sid}/candidates").json()


def by_value(c):
    return {i["value"]: i for i in c["items"]}


def test_discovery_groups_and_related(authed):
    client, h, sid = setup(authed, FakeProviders())
    c = discover(client, h, sid, ["certificates", "dns_infra"])
    assert c["scan"]["status"] == "awaiting_scope"
    items = by_value(c)
    # subdomains, grouped
    assert items["www.acme.com"]["group"] == "resolves" and items["www.acme.com"]["decision"] == "included"
    assert items["shop.acme.com"]["group"] == "third_party"          # CNAME to Shopify
    assert items["status.acme.com"]["group"] == "third_party"
    assert items["mail.acme.com"]["group"] == "no_dns"
    assert items["dev.acme.com"]["group"] == "resolves"              # from *.dev.acme.com
    assert items["acme.com"]["kind"] == "root"
    assert "bob@acme.com" not in items
    # related domains: never pre-included, with reasons
    store = items["acme-store.co.uk"]
    assert store["kind"] == "related" and store["decision"] == "suggested" and store["confidence"] == "high"
    assert any("same certificate as shop.acme.com" in r for r in store["reasons"])
    assert items["acmemail.net"]["confidence"] == "medium" and "dns_infra" in items["acmemail.net"]["sources"]
    # vendors: AWS name servers are third party; a non-brand SPF include is low confidence
    assert "awsdns-01.net" not in items or items["awsdns-01.net"]["third_party"]
    assert "awsdns-29.co.uk" not in items or items["awsdns-29.co.uk"]["third_party"]
    assert items["docebosaas.com"]["confidence"] == "low"
    assert any("likely a vendor" in r for r in items["docebosaas.com"]["reasons"])
    assert items["acme-corp.com"]["decision"] == "suggested"
    # providers are labelled third party and excluded, never suggested
    assert items["cloudflaressl.com"]["third_party"] is True and items["cloudflaressl.com"]["decision"] == "excluded"
    assert "google.com" not in items and "cloudflare.com" not in items  # ignore-listed infra
    stage = c["discovery"]
    assert stage["status"] == "done" and stage["summary"]["related"] >= 3


def test_sources_off_means_no_related(authed):
    client, h, sid = setup(authed, FakeProviders())
    c = discover(client, h, sid, [])
    assert all(i["kind"] != "related" for i in c["items"])
    assert "www.acme.com" in by_value(c)


def test_whois_needs_key_then_works(authed):
    client, h, sid = setup(authed, FakeProviders())
    c = discover(client, h, sid, ["whois"])
    assert "acme-holdings.com" not in by_value(c)
    ev = client.get(f"/api/scans/{sid}/events").json()["events"]
    assert any("no WhoisXML key" in e["message"] for e in ev)
    client.put("/api/secrets/whoisxml", json={"value": "WHOISKEY-123456"}, headers=h)
    c = discover(client, h, sid, ["whois"])
    items = by_value(c)
    assert items["acme-holdings.com"]["confidence"] == "medium"
    assert "registered to Acme Holdings Ltd" in items["acmeplc.co.uk"]["reasons"]
    # key never appears in stored events
    ev = client.get(f"/api/scans/{sid}/events").json()["events"]
    assert all("WHOISKEY-123456" not in e["message"] for e in ev)


def test_wildcard_names_listed_not_hidden(authed):
    dns = dict(DNS); dns.pop("api.acme.com")
    client, h, sid = setup(authed, FakeProviders(crt=CRT + [{"name_value": "random1.acme.com\nrandom2.acme.com"}], dns=dns, wildcard=True))
    c = discover(client, h, sid, [])
    items = by_value(c)
    assert "*.acme.com" not in items
    # names on their own certificate are real hosts even though the domain has wildcard DNS
    assert items["random1.acme.com"]["group"] == "resolves" and items["random1.acme.com"]["decision"] == "included"


def test_wildcard_group_without_ct_evidence():
    import asyncio
    from asm.discovery import Collector, _group_subdomains

    class R:
        def event(self, *a, **k): pass

    col = Collector("acme.com", ["acme.com"], [])
    col.add("guess.acme.com", "subdomain-enum", "found by speculate")
    col.add("cert.acme.com", "subdomain-enum", "found by crt_db")
    col.add("www.acme.com", "subdomain-enum", "found by otx")
    asyncio.run(_group_subdomains(R(), FakeProviders(dns={"www.acme.com": {"cname": [], "ips": ["203.0.113.9"]}}, wildcard=True),
                                  col, "acme.com", []))
    assert col.c["guess.acme.com"].grp == "wildcard"
    assert col.c["cert.acme.com"].grp == "resolves"
    assert col.c["www.acme.com"].grp == "resolves"


def test_crtsh_down_degrades_gracefully(authed, monkeypatch):
    import asm.discovery
    monkeypatch.setattr(asm.discovery, "CRT_BACKOFF_S", 0.01)
    client, h, sid = setup(authed, FakeProviders(fail_crt=True))
    c = discover(client, h, sid, ["certificates"])
    assert c["scan"]["status"] == "awaiting_scope"
    ev = [e["message"] for e in client.get(f"/api/scans/{sid}/events").json()["events"]]
    assert any("Certificate transparency unavailable" in m for m in ev)


def test_scope_patch_rules(authed):
    client, h, sid = setup(authed, FakeProviders())
    discover(client, h, sid, ["certificates", "dns_infra"])
    r = client.request("PATCH", f"/api/scans/{sid}/scope", json={
        "include": ["acme-store.co.uk", "cloudflaressl.com"], "exclude": ["mail.acme.com", "acme.com"],
        "add": ["extra.acme.com", "https://bad"], "exclude_add": ["pay.acme.com"]}, headers=h).json()
    probs = " ".join(r["problems"])
    assert "cloudflaressl.com: third-party" in probs and "acme.com: the root" in probs and "https://bad" in probs
    items = by_value(client.get(f"/api/scans/{sid}/candidates").json())
    assert items["acme-store.co.uk"]["decision"] == "included"
    assert items["cloudflaressl.com"]["decision"] == "excluded"
    assert items["mail.acme.com"]["decision"] == "excluded"
    assert items["extra.acme.com"]["kind"] == "subdomain" and items["extra.acme.com"]["decision"] == "included"
    assert items["pay.acme.com"]["kind"] == "exclusion"
    # user decisions survive a re-run of discovery
    discover(client, h, sid, ["certificates"])
    items = by_value(client.get(f"/api/scans/{sid}/candidates").json())
    assert items["mail.acme.com"]["decision"] == "excluded" and items["acme-store.co.uk"]["decision"] == "included"


def test_expand_requires_included_related(authed):
    client, h, sid = setup(authed, FakeProviders())
    discover(client, h, sid, ["certificates"])
    r = client.post(f"/api/scans/{sid}/discover", json={"sources": [], "expand": "acme-store.co.uk"}, headers=h)
    assert r.status_code == 409
    client.request("PATCH", f"/api/scans/{sid}/scope", json={"include": ["acme-store.co.uk"]}, headers=h)
    crt = [{"name_value": "www.acme-store.co.uk\nshop.acme-store.co.uk"}]
    from asm.app import state
    state.providers = FakeProviders(crt=crt, dns={**DNS, "www.acme-store.co.uk": {"cname": [], "ips": ["203.0.113.50"]}})
    c = discover(client, h, sid, [], expand="acme-store.co.uk")
    items = by_value(c)
    assert items["www.acme-store.co.uk"]["kind"] == "subdomain" and items["www.acme-store.co.uk"]["decision"] == "included"
    assert items["acme-store.co.uk"]["kind"] == "related"  # unchanged


def test_confirm_scope(authed):
    client, h, sid = setup(authed, FakeProviders())
    assert client.post(f"/api/scans/{sid}/scope/confirm", headers=h).status_code == 409
    discover(client, h, sid, ["certificates"])
    client.request("PATCH", f"/api/scans/{sid}/scope", json={"include": ["acme-store.co.uk"]}, headers=h)
    r = client.post(f"/api/scans/{sid}/scope/confirm", headers=h).json()
    assert set(r["roots"]) == {"acme.com", "acme-store.co.uk"} and r["hosts"] >= 3
    assert client.get(f"/api/scans/{sid}").json()["status"] == "scope_confirmed"
    # editing scope again un-confirms
    client.request("PATCH", f"/api/scans/{sid}/scope", json={"exclude": ["www.acme.com"]}, headers=h)
    assert client.get(f"/api/scans/{sid}").json()["status"] == "awaiting_scope"


def test_unknown_source_and_double_start(authed):
    client, h, sid = setup(authed, FakeProviders())
    assert client.post(f"/api/scans/{sid}/discover", json={"sources": ["portscan"]}, headers=h).status_code == 422


def test_bbot_runs_through_allowlist_and_is_parsed(authed, tmp_path, monkeypatch):
    """A fake bbot binary proves the real command path: allowlist, subprocess, NDJSON parsing, affiliates."""
    bindir = tmp_path / "bin"; bindir.mkdir()
    fake = bindir / "bbot"
    fake.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import json, sys, os
        a = sys.argv[1:]
        out = a[a.index("-o") + 1]; name = a[a.index("-n") + 1]
        assert "--no-deps" in a and "passive" in a and "portscan" in a and "--no-color" in a
        ef = a[a.index("-ef") + 1:]
        assert {"invasive", "loud", "download"} <= set(ef) and "deadly" not in a
        d = os.path.join(out, name); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "output.json"), "w") as f:
            for host, tags in [("api.acme.com", []), ("vpn.acme.com", []), ("acmepartners.io", ["affiliate"])]:
                f.write(json.dumps({"type": "DNS_NAME", "data": host, "tags": tags, "module": "fakemod"}) + "\\n")
            f.write("not json\\n")
        print("\\x1b[1;38;5;69m[INFO]\\x1b[0m fake bbot finished")
    """))
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    import asm.discovery
    monkeypatch.setattr(asm.discovery, "bbot_key_modules", lambda: {"shodan": ["shodan_dns"]})
    client, h, sid = setup(authed, FakeProviders(), use_bbot=True)
    client.put("/api/secrets/shodan", json={"value": "SHODAN-SECRET-999"}, headers=h)
    c = discover(client, h, sid, ["affiliates"])
    items = by_value(c)
    assert items["api.acme.com"]["group"] == "resolves" and "found by fakemod" in items["api.acme.com"]["reasons"]
    assert items["acmepartners.io"]["kind"] == "related" and items["acmepartners.io"]["confidence"] == "low"
    ev = [e for e in client.get(f"/api/scans/{sid}/events").json()["events"]]
    assert any(e["level"] == "cmd" and e["message"].startswith("$ bbot -t ") for e in ev)
    assert any(e["message"] == "[INFO] fake bbot finished" for e in ev)  # colour codes stripped
    assert any(e["message"] == "BBOT API keys configured for: shodan_dns" for e in ev)
    # API key went to the config file (mode 600), never onto the command line or into events
    cfg = tmp_path / "home" / ".config" / "bbot" / "bbot.yml"
    assert oct(cfg.stat().st_mode)[-3:] == "600" and "SHODAN-SECRET-999" in cfg.read_text()
    assert all("SHODAN-SECRET-999" not in e["message"] for e in ev)


def test_bbot_key_modules_reads_installed_modules(tmp_path, monkeypatch):
    """Only modules that exist and take an api_key (directly or via a template) get a key."""
    import importlib.util, types
    import asm.discovery as d
    pkg = tmp_path / "bbot"; (pkg / "modules" / "templates").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    T = pkg / "modules" / "templates"
    (T / "subdomain_enum.py").write_text("class subdomain_enum(BaseModule):\n    pass\nclass subdomain_enum_apikey(subdomain_enum):\n    options = {'api_key': ''}\n")
    (T / "github.py").write_text("class github(BaseModule):\n    options = {'api_key': ''}\n")
    (T / "bucket.py").write_text("class bucket_template(BaseModule):\n    pass\n")
    M = pkg / "modules"
    (M / "censys_ip.py").write_text("options = {'api_key': ''}")
    (M / "censys_dns.py").write_text("class censys_dns(subdomain_enum_apikey):\n    pass")
    (M / "virustotal.py").write_text("from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey\nclass virustotal(subdomain_enum_apikey):\n    pass")
    (M / "github_codesearch.py").write_text("class github_codesearch(github, subdomain_enum):\n    pass")
    (M / "shodan_dns.py").write_text("class shodan_dns(shodan):\n    options = {'api_key': ''}")
    (M / "shodan_idb.py").write_text("class shodan_idb(BaseModule):\n    options = {}")        # free, no key
    (M / "crt.py").write_text("class crt(subdomain_enum):\n    pass")
    spec = types.SimpleNamespace(origin=str(pkg / "__init__.py"))
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: spec if name == "bbot" else None)
    m = d.bbot_key_modules()
    assert m == {"censys": ["censys_dns", "censys_ip"], "github": ["github_codesearch"],
                 "shodan": ["shodan_dns"], "virustotal": ["virustotal"]}
