"""HTTP-level tests: auth, CSRF, Host/Origin, secrets never returned, settings, scans, CMDB."""


def test_health_public(app_env):
    client, _, _ = app_env
    assert client.get("/api/health").status_code == 200


def test_api_requires_login(app_env):
    client, _, _ = app_env
    assert client.get("/api/about").status_code == 401
    assert client.get("/api/settings").status_code == 401


def test_bad_token_rejected(app_env):
    client, _, _ = app_env
    r = client.post("/api/auth/login", json={"token": "wrong-token-xxxxxxxx"})
    assert r.status_code == 401
    assert "asm_session" not in client.cookies


def test_login_sets_httponly_strict_cookie(app_env):
    client, token, _ = app_env
    r = client.post("/api/auth/login", json={"token": token})
    assert r.status_code == 200
    sess = next(c for c in r.set_cookies if c.startswith("asm_session="))
    assert "HttpOnly" in sess and "SameSite=strict" in sess.replace("Strict", "strict")
    assert client.get("/api/about").status_code == 200


def test_host_header_rebinding_blocked(authed):
    client, h, _ = authed
    assert client.get("/api/about", host="evil.example.com").status_code == 421
    assert client.get("/api/health", host="attacker.test:8443").status_code == 421
    assert client.get("/api/about", host="127.0.0.1:8443").status_code == 200


def test_cross_origin_blocked(authed):
    client, h, _ = authed
    r = client.put("/api/settings", json={"user_agent": "Mozilla/5.0 x"}, headers={**h, "origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.get("/api/about", headers={"origin": "null"})
    assert r.status_code == 403


def test_csrf_required_for_writes(authed):
    client, h, _ = authed
    assert client.put("/api/settings", json={"user_agent": "Mozilla/5.0 test"}).status_code == 403
    assert client.put("/api/settings", json={"user_agent": "Mozilla/5.0 test"}, headers={"x-csrf-token": "nope"}).status_code == 403
    r = client.put("/api/settings", json={"user_agent": "Mozilla/5.0 test"}, headers=h)
    assert r.status_code == 200 and r.json()["user_agent"] == "Mozilla/5.0 test"


def test_settings_validation(authed):
    client, h, _ = authed
    r = client.put("/api/settings", json={"tlsx_concurrency": 500}, headers=h)
    assert r.status_code == 422
    r = client.put("/api/settings", json={"user_agent": "bad\nagent value"}, headers=h)
    assert r.status_code == 422


def test_security_headers(authed):
    client, h, _ = authed
    r = client.get("/api/about")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_secrets_write_only(authed):
    client, h, tmp = authed
    value = "SHODANKEY-1234567890-abcdef"
    r = client.put("/api/secrets/shodan", json={"value": value}, headers=h)
    assert r.status_code == 200 and value not in r.text
    r = client.get("/api/secrets")
    assert value not in r.text
    shodan = next(s for s in r.json()["secrets"] if s["name"] == "shodan")
    assert shodan["set"] is True
    # not stored in plaintext anywhere in the data folder
    for f in (tmp / "data").rglob("*"):
        if f.is_file():
            assert value.encode() not in f.read_bytes(), f
    assert client.delete("/api/secrets/shodan", headers=h).json()["set"] is False


def test_unknown_secret_name(authed):
    client, h, _ = authed
    assert client.put("/api/secrets/../../etc", json={"value": "x"}, headers=h).status_code in (404, 405)
    assert client.put("/api/secrets/notaservice", json={"value": "abc"}, headers=h).status_code == 404


def test_logout_invalidates_session(authed):
    client, h, _ = authed
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/about").status_code == 401


def test_scan_create_validates_domain(authed):
    client, h, tmp = authed
    for bad in ["https://example.com", "example.com/path", "*.example.com", "1.2.3.4", "localhost", "a b.com"]:
        assert client.post("/api/scans", json={"root_domain": bad}, headers=h).status_code == 422, bad
    r = client.post("/api/scans", json={"root_domain": "Example.COM."}, headers=h)
    assert r.status_code == 201
    scan = r.json()
    assert scan["root_domain"] == "example.com" and scan["status"] == "draft"
    assert client.get(f"/api/scans/{scan['id']}").status_code == 200
    assert len(client.get("/api/scans").json()["scans"]) == 1
    assert client.delete(f"/api/scans/{scan['id']}", headers=h).status_code == 200
    assert client.get(f"/api/scans/{scan['id']}").status_code == 404


def test_cmdb_import(authed):
    client, h, _ = authed
    data = b"host,ip\nwww.acme.com,1.2.3.4\nshop.acme.com;not a host\n# comment\nWWW.ACME.COM\n"
    r = client.post("/api/cmdb/import", data=data, headers=h)
    assert r.status_code == 200
    j = r.json()
    assert j["total"] == 3 and j["skipped"] >= 2
    assert {e["value"] for e in client.get("/api/cmdb").json()["entries"]} == {"www.acme.com", "1.2.3.4", "shop.acme.com"}


def test_spa_fallback_and_api_404(authed):
    client, h, _ = authed
    assert client.get("/api/nope").status_code == 404
    assert client.get("/settings").status_code == 200
