"""Guardrail unit tests: scope filter, domain validation, command allowlist, secrets crypto."""
import os
from pathlib import Path

import pytest

from asm.allowlist import CommandRejected, Ctx, FORBIDDEN_BINARIES, validate
from asm.scope import ScopeError, host_of, in_scope, normalise_domain


# ---- scope ----------------------------------------------------------------

def test_in_scope_exact_and_subdomains():
    items = ["www.acme.com", "acme.com", "https://dev.acme.com:8443/x", "notacme.com",
             "acme.com.evil.io", "pay.acme.com", "a.pay.acme.com", "shop.acme.co.uk", "x.other.org"]
    got = in_scope(items, ["acme.com", "acme.co.uk"], ["pay.acme.com"])
    assert got == ["www.acme.com", "acme.com", "https://dev.acme.com:8443/x", "shop.acme.co.uk"]


def test_host_of_variants():
    assert host_of("HTTPS://User@Www.Acme.com:443/path?q") == "www.acme.com"
    assert host_of("www.acme.com.\textra") == "www.acme.com"
    assert host_of("http://[2001:db8::1]:8080/") == "2001:db8::1"


@pytest.mark.parametrize("bad", ["http://a.com", "a.com/x", "*.a.com", "a.com:443", "1.2.3.4", "localhost",
                                 "-a.com", "a..com", "a b.com", "a.c", "", "user@a.com"])
def test_normalise_domain_rejects(bad):
    with pytest.raises(ScopeError):
        normalise_domain(bad)


def test_normalise_domain_ok():
    assert normalise_domain(" WWW.Example.CO.UK. ") == "www.example.co.uk"
    assert normalise_domain("münchen.de") == "xn--mnchen-3ya.de"


# ---- allowlist ------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path):
    run = tmp_path / "runs" / "r1"
    run.mkdir(parents=True)
    return Ctx(allowed_dirs=[run]), run


@pytest.fixture
def run_dir(tmp_path):
    run = tmp_path / "runs" / "ra"
    run.mkdir(parents=True)
    (run / "w.txt").write_text("www\napi\n")
    return run


def test_forbidden_binaries(ctx):
    c, _ = ctx
    for b in sorted(FORBIDDEN_BINARIES):
        with pytest.raises(CommandRejected):
            validate([b, "-h"], c)
    with pytest.raises(CommandRejected):
        validate(["/usr/bin/nmap", "-sV", "x.com"], c)
    with pytest.raises(CommandRejected):
        validate(["unknowntool"], c)


def test_bbot_safe_command_passes(ctx):
    c, run = ctx
    validate(["bbot", "-t", str(run / "roots.txt"), "-b", str(run / "bl.txt"), "-p", "subdomain-enum", "cloud-enum",
              "-rf", "passive", "-ef", "invasive", "loud", "download", "web-heavy", "-em", "portscan", "-om", "json", "csv",
              "-o", str(run / "bbot"), "-n", "passive", "-c", "web.user_agent=Mozilla/5.0 X", "-y", "--dry-run",
              "--no-color", "-s", "acme.com", "--strict-scope"], c)


@pytest.mark.parametrize("extra", [
    ["-m", "portscan"], ["-m", "nuclei"], ["-m", "ffuf"], ["-f", "aggressive"], ["-rf", "deadly"],
    ["--allow-deadly"], ["-p", "kitchen-sink"], ["-p", "web-thorough"], ["-c", "modules.nuclei.mode=severe"],
    ["-p", "webbrute"], ["-p", "waf-bypass"], ["-p", "lightfuzz"], ["-p", "nuclei"], ["-p", "virtualhost"],
    ["-m", "webbrute"], ["-m", "waf_bypass"], ["-m", "baddns_zone"], ["-w", "acme.com"],
    ["-m", "legba"], ["-m", "medusa"], ["-m", "dnsbrute"], ["-f", "invasive"], ["-f", "loud"], ["-rf", "loud"],
    ["-om", "http"], ["-o", "/etc"], ["-t", "../../etc/passwd"],
])
def test_bbot_rejections(ctx, extra):
    c, run = ctx
    with pytest.raises(CommandRejected):
        validate(["bbot", "-t", "acme.com", "-y", *extra], c)


def test_bbot_requires_target(ctx):
    c, _ = ctx
    with pytest.raises(CommandRejected):
        validate(["bbot", "-p", "subdomain-enum"], c)
    validate(["bbot", "--version"], c)


def test_zap_plan_rules(ctx):
    c, run = ctx
    validate(["zap.sh", "-cmd", "-autorun", str(run / "zap" / "plan.yaml"),
              "-config", "network.connection.defaultUserAgent=Mozilla/5.0 X"], c)
    for bad in (["-daemon"], ["-quickurl", "https://x.com"], ["-autorun", "/tmp/evil.yaml"],
                ["-autorun", str(run / "plan.txt")], ["-config", "api.disablekey=true"], ["-addoninstall", "x"]):
        with pytest.raises(CommandRejected):
            validate(["zap.sh", "-cmd", *bad], c)


def test_tlsx_limits(ctx):
    c, run = ctx
    validate(["tlsx", "-l", str(run / "h.txt"), "-p", "443", "-c", "25", "-tv", "-ex", "-ss", "-mm", "-json",
              "-silent", "-o", str(run / "tls.json")], c)
    for bad in (["-c", "500"], ["-p", "1-65535"], ["-o", "/root/x"], ["-sni", "x"]):
        with pytest.raises(CommandRejected):
            validate(["tlsx", "-l", str(run / "h.txt"), *bad], c)


def test_gau_dnstwist_dig(ctx):
    c, run = ctx
    validate(["gau", "--subs", "--threads", "5", "--providers", "wayback,otx", "--o", str(run / "g.txt"), "acme.com"], c)
    with pytest.raises(CommandRejected):
        validate(["gau", "--providers", "evil", "acme.com"], c)
    with pytest.raises(CommandRejected):
        validate(["gau", "http://acme.com/x"], c)
    validate(["dnstwist", "--registered", "--format", "json", "acme.com"], c)
    with pytest.raises(CommandRejected):
        validate(["dnstwist", "--registered", "acme.com", "other.com"], c)
    validate(["dig", "+short", "TXT", "_dmarc.acme.com"], c)
    validate(["dig", "+short", "MX", "acme.com"], c)
    for bad in (["dig", "+short", "AXFR", "acme.com"], ["dig", "@8.8.8.8", "acme.com"], ["dig", "+short", "TXT", "a;b"]):
        with pytest.raises(CommandRejected):
            validate(bad, c)


def test_flag_smuggling_and_control_chars(ctx):
    c, run = ctx
    with pytest.raises(CommandRejected):
        validate(["tlsx", "-l", "-o"], c)
    with pytest.raises(CommandRejected):
        validate(["dnstwist", "acme.com\n-rf"], c)
    with pytest.raises(CommandRejected):
        validate(["bbot", "-t", "acme.com", "-n", "x;rm -rf"], c)


def test_path_traversal_rejected(ctx):
    c, run = ctx
    with pytest.raises(CommandRejected):
        validate(["uro", "-i", str(run / ".." / ".." / "secret"), "-o", str(run / "o.txt")], c)


# ---- secrets --------------------------------------------------------------

def test_secret_store_roundtrip_and_aad(tmp_path):
    from asm.db import DB, migrate
    from asm.secrets_store import SecretError, SecretStore, load_or_create_master_key, mask
    db_path = tmp_path / "t.db"
    migrate(db_path)
    key = load_or_create_master_key(tmp_path / "k" / "master.key")
    assert oct((tmp_path / "k" / "master.key").stat().st_mode)[-3:] == "600"
    assert load_or_create_master_key(tmp_path / "k" / "master.key") == key
    db = DB(db_path)
    s = SecretStore(db, key)
    s.set("shodan", "abc123secret")
    assert s.get("shodan") == "abc123secret"
    # ciphertext swapped to another name fails authentication (name is associated data)
    row = db.one("SELECT ciphertext, nonce FROM secrets WHERE name='shodan'")
    db.run("INSERT INTO secrets (name, ciphertext, nonce, updated_at) VALUES ('github', ?, ?, 'x')", row["ciphertext"], row["nonce"])
    with pytest.raises(Exception):
        s.get("github")
    with pytest.raises(SecretError):
        s.set("shodan", "bad\nvalue")
    with pytest.raises(SecretError):
        s.set("nope", "x")
    assert mask("key=abc123secret here", ["abc123secret"]) == "key=**** here"
    db.close()


def test_active_modules_need_authorised_active_pass(run_dir):
    """ACTIVE-tier modules/flags are rejected on a passive ctx and allowed only when allow_active is set.
    The NEVER tier (credential brute, data-pull, zone walk) stays blocked even on an active pass."""
    from asm.allowlist import Ctx, validate, CommandRejected, ACTIVE_BBOT_MODULES, NEVER_BBOT_MODULES
    passive = Ctx(allowed_dirs=[run_dir])
    active = Ctx(allowed_dirs=[run_dir], allow_active=True)
    for m in ("nuclei", "ffuf", "dnsbrute", "paramminer_getparams", "badsecrets", "git", "hunt", "ntlm"):
        assert m in ACTIVE_BBOT_MODULES
        with pytest.raises(CommandRejected):
            validate(["bbot", "-t", "acme.com", "-m", m, "-y"], passive)
        validate(["bbot", "-t", "acme.com", "-m", m, "-y"], active)        # allowed now (allow_active)
    # the exact active-pass command (explicit -m, no -f flag selection) must validate on an active pass
    from asm.pipeline import ACTIVE_PASS_MODULES
    validate(["bbot", "-t", "acme.com", "-m", *ACTIVE_PASS_MODULES,
              "-em", "portscan", "webbrute", "webbrute_shortnames", "-y"], active)
    # the dead 2.x flag names are no longer accepted
    with pytest.raises(CommandRejected):
        validate(["bbot", "-t", "acme.com", "-m", "nuclei", "-f", "active", "aggressive", "-y"], active)
    # NEVER tier stays blocked on an active pass too
    for m in ("medusa", "legba", "git_clone", "baddns_zone"):
        assert m in NEVER_BBOT_MODULES
        with pytest.raises(CommandRejected):
            validate(["bbot", "-t", "acme.com", "-m", m, "-y"], active)
    # dnsx subdomain brute flags are allowed (the stage is gated, the tool is not)
    validate(["dnsx", "-d", "acme.com", "-w", str(run_dir / "w.txt"), "-a", "-json", "-o", str(run_dir / "o")], passive)
