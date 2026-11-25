"""Redaction coverage for the share pack: hosts, IPv4, IPv6 and whole emails are pseudonymised.

Covers the MEDIUM finding: IPv6 addresses and email local-parts previously survived into the
'safe to send' share-zip.
"""
from asm.reports import Redactor


def test_off_is_passthrough():
    s = "api.example.com 203.0.113.5 2001:db8::1 a.b@example.com"
    assert Redactor(False).text(s) == s


def test_hosts_ipv4_ipv6_emails_pseudonymised():
    R = Redactor(True)
    out = R.text("see api.example.com at 203.0.113.5 / 2001:db8::1, contact john.doe@example.com")
    for leak in ("api.example.com", "203.0.113.5", "2001:db8::1", "john.doe@example.com", "john.doe"):
        assert leak not in out, out
    assert "email-01" in out and "asset-01" in out and "ip-" in out


def test_email_localpart_never_survives():
    out = Redactor(True).text("alerts+sec@corp.example.co.uk raised it")
    assert "alerts" not in out and "@corp" not in out and "email-01" in out


def test_non_ip_colon_tokens_untouched():
    out = Redactor(True).text("at 12:34:56, mac 00:1b:44:11:3a:b7")
    assert "12:34:56" in out and "00:1b:44:11:3a:b7" in out


def test_stable_pseudonyms():
    R = Redactor(True)
    a = R.text("host one.example.com")
    b = R.text("host one.example.com again")
    assert R._host["one.example.com"] in a and R._host["one.example.com"] in b
