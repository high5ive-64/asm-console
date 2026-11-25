"""SSRF guard on outbound page fetches (discovery._resolved_ips_public + redirect handler).

Covers the HIGH finding: http_page followed redirects with no IP re-validation, so a scanned
target could redirect the fetch to an internal/metadata address.
"""
import socket
import urllib.error

import pytest

from asm import discovery


def _addr(ip):
    return lambda host, port=None, *a, **k: [(2, 1, 6, "", (ip, 0))]


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "192.168.1.1", "172.16.0.1"])
def test_private_and_metadata_blocked(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", _addr(ip))
    assert discovery._resolved_ips_public("target.example") is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_allowed(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", _addr(ip))
    assert discovery._resolved_ips_public("target.example") is True


def test_mixed_resolution_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0)), (2, 1, 6, "", ("127.0.0.1", 0))])
    assert discovery._resolved_ips_public("rebind.example") is False


def test_nxdomain_is_false(monkeypatch):
    def boom(*a, **k):
        raise OSError("nxdomain")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert discovery._resolved_ips_public("nope.example") is False


def test_redirect_to_internal_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _addr("127.0.0.1"))
    h = discovery._PublicOnlyRedirectHandler()
    with pytest.raises(urllib.error.URLError):
        h.redirect_request(None, None, 302, "Found", {}, "http://evil.example/redir")


def test_redirect_nonhttp_scheme_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _addr("8.8.8.8"))
    h = discovery._PublicOnlyRedirectHandler()
    with pytest.raises(urllib.error.URLError):
        h.redirect_request(None, None, 302, "Found", {}, "file:///etc/passwd")
