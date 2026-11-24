"""Scope rules: domain validation and the single in_scope() filter every stage uses."""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{LABEL}\.)+[a-z][a-z0-9-]{{1,62}}$")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


class ScopeError(ValueError):
    pass


def normalise_domain(value: str) -> str:
    """Return a lower-case hostname or raise. Rejects schemes, paths, ports, IPs, wildcards."""
    v = value.strip().lower().rstrip(".")
    if SCHEME_RE.match(v) or any(c in v for c in "/:?#@ *\\"):
        raise ScopeError("enter a bare domain name, e.g. example.com")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("invalid internationalised domain name") from exc
    if len(v) > 253 or not DOMAIN_RE.match(v):
        raise ScopeError("not a valid domain name")
    return v


def host_of(value: str) -> str:
    """Extract the host from a hostname, URL or 'host<TAB>extra' line."""
    h = value.strip().lower()
    h = SCHEME_RE.sub("", h)
    h = re.split(r"[\s/?#]", h, maxsplit=1)[0]
    if h.startswith("["):  # [ipv6]:port
        return h[1:].split("]", 1)[0]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    return h.rstrip(".")


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def in_scope(items: Iterable[str], roots: Iterable[str], exclusions: Iterable[str] = ()) -> list[str]:
    """Keep items whose host equals or is a subdomain of a root, minus excluded hosts/subtrees.

    Unlike substring matching, 'notexample.com' is not under 'example.com', and
    'example.com.evil.io' is not either.
    """
    r = [d.lower().rstrip(".") for d in roots if d.strip()]
    x = [d.lower().rstrip(".") for d in exclusions if d.strip()]
    out = []
    for item in items:
        h = host_of(item)
        if not h or any(_under(h, e) for e in x):
            continue
        if any(_under(h, d) for d in r):
            out.append(item)
    return out


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global
