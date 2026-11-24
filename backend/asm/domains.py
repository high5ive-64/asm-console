"""Domain helpers: approximate registrable domain and third-party matching.

Without a full Public Suffix List (which needs a download), registrable_domain() handles the
common multi-label suffixes. Edge cases only affect which name a related-domain suggestion is
shown under; scope enforcement never depends on this.
"""
from __future__ import annotations

MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "nhs.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "co.kr", "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk",
    "com.sg", "com.my", "co.in", "co.za", "co.il", "com.ua", "co.id", "com.ph", "com.tw", "com.vn",
    "com.pl", "com.es", "com.pt", "co.at", "or.at",
}


def registrable_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def under(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


import re

# Infrastructure providers whose names follow patterns rather than a fixed domain list
THIRD_PARTY_PATTERNS = [
    re.compile(r"(^|\.)awsdns-\d+\.(com|net|org|co\.uk)$"),        # AWS Route 53 name servers
    re.compile(r"(^|\.)azure-dns\.(com|net|org|info)$"),            # Azure DNS
    re.compile(r"(^|\.)ns\d*\.cloudflare\.com$"),
]


def is_third_party(host: str, providers: list[str]) -> bool:
    h = host.lower().rstrip(".")
    return any(under(h, p) for p in providers) or any(p.search(h) for p in THIRD_PARTY_PATTERNS)


def brand_label(domain: str) -> str:
    """'miro' for miro.com, 'acme' for acme.co.uk."""
    reg = registrable_domain(domain)
    return reg.split(".")[0]


def shares_brand(host: str, domain: str) -> bool:
    b = brand_label(domain)
    return len(b) >= 3 and b in registrable_domain(host).split(".")[0]
