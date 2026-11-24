"""Validated, non-secret application settings with defaults."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

DEFAULT_THIRD_PARTY = [
    "cloudflare.com", "cloudflare.net", "cloudflaressl.com", "cloudflare-dns.com", "incapsula.com", "impervadns.net",
    "sucuri.net", "edgecastcdn.net", "b-cdn.net", "kxcdn.com", "stackpathdns.com", "azurefd.net", "msedge.net", "akamai.net", "akamaiedge.net", "akamaihd.net", "edgekey.net",
    "fastly.net", "cloudfront.net", "amazonaws.com", "azureedge.net", "azurewebsites.net",
    "trafficmanager.net", "googleusercontent.com", "googlehosted.com", "ghs.googlehosted.com",
    "herokuapp.com", "herokudns.com", "github.io", "netlify.app", "vercel.app", "vercel-dns.com",
    "shopify.com", "myshopify.com", "hubspot.net", "hs-sites.com", "wpengine.com", "zendesk.com",
    "freshdesk.com", "salesforce.com", "force.com", "squarespace.com", "wixdns.net", "webflow.io",
    "pantheonsite.io", "statuspage.io", "atlassian.net", "outlook.com", "office365.com",
    "google.com", "googlemail.com", "mailgun.org", "sendgrid.net", "mandrillapp.com",
    "domaincontrol.com", "googledomains.com", "nsone.net", "dynect.net", "ultradns.com", "ultradns.net",
    "ultradns.org", "ultradns.biz", "akam.net", "dnsmadeeasy.com", "cloudns.net", "registrar-servers.com",
    "name-services.com", "worldnic.com", "gandi.net", "ovh.net", "hetzner.com", "digitalocean.com",
    "linode.com", "vultr.com", "mimecast.com", "pphosted.com", "ppe-hosted.com", "messagelabs.com",
    "barracudanetworks.com", "zoho.com", "zoho.eu", "protonmail.ch", "amazonses.com", "sparkpostmail.com",
    "mailchimp.com", "mcsv.net", "mailjet.com", "postmarkapp.com", "spf.protection.outlook.com",
]


DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; Outsider-ASM)"
OLD_DEFAULT_USER_AGENTS = {"Mozilla/5.0 (compatible; ASM-Console)"}


DEFAULT_TIMEOUTS = {
    "discovery": 90, "bbot_light": 90, "zap": 240, "tls": 30, "ports": 30,
    "email": 10, "gau": 30, "lookalikes": 30, "hibp": 10, "cloud": 15, "consolidate": 10,
    "cdn": 5, "takeover": 30, "tls_deep": 60, "cloudlist": 15, "intel": 20, "feeds": 10, "squat": 20,
    "urlscan": 10, "spiderfoot": 120, "tech": 20, "dns": 15, "port_check": 30, "screenshots": 90, "reenrich": 60,
}


class Settings(BaseModel):
    user_agent: str = Field(DEFAULT_USER_AGENT, min_length=8, max_length=300)
    company_name: str = Field("", max_length=120)
    tlsx_concurrency: int = Field(25, ge=1, le=50)
    zap_spider_minutes: int = Field(3, ge=1, le=30)
    zap_ajax_minutes: int = Field(3, ge=1, le=30)
    zap_ajax_hosts: str = Field("spa", pattern=r"^(spa|all|none)$")   # spa: AJAX-crawl JS SPA hosts only; all: every host; none: never
    shodan_lookups: bool = True
    spiderfoot_url: str = Field("http://spiderfoot:5001", max_length=200, pattern=r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?/?$")
    stage_timeout_minutes: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))
    third_party_providers: list[str] = Field(default_factory=lambda: list(DEFAULT_THIRD_PARTY))
    large_scope_warning: int = Field(500, ge=10, le=100000)

    @field_validator("user_agent", "company_name")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("control characters are not allowed")
        return v.strip()

    @field_validator("stage_timeout_minutes")
    @classmethod
    def sane_timeouts(cls, v: dict[str, int]) -> dict[str, int]:
        v = {**DEFAULT_TIMEOUTS, **v}   # stages added in later versions get their default
        for k, m in v.items():
            if not 1 <= int(m) <= 1440:
                raise ValueError(f"timeout for {k} must be 1-1440 minutes")
        return v

    @field_validator("third_party_providers")
    @classmethod
    def clean_providers(cls, v: list[str]) -> list[str]:
        out = sorted({p.strip().lower().rstrip(".") for p in v if p.strip()})
        if len(out) > 2000:
            raise ValueError("too many provider domains")
        return out
