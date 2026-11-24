"""Encrypted API-key storage (AES-256-GCM). Values are write-only from the API's point of view."""
from __future__ import annotations

import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .db import DB, now

# Tool keys the app knows about. AI provider keys use the prefix "ai:".
# tier: "free" (free account key), "freemium" (free tier, paid tiers add more), "paid" (needs a paid plan)
SECRET_INFO: dict[str, dict] = {
    "shodan": {"label": "Shodan", "tier": "freemium", "group": "intel",
               "note": "Free key: host lookups (banners, versions, CVEs). Search needs the one-time $49 membership (paid).",
               "signup": "https://account.shodan.io/register"},
    "leakix": {"label": "LeakIX", "tier": "free", "group": "intel",
               "note": "Free key: ~50 searches a day. Exposed services and data leaks seen on your domains.",
               "signup": "https://leakix.net/auth/register"},
    "netlas": {"label": "Netlas", "tier": "freemium", "group": "intel",
               "note": "Free key: 50 requests a day, used sparingly (5 per scan by default). Paid plans from ~$49/month raise the quota.",
               "signup": "https://app.netlas.io/registration/"},
    "nvd": {"label": "NVD API key (NIST)", "tier": "free", "group": "intel",
            "note": "Optional. Raises the NVD CVE-enrichment rate limit (CVSS, CWE, affected versions) from ~5 to ~50 "
                    "requests/30s. CVE enrichment works without a key, just slower on the first scan.",
            "signup": "https://nvd.nist.gov/developers/request-an-api-key"},
    "urlscan": {"label": "urlscan.io", "tier": "free", "group": "intel",
                "note": "Free key: ~1,000 searches a day. Search only; Outsider ASM never submits scans. Works without a key at a lower rate.",
                "signup": "https://urlscan.io/user/signup"},
    "hibp": {"label": "Have I Been Pwned", "tier": "paid", "group": "intel",
             "note": "Breach exposure for your domains (domain must be verified on HIBP). Paid subscription.",
             "signup": "https://haveibeenpwned.com/API/Key"},
    "xposedornot": {"label": "XposedOrNot (domain key)", "tier": "free", "group": "intel",
                    "note": "Free per-domain breach exposure (verify the domain on XposedOrNot to get a key). "
                            "Known-breach lookups per domain work without any key.",
                    "signup": "https://xposedornot.com/data-breaches-dashboard"},
    "opensquat": {"label": "openSquat premium", "tier": "paid", "group": "intel",
                  "note": "Optional premium feed/API key. The free community feed is used without it.",
                  "signup": "https://opensquat.com"},
    "censys": {"label": "Censys (API_ID:SECRET)", "tier": "freemium", "group": "discovery",
               "note": "Certificate and host search for discovery. Format API_ID:SECRET."},
    "securitytrails": {"label": "SecurityTrails", "tier": "freemium", "group": "discovery",
                       "note": "Historical DNS for subdomain discovery."},
    "virustotal": {"label": "VirusTotal", "tier": "free", "group": "discovery", "note": "Passive DNS for subdomain discovery."},
    "chaos": {"label": "Chaos (ProjectDiscovery)", "tier": "free", "group": "discovery",
              "note": "ProjectDiscovery's public subdomain dataset."},
    "github": {"label": "GitHub personal access token (read-only)", "tier": "free", "group": "discovery",
               "note": "Finds your organisation's public code repositories and leaked references."},
    "whoisxml": {"label": "WhoisXML (reverse WHOIS)", "tier": "paid", "group": "discovery",
                 "note": "Reverse WHOIS for the related-domains source."},
    # Read-only cloud credentials for cloudlist (and dnsReaper's Cloudflare zone check). Optional: you can upload
    # cloudlist output instead and store nothing here.
    "cloud_aws": {"label": "AWS (ACCESS_KEY_ID:SECRET)", "tier": "free", "group": "cloud",
                  "note": "Read-only IAM user (e.g. ViewOnlyAccess / SecurityAudit). Format ACCESS_KEY_ID:SECRET_KEY."},
    "cloud_gcp": {"label": "Google Cloud (service account JSON)", "tier": "free", "group": "cloud",
                  "note": "Minified service-account JSON with Cloud Asset Viewer. Paste on one line."},
    "cloud_azure": {"label": "Azure (TENANT:CLIENT:SECRET:SUBSCRIPTION)", "tier": "free", "group": "cloud",
                    "note": "App registration with the Reader role on the subscription."},
    "cloud_cloudflare": {"label": "Cloudflare (API token)", "tier": "free", "group": "cloud",
                         "note": "Token with Zone:Read and DNS:Read. Also lets dnsReaper check every record in your zones."},
    "cloud_do": {"label": "DigitalOcean (read token)", "tier": "free", "group": "cloud", "note": "Read-only personal access token."},
}
TOOL_SECRETS: dict[str, str] = {k: v["label"] for k, v in SECRET_INFO.items()}
NAME_RE = re.compile(r"^(?:[a-z0-9_]{2,32}|ai:[a-z0-9_-]{2,40})$")
MAX_SECRET_LEN = 4096


class SecretError(ValueError):
    pass


def load_or_create_master_key(path: Path) -> bytes:
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise SecretError(f"Master key at {path} is not 32 bytes")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name)) and (name.startswith("ai:") or name in TOOL_SECRETS)


class SecretStore:
    def __init__(self, db: DB, key: bytes):
        self.db = db
        self.aes = AESGCM(key)

    def set(self, name: str, value: str) -> None:
        if not valid_name(name):
            raise SecretError("unknown secret name")
        value = value.strip()
        if not value or len(value) > MAX_SECRET_LEN or any(c in value for c in "\r\n\x00"):
            raise SecretError("invalid secret value")
        nonce = os.urandom(12)
        ct = self.aes.encrypt(nonce, value.encode(), name.encode())  # name bound as associated data
        self.db.run(
            "INSERT INTO secrets (name, ciphertext, nonce, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce, "
            "updated_at = excluded.updated_at",
            name, ct, nonce, now(),
        )

    def get(self, name: str) -> str | None:
        """Decrypt for internal use only (passing to a tool). Never return this from the API."""
        row = self.db.one("SELECT ciphertext, nonce FROM secrets WHERE name = ?", name)
        if not row:
            return None
        return self.aes.decrypt(row["nonce"], row["ciphertext"], name.encode()).decode()

    def delete(self, name: str) -> bool:
        return self.db.run("DELETE FROM secrets WHERE name = ?", name).rowcount > 0

    def status(self) -> list[dict]:
        rows = {r["name"]: r["updated_at"] for r in self.db.all("SELECT name, updated_at FROM secrets")}
        out = [
            {"name": n, "label": i["label"], "tier": i["tier"], "group": i["group"], "note": i["note"],
             "signup": i.get("signup"), "set": n in rows, "updated_at": rows.get(n)}
            for n, i in SECRET_INFO.items()
        ]
        out += [{"name": n, "label": n, "set": True, "updated_at": u} for n, u in rows.items() if n.startswith("ai:")]
        return out

    def all_values(self) -> list[str]:
        """Every stored value, used only to mask secrets out of logs."""
        return [v for v in (self.get(r["name"]) for r in self.db.all("SELECT name FROM secrets")) if v]


def mask(text: str, values: list[str]) -> str:
    for v in sorted(values, key=len, reverse=True):
        if len(v) >= 6:
            text = text.replace(v, "****")
    return text
