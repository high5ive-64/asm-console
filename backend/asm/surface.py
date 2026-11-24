"""Classification of hosts and technologies into surface categories.

Phase 1 uses this to count the AI-agent / MCP surface and to normalise technology names for the dashboard.
Phase 4 (attack-path simulation) reuses the same classifier to seed agent-focused scenarios.

Everything here is pattern-based over data already collected (host names, HTTP status, technologies). It sends no
traffic and makes no network calls.
"""
from __future__ import annotations

import re

# Host-name patterns that mark a category of surface. Matched against the left-most labels of the host name so that
# "mcp.miro.com" and "digital-twin-mcp.eu01.miro.com" both hit the mcp tag, but "mcpartner.example.com" does not.
_LABEL = r"(?:^|[.-])"      # start of name, or a dot/dash boundary
_END = r"(?:[.-]|$)"       # whole-label boundary (for short, ambiguous keywords)
SURFACE_PATTERNS: dict[str, re.Pattern] = {
    # AI-agent control / tool planes. Keywords match as a label prefix ("agentcody", "aion01") since these names
    # are often concatenated; the whole set is distinctive enough that a prefix match is safe.
    "mcp": re.compile(_LABEL + r"mcp" + _END, re.I),
    "agent": re.compile(_LABEL + r"(?:agent|agentic|aion|cody|atrain|as-main|copilot|autopilot|llm|genai|"
                        r"inference|embedding|chatbot)", re.I),
    "ai": re.compile(_LABEL + r"(?:ai|ml|model|openai|anthropic|bedrock|sagemaker)" + _END, re.I),
    "twin": re.compile(_LABEL + r"(?:digital-?twin|twin)" + _END, re.I),
    # general sensitive surface that agent paths traverse (label-prefix match)
    "api": re.compile(_LABEL + r"(?:api|graphql|grpc|externalapi|betaapi|developer)", re.I),
    "auth": re.compile(_LABEL + r"(?:auth|sso|idp|login|oauth|oidc|identity|account)", re.I),
    "admin": re.compile(_LABEL + r"(?:admin|internal|intranet|console|dashboard|backoffice)", re.I),
    "webhook": re.compile(_LABEL + r"(?:webhook|callback|ingest)", re.I),
    # services that are classic SSRF / file-processing pivots
    "transform": re.compile(_LABEL + r"(?:svg|convert|render|thumbnail|pdf|export|import|unfurl|screenshot)", re.I),
}
AGENT_TAGS = ("mcp", "agent", "ai", "twin")   # the tags that make a host part of the "AI-agent surface"


def classify_host(host: str) -> list[str]:
    """Surface tags for one host name, order-stable. Empty when nothing matches."""
    host = (host or "").lower()
    return [tag for tag, rx in SURFACE_PATTERNS.items() if rx.search(host)]


def is_agent_surface(host: str) -> bool:
    return any(t in AGENT_TAGS for t in classify_host(host))


# ---- technology normalisation -----------------------------------------------------------

# BBOT emits the same technology under different casings and a few aliases, which doubles the dashboard counts
# ("Amazon" + "amazon", "HTTP/3" + "http/3", "HSTS" + "hsts"). Fold them to one display name.
_TECH_ALIASES = {
    "amazon web services": "AWS", "amazon": "AWS", "aws": "AWS", "cloudfront": "AWS CloudFront",
    "http/3": "HTTP/3", "http/2": "HTTP/2", "hsts": "HSTS", "nginx": "Nginx", "envoy": "Envoy",
    "cloudflare": "Cloudflare", "google": "Google", "contentful": "Contentful",
}


def normalise_tech(name: str) -> str:
    """One display name for a technology, case- and alias-folded. Versions are kept if present."""
    raw = (name or "").strip()
    if not raw:
        return ""
    base, _, ver = raw.partition(" ")
    key = raw.lower()
    if key in _TECH_ALIASES:
        return _TECH_ALIASES[key]
    bkey = base.lower()
    if bkey in _TECH_ALIASES:
        return f"{_TECH_ALIASES[bkey]} {ver}".strip()
    # default: Title-case a lower-case token, otherwise keep the original casing (e.g. "WordPress", "jQuery")
    return raw if any(c.isupper() for c in base) else base.capitalize() + (f" {ver}" if ver else "")


def dedup_tech(techs: list[str]) -> list[str]:
    """Normalise and de-duplicate a host's technology list, preferring an entry that carries a version."""
    best: dict[str, str] = {}
    for t in techs:
        n = normalise_tech(t)
        if not n:
            continue
        key = n.split(" ")[0].lower()
        if key not in best or (" " in n and " " not in best[key]):
            best[key] = n
    return sorted(best.values(), key=str.lower)
