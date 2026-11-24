"""End-of-life / version-currency enrichment via endoflife.date.

Given a detected product and version (e.g. 'nginx' '1.24.0'), this answers the three questions the UI
asks of a version: is it current, how far behind is it, and is it end-of-life. Data comes from
endoflife.date's public API, cached on disk under <data_dir>/cache/eol/<slug>.json with a TTL, exactly
like the KEV / NVD / EPSS caches. Pure stdlib; the only network is the cached endoflife.date fetch.

Coverage is honest: endoflife.date tracks server/runtime/CMS software (nginx, php, wordpress, tomcat,
openjdk, ...), not most JS libraries or SaaS (React, Okta, Stimulus). Anything not in PRODUCT_SLUGS
returns status 'untracked' rather than a guess.
"""
from __future__ import annotations

import datetime
import json
import re
import urllib.request
from pathlib import Path

EOL_TTL = 7 * 86400                      # release cadences move slowly; a week-old cycle list is fine
_UA = "outsider-asm/1.0 (+endoflife enrichment)"

# detected-tech name (lower-case) -> endoflife.date product slug. Only software endoflife.date tracks.
PRODUCT_SLUGS = {
    "nginx": "nginx", "apache": "apache", "apache http server": "apache", "httpd": "apache",
    "php": "php", "node.js": "nodejs", "nodejs": "nodejs",
    "mysql": "mysql", "mariadb": "mariadb", "postgresql": "postgresql", "postgres": "postgresql",
    "python": "python", "ruby": "ruby", "ruby on rails": "rails", "rails": "rails",
    "django": "django", "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
    "jquery": "jquery", "bootstrap": "bootstrap", "angular": "angular", "angularjs": "angularjs",
    "vue.js": "vue", "vue": "vue", "laravel": "laravel", "symfony": "symfony", "openssl": "openssl",
    "apache tomcat": "tomcat", "tomcat": "tomcat", "elasticsearch": "elasticsearch", "kibana": "kibana",
    "redis": "redis", "mongodb": "mongodb", "varnish": "varnish", "haproxy": "haproxy",
    "iis": "iis", "microsoft iis": "iis", ".net": "dotnet", "dotnet": "dotnet", ".net framework": "dotnetfx",
    "java": "java", "openjdk": "java", "next.js": "nextjs", "nextjs": "nextjs", "express": "express",
    "grafana": "grafana", "gitlab": "gitlab", "jenkins": "jenkins", "kubernetes": "kubernetes",
    "ubuntu": "ubuntu", "debian": "debian", "centos": "centos", "amazon linux": "amazon-linux",
    "magento": "magento", "typo3": "typo3", "moodle": "moodle", "nextcloud": "nextcloud",
}


def _vtuple(v: str) -> tuple:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def _fetch(slug: str) -> list | None:
    url = f"https://endoflife.date/api/{slug}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status != 200:
                return None
            data = json.loads(r.read().decode("utf-8", "replace"))
        return data if isinstance(data, list) else None
    except Exception:
        return None


def get_cycles(data_dir, slug: str) -> list | None:
    """Release-cycle list for a slug, cached on disk. Returns None only when there is no data at all
    (never fetched and fetch failed)."""
    cache = Path(data_dir) / "cache" / "eol" / f"{slug}.json"
    fresh = cache.exists() and (datetime.datetime.now().timestamp() - cache.stat().st_mtime) < EOL_TTL
    if not fresh:
        data = _fetch(slug)
        if data is not None:
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(data))
            except Exception:
                pass
            return data
    if cache.exists():                   # stale cache beats nothing when the fetch fails
        try:
            return json.loads(cache.read_text())
        except Exception:
            return None
    return None


def _eol_status(cycle: dict) -> tuple[str, str | None]:
    e = cycle.get("eol")
    if e is True:
        return "eol", None
    if e is False or e is None:
        return "supported", None
    try:
        d = datetime.date.fromisoformat(str(e))
        return ("eol", str(e)) if d <= datetime.date.today() else ("supported", str(e))
    except Exception:
        return "supported", None


def _cycle_match(cycles: list, vt: tuple) -> dict | None:
    """The most specific release cycle whose 'cycle' is a prefix of the installed version."""
    best = None
    best_len = 0
    for c in cycles:
        ct = _vtuple(str(c.get("cycle", "")))
        if ct and len(ct) <= len(vt) and vt[:len(ct)] == ct and len(ct) > best_len:
            best, best_len = c, len(ct)
    return best


def assess(data_dir, product: str, version: str | None) -> dict:
    """Version-currency verdict for a detected component. Always returns a dict with a 'status' in
    {current, outdated_patch, outdated, eol, untracked, unavailable, unknown_version}."""
    slug = PRODUCT_SLUGS.get((product or "").lower().strip())
    if not slug:
        return {"status": "untracked", "product": product}
    cycles = get_cycles(data_dir, slug)
    if not cycles:
        return {"status": "unavailable", "product": product, "slug": slug}
    newest = cycles[0]
    latest_version = newest.get("latest")
    latest_release = newest.get("latestReleaseDate") or newest.get("releaseDate")
    out = {"slug": slug, "product": product, "installed": version,
           "latest_version": latest_version, "latest_cycle": str(newest.get("cycle")),
           "latest_release_date": latest_release}
    if not version:
        out["status"] = "unknown_version"
        return out
    vt = _vtuple(version)
    mc = _cycle_match(cycles, vt)
    if mc is None:
        out["status"] = "unknown_version"
        return out
    status, eol_date = _eol_status(mc)
    idx = cycles.index(mc)                        # 0 = newest cycle line
    cyc_latest = mc.get("latest")
    patch_behind = bool(cyc_latest) and _vtuple(str(cyc_latest)) > vt
    out.update({"installed_cycle": str(mc.get("cycle")), "cycles_behind": idx,
                "cycle_latest": cyc_latest, "eol_date": eol_date})
    if status == "eol":
        out["status"] = "eol"
        if eol_date:
            try:
                out["eol_days_ago"] = (datetime.date.today() - datetime.date.fromisoformat(eol_date)).days
            except Exception:
                pass
    elif idx > 0:
        out["status"] = "outdated"
    elif patch_behind:
        out["status"] = "outdated_patch"
    else:
        out["status"] = "current"
    return out
