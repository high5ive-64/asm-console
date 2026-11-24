"""Milestone 4 routes: authorisation, options, estimate, start/retry, stage status, metrics."""
from __future__ import annotations

import asyncio
import json
import re
from datetime import date
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError, field_validator
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .db import now
from .pipeline import zap_candidates, estimate_total, STAGE_DEPS, STAGES, STAGE_KEYS, estimate_minutes, run_pipeline, snapshot_scope
from .runner import ZAP_GATES, ZAP_PROGRESS, ACTIVE, TASKS
from .scope import is_public_ip
from .settings_model import Settings

EDITABLE = ("scope_confirmed", "interrupted", "completed", "completed_with_errors", "cancelled", "failed")
STARTABLE = ("scope_confirmed", "interrupted", "cancelled", "failed")


class AuthIn(BaseModel):
    approved_by: str = Field(min_length=2, max_length=120)
    role: str = Field(min_length=2, max_length=120)
    approved_on: date
    scope_reference: str = Field(min_length=2, max_length=200)
    soc_notified: bool
    soc_contact: str = Field(min_length=2, max_length=200)
    source_ip: str = Field(min_length=3, max_length=64)
    test_window: str = Field(min_length=3, max_length=200)
    attested: bool

    @field_validator("soc_notified", "attested")
    @classmethod
    def must_be_true(cls, v: bool) -> bool:
        if not v:
            raise ValueError("must be confirmed before the scan can run")
        return v

    @field_validator("approved_by", "role", "scope_reference", "soc_contact", "source_ip", "test_window")
    @classmethod
    def no_control(cls, v: str) -> str:
        if any(ord(ch) < 32 for ch in v):
            raise ValueError("control characters are not allowed")
        return v.strip()


class ZapHostsIn(BaseModel):
    hosts: list[str] | None = Field(None, max_length=500)   # None = back to the recommended pick


class OptionsIn(BaseModel):
    stages: list[str] = Field(default_factory=lambda: [s.key for s in STAGES if s.default])
    zap_spider_minutes: int = Field(3, ge=1, le=30)
    zap_ajax_minutes: int = Field(3, ge=1, le=30)
    zap_max_hosts: int = Field(30, ge=1, le=1000)
    tlsx_concurrency: int = Field(25, ge=1, le=50)
    extra_ips: list[str] = Field(default_factory=list, max_length=4096)
    zap_confirm_targets: bool = True
    # testssl.sh
    testssl_hosts: list[str] = Field(default_factory=list, max_length=25)
    testssl_max_hosts: int = Field(5, ge=1, le=25)
    testssl_vuln_checks: bool = False         # INVASIVE: malformed handshakes (Heartbleed, CCS, ROBOT...)
    # email
    email_starttls: bool = False              # light-touch: connects to your MX hosts on port 25
    # takeover
    takeover_zones: bool = True               # use the Cloudflare token (if saved) to check every zone record
    takeover_include_unlikely: bool = False
    # openSquat
    opensquat_confidence: int = Field(1, ge=0, le=4)
    opensquat_portcheck: bool = False         # contacts suspected lookalike domains (third-party servers)
    opensquat_premium: bool = False           # PAID feed; needs an openSquat key
    # takeover: baddns over live hosts (light-touch, DNS/HTTP metadata) — default on
    takeover_deep: bool = True
    # discovery: map resolved IPs to ASN/netblock from public data (passive) — default on
    asn_lookup: bool = True
    reverse_dns: bool = True          # PTR over your own IPs to find co-hosted names (DNS only)
    # ACTIVE switches (all default off; each is warned, authorisation-gated and asks to confirm before it runs)
    zap_active: bool = False                 # ZAP active scan: sends attack payloads
    zap_active_minutes: int = Field(10, ge=1, le=60)
    bbot_active: bool = False                # BBOT active enumeration/vuln modules (nuclei, ffuf, paramminer…)
    bbot_active_max_hosts: int = Field(150, ge=1, le=500)
    dns_bruteforce: bool = False             # dnsx subdomain brute against your DNS
    # dnstwist: probe registered lookalikes (connects to someone else's servers)
    lookalike_probe: bool = False
    # SpiderFoot use case: passive (default) or one that lets modules touch your targets
    spiderfoot_usecase: str = Field("passive", pattern=r"^(passive|footprint|investigate|all)$")
    # feeds
    netlas_max_requests: int = Field(5, ge=1, le=50)

    @field_validator("testssl_hosts")
    @classmethod
    def hostnames(cls, v: list[str]) -> list[str]:
        out = []
        for h in v:
            h = h.strip().lower().rstrip(".")
            if h and not re.fullmatch(r"[a-z0-9.-]{1,253}", h):
                raise ValueError(f"not a hostname: {h[:60]}")
            if h:
                out.append(h)
        return list(dict.fromkeys(out))

    @field_validator("stages")
    @classmethod
    def known(cls, v: list[str]) -> list[str]:
        bad = set(v) - set(STAGE_KEYS)
        if bad:
            raise ValueError(f"unknown stages: {', '.join(sorted(bad))}")
        return [k for k in STAGE_KEYS if k in v]

    @field_validator("extra_ips")
    @classmethod
    def public_ips(cls, v: list[str]) -> list[str]:
        bad = [ip for ip in v if not is_public_ip(ip.strip())]
        if bad:
            raise ValueError(f"not public IP addresses: {', '.join(bad[:5])}")
        return sorted({ip.strip() for ip in v})


# switches that can be changed on a finished scan before re-running a stage
SWITCH_KEYS = {"testssl_vuln_checks", "testssl_max_hosts", "email_starttls", "takeover_zones", "takeover_include_unlikely",
               "opensquat_portcheck", "opensquat_premium", "opensquat_confidence", "lookalike_probe", "spiderfoot_usecase",
               "netlas_max_requests", "takeover_deep", "zap_active", "zap_active_minutes", "bbot_active",
               "bbot_active_max_hosts", "dns_bruteforce", "asn_lookup", "reverse_dns"}

# A stage sends active (attack/scan) traffic on this run when its switch is on, even though its StageDef is light/dns.
ACTIVE_WHEN = {"zap": "zap_active", "bbot_light": "bbot_active", "dns": "dns_bruteforce"}


def _active_now(key: str, opts: dict) -> bool:
    from .pipeline import STAGES
    if next((s.traffic for s in STAGES if s.key == key), "") == "active":
        return True
    return bool(opts.get(ACTIVE_WHEN.get(key, "")))


def readiness(state) -> dict[str, dict]:
    """Per stage: is what it needs in place (keys, uploads, tools)? Shown next to each stage in Options."""
    import shutil
    from .extras import cloudlist_import_path
    db = state.db()
    try:
        have = {r["name"] for r in db.all("SELECT name FROM secrets")}
    finally:
        db.close()
    out: dict[str, dict] = {}
    def note(k, ok, msg):
        out[k] = {"ok": ok, "message": msg}
    note("feeds", bool({"leakix", "netlas"} & have),
         "Using " + " and ".join(n for n, k in (("LeakIX", "leakix"), ("Netlas", "netlas")) if k in have) if {"leakix", "netlas"} & have
         else "Needs a free LeakIX or Netlas key (Settings › Sources)")
    imp = cloudlist_import_path(state).exists()
    clouds = [k.removeprefix("cloud_") for k in sorted(have) if k.startswith("cloud_")]
    note("cloudlist", imp or bool(clouds), ", ".join(filter(None, ["uploaded export" if imp else "", ("keys: " + ", ".join(clouds)) if clouds else ""]))
         or "Upload a cloudlist export or save read-only cloud keys (Settings › Sources)")
    note("hibp", "hibp" in have, "HIBP key saved" if "hibp" in have else "Needs a paid HIBP key")
    note("intel", True, "Shodan host lookups on (free key)" if "shodan" in have else "InternetDB only (add a free Shodan key for more)")
    note("urlscan", True, "Using your free key" if "urlscan" in have else "No key: works at a lower rate limit")
    note("takeover", True, "Also checking your Cloudflare zones" if "cloud_cloudflare" in have else "Names from discovery")
    from .extras import _find_tech_dir
    if not _find_tech_dir():
        note("tech", False, "Wappalyzer fingerprints aren't installed in this image (rebuild the container)")
    note("port_check", True, "Active: TCP connects to your own IPs. Only with authorisation for port scanning")
    for k, tool in (("dns", "dnsx"), ("port_check", "naabu"), ("cdn", "cdncheck"), ("takeover", "dnsreaper"), ("tls_deep", "testssl.sh"), ("squat", "opensquat"),
                    ("cloudlist", "cloudlist")):
        if not shutil.which(tool) and not (k == "cloudlist" and imp and not clouds):
            note(k, False, f"{tool} isn't installed in this image (rebuild the container)")
    return out


FINISHED = ("completed", "completed_with_errors", "cancelled", "failed", "interrupted")
PROGRESS_RE = re.compile(r"Events produced so far: (.*)$")


def _bbot_progress(msg: str) -> dict[str, int]:
    """Parse BBOT's periodic 'Events produced so far: DNS_NAME: 440, URL: 384, FINDING: 2 (1 LOW, 1 INFO)' line."""
    m = PROGRESS_RE.search(msg)
    if not m:
        return {}
    text = re.sub(r"\([^)]*\)", "", m.group(1))
    return {k: int(v.replace(",", "")) for k, v in re.findall(r"([A-Z_]+): (\d{1,3}(?:,\d{3})+|\d+)", text)}


def live_counts(db, sid: str, scan) -> dict:
    """Running totals for the ticker: what's stored so far, plus BBOT's own live counters while it runs."""
    items = db.all("SELECT kind, grp, decision, third_party FROM scope_items WHERE scan_id = ?", sid)
    domains = 1 + sum(1 for r in items if r["kind"] == "related" and r["decision"] == "included" and not r["third_party"])
    subs_in = sum(1 for r in items if r["kind"] == "subdomain" and r["decision"] == "included")
    subs_found = sum(1 for r in items if r["kind"] == "subdomain")
    related = sum(1 for r in items if r["kind"] == "related")
    a = db.one("SELECT COUNT(*) AS n, SUM(is_live) AS live FROM assets WHERE scan_id = ?", sid)
    sev = {r["severity"]: r["n"] for r in db.all(
        "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity", sid)}
    exposed = db.one("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND area = 'exposure' "
                     "AND source_tool IN ('internetdb', 'internetdb-extra', 'smap')", sid)["n"]
    takeovers = db.one("SELECT COUNT(DISTINCT host) AS n FROM findings WHERE scan_id = ? AND source_tool IN ('bbot:baddns', 'dnsreaper') "
                       "AND severity != 'low'", sid)["n"]
    summ = {r["stage_key"]: json.loads(r["summary"] or "{}") for r in
            db.all("SELECT stage_key, summary FROM stages WHERE scan_id = ?", sid)}
    running = db.one("SELECT stage_key FROM stages WHERE scan_id = ? AND status = 'running'", sid)
    stage_now = running["stage_key"] if running else ("discovery" if scan["status"] == "discovering" else None)
    live: dict[str, int] = {}
    if stage_now in ("discovery", "bbot_light"):
        # A stage can run several BBOT passes (bbot_light: "light", then "dnsonly"). Each pass reports its own
        # running totals, so keep the highest figure per pass and add the passes together; using only the
        # newest line made counts drop to 0 when the next pass started.
        st = db.one("SELECT started_at FROM stages WHERE scan_id = ? AND stage_key = ?", sid, stage_now)
        since = (st["started_at"] if st and st["started_at"] else "") if stage_now == "bbot_light" else ""
        per_pass: dict[str, dict[str, int]] = {}
        for ev in db.all("SELECT message FROM events WHERE scan_id = ? AND stage_key = ? AND ts >= ? "
                         "AND message LIKE '%Events produced so far%' ORDER BY id", sid, stage_now, since):
            m = re.search(r"\]\s*([\w.-]+): Events produced", ev["message"])
            name = m.group(1) if m else "bbot"
            cur = per_pass.setdefault(name, {})
            for k, v in _bbot_progress(ev["message"]).items():
                cur[k] = max(cur.get(k, 0), v)
        for counts_ in per_pass.values():
            for k, v in counts_.items():
                live[k] = live.get(k, 0) + v
    g = lambda st, k: int((summ.get(st) or {}).get(k) or 0)
    return {
        "stage": stage_now,
        "domains": domains,
        "related_found": related,
        "subdomains_found": subs_found,
        "subdomains_in_scope": subs_in,
        "live_hosts": int(a["live"] or 0),
        "web_endpoints": max(g("bbot_light", "web_endpoints"), live.get("URL", 0) if stage_now == "bbot_light" else 0),
        "historical_urls": g("gau", "historical_urls"),
        "open_ports": g("ports", "open_ports") + g("cloud", "open_ports"),
        "exposed_services": exposed,
        "takeover_risks": takeovers,
        "certificates": g("tls", "hosts"),
        "lookalikes": g("lookalikes", "registered"),
        "issues": sum(sev.values()),
        "issues_by_severity": sev,
        "bbot_live": live,
    }


def routes(state) -> list[Route]:
    from .app import body, err, validation_response

    def scan_row(db, sid):
        return db.one("SELECT * FROM scans WHERE id = ?", sid)

    async def get_auth(request: Request) -> Response:
        db = state.db()
        try:
            row = db.one("SELECT * FROM authorisations WHERE scan_id = ?", request.path_params["id"])
        finally:
            db.close()
        return JSONResponse({"authorisation": dict(row) if row else None})

    async def put_auth(request: Request) -> Response:
        sid = request.path_params["id"]
        try:
            a = await body(request, AuthIn)
        except ValidationError as exc:
            return validation_response(exc)
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in EDITABLE:
                return err(409, "confirm scope first" if scan["status"] in ("draft", "awaiting_scope") else
                           f"can't change authorisation while the scan is {scan['status']}")
            db.run("INSERT INTO authorisations (scan_id, approved_by, role, approved_on, scope_reference, soc_notified, "
                   "soc_contact, source_ip, test_window, attested, attested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                   "ON CONFLICT(scan_id) DO UPDATE SET approved_by=excluded.approved_by, role=excluded.role, "
                   "approved_on=excluded.approved_on, scope_reference=excluded.scope_reference, soc_notified=excluded.soc_notified, "
                   "soc_contact=excluded.soc_contact, source_ip=excluded.source_ip, test_window=excluded.test_window, "
                   "attested=excluded.attested, attested_at=excluded.attested_at",
                   sid, a.approved_by, a.role, a.approved_on.isoformat(), a.scope_reference, 1, a.soc_contact,
                   a.source_ip, a.test_window, 1, now())
        finally:
            db.close()
        return JSONResponse({"saved": True})

    async def get_options(request: Request) -> Response:
        db = state.db()
        try:
            scan = scan_row(db, request.path_params["id"])
            if not scan:
                return err(404, "scan not found")
            s = Settings.model_validate(db.get_setting("app", {}))
        finally:
            db.close()
        stored = json.loads(scan["options"]).get("run")
        opts = OptionsIn.model_validate(stored) if stored else OptionsIn(
            zap_spider_minutes=s.zap_spider_minutes, zap_ajax_minutes=s.zap_ajax_minutes, tlsx_concurrency=s.tlsx_concurrency)
        return JSONResponse({"options": opts.model_dump(), "stages": [s.__dict__ for s in STAGES], "readiness": readiness(state)})

    async def put_options(request: Request) -> Response:
        sid = request.path_params["id"]
        try:
            o = await body(request, OptionsIn)
        except ValidationError as exc:
            return validation_response(exc)
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in EDITABLE:
                return err(409, f"can't change options while the scan is {scan['status']}")
            opts = json.loads(scan["options"])
            opts["run"] = o.model_dump()
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps(opts), sid)
        finally:
            db.close()
        return JSONResponse({"options": o.model_dump()})

    async def patch_switches(request: Request) -> Response:
        """Change per-stage switches on a finished scan before re-running a stage (both copies of the options)."""
        sid = request.path_params["id"]
        try:
            changes = await request.json()
        except Exception:
            return err(400, "invalid JSON")
        if not isinstance(changes, dict) or not changes or set(changes) - SWITCH_KEYS:
            return err(422, "only these switches can be changed here: " + ", ".join(sorted(SWITCH_KEYS)))
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in EDITABLE:
                return err(409, f"can't change switches while the scan is {scan['status']}")
            opts = json.loads(scan["options"])
            try:
                merged = OptionsIn.model_validate({**(opts.get("run") or {}), **changes})
            except ValidationError as exc:
                return validation_response(exc)
            for k in changes:
                v = getattr(merged, k)
                opts.setdefault("run", {})[k] = v
                opts[k] = v
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps(opts), sid)
        finally:
            db.close()
        return JSONResponse({"switches": {k: getattr(merged, k) for k in SWITCH_KEYS}})

    def _preview_snapshot(db, sid) -> dict:
        rows = db.all("SELECT value, kind, grp, decision, third_party FROM scope_items WHERE scan_id = ?", sid)
        root = db.one("SELECT root_domain FROM scans WHERE id = ?", sid)["root_domain"]
        roots = [root] + [r["value"] for r in rows if r["kind"] == "related" and r["decision"] == "included" and not r["third_party"]]
        light = [r["value"] for r in rows if r["kind"] == "subdomain" and r["decision"] == "included"
                 and r["grp"] not in ("third_party", "no_dns") and not r["value"].startswith("*.")]
        dns = [r["value"] for r in rows if r["kind"] == "subdomain" and r["decision"] == "included" and r["grp"] in ("third_party", "no_dns")]
        return {"roots": roots, "light_hosts": sorted(set(light) | set(roots)), "dns_hosts": dns}

    async def estimate(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            snap = _preview_snapshot(db, sid)
        finally:
            db.close()
        opts = json.loads(scan["options"]).get("run") or OptionsIn().model_dump()
        per = estimate_minutes(opts, snap)
        return JSONResponse({"minutes": per, "total_minutes": max(1, round(estimate_total(per))), "hosts": len(snap["light_hosts"]),
                             "dns_only_hosts": len(snap["dns_hosts"]), "roots": snap["roots"]})

    def _start(sid: str, only: list[str] | None = None, reuse_output: bool = False):
        TASKS[sid] = asyncio.create_task(run_pipeline(state, sid, only=only, providers=getattr(state, "providers", None),
                                                      use_bbot=getattr(state, "use_bbot", True), reuse_output=reuse_output))

    async def start(request: Request) -> Response:
        sid = request.path_params["id"]
        if sid in ACTIVE or (sid in TASKS and not TASKS[sid].done()):
            return err(409, "this scan is already running")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in STARTABLE:
                return err(409, "confirm scope before starting" if scan["status"] in ("draft", "awaiting_scope")
                           else f"can't start a scan that is {scan['status']}")
            auth = db.one("SELECT * FROM authorisations WHERE scan_id = ? AND attested = 1 AND soc_notified = 1", sid)
            if not auth:
                return err(409, "complete the authorisation step before starting")
            opts = json.loads(scan["options"])
            if "run" not in opts:
                opts["run"] = OptionsIn().model_dump()
            run_dir = Path(scan["run_dir"])
            resuming = scan["status"] in ("interrupted", "cancelled")
            if not resuming:
                snap = snapshot_scope(db, sid, run_dir)
                if not snap["light_hosts"] and not snap["dns_hosts"]:
                    return err(409, "nothing is in scope")
                (run_dir / "scope" / "authorisation.json").write_text(json.dumps(dict(auth), indent=2))
                with db.tx():
                    # keep the discovery record; reset only the scan pipeline's stages
                    db.run(f"DELETE FROM stages WHERE scan_id = ? AND stage_key IN ({','.join('?' * len(STAGE_KEYS))})", sid, *STAGE_KEYS)
                    chosen = set(opts["run"].get("stages") or []) | {"consolidate"}
                    for k in STAGE_KEYS:
                        if k in chosen:
                            db.run("INSERT INTO stages (scan_id, stage_key, status) VALUES (?, ?, 'pending')", sid, k)
                        else:
                            db.run("INSERT INTO stages (scan_id, stage_key, status, summary) VALUES (?, ?, 'skipped', ?)",
                                   sid, k, json.dumps({"reason": "turned off in options"}))
            db.run("UPDATE scans SET options = ?, tool_versions = ?, finished_at = NULL WHERE id = ?",
                   json.dumps(opts), json.dumps(state.tool_versions), sid)
            # the pipeline reads options["stages"] etc. at the top level
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps({**opts, **opts["run"]}), sid)
        finally:
            db.close()
        _start(sid)
        return JSONResponse({"started": True, "resumed": resuming}, status_code=202)

    async def retry_stage(request: Request) -> Response:
        sid, key = request.path_params["id"], request.path_params["key"]
        if key not in STAGE_KEYS:
            return err(404, "unknown stage")
        if sid in ACTIVE or (sid in TASKS and not TASKS[sid].done()):
            return err(409, "this scan is already running")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            st = db.one("SELECT status FROM stages WHERE scan_id = ? AND stage_key = ?", sid, key)
        finally:
            db.close()
        if not scan:
            return err(404, "scan not found")
        if scan["status"] not in FINISHED:
            return err(409, f"can't retry while the scan is {scan['status']}")
        if not st:                     # a stage added after this scan ran: create its record and run it
            _add_missing(sid, [key])
        run_opts = json.loads(scan["options"]).get("run") or {}
        if _active_now(key, run_opts) and request.query_params.get("confirm") != "active":
            return err(428, "this stage sends active traffic on this run; confirm it explicitly")
        reuse = request.query_params.get("reuse") == "1" and key == "bbot_light"
        _enable(sid, [key])
        _start(sid, only=[key] if key == "consolidate" else [key, "consolidate"], reuse_output=reuse)
        return JSONResponse({"retrying": key, "reuse_output": reuse}, status_code=202)

    def _add_missing(sid: str, keys: list[str]) -> None:
        db = state.db()
        try:
            for k in keys:
                db.run("INSERT OR IGNORE INTO stages (scan_id, stage_key, status) VALUES (?, ?, 'pending')", sid, k)
        finally:
            db.close()

    async def run_new(request: Request) -> Response:
        """Run every stage this scan has never run (stages added in a later version), then re-consolidate."""
        sid = request.path_params["id"]
        if sid in ACTIVE or (sid in TASKS and not TASKS[sid].done()):
            return err(409, "this scan is already running")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            have = {r["stage_key"] for r in db.all("SELECT stage_key FROM stages WHERE scan_id = ?", sid)}
        finally:
            db.close()
        if scan["status"] not in FINISHED:
            return err(409, f"can't run stages while the scan is {scan['status']}")
        new = [s.key for s in STAGES if s.key not in have and s.default and s.key != "consolidate"]
        if not new:
            return err(409, "no new stages to run")
        _add_missing(sid, new)
        _enable(sid, new)
        _start(sid, only=new + ["consolidate"])
        return JSONResponse({"running": new}, status_code=202)

    def _enable(sid: str, keys: list[str]) -> None:
        """Running a stage that was turned off in options turns it on (both copies of the options)."""
        db = state.db()
        try:
            opts = json.loads(scan_row(db, sid)["options"])
            for k in keys:
                if k == "consolidate":
                    continue
                for o in (opts, opts.setdefault("run", {})):
                    st = o.setdefault("stages", [])
                    if k not in st:
                        st.append(k)
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps(opts), sid)
        finally:
            db.close()

    async def rerun_all(request: Request) -> Response:
        sid = request.path_params["id"]
        if sid in ACTIVE or (sid in TASKS and not TASKS[sid].done()):
            return err(409, "this scan is already running")
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in FINISHED:
                return err(409, f"can't re-run while the scan is {scan['status']}")
            enabled = set(json.loads(scan["options"]).get("stages") or []) | {"consolidate"}
            keys = [k for k in STAGE_KEYS if k in enabled]
            with db.tx():
                for k in keys:
                    db.run("UPDATE stages SET status = 'pending', started_at = NULL, finished_at = NULL, summary = '{}' "
                           "WHERE scan_id = ? AND stage_key = ?", sid, k)
        finally:
            db.close()
        _start(sid, only=keys)
        return JSONResponse({"rerunning": keys}, status_code=202)

    async def counts(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            return JSONResponse(live_counts(db, sid, scan))
        finally:
            db.close()

    async def stages(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            rows = db.all("SELECT * FROM stages WHERE scan_id = ?", sid)
            scan = scan_row(db, sid)
        finally:
            db.close()
        if not scan:
            return err(404, "scan not found")
        by = {r["stage_key"]: r for r in rows}
        # latest readable activity line for each running stage
        from .humanize import humanize
        activity: dict[str, str] = {}
        db = state.db()
        try:
            for r in rows:
                if r["status"] not in ("running", "waiting"):
                    continue
                for ev in db.all("SELECT level, message FROM events WHERE scan_id = ? AND stage_key = ? ORDER BY id DESC LIMIT 60",
                                 sid, r["stage_key"]):
                    h = humanize(r["stage_key"], ev["level"], ev["message"])
                    if h:
                        activity[r["stage_key"]] = h["text"]
                        break
        finally:
            db.close()
        out = []
        run_opts = json.loads(scan["options"]).get("run") or {}
        # a stage with no record on a finished scan was added in a later version: it never ran here
        missing = "not_run" if scan["status"] in FINISHED else "pending"
        for s in STAGES:
            r = by.get(s.key)
            out.append({"key": s.key, "title": s.title, "traffic": s.traffic, "description": s.description,
                        "active_now": _active_now(s.key, run_opts),
                        "status": r["status"] if r else missing, "started_at": r["started_at"] if r else None,
                        "finished_at": r["finished_at"] if r else None,
                        "summary": json.loads(r["summary"]) if r else
                        ({"reason": "added after this scan ran"} if missing == "not_run" else {}), "activity": activity.get(s.key),
                        "depends_on": sorted(STAGE_DEPS.get(s.key, set()) - {"consolidate"}) if s.key != "consolidate" else []})
        r = ACTIVE.get(sid)
        return JSONResponse({"status": scan["status"], "started_at": scan["started_at"], "finished_at": scan["finished_at"],
                             "paused": bool(r and r.paused), "zap_waiting": sid in ZAP_GATES, "stages": out})

    async def metrics(request: Request) -> Response:
        db = state.db()
        try:
            row = db.one("SELECT metrics FROM metrics WHERE scan_id = ?", request.path_params["id"])
        finally:
            db.close()
        return JSONResponse({"metrics": json.loads(row["metrics"]) if row else None})

    async def pause(request: Request) -> Response:
        r = ACTIVE.get(request.path_params["id"])
        if not r:
            return err(409, "nothing is running for this scan")
        r.pause()
        return JSONResponse({"paused": True})

    async def resume(request: Request) -> Response:
        r = ACTIVE.get(request.path_params["id"])
        if not r:
            return err(409, "nothing is running for this scan")
        r.resume()
        return JSONResponse({"paused": False})

    def _zap_info(db, sid: str, scan) -> dict:
        opts = json.loads(scan["options"])
        run = opts.get("run") or {}
        snap = _preview_snapshot(db, sid)
        info = zap_candidates(db, sid, snap["light_hosts"], snap["roots"], int(run.get("zap_max_hosts", opts.get("zap_max_hosts", 30))),
                              opts.get("zap_selected"))
        spider = int(run.get("zap_spider_minutes", 3)); ajax = int(run.get("zap_ajax_minutes", 3))
        prog = ZAP_PROGRESS.get(sid)
        info.update(per_host_minutes=spider + ajax + 0.5, waiting=sid in ZAP_GATES,
                    confirm_before=bool(run.get("zap_confirm_targets", True)), custom=opts.get("zap_selected") is not None,
                    progress={"hosts": prog["hosts"], "current": prog["host"], "job": prog["job"]} if prog else None)
        return info

    async def zap_get(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            return JSONResponse(_zap_info(db, sid, scan))
        finally:
            db.close()

    async def _zap_save(request: Request, sid: str) -> Response | None:
        try:
            data = await body(request, ZapHostsIn)
        except ValidationError as exc:
            return validation_response(exc)
        if "hosts" not in data.model_fields_set:
            return None
        hosts = data.hosts
        db = state.db()
        try:
            scan = scan_row(db, sid)
            if not scan:
                return err(404, "scan not found")
            opts = json.loads(scan["options"])
            if hosts is None:                              # back to the recommended pick
                opts.pop("zap_selected", None)
            else:
                if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts) or len(hosts) > 500:
                    return err(422, "hosts must be a list of host names")
                allowed = {c["host"] for c in _zap_info(db, sid, scan)["candidates"]}
                bad = sorted(set(hosts) - allowed)
                if bad:
                    return err(422, f"not ZAP candidates for this scan: {', '.join(bad[:5])}")
                opts["zap_selected"] = [h for h in hosts]
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps(opts), sid)
        finally:
            db.close()
        return None

    async def zap_put(request: Request) -> Response:
        sid = request.path_params["id"]
        if sid in ZAP_PROGRESS and ZAP_PROGRESS[sid].get("job") not in ("done",) and sid in ACTIVE and sid not in ZAP_GATES:
            # ZAP already running: its plan is fixed
            db = state.db()
            try:
                st = db.one("SELECT status FROM stages WHERE scan_id = ? AND stage_key = 'zap'", sid)
            finally:
                db.close()
            if st and st["status"] == "running":
                return err(409, "ZAP is already running with its chosen hosts; change them for the next run after it finishes")
        bad = await _zap_save(request, sid)
        if bad is not None:
            return bad
        return await zap_get(request)

    async def zap_confirm(request: Request) -> Response:
        sid = request.path_params["id"]
        gate = ZAP_GATES.get(sid)
        if not gate:
            return err(409, "ZAP isn't waiting for a host choice")
        bad = await _zap_save(request, sid)
        if bad is not None:
            return bad
        db = state.db()
        try:
            scan = scan_row(db, sid)
            info = _zap_info(db, sid, scan)
            if not info["selected"]:
                return err(422, "choose at least one host, or cancel the scan")
            opts = json.loads(scan["options"])
            opts["zap_selected"] = info["selected"]           # what ZAP will scan, exactly
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps(opts), sid)
        finally:
            db.close()
        gate.set()
        return JSONResponse({"confirmed": len(info["selected"])})

    return [
        Route("/api/scans/{id:str}/pause", pause, methods=["POST"]),
        Route("/api/scans/{id:str}/resume", resume, methods=["POST"]),
        Route("/api/scans/{id:str}/zap/targets", zap_get, methods=["GET"]),
        Route("/api/scans/{id:str}/zap/targets", zap_put, methods=["PUT"]),
        Route("/api/scans/{id:str}/zap/confirm", zap_confirm, methods=["POST"]),
        Route("/api/scans/{id:str}/authorisation", get_auth, methods=["GET"]),
        Route("/api/scans/{id:str}/authorisation", put_auth, methods=["PUT"]),
        Route("/api/scans/{id:str}/options", get_options, methods=["GET"]),
        Route("/api/scans/{id:str}/options", put_options, methods=["PUT"]),
        Route("/api/scans/{id:str}/estimate", estimate, methods=["GET"]),
        Route("/api/scans/{id:str}/start", start, methods=["POST"]),
        Route("/api/scans/{id:str}/stages", stages, methods=["GET"]),
        Route("/api/scans/{id:str}/stages/{key:str}/retry", retry_stage, methods=["POST"]),
        Route("/api/scans/{id:str}/metrics", metrics, methods=["GET"]),
        Route("/api/scans/{id:str}/rerun", rerun_all, methods=["POST"]),
        Route("/api/scans/{id:str}/run-new", run_new, methods=["POST"]),
        Route("/api/scans/{id:str}/switches", patch_switches, methods=["PATCH"]),
        Route("/api/scans/{id:str}/counts", counts, methods=["GET"]),
    ]
