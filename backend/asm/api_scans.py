"""Scan and CMDB routes. Milestone 2 covers create/list/get/delete and CMDB import;
discovery, scope and the pipeline are added in milestones 3-4."""
from __future__ import annotations

import json
import secrets as pysecrets
import shutil
from datetime import datetime, timezone

from pydantic import BaseModel, Field, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .db import now
from .scope import ScopeError, is_ip, normalise_domain

RUN_SUBDIRS = ["scope", "bbot", "zap", "tls", "services", "email", "urls", "lookalikes", "hibp",
               "cloud", "summary", "report", "share", "logs"]
MAX_CMDB_BYTES = 5 * 1024 * 1024


class ScanIn(BaseModel):
    root_domain: str = Field(min_length=3, max_length=253)


class DiscoverIn(BaseModel):
    sources: list[str] = Field(default_factory=lambda: ["certificates", "dns_infra"], max_length=4)
    expand: str | None = Field(None, max_length=253)


class ScopePatch(BaseModel):
    include: list[str] = Field(default_factory=list, max_length=10000)
    exclude: list[str] = Field(default_factory=list, max_length=10000)
    add: list[str] = Field(default_factory=list, max_length=500)
    exclude_add: list[str] = Field(default_factory=list, max_length=500)


def _scan_row(r) -> dict:
    return {
        "id": r["id"], "root_domain": r["root_domain"], "status": r["status"],
        "created_at": r["created_at"], "started_at": r["started_at"], "finished_at": r["finished_at"],
        "options": json.loads(r["options"]),
    }


def routes(state) -> list[Route]:
    from .app import body, err, validation_response  # late import to avoid a cycle

    async def create_scan(request: Request) -> Response:
        try:
            data = await body(request, ScanIn)
            root = normalise_domain(data.root_domain)
        except ValidationError as exc:
            return validation_response(exc)
        except ScopeError as exc:
            return err(422, str(exc))
        sid = pysecrets.token_hex(8)
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        run_dir = state.cfg.runs_dir / f"{day}-{sid}"
        for d in RUN_SUBDIRS:
            (run_dir / d).mkdir(parents=True, exist_ok=True)
        db = state.db()
        try:
            with db.tx():
                db.run("INSERT INTO scans (id, root_domain, status, created_at, run_dir) VALUES (?, ?, 'draft', ?, ?)",
                       sid, root, now(), str(run_dir))
                db.run("INSERT INTO scope_items (scan_id, value, kind, decision, confidence, sources, reasons, decided_at) "
                       "VALUES (?, ?, 'root', 'included', 'high', '[\"user\"]', '[\"entered by you\"]', ?)", sid, root, now())
            row = db.one("SELECT * FROM scans WHERE id = ?", sid)
        finally:
            db.close()
        return JSONResponse(_scan_row(row), status_code=201)

    async def list_scans(request: Request) -> Response:
        db = state.db()
        try:
            rows = db.all("SELECT * FROM scans ORDER BY created_at DESC LIMIT 500")
        finally:
            db.close()
        return JSONResponse({"scans": [_scan_row(r) for r in rows]})

    async def get_scan(request: Request) -> Response:
        db = state.db()
        try:
            row = db.one("SELECT * FROM scans WHERE id = ?", request.path_params["id"])
        finally:
            db.close()
        if not row:
            return err(404, "scan not found")
        return JSONResponse(_scan_row(row))

    async def delete_scan(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            row = db.one("SELECT run_dir, status FROM scans WHERE id = ?", sid)
            if not row:
                return err(404, "scan not found")
            if row["status"] in ("running", "discovering"):
                return err(409, "cancel the scan before deleting it")
            db.run("DELETE FROM scans WHERE id = ?", sid)
        finally:
            db.close()
        run_dir = state.cfg.runs_dir.resolve()
        target = (state.cfg.runs_dir / row["run_dir"].rsplit("/", 1)[-1]).resolve()
        if run_dir in target.parents:
            shutil.rmtree(target, ignore_errors=True)
        return JSONResponse({"deleted": sid})

    async def cloudlist_status(request: Request) -> Response:
        from .extras import cloudlist_import_path, parse_cloudlist
        p = cloudlist_import_path(state)
        if not p.exists():
            return JSONResponse({"present": False})
        items = parse_cloudlist(p.read_text(errors="replace"))
        provs = sorted({i["provider"] for i in items if i["provider"]})
        return JSONResponse({"present": True, "assets": len(items), "public_ips": len({i["ip"] for i in items if i["ip"]}),
                             "hosts": len({i["host"] for i in items if i["host"]}), "providers": provs,
                             "updated_at": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")})

    async def cloudlist_upload(request: Request) -> Response:
        from .extras import cloudlist_import_path, parse_cloudlist
        raw = await request.body()
        if len(raw) > 20 * 1024 * 1024:
            return err(413, "file too large (20 MB max)")
        text = raw.decode("utf-8", errors="replace")
        items = parse_cloudlist(text)
        if not items:
            return err(422, "no assets found: upload the output of `cloudlist -json` (or a plain list of IPs / hostnames)")
        p = cloudlist_import_path(state)
        p.parent.mkdir(parents=True, exist_ok=True)
        # store only the fields we use, one JSON object per line
        p.write_text("\n".join(json.dumps({"provider": i["provider"], "service": i["service"], "id": i["id"],
                                            "public_ipv4": i["ip"], "dns_name": i["host"]}) for i in items) + "\n")
        return await cloudlist_status(request)

    async def cloudlist_clear(request: Request) -> Response:
        from .extras import cloudlist_import_path
        cloudlist_import_path(state).unlink(missing_ok=True)
        return JSONResponse({"present": False})

    async def import_cmdb(request: Request) -> Response:
        raw = await request.body()
        if len(raw) > MAX_CMDB_BYTES:
            return err(413, "file too large (5 MB max)")
        text = raw.decode("utf-8", errors="replace")
        added, skipped = 0, 0
        db = state.db()
        try:
            with db.tx():
                for line in text.splitlines():
                    for cell in line.replace(";", ",").replace("\t", ",").split(","):
                        v = cell.strip().strip('"').lower().rstrip(".")
                        if not v or v.startswith("#"):
                            continue
                        if is_ip(v):
                            kind = "ip"
                        else:
                            try:
                                v = normalise_domain(v); kind = "host"
                            except ScopeError:
                                skipped += 1; continue
                        cur = db.run("INSERT OR IGNORE INTO cmdb_entries (value, kind, imported_at) VALUES (?, ?, ?)",
                                     v, kind, now())
                        added += cur.rowcount
            total = db.one("SELECT COUNT(*) AS n FROM cmdb_entries")["n"]
        finally:
            db.close()
        return JSONResponse({"added": added, "skipped": skipped, "total": total})

    async def list_cmdb(request: Request) -> Response:
        db = state.db()
        try:
            rows = db.all("SELECT value, kind, imported_at FROM cmdb_entries ORDER BY value LIMIT 20000")
        finally:
            db.close()
        return JSONResponse({"entries": [dict(r) for r in rows], "total": len(rows)})

    async def clear_cmdb(request: Request) -> Response:
        db = state.db()
        try:
            n = db.run("DELETE FROM cmdb_entries").rowcount
        finally:
            db.close()
        return JSONResponse({"removed": n})

    # ---- milestone 3: discovery and scope --------------------------------

    def _scan_or_404(db, sid):
        return db.one("SELECT * FROM scans WHERE id = ?", sid)

    async def discover(request: Request) -> Response:
        import asyncio
        from .discovery import SOURCES, run_discovery
        from .runner import ACTIVE, TASKS
        sid = request.path_params["id"]
        try:
            data = await body(request, DiscoverIn)
        except ValidationError as exc:
            return validation_response(exc)
        bad = set(data.sources) - set(SOURCES)
        if bad:
            return err(422, f"unknown sources: {', '.join(sorted(bad))}")
        db = state.db()
        try:
            scan = _scan_or_404(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in ("draft", "awaiting_scope"):
                return err(409, f"discovery can't run while the scan is {scan['status']}")
            expand = None
            if data.expand:
                try:
                    expand = normalise_domain(data.expand)
                except ScopeError as exc:
                    return err(422, str(exc))
                row = db.one("SELECT decision, third_party FROM scope_items WHERE scan_id = ? AND value = ? AND kind = 'related'",
                             sid, expand)
                if not row or row["decision"] != "included" or row["third_party"]:
                    return err(409, "include the related domain in scope before discovering its subdomains")
            opts = json.loads(scan["options"])
            opts["discovery_sources"] = sorted(set(data.sources))
            db.run("UPDATE scans SET options = ? WHERE id = ?", json.dumps(opts), sid)
        finally:
            db.close()
        if sid in ACTIVE or (sid in TASKS and not TASKS[sid].done()):
            return err(409, "discovery is already running")
        TASKS[sid] = asyncio.create_task(run_discovery(state, sid, set(data.sources), expand=expand,
                                                       providers=getattr(state, "providers", None),
                                                       use_bbot=getattr(state, "use_bbot", True)))
        return JSONResponse({"started": True, "target": expand or scan["root_domain"]}, status_code=202)

    async def candidates(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = _scan_or_404(db, sid)
            if not scan:
                return err(404, "scan not found")
            rows = db.all("SELECT * FROM scope_items WHERE scan_id = ? ORDER BY kind, value", sid)
            stage = db.one("SELECT status, summary, started_at, finished_at FROM stages WHERE scan_id = ? AND stage_key = 'discovery'", sid)
            cmdb = {r["value"] for r in db.all("SELECT value FROM cmdb_entries")}
        finally:
            db.close()
        items = [{
            "value": r["value"], "kind": r["kind"], "group": r["grp"], "confidence": r["confidence"],
            "decision": r["decision"], "third_party": bool(r["third_party"]),
            "sources": json.loads(r["sources"]), "reasons": json.loads(r["reasons"]),
            "in_cmdb": r["value"] in cmdb,
        } for r in rows]
        return JSONResponse({
            "scan": _scan_row(scan),
            "discovery": dict(stage) | {"summary": json.loads(stage["summary"])} if stage else None,
            "items": items,
        })

    async def patch_scope(request: Request) -> Response:
        sid = request.path_params["id"]
        try:
            data = await body(request, ScopePatch)
        except ValidationError as exc:
            return validation_response(exc)
        db = state.db()
        try:
            scan = _scan_or_404(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in ("draft", "awaiting_scope", "scope_confirmed"):
                return err(409, f"scope is locked while the scan is {scan['status']}")
            problems = []
            with db.tx():
                for value in data.include + data.exclude:
                    row = db.one("SELECT kind, third_party FROM scope_items WHERE scan_id = ? AND value = ?", sid, value)
                    if not row:
                        problems.append(f"{value}: not a candidate"); continue
                    if row["kind"] == "root":
                        problems.append(f"{value}: the root domain can't be changed"); continue
                    if value in data.include and row["third_party"]:
                        problems.append(f"{value}: third-party domains can't be added to scope"); continue
                    decision = "included" if value in data.include else "excluded"
                    db.run("UPDATE scope_items SET decision = ?, decided_at = ? WHERE scan_id = ? AND value = ?",
                           decision, now(), sid, value)
                for raw in data.add:
                    try:
                        v = normalise_domain(raw)
                    except ScopeError as exc:
                        problems.append(f"{raw}: {exc}"); continue
                    root = scan["root_domain"]
                    kind = "subdomain" if (v == root or v.endswith("." + root)) else "related"
                    db.run("INSERT INTO scope_items (scan_id, value, kind, sources, reasons, confidence, decision, decided_at) "
                           "VALUES (?, ?, ?, '[\"user\"]', '[\"added by you\"]', 'high', 'included', ?) "
                           "ON CONFLICT(scan_id, value) DO UPDATE SET decision = 'included', decided_at = excluded.decided_at",
                           sid, v, kind, now())
                for raw in data.exclude_add:
                    try:
                        v = normalise_domain(raw)
                    except ScopeError as exc:
                        problems.append(f"{raw}: {exc}"); continue
                    db.run("INSERT INTO scope_items (scan_id, value, kind, sources, reasons, decision, decided_at) "
                           "VALUES (?, ?, 'exclusion', '[\"user\"]', '[\"excluded by you\"]', 'excluded', ?) "
                           "ON CONFLICT(scan_id, value) DO UPDATE SET decision = 'excluded', decided_at = excluded.decided_at",
                           sid, v, now())
                if scan["status"] == "scope_confirmed":
                    db.run("UPDATE scans SET status = 'awaiting_scope' WHERE id = ?", sid)
        finally:
            db.close()
        return JSONResponse({"ok": not problems, "problems": problems})

    async def confirm_scope(request: Request) -> Response:
        sid = request.path_params["id"]
        db = state.db()
        try:
            scan = _scan_or_404(db, sid)
            if not scan:
                return err(404, "scan not found")
            if scan["status"] not in ("awaiting_scope", "scope_confirmed"):
                return err(409, "run discovery before confirming scope")
            included = db.all("SELECT value FROM scope_items WHERE scan_id = ? AND decision = 'included' "
                              "AND third_party = 0 AND kind IN ('root','related')", sid)
            hosts = db.one("SELECT COUNT(*) AS n FROM scope_items WHERE scan_id = ? AND decision = 'included' AND kind = 'subdomain'", sid)["n"]
            db.run("UPDATE scans SET status = 'scope_confirmed' WHERE id = ?", sid)
        finally:
            db.close()
        return JSONResponse({"confirmed": True, "roots": [r["value"] for r in included], "hosts": hosts + len(included)})

    async def events(request: Request) -> Response:
        sid = request.path_params["id"]
        try:
            after = int(request.query_params.get("after", "0"))
        except ValueError:
            after = 0
        stage = request.query_params.get("stage")
        db = state.db()
        try:
            if stage:
                rows = db.all("SELECT id, stage_key, ts, level, message FROM events WHERE scan_id = ? AND id > ? AND stage_key = ? "
                              "ORDER BY id LIMIT 1000", sid, after, stage)
            else:
                rows = db.all("SELECT id, stage_key, ts, level, message FROM events WHERE scan_id = ? AND id > ? ORDER BY id LIMIT 1000",
                              sid, after)
        finally:
            db.close()
        from .humanize import humanize
        out = []
        for r in rows:
            e = dict(r)
            e["human"] = humanize(e["stage_key"], e["level"], e["message"])
            out.append(e)
        return JSONResponse({"events": out})

    async def cancel(request: Request) -> Response:
        from .runner import ACTIVE
        sid = request.path_params["id"]
        r = ACTIVE.get(sid)
        if not r:
            return err(409, "nothing is running for this scan")
        r.cancel()
        return JSONResponse({"cancelling": True})

    return [
        Route("/api/scans/{id:str}/discover", discover, methods=["POST"]),
        Route("/api/scans/{id:str}/candidates", candidates, methods=["GET"]),
        Route("/api/scans/{id:str}/scope", patch_scope, methods=["PATCH"]),
        Route("/api/scans/{id:str}/scope/confirm", confirm_scope, methods=["POST"]),
        Route("/api/scans/{id:str}/events", events, methods=["GET"]),
        Route("/api/scans/{id:str}/cancel", cancel, methods=["POST"]),
        Route("/api/scans", create_scan, methods=["POST"]),
        Route("/api/scans", list_scans, methods=["GET"]),
        Route("/api/scans/{id:str}", get_scan, methods=["GET"]),
        Route("/api/scans/{id:str}", delete_scan, methods=["DELETE"]),
        Route("/api/cmdb/import", import_cmdb, methods=["POST"]),
        Route("/api/imports/cloudlist", cloudlist_status, methods=["GET"]),
        Route("/api/imports/cloudlist", cloudlist_upload, methods=["POST"]),
        Route("/api/imports/cloudlist", cloudlist_clear, methods=["DELETE"]),
        Route("/api/cmdb", list_cmdb, methods=["GET"]),
        Route("/api/cmdb", clear_cmdb, methods=["DELETE"]),
    ]
