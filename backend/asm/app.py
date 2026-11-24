"""Outsider ASM web application (Starlette)."""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import __version__
from . import config as config_mod
from .db import DB, migrate
from .secrets_store import SecretError, SecretStore, load_or_create_master_key, valid_name
from .security import (
    CSRF_COOKIE, SESSION_COOKIE, GuardMiddleware, check_access_token, create_session, delete_session,
    ensure_access_token, get_session,
)
from .settings_model import Settings
from .tools import tool_versions

log = logging.getLogger("asm")
MAX_BODY = 2 * 1024 * 1024


class State:
    cfg: config_mod.Config
    master_key: bytes
    tool_versions: dict[str, str] = {}

    def db(self) -> DB:
        return DB(self.cfg.db_path)


state = State()


def err(status: int, detail: str, **extra) -> JSONResponse:
    return JSONResponse({"error": detail, **extra}, status_code=status)


async def body(request: Request, model: type[BaseModel]) -> BaseModel:
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise ValueError("request too large")
    return model.model_validate_json(raw or b"{}")


def validation_response(exc: ValidationError) -> JSONResponse:
    issues = [{"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]} for e in exc.errors()]
    return err(422, "validation failed", issues=issues)


# ---- auth ----------------------------------------------------------------

class LoginIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


_login_failures: list[float] = []


async def login(request: Request) -> Response:
    loop = asyncio.get_running_loop()
    recent = [t for t in _login_failures if loop.time() - t < 60]
    if len(recent) >= 10:
        return err(429, "too many attempts, wait a minute")
    try:
        data = await body(request, LoginIn)
    except ValidationError as exc:
        return validation_response(exc)
    db = state.db()
    try:
        if not check_access_token(db, data.token):
            _login_failures.append(loop.time())
            await asyncio.sleep(0.5)
            return err(401, "invalid access token")
        sid, csrf = create_session(db, state.cfg.session_hours)
    finally:
        db.close()
    resp = JSONResponse({"ok": True, "csrf": csrf})
    common = dict(samesite="strict", secure=state.cfg.cookie_secure, path="/", max_age=state.cfg.session_hours * 3600)
    resp.set_cookie(SESSION_COOKIE, sid, httponly=True, **common)
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, **common)
    return resp


async def logout(request: Request) -> Response:
    db = state.db()
    try:
        delete_session(db, request.cookies.get(SESSION_COOKIE))
    finally:
        db.close()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")
    return resp


async def auth_status(request: Request) -> Response:
    db = state.db()
    try:
        sess = get_session(db, request.cookies.get(SESSION_COOKIE))
    finally:
        db.close()
    return JSONResponse({"authenticated": bool(sess), "csrf": sess["csrf"] if sess else None})


# ---- basics --------------------------------------------------------------

async def health(request: Request) -> Response:
    return JSONResponse({"ok": True})


async def about(request: Request) -> Response:
    return JSONResponse({
        "app_version": __version__,
        "tools": state.tool_versions,
        "data_dir": str(state.cfg.data_dir),
    })


async def get_settings(request: Request) -> Response:
    db = state.db()
    try:
        stored = db.get_setting("app", {})
    finally:
        db.close()
    return JSONResponse(Settings.model_validate(stored).model_dump())


async def put_settings(request: Request) -> Response:
    try:
        s = await body(request, Settings)
    except ValidationError as exc:
        return validation_response(exc)
    db = state.db()
    try:
        db.set_setting("app", s.model_dump())
    finally:
        db.close()
    return JSONResponse(s.model_dump())


def load_settings() -> Settings:
    db = state.db()
    try:
        return Settings.model_validate(db.get_setting("app", {}))
    finally:
        db.close()


# ---- secrets (write-only) ----------------------------------------------

class SecretIn(BaseModel):
    value: str = Field(min_length=1, max_length=4096)


def store(db: DB) -> SecretStore:
    return SecretStore(db, state.master_key)


async def list_secrets(request: Request) -> Response:
    db = state.db()
    try:
        return JSONResponse({"secrets": store(db).status()})
    finally:
        db.close()


async def put_secret(request: Request) -> Response:
    name = request.path_params["name"]
    if not valid_name(name):
        return err(404, "unknown secret name")
    try:
        data = await body(request, SecretIn)
    except ValidationError as exc:
        return validation_response(exc)
    db = state.db()
    try:
        store(db).set(name, data.value)
    except SecretError as exc:
        return err(422, str(exc))
    finally:
        db.close()
    return JSONResponse({"name": name, "set": True})  # the value is never echoed


async def delete_secret(request: Request) -> Response:
    name = request.path_params["name"]
    if not valid_name(name):
        return err(404, "unknown secret name")
    db = state.db()
    try:
        removed = store(db).delete(name)
    finally:
        db.close()
    return JSONResponse({"name": name, "set": False, "removed": removed})


# Fixed test endpoints per service. Keys travel only in request headers/query to the vendor.
SECRET_TESTS = {
    "shodan": lambda k: urllib.request.Request(f"https://api.shodan.io/api-info?key={k}"),
    "github": lambda k: urllib.request.Request("https://api.github.com/user",
                                               headers={"Authorization": f"Bearer {k}", "User-Agent": "outsider-asm"}),
    "hibp": lambda k: urllib.request.Request("https://haveibeenpwned.com/api/v3/subscription/status",
                                             headers={"hibp-api-key": k, "User-Agent": "outsider-asm"}),
    "virustotal": lambda k: urllib.request.Request("https://www.virustotal.com/api/v3/users/current",
                                                   headers={"x-apikey": k}),
    "urlscan": lambda k: urllib.request.Request("https://urlscan.io/user/quotas/", headers={"API-Key": k, "User-Agent": "outsider-asm"}),
    "nvd": lambda k: urllib.request.Request("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
                                            headers={"apiKey": k, "User-Agent": "outsider-asm"}),
    "netlas": lambda k: urllib.request.Request("https://app.netlas.io/api/users/current/",
                                               headers={"X-API-Key": k, "User-Agent": "outsider-asm"}),
    "leakix": lambda k: urllib.request.Request("https://leakix.net/api/subdomains/leakix.net",
                                               headers={"api-key": k, "Accept": "application/json", "User-Agent": "outsider-asm"}),
}


def _probe(req: urllib.request.Request) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return (200 <= r.status < 300), f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return False, f"network error: {getattr(e, 'reason', e)}"


async def test_secret(request: Request) -> Response:
    name = request.path_params["name"]
    if name not in SECRET_TESTS:
        return JSONResponse({"name": name, "testable": False, "message": "No automatic test for this service; the key is saved."})
    db = state.db()
    try:
        key = store(db).get(name)
    finally:
        db.close()
    if not key:
        return err(404, "key not set")
    ok, msg = await asyncio.to_thread(_probe, SECRET_TESTS[name](key))
    return JSONResponse({"name": name, "testable": True, "ok": ok, "message": msg})


# ---- frontend ------------------------------------------------------------

async def spa(request: Request) -> Response:
    index = state.cfg.static_dir / "index.html"
    if request.url.path.startswith("/api/"):
        return err(404, "not found")
    if index.exists():
        return FileResponse(index, headers={"cache-control": "no-cache"})
    return Response("Frontend not built. Run the Docker build, or `make frontend`.", media_type="text/plain")


# ---- app factory -----------------------------------------------------------

def startup(cfg: config_mod.Config) -> None:
    state.cfg = cfg
    migrate(cfg.db_path)
    state.master_key = load_or_create_master_key(cfg.master_key_path)
    db = state.db()
    try:
        token = ensure_access_token(db)
        # rebrand: a saved user agent that's still the old default follows the new default
        from .settings_model import DEFAULT_USER_AGENT, OLD_DEFAULT_USER_AGENTS
        saved = db.get_setting("app", {})
        if saved.get("user_agent") in OLD_DEFAULT_USER_AGENTS:
            db.set_setting("app", {**saved, "user_agent": DEFAULT_USER_AGENT})
        from .pipeline import mark_interrupted
        if mark_interrupted(db):
            print("Scans interrupted by the restart were marked 'interrupted'; resume them from the UI.", flush=True)
    finally:
        db.close()
    if token:
        banner = "=" * 64
        print(f"\n{banner}\n Outsider ASM access token (shown once):\n\n   {token}\n\n"
              f" Reset it any time with: docker compose exec asm python -m asm reset-token\n{banner}\n", flush=True)


def create_app(cfg: config_mod.Config | None = None, check_tools: bool = True) -> Starlette:
    cfg = cfg or config_mod.load()

    @asynccontextmanager
    async def lifespan(app):
        startup(cfg)
        if check_tools:
            state.tool_versions = await asyncio.to_thread(tool_versions)
        yield

    api = [
        Route("/api/health", health),
        Route("/api/auth/login", login, methods=["POST"]),
        Route("/api/auth/logout", logout, methods=["POST"]),
        Route("/api/auth/status", auth_status),
        Route("/api/about", about),
        Route("/api/settings", get_settings, methods=["GET"]),
        Route("/api/settings", put_settings, methods=["PUT"]),
        Route("/api/secrets", list_secrets),
        Route("/api/secrets/{name:str}", put_secret, methods=["PUT"]),
        Route("/api/secrets/{name:str}", delete_secret, methods=["DELETE"]),
        Route("/api/secrets/{name:str}/test", test_secret, methods=["POST"]),
    ]
    from .api_scans import routes as scan_routes  # noqa: E402  (keeps this file small)
    from .api_run import routes as run_routes  # noqa: E402
    from .api_results import routes as results_routes  # noqa: E402
    api += run_routes(state)
    api += results_routes(state)
    api += scan_routes(state)

    routes = list(api)
    assets = cfg.static_dir / "assets"
    if assets.exists():
        routes.append(Mount("/assets", app=StaticFiles(directory=assets), name="assets"))
    routes.append(Route("/{path:path}", spa))

    return Starlette(
        routes=routes,
        lifespan=lifespan,
        middleware=[Middleware(GuardMiddleware, db_factory=lambda: DB(cfg.db_path), allowed_hosts=cfg.allowed_hosts)],
    )
