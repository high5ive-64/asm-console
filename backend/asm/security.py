"""Local access control: access token, sessions, CSRF, and Host/Origin checks."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .db import DB, now

SESSION_COOKIE = "asm_session"
CSRF_COOKIE = "asm_csrf"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = {"/api/health", "/api/auth/login", "/api/auth/status"}


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---- access token -------------------------------------------------------

def ensure_access_token(db: DB) -> str | None:
    """Create the access token on first start. Returns the new token (to print once) or None."""
    if db.one("SELECT 1 FROM auth_token WHERE id = 1"):
        return None
    return reset_access_token(db)


def reset_access_token(db: DB) -> str:
    token = secrets.token_urlsafe(24)
    with db.tx():
        db.run("DELETE FROM auth_token")
        db.run("INSERT INTO auth_token (id, token_hash, created_at) VALUES (1, ?, ?)", _h(token), now())
        db.run("DELETE FROM sessions")
    return token


def check_access_token(db: DB, token: str) -> bool:
    row = db.one("SELECT token_hash FROM auth_token WHERE id = 1")
    return bool(row) and hmac.compare_digest(row["token_hash"], _h(token))


# ---- sessions ------------------------------------------------------------

def create_session(db: DB, hours: int) -> tuple[str, str]:
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
    db.run("DELETE FROM sessions WHERE expires_at < ?", now())
    db.run("INSERT INTO sessions (id_hash, csrf, created_at, expires_at) VALUES (?, ?, ?, ?)",
           _h(sid), csrf, now(), expires)
    return sid, csrf


def get_session(db: DB, sid: str | None) -> dict | None:
    if not sid:
        return None
    row = db.one("SELECT csrf, expires_at FROM sessions WHERE id_hash = ?", _h(sid))
    if not row or row["expires_at"] < now():
        return None
    return {"csrf": row["csrf"]}


def delete_session(db: DB, sid: str | None) -> None:
    if sid:
        db.run("DELETE FROM sessions WHERE id_hash = ?", _h(sid))


# ---- middleware ----------------------------------------------------------

def _host_allowed(host_header: str, allowed: list[str]) -> bool:
    host = host_header.strip().lower()
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    return host in allowed


class GuardMiddleware:
    """Pure ASGI middleware applied to every HTTP and WebSocket request.

    1. Host header must be an allowed loopback name (defeats DNS rebinding).
    2. Origin, when present, must also be allowed (defeats cross-site requests).
    3. /api/* (except public paths) requires a valid session cookie.
    4. State-changing methods require the CSRF header to match the session's token.
    5. Security headers on every response.
    """

    def __init__(self, app: ASGIApp, db_factory, allowed_hosts: list[str]):
        self.app = app
        self.db_factory = db_factory
        self.allowed = allowed_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET")

        if not _host_allowed(headers.get("host", ""), self.allowed):
            return await self._deny(scope, receive, send, 421, "host not allowed")
        origin = headers.get("origin")
        if origin and origin != "null":
            if not _host_allowed(urlsplit(origin).netloc, self.allowed):
                return await self._deny(scope, receive, send, 403, "origin not allowed")
        elif origin == "null":
            return await self._deny(scope, receive, send, 403, "origin not allowed")

        if path.startswith("/api/") and path not in PUBLIC_PATHS:
            cookies = _parse_cookies(headers.get("cookie", ""))
            db = self.db_factory()
            try:
                sess = get_session(db, cookies.get(SESSION_COOKIE))
            finally:
                db.close()
            if not sess:
                return await self._deny(scope, receive, send, 401, "login required")
            if scope["type"] == "http" and method not in SAFE_METHODS:
                if not hmac.compare_digest(headers.get(CSRF_HEADER, ""), sess["csrf"]):
                    return await self._deny(scope, receive, send, 403, "CSRF token missing or invalid")
            if scope["type"] == "websocket" and not origin:
                return await self._deny(scope, receive, send, 403, "origin required")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = list(message.get("headers", []))
                have = {k.lower() for k, _ in h}
                defaults = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"content-security-policy",
                     b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                     b"connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                     b"form-action 'self'; object-src 'none'"),
                ]
                # a response that sets a stricter policy itself (raw tool output: sandboxed) keeps it
                h += [(k, v) for k, v in defaults if k not in have]
                if path.startswith("/api/"):
                    h.append((b"cache-control", b"no-store"))
                message["headers"] = h
            await send(message)

        return await self.app(scope, receive, send_with_headers)

    @staticmethod
    async def _deny(scope, receive, send, status: int, detail: str) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4403})
            return
        await JSONResponse({"error": detail}, status_code=status)(scope, receive, send)


def _parse_cookies(header: str) -> dict[str, str]:
    out = {}
    for part in header.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            out[k] = v
    return out


def session_cookie_id(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)
