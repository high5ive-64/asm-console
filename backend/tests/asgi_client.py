"""Minimal synchronous ASGI test client (no httpx dependency). Handles lifespan and cookies."""
from __future__ import annotations

import asyncio
import json as jsonlib
from http.cookies import SimpleCookie


class Resp:
    def __init__(self, status: int, headers: list[tuple[bytes, bytes]], body: bytes):
        self.status_code = status
        self.headers = {}
        self.set_cookies = []
        for k, v in headers:
            key, val = k.decode().lower(), v.decode()
            if key == "set-cookie":
                self.set_cookies.append(val)
            self.headers[key] = val
        self.content = body

    def json(self):
        return jsonlib.loads(self.content)

    @property
    def text(self) -> str:
        return self.content.decode()


class Client:
    def __init__(self, app, host: str = "localhost:8443"):
        self.app = app
        self.host = host
        self.cookies: dict[str, str] = {}
        self.loop = asyncio.new_event_loop()
        self._lifespan_queue: asyncio.Queue | None = None
        self._start_lifespan()

    def _start_lifespan(self):
        async def run():
            q_in: asyncio.Queue = asyncio.Queue()
            q_out: asyncio.Queue = asyncio.Queue()
            self._lifespan_queue = q_in
            self._lifespan_out = q_out

            async def receive():
                return await q_in.get()

            async def send(msg):
                await q_out.put(msg)

            self._lifespan_task = asyncio.ensure_future(self.app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send))
            await q_in.put({"type": "lifespan.startup"})
            msg = await q_out.get()
            assert msg["type"] == "lifespan.startup.complete", msg
        self.loop.run_until_complete(run())

    def close(self):
        async def stop():
            await self._lifespan_queue.put({"type": "lifespan.shutdown"})
            await self._lifespan_out.get()
        self.loop.run_until_complete(stop())
        self.loop.close()

    def request(self, method: str, path: str, json=None, data: bytes | None = None,
                headers: dict | None = None, host: str | None = None) -> Resp:
        body = jsonlib.dumps(json).encode() if json is not None else (data or b"")
        hdrs = {"host": host or self.host}
        if json is not None:
            hdrs["content-type"] = "application/json"
        if self.cookies:
            hdrs["cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
        p, _, q = path.partition("?")
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
            "scheme": "http", "path": p, "raw_path": p.encode(), "query_string": q.encode(),
            "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()],
            "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8000), "root_path": "",
        }
        sent = {"body": False}
        out = {"status": None, "headers": [], "body": b""}

        async def receive():
            if not sent["body"]:
                sent["body"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            await asyncio.sleep(3600)

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]; out["headers"] = msg.get("headers", [])
            elif msg["type"] == "http.response.body":
                out["body"] += msg.get("body", b"")

        self.loop.run_until_complete(self.app(scope, receive, send))
        r = Resp(out["status"], out["headers"], out["body"])
        for sc in r.set_cookies:
            c = SimpleCookie(); c.load(sc)
            for k, m in c.items():
                if m["max-age"] == "0" or m.value in ("", '""'):
                    self.cookies.pop(k, None)
                else:
                    self.cookies[k] = m.value
        return r

    def get(self, path, **kw): return self.request("GET", path, **kw)
    def post(self, path, **kw): return self.request("POST", path, **kw)
    def put(self, path, **kw): return self.request("PUT", path, **kw)
    def delete(self, path, **kw): return self.request("DELETE", path, **kw)


def pump(client: Client, until, timeout: float = 15.0) -> bool:
    """Run the client's event loop (background tasks) until until() is true."""
    import time
    end = time.time() + timeout
    while time.time() < end:
        client.loop.run_until_complete(asyncio.sleep(0.05))
        if until():
            return True
    return False
