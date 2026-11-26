#!/usr/bin/env python3
"""Export a frozen, redacted snapshot of one completed scan for the public/offline demo.

Runs the real result handlers (via an in-process TestClient) so the snapshot is byte-for-byte
what the app serves, then redacts it:
  - emails and IPs (v4/v6) -> email-NN / ip-NN   (blanket, consistent aliases)
  - host names -> asset-NN                         (blanket EXCEPT standards/reference domains,
                                                     so MITRE/CWE/OWASP/NVD/EPSS/KEV links still work)
The snapshot is consumed by frontend/src/main-demo.tsx (GitHub Pages) and the in-app /demo tab.

Run it where the backend dependencies are installed (e.g. inside the app image):
    python tools/export_demo_snapshot.py --scan <id> --out frontend/src/demo_snapshot.json
--scan defaults to the most recent completed scan. Then rebuild the static demo:
    cd frontend && npm run build:demo
"""
from __future__ import annotations
import argparse, ipaddress, json, os, re, sys

ALLOW_BASES = {"mitre.org", "nist.gov", "owasp.org", "first.org", "cisa.gov", "ietf.org",
               "mozilla.org", "m3aawg.org", "apwg.org", "csf.tools"}
EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}", re.I)
IP4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
IP6_RE = re.compile(r"(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}", re.I)
HOST_RE = re.compile(r"\b(?:[a-z0-9_-]+\.)+[a-z]{2,}\b", re.I)


def _allowed(host: str) -> bool:
    host = host.lower()
    return any(host == b or host.endswith("." + b) for b in ALLOW_BASES)


class R:
    def __init__(self, root: str):
        self.h: dict[str, str] = {}
        self.i: dict[str, str] = {}
        self.e: dict[str, str] = {}
        self.brand = root.split(".")[-2] if "." in root else root
        self.host(root)  # seed apex -> asset-01

    def host(self, h):
        h = h.lower()
        self.h.setdefault(h, f"asset-{len(self.h) + 1:02d}")
        return self.h[h]

    def ip(self, v):
        self.i.setdefault(v, f"ip-{len(self.i) + 1:02d}")
        return self.i[v]

    def email(self, v):
        v = v.lower()
        self.e.setdefault(v, f"email-{len(self.e) + 1:02d}")
        return self.e[v]

    def _ip6(self, m):
        t = m.group(0)
        try:
            if ipaddress.ip_address(t).version != 6:
                return t
        except ValueError:
            return t
        return self.ip(t)

    def _host(self, m):
        h = m.group(0)
        return h if _allowed(h) else self.host(h)

    def s(self, v):
        if not v:
            return v
        v = EMAIL_RE.sub(lambda m: self.email(m.group(0)), v)
        v = IP4_RE.sub(lambda m: self.ip(m.group(0)), v)
        v = IP6_RE.sub(self._ip6, v)
        v = HOST_RE.sub(self._host, v)
        v = re.sub(re.escape(self.brand), "asset-01", v, flags=re.I)  # bare brand label (e.g. utm_* params)
        return v

    def walk(self, o):
        if isinstance(o, str):
            return self.s(o)
        if isinstance(o, list):
            return [self.walk(x) for x in o]
        if isinstance(o, dict):
            return {k: self.walk(v) for k, v in o.items()}
        return o


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", default=None, help="scan id (default: latest completed)")
    ap.add_argument("--out", default="frontend/src/demo_snapshot.json")
    args = ap.parse_args()

    from starlette.testclient import TestClient
    from asm.app import create_app
    from asm.db import DB
    from asm.security import create_session, SESSION_COOKIE
    from asm import config as cfgmod

    cfg = cfgmod.load()
    db = DB(cfg.db_path)
    sid_row = args.scan
    if not sid_row:
        row = db.one("SELECT id FROM scans WHERE status='completed' ORDER BY rowid DESC")
        if not row:
            print("no completed scan found", file=sys.stderr)
            return 2
        sid_row = row["id"]
    meta_row = db.one("SELECT root_domain FROM scans WHERE id = ?", sid_row)
    if not meta_row:
        print(f"scan {sid_row} not found", file=sys.stderr)
        return 2
    root = meta_row["root_domain"]
    red = R(root)

    app = create_app(cfg, check_tools=False)
    sess, _ = create_session(db, 12)
    db.close()

    snap = {"scanId": sid_row, "root": "asset-01", "endpoints": {}}
    with TestClient(app, base_url="http://localhost") as c:
        c.cookies.set(SESSION_COOKIE, sess)

        def g(ep):
            r = c.get(f"/api/scans/{sid_row}{ep}")
            if r.status_code != 200:
                raise SystemExit(f"{ep} -> {r.status_code} {r.text[:200]}")
            return r.json()

        snap["meta"] = red.walk(g(""))
        for ep in ["/overview", "/assets", "/ips", "/dns", "/graph", "/attack-paths",
                   "/findings", "/changes", "/triage", "/emails"]:
            snap["endpoints"][ep] = red.walk(g(ep))
        for a in g("/assets").get("assets", []):
            h = a.get("host")
            if h:
                snap["endpoints"][f"/endpoints?host={red.host(h)}"] = red.walk(g(f"/endpoints?host={h}"))
        for f in g("/findings").get("findings", []):
            snap["endpoints"][f"/findings/{f['id']}"] = red.walk(g(f"/findings/{f['id']}"))
        pv = g("/report/preview?kind=master")
        for k in [x["kind"] for x in pv.get("kinds", [])] or ["master"]:
            snap["endpoints"][f"/report/preview?kind={k}"] = red.walk(g(f"/report/preview?kind={k}"))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, separators=(",", ":"), ensure_ascii=False)
    print(f"wrote {args.out}: {len(snap['endpoints'])} endpoints, "
          f"{len(red.h)} hosts / {len(red.i)} ips / {len(red.e)} emails redacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
