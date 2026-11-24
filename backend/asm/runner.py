"""Runs allowlisted tool commands as subprocesses, streaming output into the events table.

Every command goes through allowlist.validate() first. Child processes get a minimal
environment, their own process group (so cancel kills the whole tree), a timeout, and
secret values are masked out of every stored log line.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import signal
import time
from pathlib import Path
from typing import Callable

from .allowlist import CommandRejected, Ctx, validate
from .db import DB, now
from .secrets_store import mask

import re

MAX_LINE = 2000
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")
BASE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "JAVA_HOME", "_JAVA_OPTIONS", "TZ")


class StageCancelled(Exception):
    pass


class StageFailed(Exception):
    pass


class Runner:
    """One per scan run. Tracks every live process (stages can run in parallel) so cancel stops them all."""

    def __init__(self, db_path: Path, scan_id: str, run_dir: Path, secret_values: list[str]):
        self.db_path = db_path
        self.scan_id = scan_id
        self.run_dir = run_dir
        self.secret_values = secret_values
        self.procs: set[asyncio.subprocess.Process] = set()
        self.cancelled = False
        self.paused = False
        self.paused_since: float | None = None
        self.paused_total = 0.0          # seconds spent paused, so time limits don't count pauses

    # ---- events -----------------------------------------------------------
    def event(self, stage: str | None, message: str, level: str = "info") -> None:
        msg = mask(message, self.secret_values)[:MAX_LINE]
        db = DB(self.db_path)
        try:
            db.run("INSERT INTO events (scan_id, stage_key, ts, level, message) VALUES (?, ?, ?, ?, ?)",
                   self.scan_id, stage, now(), level, msg)
        finally:
            db.close()

    def set_stage(self, stage: str, status: str, **fields) -> None:
        db = DB(self.db_path)
        try:
            db.run("INSERT INTO stages (scan_id, stage_key, status) VALUES (?, ?, ?) "
                   "ON CONFLICT(scan_id, stage_key) DO UPDATE SET status = excluded.status",
                   self.scan_id, stage, status)
            if status == "running" and not fields.get("keep_started"):
                # a (re)started stage begins with a clean slate: no leftover summary or error from an earlier run
                db.run("UPDATE stages SET started_at = ?, finished_at = NULL, exit_code = NULL, summary = '{}' "
                       "WHERE scan_id = ? AND stage_key = ?", now(), self.scan_id, stage)
            elif status in ("done", "failed", "cancelled", "skipped"):
                db.run("UPDATE stages SET finished_at = ? WHERE scan_id = ? AND stage_key = ?", now(), self.scan_id, stage)
            for k, v in fields.items():
                if k in ("exit_code", "summary", "log_path"):
                    db.run(f"UPDATE stages SET {k} = ? WHERE scan_id = ? AND stage_key = ?", v, self.scan_id, stage)
        finally:
            db.close()

    # ---- processes --------------------------------------------------------
    async def run(self, stage: str, argv: list[str], timeout_s: int, env: dict[str, str] | None = None,
                  line_filter: Callable[[str], bool] | None = None, cwd: Path | None = None,
                  stdout_file: Path | None = None, allow_active: bool = False,
                  idle_timeout_s: int | None = None, is_progress: Callable[[str], bool] | None = None) -> int:
        """Run argv. stdout_file: write the tool's stdout there (for JSON output) instead of the log.

        allow_active=True permits BBOT's active-tier modules/flags for this one command: set only by the pipeline
        when the scan explicitly requested an authorised active pass.
        """
        if self.cancelled:
            raise StageCancelled()
        ctx = Ctx(allowed_dirs=[self.run_dir], allow_active=allow_active)
        try:
            validate(argv, ctx)
        except CommandRejected as exc:
            self.event(stage, f"Command blocked by allowlist: {exc}", "error")
            raise StageFailed(str(exc)) from exc
        binary = shutil.which(argv[0]) or argv[0]
        child_env = {k: os.environ[k] for k in BASE_ENV_KEYS if k in os.environ}
        child_env.update(env or {})
        self.event(stage, "$ " + " ".join(argv), "cmd")
        log_path = self.run_dir / "logs" / f"{stage}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        out_fh = open(stdout_file, "wb") if stdout_file else None
        proc = await asyncio.create_subprocess_exec(
            binary, *argv[1:], stdout=out_fh or asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE if out_fh else asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL, env=child_env, cwd=str(cwd or self.run_dir),
            start_new_session=True,
        )
        self.procs.add(proc)
        if self.paused:                      # started while the scan is paused: hold it straight away
            self._signal(proc, signal.SIGSTOP)
        activity = [time.monotonic()]        # last time the tool made forward progress (for idle_timeout_s)
        pump = asyncio.create_task(self._pump(proc, stage, log_path, line_filter, is_progress, activity))
        try:
            start, paused_at_start = time.monotonic(), self.paused_seconds()
            while True:
                done, _ = await asyncio.wait({pump}, timeout=2)
                if done:
                    pump.result()
                    break
                now = time.monotonic()
                if self.paused:              # don't let idle (or the clock's intent) accrue while paused
                    activity[0] = now
                active = now - start - (self.paused_seconds() - paused_at_start)
                if active > timeout_s:
                    pump.cancel()
                    self._kill(proc)
                    self.event(stage, f"Timed out after {timeout_s // 60} min; stopped.", "error")
                    raise StageFailed("timeout")
                if idle_timeout_s and (now - activity[0]) > idle_timeout_s:
                    pump.cancel()
                    self._kill(proc)
                    self.event(stage, f"No new activity for {idle_timeout_s // 60} min {idle_timeout_s % 60}s; "
                                      f"stopped and kept results so far.", "warn")
                    raise StageFailed("timeout")
            rc = await proc.wait()
        finally:
            if out_fh:
                out_fh.close()
            self.procs.discard(proc)
            if proc.returncode is None:
                self._kill(proc)
        if self.cancelled:
            raise StageCancelled()
        return rc

    async def _pump(self, proc, stage: str, log_path: Path, line_filter,
                    is_progress: Callable[[str], bool] | None = None, activity: list | None = None) -> None:
        stream = proc.stdout or proc.stderr
        assert stream is not None
        with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
            async for raw in stream:
                line = ANSI_RE.sub("", raw.decode("utf-8", errors="replace")).rstrip()
                line = mask(line, self.secret_values)
                fh.write(line + "\n")
                fh.flush()
                if activity is not None and line and (is_progress is None or is_progress(line)):
                    activity[0] = time.monotonic()        # forward progress: reset the idle watchdog
                if line and (line_filter is None or line_filter(line)):
                    self.event(stage, line[:MAX_LINE], "log")

    def _kill(self, p: asyncio.subprocess.Process) -> None:
        if not p or p.returncode is not None:
            return
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        asyncio.get_event_loop().call_later(10, self._force_kill, p.pid)

    @staticmethod
    def _force_kill(pid: int) -> None:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def cancel(self) -> None:
        self.cancelled = True
        if self.paused:
            self.resume()                    # stopped processes can't act on SIGTERM
        for p in list(self.procs):
            self._kill(p)

    # ---- pause / resume -----------------------------------------------------
    def paused_seconds(self) -> float:
        return self.paused_total + (time.monotonic() - self.paused_since if self.paused and self.paused_since else 0.0)

    def pause(self) -> None:
        if self.paused:
            return
        self.paused, self.paused_since = True, time.monotonic()
        for p in list(self.procs):
            self._signal(p, signal.SIGSTOP)
        self.event(None, "Scan paused: running tools are frozen and no new stages will start.", "warn")

    def resume(self) -> None:
        if not self.paused:
            return
        self.paused_total += time.monotonic() - (self.paused_since or time.monotonic())
        self.paused, self.paused_since = False, None
        for p in list(self.procs):
            self._signal(p, signal.SIGCONT)
        self.event(None, "Scan resumed.", "info")

    @staticmethod
    def _signal(p, sig) -> None:
        if p.returncode is not None:
            return
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            pass

    async def wait_while_paused(self) -> None:
        while self.paused and not self.cancelled:
            await asyncio.sleep(1)


# Live runners by scan id (single process, so a dict is enough)
ACTIVE: dict[str, Runner] = {}
TASKS: dict[str, asyncio.Task] = {}
# ZAP checkpoint: scan id -> event set when the operator confirms which hosts ZAP should scan
ZAP_GATES: dict[str, asyncio.Event] = {}
# ZAP progress: scan id -> {"hosts": [...], "current": n, "job": str}
ZAP_PROGRESS: dict[str, dict] = {}
