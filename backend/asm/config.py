"""Runtime configuration from environment variables (set in docker-compose.yml)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _list(name: str, default: str) -> list[str]:
    return [p.strip().lower() for p in os.environ.get(name, default).split(",") if p.strip()]


@dataclass(frozen=True)
class Config:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("ASM_DATA_DIR", "/data")))
    secrets_dir: Path = field(default_factory=lambda: Path(os.environ.get("ASM_SECRETS_DIR", "/secrets")))
    static_dir: Path = field(default_factory=lambda: Path(os.environ.get("ASM_STATIC_DIR", "/app/static")))
    # Host headers accepted (DNS-rebinding defence). Ports are ignored when matching.
    allowed_hosts: list[str] = field(default_factory=lambda: _list("ASM_ALLOWED_HOSTS", "localhost,127.0.0.1"))
    session_hours: int = field(default_factory=lambda: int(os.environ.get("ASM_SESSION_HOURS", "12")))
    cookie_secure: bool = field(default_factory=lambda: os.environ.get("ASM_COOKIE_SECURE", "false").lower() == "true")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "asm.db"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def master_key_path(self) -> Path:
        return self.secrets_dir / "master.key"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.mkdir(parents=True, exist_ok=True)


def load() -> Config:
    cfg = Config()
    cfg.ensure_dirs()
    return cfg
