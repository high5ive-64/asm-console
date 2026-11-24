import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from asgi_client import Client  # noqa: E402


@pytest.fixture
def app_env(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ASM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ASM_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("ASM_STATIC_DIR", str(tmp_path / "static"))
    from asm import config
    from asm.app import create_app
    app = create_app(config.load(), check_tools=False)
    client = Client(app)
    out = capsys.readouterr().out
    token = next(line.strip() for line in out.splitlines() if len(line.strip()) >= 30 and " " not in line.strip() and set(line.strip()) != {"="})
    yield client, token, tmp_path
    client.close()


@pytest.fixture
def authed(app_env):
    client, token, tmp = app_env
    r = client.post("/api/auth/login", json={"token": token})
    assert r.status_code == 200, r.text
    csrf = r.json()["csrf"]
    return client, {"x-csrf-token": csrf}, tmp
