"""CLI: python -m asm [serve|reset-token|migrate|versions]"""
from __future__ import annotations

import json
import sys

from . import config as config_mod
from .db import DB, migrate
from .security import reset_access_token
from .tools import tool_versions


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "serve"
    cfg = config_mod.load()
    if cmd == "serve":
        import uvicorn
        uvicorn.run("asm.app:create_app", factory=True, host="0.0.0.0", port=8000,
                    proxy_headers=False, server_header=False, log_level="info")
        return 0
    if cmd == "migrate":
        print(f"schema version {migrate(cfg.db_path)}")
        return 0
    if cmd == "reset-token":
        migrate(cfg.db_path)
        db = DB(cfg.db_path)
        try:
            token = reset_access_token(db)
        finally:
            db.close()
        print(f"New access token (all sessions signed out):\n\n  {token}\n")
        return 0
    if cmd == "versions":
        print(json.dumps(tool_versions(), indent=2))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
