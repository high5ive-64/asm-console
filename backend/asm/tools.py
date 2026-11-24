"""Discover installed tool versions (shown on About and recorded with each scan)."""
from __future__ import annotations

import re
import shutil
import subprocess

# name -> (binary, version args). Version commands are fixed and never take user input.
VERSION_COMMANDS: dict[str, tuple[str, list[str]]] = {
    "bbot": ("bbot", ["--version"]),
    "zap": ("zap.sh", ["-cmd", "-version"]),
    "tlsx": ("tlsx", ["-version"]),
    "smap": ("smap", ["-h"]),
    "gau": ("gau", ["--version"]),
    "dnstwist": ("dnstwist", ["--version"]),
    "uro": ("uro", ["--help"]),
    "dig": ("dig", ["-v"]),
    "typst": ("typst", ["--version"]),
    "firefox": ("firefox-esr", ["--version"]),
    "geckodriver": ("geckodriver", ["--version"]),
    "java": ("java", ["-version"]),
    "cdncheck": ("cdncheck", ["-version"]),
    "cloudlist": ("cloudlist", ["-version"]),
    "dnsreaper": ("dnsreaper", ["--help"]),
    "checkdmarc": ("checkdmarc", ["-v"]),
    "testssl.sh": ("testssl.sh", ["--version"]),
    "opensquat": ("opensquat", ["-h"]),
    "dnsx": ("dnsx", ["-version"]),
    "naabu": ("naabu", ["-version"]),
}
VER_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z]+)?)")


def tool_versions(timeout: float = 20.0) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, (binary, args) in VERSION_COMMANDS.items():
        path = shutil.which(binary)
        if not path:
            out[name] = "not installed"
            continue
        try:
            p = subprocess.run([path, *args], capture_output=True, text=True, timeout=timeout)
            text = (p.stdout or "") + (p.stderr or "")
            m = VER_RE.search(text)
            out[name] = m.group(1) if m else "installed"
        except (subprocess.TimeoutExpired, OSError):
            out[name] = "installed (version check failed)"
    return out
