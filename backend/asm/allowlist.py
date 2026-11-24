"""Command allowlist: every argv the app executes is checked here first.

A stage builds an argument list (never a shell string) and calls validate(). Anything not
explicitly allowed - an unknown binary, an unknown flag, a forbidden module or preset, a path
outside the run folder - raises CommandRejected and the command never runs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .scope import ScopeError, normalise_domain

FORBIDDEN_BINARIES = {
    "nmap", "masscan", "rustscan", "zmap", "ffuf", "gobuster", "dirsearch", "feroxbuster",
    "dirb", "wfuzz", "nuclei", "sqlmap", "nikto", "hydra", "medusa", "ncrack", "wpscan", "msfconsole",
    "zap-full-scan.py", "zap-api-scan.py", "sh", "bash", "zsh", "dash", "python", "python3", "perl",
    "ruby", "node", "curl", "wget", "nc", "ncat", "socat",
}

# naabu is the one port scanner allowed, only as an opt-in stage (off by default, warned in the UI) and only as a
# plain TCP connect scan at a low rate: the flags below don't permit SYN scans, host discovery or high rates.
NAABU_PORTS = re.compile(r"\d{1,5}(,\d{1,5}){0,999}")

# Two tiers of non-passive BBOT modules.
#   NEVER: credential brute-forcers and anything that downloads/exfiltrates target data or walks DNS zones.
#          Blocked unconditionally, whatever switches are set — this line is never crossed from the UI.
#   ACTIVE: enumeration, content-discovery and vulnerability modules. Blocked by default; allowed only on an
#          explicit active pass (the "BBOT active modules" switch, which is off by default, warned and
#          authorisation-gated). The pipeline, not the allowlist, decides when an active pass is permitted.
NEVER_BBOT_MODULES = {
    "legba", "medusa", "webbrute", "webbrute_shortnames",   # login / credential brute-forcers
    "baddns_zone",                                           # zone transfers / NSEC walks against the target's NS
    "gitdumper", "git_clone", "docker_pull", "apkpure", "postman_download", "filedownload",  # pull/exfil target data
    "masscan", "nmap",                                       # use the gated naabu stage instead
}
ACTIVE_BBOT_MODULES = {
    "nuclei", "ffuf", "ffuf_shortnames", "iis_shortnames", "bypass403", "smuggler", "vhost", "virtualhost",
    "host_header", "generic_ssrf", "telerik", "dotnetnuke", "url_manipulation", "lightfuzz", "dastardly",
    "wpscan", "ajaxpro", "fingerprintx", "waf_bypass", "nowafpls", "reflected_parameters", "aspnet_bin_exposure",
    "paramminer_headers", "paramminer_getparams", "paramminer_cookies", "dnsbrute", "dnsbrute_mutations",
    "wafw00f", "ipneighbor", "portscan",
    "badsecrets", "secretsdb", "git", "hunt", "ntlm",   # BBOT 3.0 "safe" active checks (gated to active passes)
}
FORBIDDEN_BBOT_MODULES = NEVER_BBOT_MODULES | ACTIVE_BBOT_MODULES   # default: both tiers blocked
# BBOT 3.0 flags that mark risky modules; they may only ever appear after -ef, never -f/-rf.
# (3.0 renamed the 2.x risk flags: aggressive -> loud/invasive, web-thorough -> web-heavy, web-basic -> web.)
BBOT_RISK_FLAGS = {"invasive", "loud", "download", "web-heavy", "web-paramminer", "iis-shortnames", "portscan",
                   "deadly"}
SAFE_BBOT_PRESETS = {"subdomain-enum", "cloud-enum", "code-enum", "email-enum"}
SAFE_BBOT_FLAGS = {"passive", "safe", "subdomain-enum", "cloud-enum", "code-enum", "email-enum", "web"}
ACTIVE_BBOT_FLAGS = {"active", "loud", "invasive", "web-heavy", "deadly"}
ALLOWED_BBOT_FLAGS = SAFE_BBOT_FLAGS | ACTIVE_BBOT_FLAGS
BBOT_OUTPUTS = {"json", "csv", "asset_inventory", "txt", "subdomains"}
BBOT_CONFIG_KEYS = {"web.user_agent"}
ZAP_CONFIG_KEYS = {"network.connection.defaultUserAgent", "selenium.firefoxDriver", "selenium.firefoxBinary"}
DIG_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"}
GAU_PROVIDERS = {"wayback", "commoncrawl", "otx", "urlscan"}


class CommandRejected(ValueError):
    pass


@dataclass
class Ctx:
    """Where file arguments may point, and whether this command is an authorised active pass."""
    allowed_dirs: list[Path]
    allow_active: bool = False     # set only by the pipeline when the scan explicitly requested an active pass


Check = Callable[[str, Ctx], None]


def _path(v: str, ctx: Ctx) -> None:
    p = Path(v).resolve()
    if not any(p == d.resolve() or d.resolve() in p.parents for d in ctx.allowed_dirs):
        raise CommandRejected(f"path outside allowed folders: {v}")


def _yaml_path(v: str, ctx: Ctx) -> None:
    if not v.endswith((".yaml", ".yml")):
        raise CommandRejected("plan must be a .yaml file")
    _path(v, ctx)


def _domain(v: str, ctx: Ctx) -> None:
    try:
        normalise_domain(v)
    except ScopeError as exc:
        raise CommandRejected(f"invalid domain {v!r}") from exc


def _int(lo: int, hi: int) -> Check:
    def check(v: str, ctx: Ctx) -> None:
        if not v.isdigit() or not lo <= int(v) <= hi:
            raise CommandRejected(f"number out of range {lo}-{hi}: {v}")
    return check


def _choice(options: set[str], what: str) -> Check:
    def check(v: str, ctx: Ctx) -> None:
        if v not in options:
            raise CommandRejected(f"{what} not allowed: {v}")
    return check


def _csv_choice(options: set[str], what: str) -> Check:
    def check(v: str, ctx: Ctx) -> None:
        for part in v.split(","):
            if part not in options:
                raise CommandRejected(f"{what} not allowed: {part}")
    return check


def _regex(rx: str, what: str) -> Check:
    pat = re.compile(rx)
    def check(v: str, ctx: Ctx) -> None:
        if not pat.fullmatch(v):
            raise CommandRejected(f"invalid {what}: {v!r}")
    return check


def _config(keys: set[str]) -> Check:
    def check(v: str, ctx: Ctx) -> None:
        k, sep, val = v.partition("=")
        if not sep or k not in keys:
            raise CommandRejected(f"config key not allowed: {k}")
        if any(c in val for c in "\r\n\x00"):
            raise CommandRejected("control characters in config value")
    return check


def _target(v: str, ctx: Ctx) -> None:
    """BBOT targets/whitelists/blacklists: a domain or a file in the run folder."""
    if "/" in v:
        _path(v, ctx)
    else:
        _domain(v, ctx)


def _not_forbidden_module(v: str, ctx: Ctx) -> None:
    # NEVER-tier modules (credential brute-forcers, data-pull, zone walks) are blocked no matter what.
    # ACTIVE-tier modules are allowed only on an authorised active pass (ctx.allow_active).
    if v in NEVER_BBOT_MODULES:
        raise CommandRejected(f"forbidden BBOT module: {v}")
    if v in ACTIVE_BBOT_MODULES and not ctx.allow_active:
        raise CommandRejected(f"active BBOT module not allowed on a passive scan: {v}")
    _regex(r"[a-z0-9_]{2,40}", "module name")(v, ctx)


def _bbot_flag(v: str, ctx: Ctx) -> None:
    if v in SAFE_BBOT_FLAGS:
        return
    if v in ACTIVE_BBOT_FLAGS and ctx.allow_active:
        return
    raise CommandRejected(f"BBOT flag not allowed{' on a passive scan' if v in ACTIVE_BBOT_FLAGS else ''}: {v}")


@dataclass
class Flag:
    arity: int | str              # 0, 1 or "+" (one or more values)
    check: Check | None = None


@dataclass
class ToolSpec:
    flags: dict[str, Flag]
    positional: Check | None = None
    max_positional: int = 0
    required: set[str] = field(default_factory=set)


TOOLS: dict[str, ToolSpec] = {
    "bbot": ToolSpec(flags={
        "-t": Flag("+", _target), "-s": Flag("+", _target), "-b": Flag("+", _target),
        "--strict-scope": Flag(0), "--no-color": Flag(0),
        "-p": Flag("+", _choice(SAFE_BBOT_PRESETS, "BBOT preset")),
        "-m": Flag("+", _not_forbidden_module), "-em": Flag("+", _regex(r"[a-z0-9_]{2,40}", "module name")),
        "-f": Flag("+", _bbot_flag), "-rf": Flag("+", _bbot_flag),
        "-ef": Flag("+", _regex(r"[a-z0-9-]{2,30}", "flag")),
        "-om": Flag("+", _choice(BBOT_OUTPUTS, "BBOT output module")),
        "-o": Flag(1, _path), "-n": Flag(1, _regex(r"[a-z0-9_-]{1,40}", "scan name")),
        "-c": Flag("+", _config(BBOT_CONFIG_KEYS)),
        "-y": Flag(0), "--dry-run": Flag(0), "--no-deps": Flag(0), "--version": Flag(0),
        # --force only makes BBOT continue when a module's *setup* fails (missing optional binary,
        # failed template refresh); it does not bypass --strict-scope or change which modules load.
        "--force": Flag(0),
    }, required={"-t"}),
    "zap.sh": ToolSpec(flags={
        "-cmd": Flag(0), "-autorun": Flag(1, _yaml_path), "-dir": Flag(1, _path),
        "-config": Flag(1, _config(ZAP_CONFIG_KEYS)), "-silent": Flag(0), "-version": Flag(0),
    }),
    "tlsx": ToolSpec(flags={
        "-l": Flag(1, _path), "-p": Flag(1, _regex(r"\d{1,5}(,\d{1,5}){0,4}", "ports")),
        "-c": Flag(1, _int(1, 50)), "-timeout": Flag(1, _int(1, 30)),
        "-tv": Flag(0), "-cipher": Flag(0), "-ex": Flag(0), "-ss": Flag(0), "-mm": Flag(0),
        "-json": Flag(0), "-silent": Flag(0), "-o": Flag(1, _path), "-version": Flag(0),
    }),
    "smap": ToolSpec(flags={
        "-iL": Flag(1, _path), "-oN": Flag(1, _path), "-oP": Flag(1, _path), "-oJ": Flag(1, _path),
    }),
    "gau": ToolSpec(flags={
        "--subs": Flag(0), "--threads": Flag(1, _int(1, 10)),
        "--providers": Flag(1, _csv_choice(GAU_PROVIDERS, "gau provider")),
        "--blacklist": Flag(1, _regex(r"[a-z0-9]{1,8}(,[a-z0-9]{1,8}){0,30}", "extension list")),
        "--o": Flag(1, _path), "--version": Flag(0),
    }, positional=_domain, max_positional=50),
    "dnstwist": ToolSpec(flags={
        "--registered": Flag(0), "--format": Flag(1, _choice({"json", "csv"}, "format")),
        "--whois": Flag(0), "--version": Flag(0),
        "--banners": Flag(0), "--mxcheck": Flag(0),    # only with the scan's "probe lookalikes" switch
    }, positional=_domain, max_positional=1),
    "dig": ToolSpec(flags={"+short": Flag(0), "-v": Flag(0)}, positional=None, max_positional=2),
    "uro": ToolSpec(flags={"-i": Flag(1, _path), "-o": Flag(1, _path)}),
    "typst": ToolSpec(flags={"compile": Flag(0), "--version": Flag(0)}, positional=_path, max_positional=2),
    # v0.6 additions. Each is passive, DNS-only or light-touch with these flags; nothing else is accepted.
    "cdncheck": ToolSpec(flags={
        "-i": Flag(1, _path), "-resp": Flag(0), "-jsonl": Flag(0), "-silent": Flag(0), "-nc": Flag(0), "-version": Flag(0),
    }),
    "dnsreaper": ToolSpec(flags={
        "--filename": Flag(1, _path), "--out": Flag(1, _path), "--out-format": Flag(1, _choice({"json"}, "format")),
        "--parallelism": Flag(1, _int(1, 50)), "--cloudflare-token": Flag(1, _regex(r"[A-Za-z0-9_\-]{20,200}", "token")),
        "--help": Flag(0),
    }, positional=_choice({"file", "cloudflare"}, "dnsReaper input"), max_positional=1),
    "checkdmarc": ToolSpec(flags={
        "-f": Flag(1, _choice({"json"}, "format")), "-o": Flag(1, _path), "--skip-tls": Flag(0), "-v": Flag(0),
    }, positional=_domain, max_positional=200),
    "testssl.sh": ToolSpec(flags={
        "--quiet": Flag(0), "--warnings": Flag(1, _choice({"batch"}, "warnings")), "--color": Flag(1, _choice({"0"}, "color")),
        "--ip": Flag(1, _choice({"one"}, "ip")), "--connect-timeout": Flag(1, _int(1, 60)), "--openssl-timeout": Flag(1, _int(1, 60)),
        "--protocols": Flag(0), "--server-defaults": Flag(0), "--server-preference": Flag(0), "--std": Flag(0), "--headers": Flag(0),
        "--vulnerable": Flag(0),          # only added when the scan's "vulnerability probes" switch is on
        "--jsonfile": Flag(1, _path), "--version": Flag(0),
    }, positional=_domain, max_positional=1),
    "opensquat": ToolSpec(flags={
        "-k": Flag(1, _path), "-o": Flag(1, _path), "-t": Flag(1, _choice({"json"}, "format")), "-c": Flag(1, _int(0, 4)),
        "--portcheck": Flag(0),           # only added when the scan's port-check switch is on
        "--premium": Flag(0), "-h": Flag(0),
    }),
    "dnsx": ToolSpec(flags={
        "-l": Flag(1, _path), "-a": Flag(0), "-aaaa": Flag(0), "-cname": Flag(0), "-mx": Flag(0), "-ns": Flag(0),
        "-txt": Flag(0), "-caa": Flag(0), "-resp": Flag(0), "-json": Flag(0), "-o": Flag(1, _path), "-silent": Flag(0),
        "-t": Flag(1, _int(1, 50)), "-rl": Flag(1, _int(1, 1000)), "-duc": Flag(0), "-version": Flag(0),
        "-ptr": Flag(0),      # reverse DNS over a list of IPs (own-IP co-hosting)
        # opt-in subdomain brute (the "DNS brute-force" switch): a wordlist resolved against one root domain
        "-d": Flag(1, _domain), "-w": Flag(1, _path),
    }),
    "naabu": ToolSpec(flags={
        "-list": Flag(1, _path), "-p": Flag(1, _regex(NAABU_PORTS.pattern, "port list")),
        "-s": Flag(1, _choice({"c"}, "scan type (connect only)")), "-rate": Flag(1, _int(1, 200)), "-c": Flag(1, _int(1, 50)),
        "-retries": Flag(1, _int(0, 2)), "-timeout": Flag(1, _int(200, 5000)), "-json": Flag(0), "-o": Flag(1, _path),
        "-silent": Flag(0), "-duc": Flag(0), "-version": Flag(0),
    }),
    "cloudlist": ToolSpec(flags={
        "-pc": Flag(1, _yaml_path), "-json": Flag(0), "-silent": Flag(0), "-duc": Flag(0), "-o": Flag(1, _path), "-version": Flag(0),
    }),
}


def _dig_positional(args: list[str], ctx: Ctx) -> None:
    # dig +short TYPE name
    if len(args) == 2:
        _choice(DIG_TYPES, "record type")(args[0], ctx)
        name = args[1]
        try:
            normalise_domain(name.lstrip("_").split(".", 1)[1] if name.startswith("_") else name)
        except (ScopeError, IndexError) as exc:
            raise CommandRejected(f"invalid DNS name {name!r}") from exc
    elif args:
        raise CommandRejected("dig expects: +short TYPE NAME")


def validate(argv: list[str], ctx: Ctx) -> None:
    if not argv:
        raise CommandRejected("empty command")
    if any(not isinstance(a, str) or any(c in a for c in "\r\n\x00") for a in argv):
        raise CommandRejected("control characters in arguments")
    name = Path(argv[0]).name
    if name in FORBIDDEN_BINARIES:
        raise CommandRejected(f"forbidden binary: {name}")
    spec = TOOLS.get(name)
    if spec is None:
        raise CommandRejected(f"binary not on the allowlist: {name}")

    seen: set[str] = set()
    positional: list[str] = []
    args = argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in spec.flags:
            flag = spec.flags[a]
            seen.add(a)
            i += 1
            values: list[str] = []
            if flag.arity == "+":
                while i < len(args) and args[i] not in spec.flags:
                    values.append(args[i]); i += 1
                if not values:
                    raise CommandRejected(f"{a} needs at least one value")
            else:
                for _ in range(int(flag.arity)):
                    if i >= len(args):
                        raise CommandRejected(f"{a} needs a value")
                    values.append(args[i]); i += 1
            for v in values:
                if v.startswith("-") and v not in ("-",):
                    raise CommandRejected(f"value for {a} looks like a flag: {v}")
                if flag.check:
                    flag.check(v, ctx)
        elif a.startswith("-") or (name == "dig" and a.startswith("+")):
            raise CommandRejected(f"flag not allowed for {name}: {a}")
        else:
            positional.append(a); i += 1

    if name == "dig":
        _dig_positional(positional, ctx)
    else:
        if len(positional) > spec.max_positional:
            raise CommandRejected(f"unexpected arguments for {name}: {positional[spec.max_positional:]}")
        for p in positional:
            if spec.positional:
                spec.positional(p, ctx)
    missing = spec.required - seen
    if missing and not ({"--version", "-version"} & seen):
        raise CommandRejected(f"{name} requires {', '.join(sorted(missing))}")
