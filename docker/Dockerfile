# syntax=docker/dockerfile:1.7
# Outsider ASM: one image with the app and every CLI tool. Built for linux/arm64 (Apple silicon)
# and linux/amd64. Nothing is installed at runtime.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# ---------- Go tools ----------------------------------------------------------
# Latest Go 1.x; GOTOOLCHAIN=auto lets Go fetch a newer toolchain if a tool's go.mod needs one.
FROM golang:1-bookworm AS gotools
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
ARG TLSX_VERSION=latest
ARG GAU_VERSION=latest
ARG SMAP_VERSION=latest
ARG CDNCHECK_VERSION=latest
ARG CLOUDLIST_VERSION=latest
ARG DNSX_VERSION=latest
ARG NAABU_VERSION=latest
ENV CGO_ENABLED=0 GOBIN=/out GOTOOLCHAIN=auto
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VERSION} \
 && go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} \
 && go install github.com/s0md3v/smap/cmd/smap@${SMAP_VERSION} \
 && go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@${CDNCHECK_VERSION} \
 && go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@${CLOUDLIST_VERSION} \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}
# naabu links libpcap (even for the connect scans this app allows), so it's built with cgo
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}

# ---------- Frontend ------------------------------------------------------------
FROM node:22-bookworm-slim AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

# ---------- Runtime -------------------------------------------------------------
FROM ${PYTHON_IMAGE}
ARG TARGETARCH
ARG ZAP_VERSION
ARG ZAP_SHA256=
ARG GECKODRIVER_VERSION
ARG TYPST_VERSION
ARG BBOT_VERSION=
ARG DNSTWIST_VERSION=
ARG URO_VERSION=
ARG TESTSSL_REF=3.2
ARG DNSREAPER_REF=main
ARG CHECKDMARC_VERSION=
ARG OPENSQUAT_VERSION=
ARG WAPPALYZER_REF=

ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# System packages. The second line is BBOT 3's "core dependencies" (7z, gcc, make, OpenSSL
# headers): BBOT checks for them before every scan and tries to install them with sudo if
# missing. The container has no sudo by design, so they must be present at build time.
# chromium is for BBOT's gowitness screenshot module.
RUN apt-get update && apt-get install -y --no-install-recommends \
      openjdk-17-jre-headless firefox-esr dnsutils ca-certificates curl xz-utils tini jq git unzip \
      p7zip-full gcc make libssl-dev libffi-dev chromium fonts-liberation \
      openssl bsdextrautils procps libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

# ZAP (cross-platform Linux package), checksum-verified when ZAP_SHA256 is set
RUN set -eux; \
    curl -fsSL -o /tmp/zap.tgz "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"; \
    if [ -n "${ZAP_SHA256}" ]; then echo "${ZAP_SHA256}  /tmp/zap.tgz" | sha256sum -c -; \
    else echo "WARNING: ZAP_SHA256 not set; computed: $(sha256sum /tmp/zap.tgz)"; fi; \
    mkdir -p /opt/zap && tar -xzf /tmp/zap.tgz -C /opt/zap --strip-components=1 && rm /tmp/zap.tgz; \
    ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh

# geckodriver for ZAP's AJAX spider (headless Firefox)
RUN set -eux; \
    case "${TARGETARCH}" in arm64) GD=linux-aarch64 ;; amd64) GD=linux64 ;; *) echo "unsupported arch"; exit 1 ;; esac; \
    curl -fsSL "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-${GD}.tar.gz" \
      | tar -xz -C /usr/local/bin geckodriver

# Typst for PDF reports
RUN set -eux; \
    case "${TARGETARCH}" in arm64) TA=aarch64-unknown-linux-musl ;; amd64) TA=x86_64-unknown-linux-musl ;; esac; \
    curl -fsSL "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${TA}.tar.xz" \
      | tar -xJ -C /tmp && mv /tmp/typst-${TA}/typst /usr/local/bin/typst && rm -rf /tmp/typst-*

COPY --from=gotools /out/ /usr/local/bin/

# Python tools + app dependencies
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
 && pip install "bbot${BBOT_VERSION:+==${BBOT_VERSION}}" "dnstwist${DNSTWIST_VERSION:+==${DNSTWIST_VERSION}}" "uro${URO_VERSION:+==${URO_VERSION}}"

# v0.6 tools. Python ones get their own virtualenvs so their pinned dependencies can't clash with BBOT's.
#   checkdmarc (SPF/DMARC/MTA-STS/BIMI), openSquat (newly registered lookalikes), dnsReaper (takeover signatures)
# dnsReaper's venv gets setuptools<80: its google-cloud-dns dependency still imports pkg_resources, which
# Python 3.12 virtualenvs no longer include.
RUN set -eux; \
    python -m venv /opt/venvs/checkdmarc && /opt/venvs/checkdmarc/bin/pip install "checkdmarc${CHECKDMARC_VERSION:+==${CHECKDMARC_VERSION}}"; \
    ln -s /opt/venvs/checkdmarc/bin/checkdmarc /usr/local/bin/checkdmarc; \
    python -m venv /opt/venvs/opensquat && /opt/venvs/opensquat/bin/pip install "opensquat${OPENSQUAT_VERSION:+==${OPENSQUAT_VERSION}}"; \
    ln -s /opt/venvs/opensquat/bin/opensquat /usr/local/bin/opensquat; \
    git clone --depth 1 --branch "${DNSREAPER_REF}" https://github.com/punk-security/dnsReaper /opt/dnsreaper; \
    python -m venv /opt/venvs/dnsreaper; \
    /opt/venvs/dnsreaper/bin/pip install "setuptools<80" -r /opt/dnsreaper/requirements.txt; \
    printf '#!/bin/sh\ncd /opt/dnsreaper && exec /opt/venvs/dnsreaper/bin/python main.py "$@"\n' > /usr/local/bin/dnsreaper; \
    chmod 755 /usr/local/bin/dnsreaper; \
    git clone --depth 1 --branch "${TESTSSL_REF}" https://github.com/testssl/testssl.sh /opt/testssl; \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh; \
    git clone --depth 1 ${WAPPALYZER_REF:+--branch "$WAPPALYZER_REF"} https://github.com/dochne/wappalyzer /opt/wappalyzer; \
    test -n "$(find /opt/wappalyzer -path '*technologies*' -name 'a.json' | head -1)"; \
    checkdmarc -v; opensquat -h >/dev/null; dnsreaper --help >/dev/null; testssl.sh --version >/dev/null

# Non-root user. BBOT keeps its home (module deps, cache) under /home/asm.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin asm \
 && mkdir -p /data /secrets /app && chown asm:asm /data /secrets /app

# Pre-install BBOT module dependencies at build time so scans never install anything.
# Some modules may fail to install on arm64; those modules are then unavailable, which the
# app reports, rather than failing the build.
# Pre-install every BBOT module's dependencies at build time so scans never install anything.
# Runs as root (some modules need apt packages) but with HOME=/home/asm, so BBOT's tool binaries
# land in /home/asm/.bbot where the app (running as asm) expects them; ownership is then handed
# back. The log stays in the image (/tmp is a tmpfs at runtime):
#   docker compose exec asm tail -80 /home/asm/bbot-deps.log
RUN HOME=/home/asm bbot --install-all-deps -y --no-color > /home/asm/bbot-deps.log 2>&1 \
 || (echo "WARNING: some BBOT module deps failed; see /home/asm/bbot-deps.log"; tail -40 /home/asm/bbot-deps.log); \
 chown -R asm:asm /home/asm

# "Install all" also fetches tools this app must never run: raw port scanners (masscan, nmap — the
# gated naabu stage owns port scanning) and login brute-forcers (medusa, legba, hydra, ffuf/webbrute).
# The allowlist already blocks them; deleting them as well keeps the promise that the image contains
# none. The build fails if any remain. nuclei is deliberately NOT in this list: it is a vulnerability
# scanner used only on authorised, off-by-default active passes (the allowlist gates it to active
# scans, and the Options screen requires explicit confirmation), so its binary must stay.
RUN set -eu; \
    for t in masscan nmap medusa legba hydra ffuf; do \
      find / -xdev \( -path /proc -o -path /sys \) -prune -o \( -type f -o -type l \) -name "$t" -print 2>/dev/null \
        | while read -r f; do echo "removing $f"; rm -f "$f"; done; \
    done; \
    for t in masscan nmap medusa legba hydra ffuf; do \
      if command -v "$t" >/dev/null 2>&1 || find /home/asm /usr /opt -xdev \( -type f -o -type l \) -name "$t" 2>/dev/null | grep -q .; then \
        echo "ERROR: $t is still present in the image"; exit 1; fi; \
    done; \
    apt-get purge -y masscan nmap medusa hydra 2>/dev/null || true

# Seed nuclei's templates at build time, into the path BBOT's nuclei module uses, so that the template
# refresh BBOT runs at the start of an authorised active scan is a fast incremental update rather than a
# full first-time download. (BBOT's nuclei module always refreshes templates at setup and has no config
# to disable it, so a small outbound fetch still happens at scan time — the same network the passive
# intel sources already use.) Best-effort: a build with no network still succeeds, and --force keeps a
# template-refresh failure from aborting the active pass.
RUN set -eu; \
    NUCLEI="$(command -v nuclei || find /home/asm /usr /opt -type f -name nuclei 2>/dev/null | head -1 || true)"; \
    if [ -n "$NUCLEI" ]; then \
      HOME=/home/asm "$NUCLEI" -update-template-dir /home/asm/.bbot/tools/nuclei-state/templates \
        -update-templates -no-color || echo "WARNING: nuclei template pre-fetch failed (no network at build?)"; \
      chown -R asm:asm /home/asm/.bbot 2>/dev/null || true; \
    else echo "WARNING: nuclei binary not found; active nuclei scans will have no templates"; fi

# BBOT downloads a prebuilt x86-64 Chrome for gowitness, which can't run on Apple silicon (arm64).
# Point that path at Debian's Chromium instead (native on both arches). --no-sandbox is needed
# because the container drops all capabilities; the container itself is the sandbox.
RUN set -eu; d=/home/asm/.bbot/tools/chrome-linux; rm -rf "$d"; mkdir -p "$d"; \
    printf '#!/bin/sh\nexec /usr/bin/chromium --no-sandbox --disable-dev-shm-usage "$@"\n' > "$d/chrome"; \
    chmod 755 "$d/chrome"; chown -R asm:asm /home/asm/.bbot; "$d/chrome" --version

WORKDIR /app
COPY backend/asm /app/asm
COPY --from=frontend /fe/dist /app/static
RUN python -m compileall -q /app/asm && chown -R root:root /app && chmod -R a+rX /app

ENV ASM_DATA_DIR=/data ASM_SECRETS_DIR=/secrets ASM_STATIC_DIR=/app/static PYTHONPATH=/app \
    HOME=/home/asm _JAVA_OPTIONS="-Xmx2g"
USER asm
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD curl -fsS -H "Host: localhost" http://127.0.0.1:8000/api/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "asm", "serve"]
