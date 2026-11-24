# Outsider ASM — dev notes

Local external attack-surface-management app (FastAPI/Starlette + React, Docker).
**Passive + light-touch by default.** Credential brute-forcers (medusa/legba/
hydra/webbrute) and raw port scanners (masscan/nmap) are blocked and stripped
from the image. ZAP active scan and port_check (naabu) are off by default.

## Run it (Docker)

    make build     # build the image (tool pins in docker/versions.env)
    make up        # start the app
    make down      # stop
    make logs      # tail logs
    make token     # print/refresh the login token
    make versions  # tool versions actually baked into the image
    make smoke     # quick smoke test
    make test      # backend tests
    make shell     # shell into the container

## Frontend

React/TSX bundled by esbuild via `frontend/build.mjs` (esbuild only, no tsc).
`make build` rebuilds it into the image. The real gate is a clean esbuild bundle:

    cd frontend && node_modules/.bin/esbuild src/main.tsx --bundle \
      --loader:.tsx=tsx --loader:.ts=ts --jsx=automatic --outfile=/tmp/check.js

## Secrets & data — never commit

- `secrets/` (incl. `secrets/master.key`) and `data/` (scan outputs on real
  third-party domains) are gitignored. Never `git add -f` them.
- If you add a remote, keep it **private** — `data/` holds live recon.

## Secret-scan pre-commit hook

Tripwire in `.githooks/pre-commit` runs gitleaks on staged changes (no-ops with
a warning if gitleaks isn't installed). Turn it on:

    git config core.hooksPath .githooks     # already set locally
    brew install gitleaks                    # or: go install github.com/gitleaks/gitleaks/v8@latest
