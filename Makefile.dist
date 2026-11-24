COMPOSE = docker compose --env-file docker/versions.env

.PHONY: build up down logs token versions smoke test frontend shell

build:            ## Build the image (all tools pinned in docker/versions.env)
	$(COMPOSE) build

up:               ## Start in the background, then print the access token if this is the first start
	mkdir -p data secrets && chmod 700 secrets
	$(COMPOSE) up -d --force-recreate
	@echo "Waiting for startup..."; sleep 8
	@$(COMPOSE) logs asm | grep -A3 "access token" || echo "(token already issued; use 'make token' to reset)"
	@echo "Open http://localhost:8443"

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f asm

token:            ## Issue a new access token (signs out all sessions)
	$(COMPOSE) exec asm python -m asm reset-token

versions:         ## Show the tool versions inside the image
	$(COMPOSE) exec asm python -m asm versions

smoke:            ## Check every tool runs inside the image
	$(COMPOSE) run --rm --no-deps asm python -m asm versions
	$(COMPOSE) run --rm --no-deps asm bash -lc 'bbot --version && zap.sh -cmd -version && tlsx -version && gau --version && dnstwist --version && typst --version && geckodriver --version | head -1 && firefox-esr --version'

test:             ## Backend tests (run on your Mac with Python 3.11+: pip install -r backend/requirements.txt pytest)
	cd backend && python3 -m pytest -q

frontend:         ## Build the frontend locally (needs Node 20+)
	cd frontend && npm install && npm run build

shell:
	$(COMPOSE) exec asm bash
