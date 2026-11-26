# Changelog

Notable changes to Outsider ASM. The project is pre-1.0 and ships from `main`; the
version tracks `frontend/package.json` (currently **0.6.0**). Newest first.

## Unreleased

### Added
- **Redacted demo** — the full results UI running against a frozen, redacted snapshot
  of a real scan, with no backend. Served both as an in-app **Demo** tab (`/demo`) and
  as a static **GitHub Pages** build under `docs/`. `tools/export_demo_snapshot.py`
  regenerates the snapshot (hosts → `asset-NN`, IPs → `ip-NN`, emails → `email-NN`;
  standards references preserved).
- **CI pipeline** (GitHub Actions) — `pytest` gate, esbuild build gate, and a
  `gitleaks` secret-scan gate; `pip-audit`, `npm audit` and `tsc` run as advisory.
- **gitleaks pre-commit tripwire** and config (`.githooks/pre-commit`, `.gitleaks.toml`).
- **SSRF guard** on outbound discovery fetches — only public IPs, redirect-safe.
- Share-pack **redaction extended** to IPv6 and email addresses.
- **Incomplete scans surfaced** — a banner in the overview and a note in the report
  when a stage failed, so a partial result can't be mistaken for a clean one.

### Changed
- Dropped `gowitness` from the default light pipeline; screenshots stay opt-in.

### Fixed
- Repaired double-encoded UTF-8 ("mojibake") in the results UI.
- Hardened a plan-only pipeline path (`_spa_hosts`) and refreshed stale tests.

## 0.6.0 — Milestones 1–6

- **Discovery & scope** — passive external footprint (subdomains, related domains,
  DNS, certificates, cloud) with an explicit, confirmed scope.
- **Authorisation** — who approved the test, reference, window, source IP and SOC
  awareness, saved with the run as audit evidence.
- **Light-touch pipeline** — dependency-ordered stages, 5-way parallel scheduler,
  live view, pause / resume / retry, and a ZAP host picker. Active traffic is off by
  default, authorisation-gated, and confirmed per stage.
- **Results** — RAG overview, surface map, trend-vs-last-scan, attack paths / kill
  chains, assets, IPs, DNS, findings with embedded evidence, triage, and a file browser.
- **Reports** — a full board-to-engineering document plus a redacted share pack.

## Planned

### M7 — AI providers (next)
- Optional AI-assisted analysis and triage over scan data, with provider keys held in
  the encrypted secret store.
- Modelling of the AI-agent / MCP attack surface (OWASP LLM Top 10, MITRE ATLAS),
  consistent with the theoretical-only attack-path approach.
- Guardrails first: least-privilege tool/action permissions, no secret egress, auditable.

### Later
- Promote the advisory CI steps (`pip-audit`, `npm audit`, `tsc`) to gates.
- Scheduled / recurring scans with change diffing.
- Multi-tenant hardening, if it ever moves beyond single-operator self-host.
