-- 001: initial schema (see Build Spec "Data model")

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL            -- JSON
);

CREATE TABLE secrets (
  name       TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  nonce      BLOB NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE auth_token (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE sessions (
  id_hash    TEXT PRIMARY KEY,
  csrf       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE scans (
  id            TEXT PRIMARY KEY,
  root_domain   TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'draft',
  created_at    TEXT NOT NULL,
  started_at    TEXT,
  finished_at   TEXT,
  run_dir       TEXT NOT NULL,
  options       TEXT NOT NULL DEFAULT '{}',
  tool_versions TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE scope_items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  value       TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('root','subdomain','related','exclusion')),
  grp         TEXT,                   -- resolves / third_party / no_dns / wildcard (subdomains)
  sources     TEXT NOT NULL DEFAULT '[]',
  reasons     TEXT NOT NULL DEFAULT '[]',
  confidence  TEXT CHECK (confidence IN ('high','medium','low')),
  decision    TEXT NOT NULL DEFAULT 'suggested' CHECK (decision IN ('suggested','included','excluded')),
  third_party INTEGER NOT NULL DEFAULT 0,
  decided_at  TEXT,
  UNIQUE (scan_id, value)
);

CREATE TABLE authorisations (
  scan_id         TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  approved_by     TEXT NOT NULL,
  role            TEXT NOT NULL,
  approved_on     TEXT NOT NULL,
  scope_reference TEXT NOT NULL,
  soc_notified    INTEGER NOT NULL,
  soc_contact     TEXT NOT NULL,
  source_ip       TEXT NOT NULL,
  test_window     TEXT NOT NULL,
  attested        INTEGER NOT NULL,
  attested_at     TEXT NOT NULL
);

CREATE TABLE stages (
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  stage_key   TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  started_at  TEXT,
  finished_at TEXT,
  exit_code   INTEGER,
  summary     TEXT NOT NULL DEFAULT '{}',
  log_path    TEXT,
  PRIMARY KEY (scan_id, stage_key)
);

CREATE TABLE events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id   TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  stage_key TEXT,
  ts        TEXT NOT NULL,
  level     TEXT NOT NULL,
  message   TEXT NOT NULL
);
CREATE INDEX events_scan ON events(scan_id, id);

CREATE TABLE assets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  host        TEXT NOT NULL,
  ips         TEXT NOT NULL DEFAULT '[]',
  in_cmdb     INTEGER NOT NULL DEFAULT 0,
  is_live     INTEGER NOT NULL DEFAULT 0,
  web_url     TEXT,
  tech        TEXT NOT NULL DEFAULT '[]',
  tls         TEXT NOT NULL DEFAULT '{}',
  ports       TEXT NOT NULL DEFAULT '[]',
  cdn         INTEGER NOT NULL DEFAULT 0,
  third_party INTEGER NOT NULL DEFAULT 0,
  UNIQUE (scan_id, host)
);

CREATE TABLE findings (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  area         TEXT NOT NULL,
  severity     TEXT NOT NULL,
  title        TEXT NOT NULL,
  host         TEXT,
  source_tool  TEXT NOT NULL,
  evidence_ref TEXT,
  status       TEXT NOT NULL DEFAULT 'observation'
);

CREATE TABLE triage (
  scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  host       TEXT NOT NULL,
  decision   TEXT CHECK (decision IN ('ours_unrecorded','third_party_ours','should_not_exist')),
  note       TEXT,
  decided_at TEXT,
  PRIMARY KEY (scan_id, host)
);

CREATE TABLE metrics (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  metrics TEXT NOT NULL
);

CREATE TABLE reports (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  format      TEXT NOT NULL,
  generator   TEXT NOT NULL,
  provider_id TEXT,
  model       TEXT,
  approved    INTEGER NOT NULL DEFAULT 0,
  path        TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE cmdb_entries (
  value       TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('host','ip')),
  imported_at TEXT NOT NULL
);

CREATE TABLE ai_providers (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('ollama','lmstudio','openai_compat','anthropic','openai','gemini')),
  label       TEXT NOT NULL,
  base_url    TEXT,
  secret_name TEXT,
  is_local    INTEGER NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE ai_feature_models (
  feature     TEXT PRIMARY KEY CHECK (feature IN ('board_narrative','appendix','triage_hints')),
  provider_id TEXT REFERENCES ai_providers(id) ON DELETE SET NULL,
  model       TEXT
);
