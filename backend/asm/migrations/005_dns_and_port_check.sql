-- dnsx: every DNS record per host per scan, so changes between scans can be shown
CREATE TABLE dns_records (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  host    TEXT NOT NULL,
  rtype   TEXT NOT NULL,
  value   TEXT NOT NULL,
  PRIMARY KEY (scan_id, host, rtype, value)
);
-- naabu (opt-in active check): ports confirmed open by a TCP connect
ALTER TABLE assets ADD COLUMN ports_confirmed TEXT;
