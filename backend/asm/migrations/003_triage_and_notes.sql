-- more triage outcomes, and analyst notes on findings
CREATE TABLE triage_new (
  scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  host       TEXT NOT NULL,
  decision   TEXT CHECK (decision IN ('ours_unrecorded','third_party_ours','should_not_exist','not_ours','investigating')),
  note       TEXT,
  decided_at TEXT,
  PRIMARY KEY (scan_id, host)
);
INSERT INTO triage_new SELECT scan_id, host, decision, note, decided_at FROM triage;
DROP TABLE triage;
ALTER TABLE triage_new RENAME TO triage;
ALTER TABLE findings ADD COLUMN note TEXT;
ALTER TABLE findings ADD COLUMN status_at TEXT;
