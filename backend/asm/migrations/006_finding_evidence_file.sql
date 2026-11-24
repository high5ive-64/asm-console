-- Per-finding pointer to the raw artifact it was derived from, as a path relative to the scan's run
-- folder (e.g. bbot/<name>/output.json, zap/zap-estate.json, email/posture.json). Nullable: tools that
-- don't emit a single identifiable artifact leave it NULL and the UI falls back to the tool's folder.
ALTER TABLE findings ADD COLUMN evidence_file TEXT;
