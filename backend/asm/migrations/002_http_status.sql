-- best HTTP status seen at each host's root (from BBOT), used to skip dead ends when planning ZAP
ALTER TABLE assets ADD COLUMN http_status INTEGER;
