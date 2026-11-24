-- cdncheck classification per host ({"cdn": "cloudflare", "waf": "...", "cloud": "aws"}) and which extra
-- sources reported an asset that DNS discovery didn't (cloudlist, Netlas, SpiderFoot, ...)
ALTER TABLE assets ADD COLUMN edge TEXT NOT NULL DEFAULT '{}';
ALTER TABLE assets ADD COLUMN found_by TEXT NOT NULL DEFAULT '[]';
