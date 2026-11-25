"""Incomplete-scan surfacing: a failed stage must mark the report (and overview) as incomplete,
so a shared report never implies a clean bill it didn't earn."""
from asm.reports import _incomplete_banner


def test_banner_empty_when_clean():
    assert _incomplete_banner({"overview": {"failed_stages": []}, "scan": {"status": "completed"}}) == ""


def test_banner_lists_failed_stages():
    out = _incomplete_banner({"overview": {"failed_stages": ["tls", "zap"]},
                              "scan": {"status": "completed_with_errors"}})
    assert "Incomplete scan" in out and "tls" in out and "zap" in out


def test_banner_on_status_even_without_list():
    out = _incomplete_banner({"overview": {"failed_stages": []},
                              "scan": {"status": "completed_with_errors"}})
    assert "Incomplete scan" in out
