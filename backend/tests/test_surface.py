from asm.surface import classify_host, dedup_tech, is_agent_surface, normalise_tech


def test_agent_classification():
    assert "mcp" in classify_host("mcp.miro.com")
    assert "mcp" in classify_host("digital-twin-mcp.eu01.miro.com") and "twin" in classify_host("digital-twin-mcp.eu01.miro.com")
    assert "agent" in classify_host("production-agentcody.eu02.miro.com")
    assert "agent" in classify_host("production-aion.eu02.miro.com")
    assert "api" in classify_host("externalapi.miro.com")
    assert "transform" in classify_host("svg-convert-v2-api-cdn.us01.miro.com")
    assert is_agent_surface("mcp.miro.com") and is_agent_surface("production-atrain.eu02.miro.com")
    # must not false-positive on substrings
    assert classify_host("mainsite.example.com") == [] or "agent" not in classify_host("mainsite.example.com")
    assert not is_agent_surface("www.miro.com") and not is_agent_surface("blog.example.com")


def test_tech_dedup():
    assert normalise_tech("amazon") == "AWS" and normalise_tech("Amazon") == "AWS"
    assert normalise_tech("HSTS") == "HSTS" and normalise_tech("hsts") == "HSTS"
    out = dedup_tech(["Amazon", "amazon", "HTTP/3", "http/3", "HSTS", "hsts", "Nginx 1.18.0", "nginx"])
    assert "AWS" in out and out.count("AWS") == 1
    assert "HTTP/3" in out and sum(1 for t in out if t.startswith("HTTP/3")) == 1
    assert "Nginx 1.18.0" in out and "Nginx" not in [t for t in out if t == "Nginx"]   # version kept
