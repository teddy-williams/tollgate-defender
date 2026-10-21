
from tollgate.db import Store
from tollgate.urlcheck import analyze_url, defang, defang_text, normalize_url, refang


def ids(report):
    return {f.rule_id for f in report.findings}


def test_defang_refang_roundtrip():
    assert defang("https://evil.com/a.b?x=1") == "hxxps://evil[.]com/a.b?x=1"
    assert defang(defang("http://evil.com")) == "hxxp://evil[.]com"      # idempotent
    assert refang("hxxps://evil[.]com/x") == "https://evil.com/x"
    assert refang("evil(.)com[:]8080") == "evil.com:8080"
    assert defang("evil.com/path") == "evil[.]com/path"
    assert defang_text("see http://a.b/c and ftp://x.y") == "see hxxp://a[.]b/c and fxp://x[.]y"


def test_normalize():
    assert normalize_url("HTTP://Evil.COM:80/a#frag") == "http://evil.com/a"
    assert normalize_url("hxxps://evil[.]com") == "https://evil.com/"
    assert normalize_url("evil.com/x") == "http://evil.com/x"
    assert normalize_url("http://user:pw@evil.com/") == "http://evil.com/"
    assert normalize_url("http://bücher.example/") == "http://xn--bcher-kva.example/"
    assert normalize_url("") is None


def test_heuristics():
    assert "URL_USERINFO" in ids(analyze_url("http://paypal.com@evil.com/login"))
    r = analyze_url("http://3232235777/update.exe")
    assert {"URL_OBFUSCATED_IP", "URL_PAYLOAD_EXT"} <= ids(r)
    assert "URL_RAW_IP" in ids(analyze_url("http://192.0.2.10/x"))
    assert "URL_HOMOGRAPH" in ids(analyze_url("http://p\u0430ypal.com/"))   # Cyrillic 'a'
    assert "URL_SCHEME" in ids(analyze_url("javascript:alert(1)"))
    assert "URL_EXFIL_WEBHOOK" in ids(analyze_url("https://discord.com/api/webhooks/1/abc"))


def test_clean_url():
    r = analyze_url("https://www.example.com/docs/index.html")
    assert r.verdict == "Clean" and r.findings == []


def test_intel_domain_match_is_decisive():
    store = Store(":memory:")
    store.add_ioc("domain", "evil.example", family="TestFamily", source="unit")
    r = analyze_url("http://cdn.a.evil.example/x", store)
    assert r.verdict == "Malicious" and "INTEL_URL_MATCH" in ids(r)
    assert analyze_url("http://notevil.example/", store).verdict == "Clean"   # no partial-label match
