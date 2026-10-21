import pytest

from tollgate import intel
from tollgate.db import Store, normalize_ioc
from tollgate.engine import analyze_bytes
from tests.helpers import CODE, build_pe

PE = build_pe([(".text", b"\x55\x8b\xec\x90\xc3" * 200, CODE)])


def test_ioc_validation():
    assert normalize_ioc("sha256", "A" * 64) == "a" * 64
    with pytest.raises(ValueError):
        normalize_ioc("sha256", "xyz")
    with pytest.raises(ValueError):
        normalize_ioc("domain", "not a domain")
    assert normalize_ioc("domain", "Evil[.]Example") == "evil.example"


def test_history_and_seen_before():
    store = Store(":memory:")
    r1 = analyze_bytes(PE, "tool.exe", store)
    r2 = analyze_bytes(PE, "tool.exe", store)
    assert r1.scan_id and r2.scan_id and r2.scan_id != r1.scan_id
    assert "FILE_SEEN_BEFORE" in {f.rule_id for f in r2.findings}
    assert len(store.history()) == 2
    assert store.get_scan(r1.scan_id)["filename"] == "tool.exe"
    assert len(store.history(verdict="clean")) == 2


def test_no_record_flag():
    store = Store(":memory:")
    analyze_bytes(PE, "tool.exe", store, record=False)
    assert store.history() == []


def test_hash_ioc_forces_malicious_and_retro_hunt():
    store = Store(":memory:")
    first = analyze_bytes(PE, "tool.exe", store)
    assert first.verdict == "Clean"
    assert store.retro_hunt() == []
    # a new attack emerges: its hash lands in the database
    store.add_ioc("sha256", first.hashes["sha256"], family="NewBot", source="unit")
    hits = store.retro_hunt()                       # past scan is now a known-bad
    assert hits and hits[0]["family"] == "NewBot" and hits[0]["verdict_at_scan"] == "Clean"
    again = analyze_bytes(PE, "tool.exe", store)
    assert again.verdict == "Malicious" and "INTEL_HASH_MATCH" in {f.rule_id for f in again.findings}


def test_custom_rule_detects_new_attack():
    store = Store(":memory:")
    sample = build_pe([(".text", b"\x90" * 300 + b"ZetaLoader_beacon_v2" + b"\x90" * 300, CODE)])
    assert "RULE_zeta" not in {f.rule_id for f in analyze_bytes(sample, "a.exe", store).findings}
    store.add_rule("zeta", r"zetaloader_beacon_v\d", "high", "ZetaLoader beacon string")
    assert "RULE_zeta" in {f.rule_id for f in analyze_bytes(sample, "a.exe", store).findings}
    with pytest.raises(ValueError):
        store.add_rule("bad", "(unclosed")


def test_url_tracking_counts():
    store = Store(":memory:")
    store.track_url("hxxp://evil[.]example/a")
    store.track_url("http://EVIL.example/a")
    rows = store.tracked_urls()
    assert len(rows) == 1 and rows[0]["times_seen"] == 2


def test_embedded_url_intel_match():
    store = Store(":memory:")
    store.add_ioc("domain", "c2.badhost.example", family="X", source="unit")
    sample = build_pe([(".text", b"\x90" * 200 + b"http://c2.badhost.example/gate.php\x00" + b"\x90" * 200, CODE)])
    r = analyze_bytes(sample, "a.exe", store)
    assert r.verdict == "Malicious" and "INTEL_URL_MATCH" in {f.rule_id for f in r.findings}
    assert store.retro_hunt()                         # sighting recorded, visible to retro-hunt


def test_import_plain_and_csv():
    store = Store(":memory:")
    text = "# comment\n" + ("a" * 64) + "\n" + ("B" * 64) + "\nnot-a-hash\n" + ("a" * 64) + "\n"
    res = intel.import_text(store, text, "sha256", family="Fam", source="unit")
    assert res == {"added": 2, "updated": 0, "invalid": 1}
    csv_text = '# id,dateadded,url,threat\n"1","2026","http://x.example/a","malware_download"\n'
    res = intel.import_text(store, csv_text, "url", column="url", source="urlhaus-like")
    assert res["added"] == 1
    assert store.lookup_ioc("url", "http://x.example/a")
    res = intel.import_text(store, "h,val\nr1,evil2.example\n", "domain", column="val")
    assert res["added"] == 1
    assert store.stats()["iocs_total"] == 4


def test_export_and_load_roundtrip(tmp_path):
    from tollgate import intel as intel_mod
    a, b = Store(":memory:"), Store(":memory:")
    a.add_ioc("sha256", "a" * 64, family="Fam", source="feedA", severity="high", note="n1")
    a.add_ioc("domain", "evil.example", source="feedB")
    rows = a.export_iocs()
    assert [r["ioc_type"] for r in rows] == ["domain", "sha256"]
    import csv
    path = tmp_path / "export.csv"
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["ioc_type", "value", "family", "source", "severity", "note"])
        w.writeheader(); w.writerows(rows)
    assert intel_mod.load_export(b, str(path)) == {"added": 2, "updated": 0, "invalid": 0}
    assert b.lookup_ioc("sha256", "a" * 64)["family"] == "Fam"
