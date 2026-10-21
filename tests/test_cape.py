import pytest

from tollgate import cape, dynamic, fake_cape
from tollgate.db import Store
from tollgate.engine import analyze_bytes
from tests.helpers import CODE, build_pe

PE = build_pe([(".text", b"\x55\x8b\xec\x90\xc3" * 200, CODE)])


@pytest.fixture()
def fake():
    server, url = fake_cape.start(token="s3cret")
    yield url
    server.shutdown()


def client(url, token="s3cret"):
    return cape.CapeClient(cape.CapeConfig(url=url, token=token, analysis_timeout=60, options="route=none"))


def test_config_and_auth(fake):
    assert not cape.CapeConfig().enabled and not cape.CapeConfig(url="file:///etc/passwd").enabled
    with pytest.raises(cape.CapeError):
        cape.CapeClient(cape.CapeConfig())
    assert client(fake).ping()["data"]["fake"] is True
    with pytest.raises(cape.CapeError) as e:
        client(fake, token="wrong").ping()
    assert "TOLLGATE_CAPE_TOKEN" in str(e.value)
    with pytest.raises(cape.CapeError):
        cape.CapeClient(cape.CapeConfig(url="http://127.0.0.1:9")).ping()          # nothing listening


def test_submit_poll_report_roundtrip(fake):
    c = client(fake)
    task = c.submit_file("sample.exe", PE)
    assert [c.status(task) for _ in range(3)] == ["pending", "running", "reported"]
    rep = c.report(task)
    assert rep["_fake"] and rep["target"]["file"]["name"] == "sample.exe"
    with pytest.raises(cape.CapeError):
        c.report(9999)


def test_summary_and_findings_for_bad_and_good_reports(fake):
    c = client(fake)
    bad = c.submit_file("malware-sample.exe", PE)
    summary = cape.summarize_report(c.report(bad))
    assert summary["families"][0] == "FakeFamily" and summary["malscore"] == 9.5
    assert summary["network"]["domains"] == ["c2.demo-sandbox.example"]      # time.windows.com filtered as guest noise
    assert summary["network"]["ips"] == [] and "http://c2.demo-sandbox.example/gate.php" in summary["network"]["urls"]  # doc-range IPs are not public
    assert summary["dropped"][0]["name"] == "payload.dll" and "T1055" in summary["ttps"] and summary["mutexes"]
    ids = {f.rule_id for f in cape.dynamic_findings(summary)}
    assert {"DYN_FAMILY", "DYN_MALSCORE", "DYN_SIG_injection_createremotethread", "DYN_SIGNATURES_MEDIUM", "DYN_NETWORK_ALERTS"} <= ids
    good = cape.summarize_report(c.report(c.submit_file("notepad.exe", PE)))
    gids = {f.rule_id for f in cape.dynamic_findings(good)}
    assert "DYN_FAMILY" not in gids and good["families"] == []


def test_summary_survives_odd_reports():
    for odd in ({}, {"signatures": "nope", "network": [], "behavior": 3, "CAPE": None, "malscore": "high"},
                {"signatures": [None, 5, {"severity": "x"}], "network": {"hosts": [None, 7, {"ip": 3}], "http": [{"uri": 3}]},
                 "dropped": [{"sha256": 5}], "CAPE": {"configs": [5, {"Fam": None}]}}):
        s = cape.summarize_report(odd)
        cape.dynamic_findings(s)
    assert s["families"] == ["Fam"]


def test_dynamic_workflow_updates_stored_scan_and_is_idempotent(fake):
    store, c = Store(":memory:"), client(fake)
    report = analyze_bytes(PE, "malware-sample.exe", store, user="ana")
    assert report.verdict == "Clean"
    task = dynamic.submit(store, c, "malware-sample.exe", PE, report.scan_id, "ana")
    assert task["status"] == "submitted" and task["remote_id"]
    assert dynamic.refresh(store, c, task["id"])["status"] == "pending"
    assert dynamic.refresh(store, c, task["id"])["status"] == "running"
    done = dynamic.refresh(store, c, task["id"])
    assert done["status"] == "reported" and done["summary"]["families"] == ["FakeFamily"] and done["completed_at"]
    stored = store.get_scan(report.scan_id)
    assert stored["verdict"] == "Malicious" and stored["metadata"]["dynamic"]["malscore"] == 9.5
    assert any(f["rule_id"] == "DYN_FAMILY" for f in stored["findings"])
    assert store.history()[0]["verdict"] == "Malicious"
    dynamic.merge_into_scan(store, report.scan_id, done["summary"], cape.dynamic_findings(done["summary"], store))
    assert sum(f["rule_id"] == "DYN_FAMILY" for f in store.get_scan(report.scan_id)["findings"]) == 1
    assert dynamic.refresh(store, c, task["id"])["status"] == "reported"          # final: no further CAPE calls


def test_dynamic_intel_matches_observed_traffic_and_drops(fake):
    store, c = Store(":memory:"), client(fake)
    store.add_ioc("domain", "demo-sandbox.example", family="Demo", source="unit", severity="high")
    summary = cape.summarize_report(c.report(c.submit_file("malware.exe", PE)))
    store.add_ioc("sha256", summary["dropped"][0]["sha256"], family="DropperY", source="unit")
    findings = cape.dynamic_findings(summary, store)
    assert {"INTEL_URL_MATCH", "INTEL_HASH_MATCH"} <= {f.rule_id for f in findings}
    assert all(f.category == "dynamic" for f in findings)


def test_failed_and_timed_out_tasks(fake):
    store, c = Store(":memory:"), client(fake)
    task = dynamic.submit(store, c, "x.exe", PE, None, "ana")
    store.update_dynamic_task(task["id"], status="submitted")
    store.conn.execute("UPDATE dynamic_tasks SET submitted_at='2000-01-01T00:00:00+00:00'")
    store.conn.commit()
    assert dynamic.refresh(store, c, task["id"])["status"] == "failed"            # stuck far too long
    dead = cape.CapeClient(cape.CapeConfig(url="http://127.0.0.1:9"))
    t2 = store.create_dynamic_task(None, "cape", "1", "ana")
    with pytest.raises(cape.CapeError):
        dynamic.refresh(store, dead, t2)
    assert store.get_dynamic_task(t2)["status"] == "submitted"                     # outage is not a failure
