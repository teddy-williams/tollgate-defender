import io
import os

import pytest
from fastapi.testclient import TestClient

from tollgate import redirects
from tollgate.accounts import Accounts
from tollgate.api import Settings, create_app
from tollgate.db import Store
from tests.helpers import CODE, build_pe

RULES = os.path.join(os.path.dirname(__file__), "..", "tollgate", "rules")
PE = build_pe([(".text", b"\x55\x8b\xec\x90\xc3" * 200, CODE)])
PW = "correct horse battery staple"


def make_settings(tmp_path, **kw):
    return Settings(db=str(tmp_path / "t.db"), max_upload_mb=1, yara_dirs=[RULES, str(tmp_path / "rules")], **kw)


class Session:
    """A logged-in test client that sends the CSRF header like the UI does."""

    def __init__(self, app, username, password=PW):
        self.http = TestClient(app)
        r = self.http.post("/api/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf"]

    def req(self, method, url, **kw):
        headers = {**kw.pop("headers", {}), "X-CSRF-Token": self.csrf}
        return self.http.request(method, url, headers=headers, **kw)

    def get(self, url, **kw): return self.req("GET", url, **kw)
    def post(self, url, **kw): return self.req("POST", url, **kw)
    def patch(self, url, **kw): return self.req("PATCH", url, **kw)
    def delete(self, url, **kw): return self.req("DELETE", url, **kw)

    def upload(self, name, content, **form):
        return self.post("/api/scan", data=form or None, files={"file": (name, io.BytesIO(content), "application/octet-stream")})


@pytest.fixture()
def env(tmp_path):
    cfg = make_settings(tmp_path)
    acc = Accounts(Store(cfg.db))
    acc.create_user("owner", PW, is_master=True)
    acc.create_user("boss", PW, role="admin")
    acc.create_user("ana", PW, role="analyst")
    acc.create_user("vic", PW, role="viewer")
    app = create_app(cfg)
    return app, cfg


def test_open_endpoints_and_headers(env):
    app, _ = env
    c = TestClient(app)
    assert c.get("/api/health").json()["status"] == "ok"
    st = c.get("/api/auth/status").json()
    assert st == {"setup_required": False, "authenticated": False, "user": None, "csrf": None}
    r = c.get("/")
    assert r.status_code == 200 and "Tollgate" in r.text and "default-src 'self'" in r.headers["content-security-policy"]
    assert c.get("/static/app.js").status_code == 200


def test_everything_else_needs_login(env):
    app, _ = env
    c = TestClient(app)
    for method, url in [("get", "/api/history"), ("get", "/api/status"), ("get", "/api/rules"), ("get", "/api/users"),
                        ("get", "/api/audit"), ("get", "/api/me"), ("get", "/api/intel/stats"), ("get", "/api/retro")]:
        assert getattr(c, method)(url).status_code == 401, url
    assert c.post("/api/scan", files={"file": ("a.bin", b"x")}).status_code == 401
    assert c.post("/api/intel/ioc", json={"type": "ip", "value": "1.2.3.4"}).status_code == 401


def test_setup_required_when_no_master(tmp_path):
    c = TestClient(create_app(make_settings(tmp_path)))
    assert c.get("/api/auth/status").json()["setup_required"] is True


def test_master_bootstrap_from_environment_forces_password_change(tmp_path):
    cfg = make_settings(tmp_path, master_username="teddy-owner", master_password="initial passphrase from env")
    app = create_app(cfg)
    s = Session(app, "teddy-owner", "initial passphrase from env")
    assert s.http.get("/api/auth/status").json()["user"]["is_master"] == 1
    assert s.get("/api/history").status_code == 403                       # must change password first
    assert s.get("/api/me").status_code == 200
    r = s.post("/api/auth/change-password", json={"current_password": "initial passphrase from env", "new_password": "a brand new long passphrase"})
    assert r.status_code == 200 and s.get("/api/history").status_code == 200
    create_app(cfg)                                                        # restart: existing master is not overwritten
    assert TestClient(app).post("/api/auth/login", json={"username": "teddy-owner", "password": "initial passphrase from env"}).status_code == 401
    with pytest.raises(RuntimeError):
        create_app(make_settings(tmp_path / "x", master_username="m1", master_password="short"))


def test_login_logout_cookie_flags_and_csrf(env):
    app, _ = env
    c = TestClient(app)
    bad = c.post("/api/auth/login", json={"username": "ana", "password": "nope nope nope nope"})
    assert bad.status_code == 401
    ok = c.post("/api/auth/login", json={"username": "ana", "password": PW})
    cookie = ok.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert c.get("/api/me").json()["username"] == "ana"                    # GET works with the cookie alone
    assert c.post("/api/url", json={"url": "http://a.test/"}).status_code == 403          # no CSRF header
    csrf = ok.json()["csrf"]
    assert c.post("/api/url", json={"url": "http://a.test/"}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.post("/api/url", json={"url": "http://a.test/"}, headers={"X-CSRF-Token": csrf}).status_code == 200
    assert c.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert c.get("/api/me").status_code == 401


def test_secure_cookie_behind_https(env):
    app, _ = env
    r = TestClient(app).post("/api/auth/login", json={"username": "ana", "password": PW}, headers={"X-Forwarded-Proto": "https"})
    assert "secure" in r.headers["set-cookie"].lower()


def test_login_rate_limit(env):
    app, _ = env
    c = TestClient(app)
    codes = [c.post("/api/auth/login", json={"username": f"ghost{i}", "password": "x" * 14}).status_code for i in range(22)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429, 429]


def test_role_matrix(env):
    app, _ = env
    vic, ana, boss = Session(app, "vic"), Session(app, "ana"), Session(app, "boss")
    assert vic.get("/api/history").status_code == 200 and vic.get("/api/rules").status_code == 200
    assert vic.upload("a.bin", b"hello").status_code == 403
    assert vic.post("/api/url", json={"url": "http://a.test/"}).status_code == 403
    assert ana.upload("a.bin", b"hello").status_code == 200
    assert ana.post("/api/intel/ioc", json={"type": "ip", "value": "1.2.3.4"}).status_code == 403
    assert ana.get("/api/users").status_code == 403 and ana.get("/api/audit").status_code == 403
    assert boss.post("/api/intel/ioc", json={"type": "ip", "value": "1.2.3.4"}).json() == {"result": "added"}
    assert boss.get("/api/users").status_code == 200


def test_scan_records_who_scanned_and_uses_real_filename(env):
    app, _ = env
    ana = Session(app, "ana")
    body = ana.upload("invoice.pdf.exe", PE).json()
    assert "NAME_DOUBLE_EXT" in {f["rule_id"] for f in body["findings"]}
    row = ana.get("/api/history").json()[0]
    assert row["filename"] == "invoice.pdf.exe" and row["scanned_by"] == "ana"
    assert ana.upload("../../etc/evil.exe", PE, record="false").json()["filename"] == "evil.exe"
    assert ana.upload("big.bin", b"A" * (1024 * 1024 + 10)).status_code == 413


def test_new_attack_flow_ioc_retro_rescan(env):
    app, _ = env
    ana, boss = Session(app, "ana"), Session(app, "boss")
    first = ana.upload("tool.exe", PE).json()
    assert first["verdict"] == "Clean"
    boss.post("/api/intel/ioc", json={"type": "sha256", "value": first["hashes"]["sha256"], "family": "NewBot"})
    assert boss.get("/api/retro").json()[0]["family"] == "NewBot"
    assert ana.upload("tool.exe", PE).json()["verdict"] == "Malicious"


def test_yara_upload_regex_rule_and_import_are_admin_and_audited(env):
    app, _ = env
    ana, boss = Session(app, "ana"), Session(app, "boss")
    src = 'rule Zeta { meta: severity = "critical" strings: $a = "zeta_c2" condition: $a }'
    assert ana.post("/api/rules/yara", json={"name": "zeta", "text": src}).status_code == 403
    assert boss.post("/api/rules/yara", json={"name": "zeta", "text": src}).status_code == 200
    assert ana.upload("x.bin", b"..zeta_c2..").json()["verdict"] == "Malicious"
    assert boss.post("/api/rules/yara", json={"name": "bad", "text": "rule x {"}).status_code == 400
    assert boss.post("/api/rules/regex", json={"name": "r1", "regex": "(bad"}).status_code == 400
    res = boss.post("/api/intel/import", json={"type": "domain", "text": "evil1.example\nevil2.example\nnope nope\n"}).json()
    assert res == {"added": 2, "updated": 0, "invalid": 1}
    actions = [a["action"] for a in boss.get("/api/audit").json()]
    assert {"rule.yara", "intel.import", "login.ok"} <= set(actions)


def test_user_management_rules(env):
    app, _ = env
    owner, boss, ana = Session(app, "owner"), Session(app, "boss"), Session(app, "ana")
    # an admin can create analysts/viewers but not admins; only the master creates admins
    assert boss.post("/api/users", json={"username": "newbie", "password": PW, "role": "viewer"}).status_code == 200
    assert boss.post("/api/users", json={"username": "evil-admin", "password": PW, "role": "admin"}).status_code == 403
    assert owner.post("/api/users", json={"username": "admin2", "password": PW, "role": "admin"}).status_code == 200
    assert boss.patch("/api/users/admin2", json={"active": False}).status_code == 403          # admins cannot touch admins
    assert boss.patch("/api/users/owner", json={"password": PW + "x"}).status_code == 403      # nor the master
    assert owner.patch("/api/users/owner", json={"role": "viewer"}).status_code == 400          # no self-edit
    assert boss.delete("/api/users/owner").status_code == 403 and owner.delete("/api/users/owner").status_code == 400
    assert boss.patch("/api/users/newbie", json={"role": "analyst"}).json()["role"] == "analyst"
    # disabling a user kills their live session immediately
    assert ana.get("/api/history").status_code == 200
    assert boss.patch("/api/users/ana", json={"active": False}).status_code == 200
    assert ana.get("/api/history").status_code == 401
    assert owner.patch("/api/users/ana", json={"active": True}).status_code == 200
    weak = boss.post("/api/users", json={"username": "weak1", "password": "short", "role": "viewer"})
    assert weak.status_code == 400 and "at least 12" in weak.json()["detail"]
    users = {u["username"]: u for u in owner.get("/api/users").json()}
    assert users["owner"]["is_master"] == 1 and "password_hash" not in users["owner"]


def test_admin_reset_forces_change_and_lockout_unlock(env):
    app, _ = env
    boss = Session(app, "boss")
    assert boss.patch("/api/users/vic", json={"password": "temporary passphrase 123", "must_change": True}).status_code == 200
    vic = Session(app, "vic", "temporary passphrase 123")
    assert vic.get("/api/history").status_code == 403
    assert vic.post("/api/auth/change-password", json={"current_password": "temporary passphrase 123", "new_password": "my own new passphrase"}).status_code == 200
    assert vic.get("/api/history").status_code == 200
    c = TestClient(app)
    for _ in range(5):
        c.post("/api/auth/login", json={"username": "vic", "password": "wrong wrong wrong"})
    assert c.post("/api/auth/login", json={"username": "vic", "password": "my own new passphrase"}).status_code == 401
    assert boss.patch("/api/users/vic", json={"unlock": True}).status_code == 200
    assert c.post("/api/auth/login", json={"username": "vic", "password": "my own new passphrase"}).status_code == 200


def test_api_tokens_for_automation(env):
    app, _ = env
    ana = Session(app, "ana")
    token = ana.post("/api/me/tokens", json={"label": "ci"}).json()["token"]
    plain = TestClient(app)                                               # no cookie, no CSRF: bearer token only
    h = {"Authorization": f"Bearer {token}"}
    assert plain.post("/api/scan", files={"file": ("a.bin", io.BytesIO(b"hello"))}, headers=h).status_code == 200
    assert plain.post("/api/intel/ioc", json={"type": "ip", "value": "1.2.3.4"}, headers=h).status_code == 403   # inherits analyst role
    assert plain.get("/api/me", headers={"Authorization": "Bearer tg_bogus"}).status_code == 401
    listed = ana.get("/api/me/tokens").json()
    assert listed[0]["label"] == "ci" and "token" not in listed[0]
    assert ana.delete(f"/api/me/tokens/{listed[0]['id']}").status_code == 200
    assert plain.get("/api/me", headers=h).status_code == 401


def test_tracing_disabled_by_default_and_via_tracer(tmp_path, monkeypatch):
    cfg = make_settings(tmp_path)
    acc = Accounts(Store(cfg.db)); acc.create_user("ana", PW, role="analyst"); acc.create_user("boss", PW, role="admin")
    s = Session(create_app(cfg), "ana")
    assert s.post("/api/url", json={"url": "http://a.test/", "trace": True}).status_code == 503
    cfg2 = make_settings(tmp_path, tracer_url="http://tracer:8081")
    fake = redirects.TraceResult(start="http://a.test/", hops=[
        redirects.Hop(url="http://a.test/", status=302, location="http://b.test/"), redirects.Hop(url="http://b.test/", status=200)],
        final_url="http://b.test/", completed=True)
    monkeypatch.setattr("tollgate.api._forward_trace", lambda settings, url: fake)
    app2 = create_app(cfg2)
    boss, ana2 = Session(app2, "boss"), Session(app2, "ana")
    boss.post("/api/intel/ioc", json={"type": "domain", "value": "b.test", "family": "Demo"})
    out = ana2.post("/api/url", json={"url": "http://a.test/", "trace": True}).json()
    assert out["trace"]["verdict"] == "Malicious" and len(out["trace"]["hops"]) == 2


def test_cli_trace_yara_and_defang(tmp_path, capsys, monkeypatch):
    from tollgate import cli, yara_engine
    monkeypatch.setenv("TOLLGATE_YARA_DIRS", os.pathsep.join([RULES, str(tmp_path / "rules")]))
    db = str(tmp_path / "c.db")
    rule = tmp_path / "zeta.yar"
    rule.write_text('rule Zeta { meta: severity = "critical" strings: $a = "zeta_c2" condition: $a }')
    assert cli.main(["--db", db, "yara", "add", str(rule)]) == 0
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"..zeta_c2..")
    monkeypatch.setattr(yara_engine, "_default", None)
    assert cli.main(["--db", db, "scan", str(sample)]) == 2
    assert cli.main(["--db", db, "trace", "ftp://x.test/"]) == 0
    assert cli.main(["defang", "http://a.b/c"]) == 0
    assert "hxxp://a[.]b/c" in capsys.readouterr().out


# ------------------------------------------------------------------ dynamic analysis through the API
from tollgate import cape, fake_cape  # noqa: E402


@pytest.fixture()
def dyn_env(tmp_path):
    server, url = fake_cape.start(token="s3cret")
    cfg = make_settings(tmp_path, cape=cape.CapeConfig(url=url, token="s3cret", analysis_timeout=30))
    acc = Accounts(Store(cfg.db))
    for name, role in (("boss", "admin"), ("ana", "analyst"), ("vic", "viewer")):
        acc.create_user(name, PW, role=role)
    yield create_app(cfg), cfg
    server.shutdown()


def test_detonation_is_opt_in_and_analyst_only(dyn_env):
    app, _ = dyn_env
    ana, vic = Session(app, "ana"), Session(app, "vic")
    assert ana.get("/api/status").json()["dynamic"] == "cape"
    plain = ana.upload("malware-x.exe", PE).json()
    assert "dynamic" not in plain                                          # nothing is sent unless asked
    assert vic.upload("a.exe", PE, detonate="true").status_code == 403
    r = ana.upload("malware-x.exe", PE, detonate="true").json()
    assert r["dynamic"]["task_id"] >= 1 and r["dynamic"]["status"] == "submitted"
    assert "dynamic.submit" in [a["action"] for a in Session(app, "boss").get("/api/audit").json()]


def test_dynamic_polling_updates_verdict_and_iocs_can_be_added(dyn_env):
    app, _ = dyn_env
    ana, boss, vic = Session(app, "ana"), Session(app, "boss"), Session(app, "vic")
    r = ana.upload("malware-x.exe", PE, detonate="true").json()
    assert r["verdict"] == "Clean"
    tid = r["dynamic"]["task_id"]
    states = [vic.get(f"/api/dynamic/{tid}").json()["status"] for _ in range(3)]       # a viewer may watch progress
    assert states == ["pending", "running", "reported"]
    done = vic.get(f"/api/dynamic/{tid}").json()
    assert done["summary"]["families"] == ["FakeFamily"] and done["scan"]["verdict"] == "Malicious"
    assert ana.get(f"/api/history/{r['scan_id']}").json()["metadata"]["dynamic"]["malscore"] == 9.5
    assert vic.get(f"/api/dynamic?scan_id={r['scan_id']}").json()[0]["status"] == "reported"
    items = [{"type": "domain", "value": "c2.demo-sandbox.example", "severity": "high"},
             {"type": "sha256", "value": done["summary"]["dropped"][0]["sha256"], "severity": "critical"},
             {"type": "domain", "value": "not-observed.example"}]
    assert ana.post(f"/api/dynamic/{tid}/iocs", json={"items": items}).status_code == 403
    out = boss.post(f"/api/dynamic/{tid}/iocs", json={"items": items}).json()
    assert out["added"] == 2 and out["skipped"] == ["not-observed.example"]
    assert boss.get("/api/intel/search?q=c2.demo-sandbox.example").json()[0]["source"] == f"cape:task{tid}"
    assert vic.get("/api/dynamic/9999").status_code == 404


def test_detonation_when_cape_unconfigured_or_down(tmp_path, dyn_env):
    app, _ = dyn_env
    cfg = make_settings(tmp_path / "other")
    Accounts(Store(cfg.db)).create_user("ana", PW, role="analyst")
    ana = Session(create_app(cfg), "ana")
    r = ana.upload("a.exe", PE, detonate="true").json()
    assert "not configured" in r["dynamic"]["error"] and r["verdict"] == "Clean"          # static result still delivered
    cfg2 = make_settings(tmp_path / "down", cape=cape.CapeConfig(url="http://127.0.0.1:9"))
    Accounts(Store(cfg2.db)).create_user("ana", PW, role="analyst")
    r2 = Session(create_app(cfg2), "ana").upload("a.exe", PE, detonate="true").json()
    assert "cannot reach CAPE" in r2["dynamic"]["error"] and r2["scan_id"]
