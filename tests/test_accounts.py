import sqlite3

import pytest

from tollgate import auth
from tollgate.accounts import Accounts, AuthError, IDLE_HOURS
from tollgate.db import Store

PW = "correct horse battery staple"


@pytest.fixture()
def acc():
    return Accounts(Store(":memory:"))


def test_password_hash_and_policy(monkeypatch):
    h1, h2 = auth.hash_password(PW), auth.hash_password(PW)
    assert h1 != h2 and h1.startswith("scrypt$") and auth.verify_password(PW, h1) and not auth.verify_password(PW + "x", h1)
    assert not auth.verify_password(PW, "garbage") and not auth.verify_password(PW, "scrypt$1$2$3$x$y")
    for bad in ("short", "a" * 11, "teddy-owner-2026", "passwordpassword", "aaaaaaaaaaaaaaaa", "x" * 300):
        with pytest.raises(auth.PolicyError):
            auth.check_password_policy(bad, "teddy-owner")
    auth.check_password_policy(PW, "teddy-owner")
    monkeypatch.undo()                                               # production cost parameters
    assert f"${2 ** 15}$8$1$" in auth.hash_password("production-cost-check")


def test_username_rules(acc):
    for bad in ("ab", "has space", "x" * 65, "a;b", ""):
        with pytest.raises(auth.PolicyError):
            acc.create_user(bad, PW)
    acc.create_user("Alice_1", PW)
    with pytest.raises(auth.PolicyError):
        acc.create_user("alice_1", PW)                               # usernames are case-insensitive


def test_single_master_and_protection(acc):
    m = acc.create_user("owner", PW, role="viewer", is_master=True)
    assert m["role"] == "admin" and m["is_master"] == 1 and acc.has_master()
    with pytest.raises(auth.PolicyError):
        acc.create_user("second", PW, is_master=True)
    for kwargs in ({"role": "viewer"}, {"active": False}):
        with pytest.raises(auth.PolicyError):
            acc.update_user("owner", **kwargs)
    with pytest.raises(auth.PolicyError):
        acc.delete_user("owner")


def test_login_lockout_and_generic_errors(acc):
    acc.create_user("bob", PW)
    with pytest.raises(AuthError) as unknown:
        acc.authenticate("nobody", PW)
    with pytest.raises(AuthError) as wrong:
        acc.authenticate("bob", "wrong password here")
    assert str(unknown.value).split(",")[0] == str(wrong.value).split(",")[0]       # no user enumeration
    for _ in range(4):
        with pytest.raises(AuthError):
            acc.authenticate("bob", "wrong password here")
    with pytest.raises(AuthError):                                   # now locked: even the right password fails
        acc.authenticate("bob", PW)
    acc.unlock("bob")
    assert acc.authenticate("bob", PW)["username"] == "bob"
    actions = [r["action"] for r in acc.audit_log()]
    assert "login.fail" in actions and "login.locked" in actions and "login.ok" in actions


def test_disabled_user_cannot_login_or_use_session(acc):
    u = acc.create_user("carol", PW)
    token, _ = acc.create_session(u["id"])
    assert acc.get_session(token)
    acc.update_user("carol", active=False)
    assert acc.get_session(token) is None
    with pytest.raises(AuthError):
        acc.authenticate("carol", PW)


def test_sessions_expire_and_are_revoked(acc):
    u = acc.create_user("dave", PW)
    token, csrf = acc.create_session(u["id"], "1.2.3.4", "ua")
    user, sess = acc.get_session(token)
    assert user["username"] == "dave" and sess["csrf"] == csrf
    assert acc.get_session("not-a-token") is None
    acc.db.execute("UPDATE sessions SET last_seen='2000-01-01T00:00:00+00:00'")          # idle too long
    assert acc.get_session(token) is None
    t2, _ = acc.create_session(u["id"])
    acc.set_password("dave", "another long passphrase here", actor="admin")               # password change kills sessions
    assert acc.get_session(t2) is None and IDLE_HOURS == 4
    t3, _ = acc.create_session(u["id"])
    acc.destroy_session(t3)
    assert acc.get_session(t3) is None


def test_api_tokens(acc):
    u = acc.create_user("erin", PW, role="analyst")
    token = acc.create_token(u["id"], "ci")
    assert token.startswith("tg_") and acc.authenticate_token(token)["username"] == "erin"
    listed = acc.list_tokens(u["id"])
    assert listed[0]["prefix"] == token[:11] and "token_hash" not in listed[0]
    assert acc.authenticate_token("tg_wrong") is None and acc.authenticate_token("notatoken") is None
    acc.db.execute("UPDATE api_tokens SET expires_at='2000-01-01T00:00:00+00:00'")
    assert acc.authenticate_token(token) is None
    t2 = acc.create_token(u["id"], "second")
    assert acc.revoke_token(listed[0]["id"] + 1, u["id"]) and acc.authenticate_token(t2) is None
    assert not acc.revoke_token(listed[0]["id"], 9999)


def test_delete_user_cascades(acc):
    u = acc.create_user("frank", PW)
    token, _ = acc.create_session(u["id"])
    api = acc.create_token(u["id"], "x")
    acc.delete_user("frank")
    assert acc.get_session(token) is None and acc.authenticate_token(api) is None


def test_migration_from_0_3_0_database(tmp_path):
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'cli',
          filename TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, md5 TEXT NOT NULL, sha1 TEXT NOT NULL, imphash TEXT,
          detected_type TEXT NOT NULL, verdict TEXT NOT NULL, score INTEGER NOT NULL, report_json TEXT NOT NULL);
        INSERT INTO scans (scanned_at, filename, size, sha256, md5, sha1, detected_type, verdict, score, report_json)
          VALUES ('2026-10-01T00:00:00+00:00', 'old.exe', 5, 'a', 'b', 'c', 'pe', 'Clean', 0, '{}');
    """)
    old.commit(); old.close()
    store = Store(path)                                                # opening upgrades in place
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == 2
    assert store.history()[0]["filename"] == "old.exe" and store.history()[0]["scanned_by"] is None
    assert Accounts(store).count_users() == 0
    Store(path)                                                        # idempotent
