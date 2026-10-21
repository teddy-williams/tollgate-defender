"""User accounts, sessions, API tokens and the audit log (stored in the same SQLite database)."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from . import auth

SESSION_HOURS = 12
IDLE_HOURS = 4
LOCK_AFTER = 5
LOCK_MINUTES = 15
TOKEN_PREFIX = "tg_"


class AuthError(Exception):
    """Login failed. The message is deliberately generic."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def public(user: dict | None) -> dict | None:
    """Fields safe to show to clients."""
    if not user:
        return None
    return {k: user[k] for k in ("id", "username", "role", "is_master", "active", "must_change_password",
                                 "created_at", "last_login") if k in user}


class Accounts:
    def __init__(self, store):
        self.db = store.conn

    # --- audit ---------------------------------------------------------------
    def audit(self, actor: str | None, action: str, detail: str = "", ip: str | None = None) -> None:
        self.db.execute("INSERT INTO audit_log (ts, actor, action, detail, ip) VALUES (?,?,?,?,?)",
                        (_iso(_now()), actor, action, detail[:500], ip))
        self.db.commit()

    def audit_log(self, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT ts, actor, action, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    # --- users ---------------------------------------------------------------
    def _row(self, where: str, arg) -> dict | None:
        r = self.db.execute(f"SELECT * FROM users WHERE {where}", (arg,)).fetchone()
        return dict(r) if r else None

    def get_user(self, username: str) -> dict | None:
        return self._row("username = ?", username)

    def has_master(self) -> bool:
        return self.db.execute("SELECT 1 FROM users WHERE is_master=1").fetchone() is not None

    def count_users(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def list_users(self) -> list[dict]:
        return [public(dict(r)) | {"locked": bool(r["locked_until"] and r["locked_until"] > _iso(_now()))}
                for r in self.db.execute("SELECT * FROM users ORDER BY is_master DESC, username COLLATE NOCASE")]

    def create_user(self, username: str, password: str, role: str = "analyst", is_master: bool = False,
                    must_change: bool = False, created_by: str | None = None) -> dict:
        auth.check_username(username)
        if role not in auth.ROLES:
            raise auth.PolicyError(f"role must be one of {', '.join(auth.ROLES)}")
        auth.check_password_policy(password, username)
        if is_master:
            if self.has_master():
                raise auth.PolicyError("a master account already exists")
            role = "admin"
        if self.get_user(username):
            raise auth.PolicyError("that username is already taken")
        self.db.execute(
            "INSERT INTO users (username, password_hash, role, is_master, must_change_password, created_at, created_by)"
            " VALUES (?,?,?,?,?,?,?)",
            (username, auth.hash_password(password), role, int(is_master), int(must_change), _iso(_now()), created_by))
        self.db.commit()
        self.audit(created_by, "user.create", f"{username} role={role}{' (master)' if is_master else ''}")
        return self.get_user(username)

    def set_password(self, username: str, new_password: str, actor: str | None, must_change: bool = False,
                     keep_session: str | None = None) -> None:
        user = self.get_user(username)
        if not user:
            raise auth.PolicyError("no such user")
        auth.check_password_policy(new_password, username)
        self.db.execute("UPDATE users SET password_hash=?, must_change_password=?, failed_attempts=0, locked_until=NULL WHERE id=?",
                        (auth.hash_password(new_password), int(must_change), user["id"]))
        self.destroy_user_sessions(user["id"], except_token=keep_session)
        self.db.commit()
        self.audit(actor, "user.password", username)

    def update_user(self, username: str, role: str | None = None, active: bool | None = None, actor: str | None = None) -> dict:
        user = self.get_user(username)
        if not user:
            raise auth.PolicyError("no such user")
        if user["is_master"] and (role not in (None, "admin") or active is False):
            raise auth.PolicyError("the master account cannot be demoted or disabled")
        if role is not None:
            if role not in auth.ROLES:
                raise auth.PolicyError(f"role must be one of {', '.join(auth.ROLES)}")
            self.db.execute("UPDATE users SET role=? WHERE id=?", (role, user["id"]))
        if active is not None:
            self.db.execute("UPDATE users SET active=? WHERE id=?", (int(active), user["id"]))
        if role is not None or active is False:
            self.destroy_user_sessions(user["id"])
        self.db.commit()
        self.audit(actor, "user.update", f"{username} role={role} active={active}")
        return self.get_user(username)

    def unlock(self, username: str, actor: str | None = None) -> None:
        self.db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
        self.db.commit()
        self.audit(actor, "user.unlock", username)

    def delete_user(self, username: str, actor: str | None = None) -> None:
        user = self.get_user(username)
        if not user:
            raise auth.PolicyError("no such user")
        if user["is_master"]:
            raise auth.PolicyError("the master account cannot be deleted")
        self.db.execute("DELETE FROM users WHERE id=?", (user["id"],))
        self.db.commit()
        self.audit(actor, "user.delete", username)

    # --- login / sessions ----------------------------------------------------
    def authenticate(self, username: str, password: str, ip: str | None = None) -> dict:
        user = self.get_user(username or "")
        if len(password or "") > auth.MAX_PASSWORD or not user:
            auth.burn_time(password or "")
            self.audit(None, "login.fail", f"unknown user {str(username)[:64]!r}", ip)
            raise AuthError("invalid username or password")
        if user["locked_until"] and user["locked_until"] > _iso(_now()):
            auth.burn_time(password)
            self.audit(user["username"], "login.locked", "attempt while locked", ip)
            raise AuthError("invalid username or password, or account temporarily locked")
        if not user["active"] or not auth.verify_password(password, user["password_hash"]):
            attempts = user["failed_attempts"] + 1
            locked = _iso(_now() + timedelta(minutes=LOCK_MINUTES)) if attempts >= LOCK_AFTER else None
            self.db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                            (0 if locked else attempts, locked, user["id"]))
            self.db.commit()
            self.audit(user["username"], "login.fail", "disabled account" if not user["active"] else f"bad password ({attempts})", ip)
            raise AuthError("invalid username or password, or account temporarily locked")
        self.db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?", (_iso(_now()), user["id"]))
        self.db.commit()
        self.audit(user["username"], "login.ok", "", ip)
        return self.get_user(username)

    def create_session(self, user_id: int, ip: str | None = None, user_agent: str | None = None) -> tuple[str, str]:
        token, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(24), _now()
        self.db.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
            (_sha(token), user_id, csrf, _iso(now), _iso(now + timedelta(hours=SESSION_HOURS)), _iso(now), ip, (user_agent or "")[:200]))
        self.db.commit()
        return token, csrf

    def get_session(self, token: str) -> tuple[dict, dict] | None:
        r = self.db.execute("SELECT * FROM sessions WHERE token_hash=?", (_sha(token),)).fetchone()
        if not r:
            return None
        sess, now = dict(r), _now()
        idle_limit = _iso(now - timedelta(hours=IDLE_HOURS))
        if sess["expires_at"] < _iso(now) or sess["last_seen"] < idle_limit:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?", (sess["token_hash"],))
            self.db.commit()
            return None
        user = self._row("id = ?", sess["user_id"])
        if not user or not user["active"]:
            return None
        if sess["last_seen"] < _iso(now - timedelta(minutes=1)):
            self.db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (_iso(now), sess["token_hash"]))
            self.db.commit()
        return user, sess

    def destroy_session(self, token: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE token_hash=?", (_sha(token),))
        self.db.commit()

    def destroy_user_sessions(self, user_id: int, except_token: str | None = None) -> None:
        if except_token:
            self.db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, _sha(except_token)))
        else:
            self.db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        self.db.commit()

    # --- API tokens ----------------------------------------------------------
    def create_token(self, user_id: int, label: str, days: int | None = None) -> str:
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        expires = _iso(_now() + timedelta(days=days)) if days else None
        self.db.execute("INSERT INTO api_tokens (user_id, label, token_hash, prefix, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                        (user_id, label[:80] or "token", _sha(token), token[:11], _iso(_now()), expires))
        self.db.commit()
        return token

    def list_tokens(self, user_id: int) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT id, label, prefix, created_at, last_used, expires_at, revoked FROM api_tokens WHERE user_id=? ORDER BY id DESC", (user_id,))]

    def revoke_token(self, token_id: int, user_id: int) -> bool:
        cur = self.db.execute("UPDATE api_tokens SET revoked=1 WHERE id=? AND user_id=?", (token_id, user_id))
        self.db.commit()
        return cur.rowcount > 0

    def authenticate_token(self, token: str) -> dict | None:
        if not token.startswith(TOKEN_PREFIX):
            return None
        r = self.db.execute("SELECT * FROM api_tokens WHERE token_hash=? AND revoked=0", (_sha(token),)).fetchone()
        if not r or (r["expires_at"] and r["expires_at"] < _iso(_now())):
            return None
        user = self._row("id = ?", r["user_id"])
        if not user or not user["active"]:
            return None
        self.db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (_iso(_now()), r["id"]))
        self.db.commit()
        return user
