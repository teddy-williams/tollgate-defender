"""SQLite storage: scan history, URL tracking, threat-intel IOCs and detection rules.

One file, no server. The analyzer stores metadata, hashes and reports, never the
sample itself (so the database is not a malware archive).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .urlcheck import normalize_url, refang

IOC_TYPES = ("sha256", "md5", "sha1", "imphash", "domain", "url", "ip")
SEVERITIES = ("critical", "high", "medium", "low")
_HEX_LEN = {"sha256": 64, "sha1": 40, "md5": 32, "imphash": 32}
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scanned_at TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'cli',
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL, md5 TEXT NOT NULL, sha1 TEXT NOT NULL,
  imphash TEXT,
  detected_type TEXT NOT NULL,
  verdict TEXT NOT NULL,
  score INTEGER NOT NULL,
  report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_imphash ON scans(imphash);
CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  times_seen INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);
CREATE TABLE IF NOT EXISTS url_sightings (
  url_id INTEGER NOT NULL REFERENCES urls(id),
  scan_id INTEGER REFERENCES scans(id),
  seen_at TEXT NOT NULL,
  context TEXT NOT NULL DEFAULT 'file'
);
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ioc_type TEXT NOT NULL,
  value TEXT NOT NULL,
  family TEXT,
  source TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'critical',
  note TEXT,
  added_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(ioc_type, value)
);
CREATE TABLE IF NOT EXISTS intel_updates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, source TEXT NOT NULL,
  added INTEGER NOT NULL, updated INTEGER NOT NULL, invalid INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
  is_master INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen TEXT NOT NULL,
  ip TEXT, user_agent TEXT
);
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  created_at TEXT NOT NULL, last_used TEXT, expires_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, detail TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS dynamic_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER REFERENCES scans(id),
  backend TEXT NOT NULL, remote_id TEXT NOT NULL, status TEXT NOT NULL,
  submitted_by TEXT, submitted_at TEXT NOT NULL, completed_at TEXT,
  summary_json TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  regex TEXT NOT NULL,
  severity TEXT NOT NULL,
  description TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  added_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_ioc(ioc_type: str, value: str) -> str:
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"unknown IOC type {ioc_type!r}; use one of {', '.join(IOC_TYPES)}")
    v = value.strip()
    if ioc_type in _HEX_LEN:
        v = v.lower()
        if len(v) != _HEX_LEN[ioc_type] or not re.fullmatch(r"[0-9a-f]+", v):
            raise ValueError(f"invalid {ioc_type}: {value[:80]!r}")
        return v
    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(refang(v)))
        except ValueError:
            raise ValueError(f"invalid ip: {value[:80]!r}") from None
    if ioc_type == "domain":
        v = refang(v).lower().rstrip(".")
        try:
            v = v.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(f"invalid domain: {value[:80]!r}") from None
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"invalid domain: {value[:80]!r}")
        return v
    n = normalize_url(v)
    if not n or "://" not in n:
        raise ValueError(f"invalid url: {value[:80]!r}")
    return n


class Store:
    def __init__(self, path: str, init: bool = True):
        if path != ":memory:" and init:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        # One Store per request/command; check_same_thread=False lets a framework hop threads.
        self.conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        if init:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self._migrate()

    SCHEMA_VERSION = 2

    def _migrate(self) -> None:
        """v0/1 = Tollgate 0.1-0.3 (no accounts). v2 adds accounts, audit log, dynamic tasks and scans.scanned_by."""
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version < 2:
            cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(scans)")}
            if "scanned_by" not in cols:
                self.conn.execute("ALTER TABLE scans ADD COLUMN scanned_by TEXT")
            self.conn.execute("PRAGMA user_version = 2")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- scan history ------------------------------------------------------

    def record_scan(self, report, source: str = "cli", user: str | None = None) -> int:
        imphash = (report.metadata.get("pe", {}).get("imports", {}) or {}).get("imphash") or None
        cur = self.conn.execute(
            "INSERT INTO scans (scanned_at, source, filename, size, sha256, md5, sha1, imphash,"
            " detected_type, verdict, score, report_json, scanned_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_now(), source, report.filename, report.size, report.hashes["sha256"], report.hashes["md5"],
             report.hashes["sha1"], imphash, report.detected_type, report.verdict, report.score,
             json.dumps(report.to_dict()), user))
        scan_id = cur.lastrowid
        for url in report.metadata.get("pe", {}).get("urls", []):
            self.track_url(url, scan_id, "file", commit=False)
        self.conn.commit()
        return scan_id

    def previous_sightings(self, sha256: str) -> dict:
        r = self.conn.execute(
            "SELECT COUNT(*) c, MIN(scanned_at) first, MAX(scanned_at) last FROM scans WHERE sha256=?",
            (sha256,)).fetchone()
        return {"count": r["c"], "first": r["first"], "last": r["last"]}

    def history(self, limit: int = 20, verdict: str | None = None, sha256: str | None = None,
                name: str | None = None) -> list[dict]:
        sql, params = "SELECT id, scanned_at, filename, size, sha256, detected_type, verdict, score, scanned_by FROM scans", []
        where = []
        if verdict:
            where.append("lower(verdict)=lower(?)"); params.append(verdict)
        if sha256:
            where.append("sha256=?"); params.append(sha256.lower())
        if name:
            where.append("filename LIKE ?"); params.append(f"%{name}%")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def update_scan_result(self, scan_id: int, report: dict, verdict: str, score: int) -> None:
        self.conn.execute("UPDATE scans SET report_json=?, verdict=?, score=? WHERE id=?", (json.dumps(report), verdict, score, scan_id))
        self.conn.commit()

    # --- dynamic analysis tasks ---------------------------------------------

    def create_dynamic_task(self, scan_id: int | None, backend: str, remote_id: str, user: str | None) -> int:
        cur = self.conn.execute(
            "INSERT INTO dynamic_tasks (scan_id, backend, remote_id, status, submitted_by, submitted_at) VALUES (?,?,?,?,?,?)",
            (scan_id, backend, str(remote_id), "submitted", user, _now()))
        self.conn.commit()
        return cur.lastrowid

    def get_dynamic_task(self, task_id: int) -> dict | None:
        r = self.conn.execute("SELECT * FROM dynamic_tasks WHERE id=?", (task_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["summary"] = json.loads(d.pop("summary_json")) if d.get("summary_json") else None
        return d

    def update_dynamic_task(self, task_id: int, **fields) -> None:
        allowed = {"status", "completed_at", "summary_json", "error"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        self.conn.execute(f"UPDATE dynamic_tasks SET {', '.join(k + '=?' for k in sets)} WHERE id=?", (*sets.values(), task_id))
        self.conn.commit()

    def list_dynamic_tasks(self, scan_id: int | None = None, limit: int = 50) -> list[dict]:
        sql, args = "SELECT id, scan_id, backend, remote_id, status, submitted_by, submitted_at, completed_at, error FROM dynamic_tasks", []
        if scan_id is not None:
            sql += " WHERE scan_id=?"
            args.append(scan_id)
        return [dict(r) for r in self.conn.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit))]

    def get_scan(self, scan_id: int) -> dict | None:
        r = self.conn.execute("SELECT report_json FROM scans WHERE id=?", (scan_id,)).fetchone()
        return json.loads(r["report_json"]) if r else None

    # --- URL tracking ------------------------------------------------------

    def track_url(self, url: str, scan_id: int | None = None, context: str = "file",
                  commit: bool = True) -> int | None:
        norm = normalize_url(url)
        if not norm or "://" not in norm or norm.lower().startswith(("file:",)):
            return None
        host = urlsplit(norm).hostname or ""
        now = _now()
        row = self.conn.execute("SELECT id FROM urls WHERE url=?", (norm,)).fetchone()
        if row:
            url_id = row["id"]
            self.conn.execute("UPDATE urls SET times_seen=times_seen+1, last_seen=? WHERE id=?", (now, url_id))
        else:
            url_id = self.conn.execute(
                "INSERT INTO urls (url, host, first_seen, last_seen) VALUES (?,?,?,?)",
                (norm, host, now, now)).lastrowid
        self.conn.execute("INSERT INTO url_sightings (url_id, scan_id, seen_at, context) VALUES (?,?,?,?)",
                          (url_id, scan_id, now, context))
        if commit:
            self.conn.commit()
        return url_id

    def tracked_urls(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT url, host, first_seen, last_seen, times_seen FROM urls ORDER BY last_seen DESC, id DESC LIMIT ?",
            (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["intel"] = bool(self.match_url(d["url"], d["host"]))
            out.append(d)
        return out

    # --- threat intel ------------------------------------------------------

    def add_ioc(self, ioc_type: str, value: str, family: str | None = None, source: str = "manual",
                severity: str = "critical", note: str | None = None, commit: bool = True) -> str:
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        v = normalize_ioc(ioc_type, value)
        now = _now()
        exists = self.conn.execute("SELECT 1 FROM iocs WHERE ioc_type=? AND value=?", (ioc_type, v)).fetchone()
        self.conn.execute(
            "INSERT INTO iocs (ioc_type, value, family, source, severity, note, added_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ioc_type, value) DO UPDATE SET"
            " family=COALESCE(excluded.family, family), source=excluded.source,"
            " severity=excluded.severity, note=COALESCE(excluded.note, note), updated_at=excluded.updated_at",
            (ioc_type, v, family, source, severity, note, now, now))
        if commit:
            self.conn.commit()
        return "updated" if exists else "added"

    def export_iocs(self, ioc_type: str | None = None) -> list[dict]:
        sql = "SELECT ioc_type, value, family, source, severity, note FROM iocs"
        args: tuple = ()
        if ioc_type:
            sql += " WHERE ioc_type=?"
            args = (ioc_type,)
        return [dict(r) for r in self.conn.execute(sql + " ORDER BY ioc_type, value", args)]

    def log_update(self, source: str, added: int, updated: int, invalid: int = 0) -> None:
        self.conn.execute("INSERT INTO intel_updates (ts, source, added, updated, invalid) VALUES (?,?,?,?,?)",
                          (_now(), source, added, updated, invalid))
        self.conn.commit()

    def lookup_ioc(self, ioc_type: str, value: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM iocs WHERE ioc_type=? AND value=?", (ioc_type, value)).fetchone()
        return dict(r) if r else None

    def lookup_any(self, value: str) -> list[dict]:
        out = []
        for t in IOC_TYPES:
            try:
                v = normalize_ioc(t, value)
            except ValueError:
                continue
            r = self.lookup_ioc(t, v)
            if r:
                out.append(r)
        return out

    def remove_ioc(self, ioc_type: str, value: str) -> bool:
        cur = self.conn.execute("DELETE FROM iocs WHERE ioc_type=? AND value=?",
                                (ioc_type, normalize_ioc(ioc_type, value)))
        self.conn.commit()
        return cur.rowcount > 0

    def match_url(self, norm_url: str, host: str) -> list[dict]:
        rows = []
        r = self.lookup_ioc("url", norm_url)
        if r:
            rows.append(r)
        if host:
            try:
                ipaddress.ip_address(host.strip("[]"))
                r = self.lookup_ioc("ip", host.strip("[]"))
                if r:
                    rows.append(r)
            except ValueError:
                labels = host.split(".")
                for i in range(len(labels) - 1):  # stops before the bare TLD
                    r = self.lookup_ioc("domain", ".".join(labels[i:]))
                    if r:
                        rows.append(r)
        return rows

    def stats(self) -> dict:
        c = self.conn
        by_type = {r["ioc_type"]: r["n"] for r in c.execute("SELECT ioc_type, COUNT(*) n FROM iocs GROUP BY ioc_type")}
        last = c.execute("SELECT ts, source FROM intel_updates ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "scans": c.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "tracked_urls": c.execute("SELECT COUNT(*) FROM urls").fetchone()[0],
            "iocs_total": sum(by_type.values()),
            "iocs_by_type": by_type,
            "rules": c.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0],
            "last_update": dict(last) if last else None,
        }

    # --- detection rules (analyst-defined, applied to extracted strings) --

    def add_rule(self, name: str, regex: str, severity: str = "high", description: str = "") -> None:
        if not _RULE_NAME_RE.match(name):
            raise ValueError("rule name must be 1-64 chars of letters, digits, _ . -")
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        try:
            re.compile(regex)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from None
        self.conn.execute(
            "INSERT INTO rules (name, regex, severity, description, added_at) VALUES (?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET regex=excluded.regex, severity=excluded.severity,"
            " description=excluded.description, enabled=1",
            (name, regex, severity, description, _now()))
        self.conn.commit()

    def list_rules(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM rules ORDER BY name")]

    def enabled_rules(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT name, regex, severity, description FROM rules WHERE enabled=1")]

    def remove_rule(self, name: str) -> bool:
        cur = self.conn.execute("DELETE FROM rules WHERE name=?", (name,))
        self.conn.commit()
        return cur.rowcount > 0

    # --- retro-hunt: old scans vs. the *current* intel ---------------------

    def retro_hunt(self) -> list[dict]:
        cols = "s.id scan_id, s.scanned_at, s.filename, s.verdict verdict_at_scan, i.ioc_type, i.value, i.family, i.source, i.severity"
        files = self.conn.execute(
            f"SELECT {cols} FROM scans s JOIN iocs i ON "
            "(i.ioc_type='sha256' AND i.value=s.sha256) OR (i.ioc_type='sha1' AND i.value=s.sha1) OR "
            "(i.ioc_type='md5' AND i.value=s.md5) OR (i.ioc_type='imphash' AND i.value=s.imphash)").fetchall()
        urls = self.conn.execute(
            f"SELECT DISTINCT {cols} FROM url_sightings us JOIN urls u ON u.id=us.url_id "
            "JOIN scans s ON s.id=us.scan_id JOIN iocs i ON "
            "(i.ioc_type='url' AND i.value=u.url) OR (i.ioc_type='ip' AND i.value=u.host) OR "
            "(i.ioc_type='domain' AND (u.host=i.value OR substr(u.host, -length(i.value)-1)='.'||i.value))").fetchall()
        return [dict(r) for r in list(files) + list(urls)]
