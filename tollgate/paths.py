"""Where Tollgate keeps its files.

TOLLGATE_HOME (default ~/.tollgate) holds the database, your own YARA rules and (optionally) feeds.json.
Docker sets TOLLGATE_HOME=/data. TOLLGATE_DB / TOLLGATE_YARA_DIRS / TOLLGATE_FEEDS override single items.
"""
from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("TOLLGATE_HOME") or (Path.home() / ".tollgate"))


def default_db() -> str:
    return os.environ.get("TOLLGATE_DB") or str(home() / "tollgate.db")


def default_feeds() -> str:
    return os.environ.get("TOLLGATE_FEEDS") or str(home() / "feeds.json")


def builtin_rules_dir() -> str:
    return str(Path(__file__).parent / "rules")


def user_rules_dir() -> str:
    return str(home() / "rules")
