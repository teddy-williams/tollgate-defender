"""Threat-intel ingestion: import indicator lists/CSVs and fetch configured feeds.

The scanning container needs no network. Run `intel fetch` from a separate,
network-enabled job that writes to the same database (see docker-compose.yml).
"""
from __future__ import annotations

import csv
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .db import Store


def iter_values(text: str, column: str | int | None = None):
    """Yield raw indicator strings from a plain list or CSV. Skips blanks and '#' comments."""
    comments, rows = [], []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            comments.append(s.lstrip("# ").strip())
        else:
            rows.append(s)
    if column is None:
        yield from dict.fromkeys(rows)
        return

    parsed = list(csv.reader(rows, skipinitialspace=True))
    idx, skip_first = None, False
    if isinstance(column, int) or str(column).isdigit():
        idx = int(column)
    else:
        wanted = str(column).strip().lower()
        candidates = ([(parsed[0], True)] if parsed else []) + \
                     [(next(csv.reader([c], skipinitialspace=True)), False) for c in comments[::-1]]
        for header, is_first in candidates:
            names = [h.strip().strip('"').lower() for h in header]
            if wanted in names:
                idx, skip_first = names.index(wanted), is_first
                break
        if idx is None:
            raise ValueError(f"column {column!r} not found in file header")
    seen = set()
    for row in parsed[1 if skip_first else 0:]:
        if idx < len(row):
            v = row[idx].strip()
            if v and v not in seen:
                seen.add(v)
                yield v


def import_text(store: Store, text: str, ioc_type: str, column=None, family=None,
                source="import", severity="critical", note=None) -> dict:
    added = updated = invalid = 0
    for value in iter_values(text, column):
        try:
            result = store.add_ioc(ioc_type, value, family, source, severity, note, commit=False)
        except ValueError:
            invalid += 1
            continue
        added += result == "added"
        updated += result == "updated"
    store.conn.commit()
    store.log_update(source, added, updated, invalid)
    return {"added": added, "updated": updated, "invalid": invalid}


def import_file(store: Store, path: str, ioc_type: str, **kwargs) -> dict:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return import_text(store, fh.read(), ioc_type, **kwargs)


_THREATFOX_TYPES = {"domain": "domain", "url": "url", "ip:port": "ip", "md5_hash": "md5", "sha256_hash": "sha256"}


def _json_path(data, path: str | None):
    for key in (path or "").split("."):
        if key:
            data = data.get(key) if isinstance(data, dict) else None
    return data


def parse_feed(text: str, feed: dict) -> list[tuple[str, str, str | None]]:
    """Turn a downloaded feed into (ioc_type, value, family) records. Formats: lines (default), json, threatfox."""
    fmt, family = feed.get("format", "lines"), feed.get("family")
    if fmt == "lines":
        return [(feed["type"], v, family) for v in iter_values(text, feed.get("column"))]
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("feed did not return JSON (wrong URL, or an HTML error page?)") from None
    status = data.get("query_status") if isinstance(data, dict) else None
    if status not in (None, "ok", "no_result"):
        raise ValueError(f"feed reported: {status}" + (" (check the API key)" if "auth" in str(status) or "key" in str(status) else ""))
    if fmt == "threatfox":
        floor = int(feed.get("min_confidence", 75))
        out = []
        for item in (data.get("data") or []) if isinstance(data, dict) else []:
            kind = _THREATFOX_TYPES.get(item.get("ioc_type")) if isinstance(item, dict) else None
            if not kind or int(item.get("confidence_level") or 0) < floor:
                continue
            value = str(item.get("ioc", ""))
            out.append((kind, value.rsplit(":", 1)[0] if kind == "ip" else value, item.get("malware_printable") or family))
        return out
    if fmt == "json":
        items = _json_path(data, feed.get("json_path"))
        out = []
        for item in items if isinstance(items, list) else []:
            value = item if isinstance(item, str) else item.get(feed.get("json_field", "value")) if isinstance(item, dict) else None
            fam = (item.get(feed["family_field"]) if isinstance(item, dict) and feed.get("family_field") else None) or family
            if isinstance(value, str) and value:
                out.append((feed["type"], value, fam))
        return out
    raise ValueError(f"unknown feed format {fmt!r}")


def import_records(store: Store, records, source: str, severity: str = "critical") -> dict:
    added = updated = invalid = 0
    for kind, value, family in records:
        try:
            result = store.add_ioc(kind, value, family, source, severity, None, commit=False)
        except ValueError:
            invalid += 1
            continue
        added += result == "added"
        updated += result == "updated"
    store.conn.commit()
    store.log_update(source, added, updated, invalid)
    return {"added": added, "updated": updated, "invalid": invalid}


def _download(url: str, headers: dict, timeout: int, max_bytes: int, body: bytes | None = None, content_type: str | None = None) -> str:
    hdrs = {"User-Agent": "tollgate/0.4", **headers}
    if content_type:
        hdrs["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced by caller
            data = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        hint = " (the API key is missing or wrong)" if exc.code in (401, 403) else ""
        raise ValueError(f"HTTP {exc.code}{hint}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise ValueError(f"cannot download ({exc.__class__.__name__})") from None
    if len(data) > max_bytes:
        raise ValueError(f"feed larger than {max_bytes} bytes")
    return data.decode("utf-8", errors="replace")


def fetch_feeds(store: Store, config_path: str, timeout: int = 30, max_bytes: int = 50 * 1024 * 1024,
                allow_insecure: bool = False) -> list[dict]:
    """Download every feed in the JSON config and merge it into the database. Secrets come from environment variables."""
    with open(config_path, encoding="utf-8") as fh:
        config = json.load(fh)
    results = []
    for feed in config.get("feeds", []):
        name, url = feed.get("name", "?"), feed.get("url", "")
        if not (url.lower().startswith("https://") or (allow_insecure and url.lower().startswith("http://127.0.0.1"))):
            results.append({"feed": name, "error": "only https:// feeds are allowed"})
            continue
        headers = dict(feed.get("headers", {}))
        missing = [v for v in feed.get("headers_from_env", {}).values() if not os.environ.get(v)]
        if missing:
            results.append({"feed": name, "error": f"environment variable {missing[0]} is not set (put the key in .env; see docs/FEEDS.md)"})
            continue
        headers.update({h: os.environ[v] for h, v in feed.get("headers_from_env", {}).items()})
        body = ctype = None
        if feed.get("body") is not None:
            if feed.get("body_format", "form") == "json":
                body, ctype = json.dumps(feed["body"]).encode(), "application/json"
            else:
                body, ctype = urllib.parse.urlencode(feed["body"]).encode(), "application/x-www-form-urlencoded"
        try:
            records = parse_feed(_download(url, headers, timeout, max_bytes, body, ctype), feed)
            res = import_records(store, records, feed.get("source", name), feed.get("severity", "critical"))
            results.append({"feed": name, "records": len(records), **res})
        except (ValueError, KeyError, OSError) as exc:
            results.append({"feed": name, "error": str(exc)})
    return results


def load_export(store: Store, path: str) -> dict:
    """Load a CSV written by `intel export` (columns: ioc_type,value,family,source,severity,note)."""
    added = updated = invalid = 0
    with open(path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            try:
                result = store.add_ioc(row["ioc_type"], row["value"], row.get("family") or None,
                                       row.get("source") or "load", row.get("severity") or "critical",
                                       row.get("note") or None, commit=False)
            except (ValueError, KeyError):
                invalid += 1
                continue
            added += result == "added"
            updated += result == "updated"
    store.conn.commit()
    store.log_update(f"load:{os.path.basename(path)}", added, updated, invalid)
    return {"added": added, "updated": updated, "invalid": invalid}
