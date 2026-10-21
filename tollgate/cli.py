"""Tollgate command line interface.

  scan FILE            analyze a file (also the default: `tollgate FILE`)
  url URL...           check URLs (offline heuristics + threat intel)
  defang / refang      make URLs safe to share / restore them for lookups
  history, urls        what has been scanned / which URLs are tracked
  trace URL            follow a redirect chain safely (contacts the URL; needs network)
  retro                re-check all past scans against the current intel
  intel ...            add/import/fetch indicators, manage regex rules
  yara add/list        manage YARA rule files
  user ...             accounts: create-master, create, list, set-password, disable, enable, unlock, delete, token
  dynamic ...          sandbox (CAPE) tasks: list, show, refresh
  serve                run the web UI + API (uvicorn)

Exit codes (scan/url): 0 clean, 1 suspicious, 2 malicious, 3 error.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import sqlite3
import sys
import time

from . import auth, cape, dynamic as dynamic_mod, intel as intel_mod, paths, redirects, yara_engine
from .accounts import Accounts
from .models import Finding
from .db import IOC_TYPES, SEVERITIES, Store
from .engine import DEFAULT_MAX_SIZE, analyze_file
from .models import SEVERITY_ORDER, Report, Severity
from .urlcheck import UrlReport, analyze_url, defang, defang_text, refang

COMMANDS = {"scan", "url", "trace", "defang", "refang", "history", "urls", "retro", "intel", "yara", "serve", "user", "dynamic"}
COLORS = {Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
          Severity.LOW: "\033[36m", Severity.INFO: "\033[90m"}
VERDICT_COLORS = {"Malicious": "\033[1;31m", "Suspicious": "\033[1;33m", "Clean": "\033[1;32m"}
RESET = "\033[0m"
EXIT = {"Clean": 0, "Suspicious": 1, "Malicious": 2}


def _paint(text, code, on):
    return f"{code}{text}{RESET}" if on else text


def _finding_lines(findings, color):
    lines = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
        tag = _paint(f"[{f.severity.value.upper():8}]", COLORS[f.severity], color)
        lines.append(f"  {tag} {f.rule_id}: {defang_text(f.title)}")
        if f.detail:
            lines.append(f"             {defang_text(f.detail)}")
    return lines


def render_text(report: Report, color: bool = False) -> str:
    lines = [
        f"File:     {report.filename.encode('unicode_escape').decode('ascii')}",
        f"Size:     {report.size:,} bytes",
        f"Type:     {report.detected_type} (from content)",
        f"SHA256:   {report.hashes['sha256']}",
        f"MD5:      {report.hashes['md5']}",
        f"Verdict:  {_paint(report.verdict.upper(), VERDICT_COLORS[report.verdict], color)}  (score {report.score}/100)",
    ]
    if report.scan_id:
        lines.append(f"Logged:   scan #{report.scan_id}")
    lines.append("")
    lines += ["Findings:"] + _finding_lines(report.findings, color) if report.findings else ["Findings: none"]
    pe = report.metadata.get("pe")
    if pe:
        lines += ["", "PE summary:",
                  f"  machine={pe.get('machine')} subsystem={pe.get('subsystem')} dll={pe.get('is_dll')} .net={pe.get('is_dotnet')}",
                  f"  compile_time={pe.get('compile_time')} imphash={pe.get('imports', {}).get('imphash')}"]
        for s in pe.get("sections", []):
            lines.append(f"  section {s['name']:<10} {s['perms']} raw={s['raw_size']:<8} entropy={s['entropy']}")
        for u in pe.get("urls", [])[:5]:
            lines.append(f"  url {defang(u)}")
    lines += ["", "Note: 'Clean' means no known indicators were found. It is not proof of safety."]
    return "\n".join(lines)


def render_url(ur: UrlReport, color: bool = False) -> str:
    lines = [f"URL:      {ur.defanged}",
             f"Verdict:  {_paint(ur.verdict.upper(), VERDICT_COLORS[ur.verdict], color)}  (score {ur.score}/100)"]
    if ur.findings:
        lines += _finding_lines(ur.findings, color)
    return "\n".join(lines)


def render_trace(res, color: bool = False) -> str:
    lines = [f"Start:    {defang(res.start)}", f"Result:   {res.reason or 'n/a'}",
             f"Verdict:  {_paint(res.verdict.upper(), VERDICT_COLORS[res.verdict], color)}  (score {res.score}/100)", "", "Hops:"]
    for i, h in enumerate(res.hops, 1):
        bits = [f"HTTP {h.status}" if h.status else None, h.kind if h.kind != "http" else None, f"ip {h.ip}" if h.ip else None,
                h.content_type, "DOWNLOAD" if h.download else None, f"-> {defang_text(h.location)}" if h.location else None,
                h.note, f"NOT FOLLOWED: {h.blocked}" if h.blocked else None, f"ERROR: {h.error}" if h.error else None]
        lines.append(f"  {i}. {defang(h.url)}")
        detail = "  |  ".join(b for b in bits if b)
        if detail:
            lines.append(f"       {detail}")
    if res.findings:
        lines += ["", "Findings:"] + _finding_lines(res.findings, color)
    return "\n".join(lines)


def _yara(args) -> int:
    if not yara_engine.available():
        print("error: yara-python is not installed", file=sys.stderr)
        return 3
    if args.ycmd == "add":
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
        name = args.name or os.path.basename(args.file)
        path = yara_engine.add_rule_file(name, text, yara_engine.user_rules_dir())
        print(f"installed {path}")
        return 0
    eng = yara_engine.YaraEngine(yara_engine.dirs_from_env())
    print(f"{eng.rule_count()} rules from {len(eng.loaded)} file(s)")
    for path in eng.loaded:
        print(f"  ok     {path}")
    for err in eng.errors:
        print(f"  ERROR  {err['file']}: {err['error']}")
    return 1 if eng.errors else 0


def _table(rows, cols):
    if not rows:
        return "(none)"
    widths = [max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols]
    out = ["  ".join(c.ljust(w) for c, w in zip(cols, widths))]
    out += ["  ".join(str(r.get(c, "")).ljust(w) for c, w in zip(cols, widths)) for r in rows]
    return "\n".join(out)


def _open_store(path):
    try:
        return Store(path)
    except (sqlite3.Error, OSError) as exc:
        print(f"warning: database unavailable ({exc}); history and threat intel are disabled", file=sys.stderr)
        return None


def _need_store(store):
    if store is None:
        print("error: this command needs the database (set --db or TOLLGATE_DB)", file=sys.stderr)
        raise SystemExit(3)
    return store


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tollgate", description="File + URL analyzer with history and threat intel.")
    p.add_argument("--db", default=paths.default_db(), help="SQLite database path (default: $TOLLGATE_HOME/tollgate.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyze a file (read-only, never executed)")
    s.add_argument("path")
    s.add_argument("--name", help="original filename if the sample was renamed on disk")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-record", action="store_true", help="do not write this scan to history")
    s.add_argument("--max-size-mb", type=int, default=DEFAULT_MAX_SIZE // (1024 * 1024))
    s.add_argument("--detonate", action="store_true", help="also send the file to your CAPE sandbox (needs TOLLGATE_CAPE_URL)")
    s.add_argument("--wait", type=int, default=0, metavar="SECONDS", help="with --detonate: wait for the sandbox result")

    u = sub.add_parser("url", help="check one or more URLs")
    u.add_argument("urls", nargs="+")
    u.add_argument("--json", action="store_true")
    u.add_argument("--no-record", action="store_true", help="do not track these URLs")

    tr = sub.add_parser("trace", help="follow a redirect chain (network; SSRF-guarded)")
    tr.add_argument("url")
    tr.add_argument("--json", action="store_true")
    tr.add_argument("--no-record", action="store_true")
    tr.add_argument("--max-hops", type=int, default=8)

    y = sub.add_parser("yara", help="manage YARA rules")
    ysub = y.add_subparsers(dest="ycmd", required=True)
    ya = ysub.add_parser("add", help="validate and install a rule file into the user rules directory")
    ya.add_argument("file"); ya.add_argument("--name", help="name to store it under (default: file name)")
    ysub.add_parser("list", help="list loaded rule files and compile errors")

    us = sub.add_parser("user", help="manage accounts (local: works directly on the database)")
    usub = us.add_subparsers(dest="ucmd", required=True)
    cm = usub.add_parser("create-master", help="create the owner account (only one can exist)")
    cm.add_argument("username"); cm.add_argument("--password-env", metavar="VAR", help="read the password from this environment variable")
    cu = usub.add_parser("create", help="create an account")
    cu.add_argument("username"); cu.add_argument("--role", choices=auth.ROLES, default="analyst")
    cu.add_argument("--password-env", metavar="VAR"); cu.add_argument("--no-force-change", action="store_true")
    usub.add_parser("list", help="list accounts")
    sp = usub.add_parser("set-password", help="reset a password")
    sp.add_argument("username"); sp.add_argument("--password-env", metavar="VAR"); sp.add_argument("--force-change", action="store_true")
    for name, text in (("disable", "disable an account"), ("enable", "enable an account"), ("unlock", "clear a lockout"),
                       ("delete", "delete an account (not the master)")):
        usub.add_parser(name, help=text).add_argument("username")
    tk = usub.add_parser("token", help="create an API token for a user (shown once)")
    tk.add_argument("username"); tk.add_argument("--label", default="cli"); tk.add_argument("--days", type=int)

    dy = sub.add_parser("dynamic", help="sandbox (CAPE) tasks")
    dsub = dy.add_subparsers(dest="dcmd", required=True)
    dsub.add_parser("list", help="recent tasks")
    for name in ("show", "refresh"):
        dsub.add_parser(name, help=f"{name} a task").add_argument("id", type=int)

    sv = sub.add_parser("serve", help="run the web UI and API")
    sv.add_argument("--host", default="127.0.0.1"); sv.add_argument("--port", type=int, default=8080)

    for name in ("defang", "refang"):
        d = sub.add_parser(name, help=f"{name} URLs/IOCs ('-' reads stdin)")
        d.add_argument("text", nargs="+")

    h = sub.add_parser("history", help="list past scans")
    h.add_argument("--limit", type=int, default=20)
    h.add_argument("--verdict")
    h.add_argument("--sha256")
    h.add_argument("--name", help="filename contains")
    h.add_argument("--show", type=int, metavar="ID", help="print the stored report for a scan")

    t = sub.add_parser("urls", help="list tracked URLs")
    t.add_argument("--limit", type=int, default=50)

    sub.add_parser("retro", help="re-check history against current threat intel")

    i = sub.add_parser("intel", help="manage threat intel and rules")
    isub = i.add_subparsers(dest="icmd", required=True)
    a = isub.add_parser("add", help="add one indicator")
    a.add_argument("type", choices=IOC_TYPES)
    a.add_argument("value")
    for x in (a,):
        x.add_argument("--family"); x.add_argument("--source", default="manual")
        x.add_argument("--severity", choices=SEVERITIES, default="critical"); x.add_argument("--note")
    im = isub.add_parser("import", help="import a list/CSV of indicators")
    im.add_argument("file")
    im.add_argument("--type", required=True, choices=IOC_TYPES)
    im.add_argument("--column", help="CSV column index (0-based) or header name")
    im.add_argument("--family"); im.add_argument("--source", default="import")
    im.add_argument("--severity", choices=SEVERITIES, default="critical")
    f = isub.add_parser("fetch", help="download configured feeds (needs network)")
    f.add_argument("--config", default=paths.default_feeds())
    f.add_argument("--every", type=int, metavar="SECONDS", help="keep running and fetch repeatedly (minimum 300)")
    rm = isub.add_parser("remove", help="remove an indicator (e.g. a false positive)")
    rm.add_argument("type", choices=IOC_TYPES); rm.add_argument("value")
    se = isub.add_parser("search", help="look a value up in the intel database")
    se.add_argument("value")
    isub.add_parser("stats", help="database statistics")
    ex = isub.add_parser("export", help="export indicators as CSV (move intel to an offline machine)")
    ex.add_argument("--type", choices=IOC_TYPES); ex.add_argument("--out", help="file (default: stdout)")
    ld = isub.add_parser("load", help="load a CSV produced by `intel export`")
    ld.add_argument("file")
    ra = isub.add_parser("rule-add", help="add/replace a detection rule (regex over extracted strings)")
    ra.add_argument("name"); ra.add_argument("regex")
    ra.add_argument("--severity", choices=SEVERITIES, default="high"); ra.add_argument("--description", default="")
    isub.add_parser("rules", help="list detection rules")
    rr = isub.add_parser("rule-remove", help="remove a detection rule"); rr.add_argument("name")
    return p


def _default_command(argv: list[str]) -> list[str]:
    """Allow `tollgate FILE` as shorthand for `tollgate scan FILE`."""
    i = 0
    while i < len(argv):
        if argv[i] == "--db":
            i += 2
        elif argv[i].startswith("--db="):
            i += 1
        else:
            break
    if i < len(argv) and argv[i] not in COMMANDS and not argv[i].startswith("-"):
        return argv[:i] + ["scan"] + argv[i:]
    return argv


def main(argv=None) -> int:
    argv = _default_command(list(sys.argv[1:] if argv is None else argv))
    args = build_parser().parse_args(argv)
    color = sys.stdout.isatty()
    try:
        return _run(args, color)
    except (OSError, ValueError, sqlite3.Error, cape.CapeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


def _run(args, color) -> int:
    if args.cmd in ("defang", "refang"):
        fn = defang if args.cmd == "defang" else refang
        items = sys.stdin.read().split() if args.text == ["-"] else args.text
        for item in items:
            print(fn(item))
        return 0

    if args.cmd == "serve":
        try:
            import uvicorn  # noqa: F401
            from . import api  # noqa: F401
        except ImportError:
            print("error: the web UI needs extra packages: pip install 'tollgate-defender[web]'", file=sys.stderr)
            return 3
        os.environ["TOLLGATE_DB"] = args.db
        uvicorn.run("tollgate.api:create_app", factory=True, host=args.host, port=args.port, workers=1)
        return 0

    if args.cmd == "yara":
        return _yara(args)

    store = _open_store(args.db)

    if args.cmd == "scan":
        report = analyze_file(args.path, args.name, args.max_size_mb * 1024 * 1024,
                              store=store, record=not args.no_record, yara_engine=yara_engine.default_engine())
        verdict = report.verdict
        if args.detonate:
            verdict = _detonate(args, report, store) or verdict
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(render_text(report, color))
        return EXIT[verdict]

    if args.cmd == "url":
        worst, reports = 0, []
        for raw in args.urls:
            ur = analyze_url(raw, store)
            if store and not args.no_record and ur.normalized:
                store.track_url(ur.normalized, None, "manual")
            reports.append(ur)
            worst = max(worst, EXIT[ur.verdict])
        if args.json:
            print(json.dumps([r.to_dict() for r in reports], indent=2))
        else:
            print("\n\n".join(render_url(r, color) for r in reports))
        return worst

    if args.cmd == "user":
        return _user(args, _need_store(store))
    if args.cmd == "dynamic":
        return _dynamic(args, _need_store(store))

    if args.cmd == "trace":
        res = redirects.trace(args.url, store=store if not args.no_record else None, max_hops=args.max_hops)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(render_trace(res, color))
        return EXIT[res.verdict]

    store = _need_store(store)

    if args.cmd == "history":
        if args.show:
            rep = store.get_scan(args.show)
            if rep is None:
                print(f"error: no scan #{args.show}", file=sys.stderr)
                return 3
            print(json.dumps(rep, indent=2))
            return 0
        rows = store.history(args.limit, args.verdict, args.sha256, args.name)
        for r in rows:
            r["sha256"] = r["sha256"][:16] + "..."
            r["filename"] = r["filename"].encode("unicode_escape").decode("ascii")[:40]
        print(_table(rows, ["id", "scanned_at", "filename", "detected_type", "verdict", "score", "sha256"]))
        return 0

    if args.cmd == "urls":
        rows = store.tracked_urls(args.limit)
        for r in rows:
            r["url"] = defang(r["url"])[:70]
            r["intel"] = "MATCH" if r["intel"] else ""
        print(_table(rows, ["url", "times_seen", "first_seen", "last_seen", "intel"]))
        return 0

    if args.cmd == "retro":
        hits = store.retro_hunt()
        for h in hits:
            h["value"] = defang_text(h["value"])[:48]
            h["filename"] = h["filename"].encode("unicode_escape").decode("ascii")[:30]
        print(_table(hits, ["scan_id", "scanned_at", "filename", "verdict_at_scan", "ioc_type", "value", "family", "source"]))
        print(f"\n{len(hits)} retroactive match(es) between past scans and current intel.")
        return 2 if hits else 0

    return _intel(args, store)


def _intel(args, store) -> int:
    c = args.icmd
    if c == "add":
        print(store.add_ioc(args.type, args.value, args.family, args.source, args.severity, args.note))
    elif c == "import":
        col = args.column
        print(json.dumps(intel_mod.import_file(store, args.file, args.type, column=col, family=args.family,
                                               source=args.source, severity=args.severity)))
    elif c == "fetch":
        if args.every is not None and args.every < 300:
            print("error: --every must be at least 300 seconds (be kind to the feed providers)", file=sys.stderr)
            return 3
        while True:
            results = intel_mod.fetch_feeds(store, args.config)
            for r in results:
                print(json.dumps(r), flush=True)
            if args.every is None:
                return 3 if any("error" in r for r in results) else 0
            time.sleep(args.every)
    elif c == "remove":
        ok = store.remove_ioc(args.type, args.value)
        print("removed" if ok else "not found")
        return 0 if ok else 1
    elif c == "search":
        rows = store.lookup_any(args.value)
        for r in rows:
            r["value"] = defang_text(r["value"])
        print(_table(rows, ["ioc_type", "value", "family", "source", "severity", "updated_at"]))
        return 0 if rows else 1
    elif c == "stats":
        print(json.dumps(store.stats(), indent=2))
    elif c == "export":
        rows = store.export_iocs(args.type)
        out = open(args.out, "w", newline="", encoding="utf-8") if args.out else sys.stdout
        w = csv.DictWriter(out, fieldnames=["ioc_type", "value", "family", "source", "severity", "note"], extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
        if args.out:
            out.close()
            print(f"exported {len(rows)} indicator(s) to {args.out}")
    elif c == "load":
        print(json.dumps(intel_mod.load_export(store, args.file)))
    elif c == "rule-add":
        store.add_rule(args.name, args.regex, args.severity, args.description)
        print("ok")
    elif c == "rules":
        print(_table(store.list_rules(), ["name", "severity", "enabled", "regex", "description"]))
    elif c == "rule-remove":
        ok = store.remove_rule(args.name)
        print("removed" if ok else "not found")
        return 0 if ok else 1
    return 0


def _read_password(env_name: str | None, confirm: bool = True) -> str:
    if env_name:
        value = os.environ.get(env_name)
        if not value:
            raise ValueError(f"environment variable {env_name} is empty or not set")
        return value
    first = getpass.getpass("Password: ")
    if confirm and first != getpass.getpass("Repeat password: "):
        raise ValueError("passwords did not match")
    return first


def _user(args, store) -> int:
    acc, c = Accounts(store), args.ucmd
    try:
        if c == "create-master":
            u = acc.create_user(args.username, _read_password(args.password_env), is_master=True, created_by="cli")
            print(f"master account '{u['username']}' created. Sign in at the web UI.")
        elif c == "create":
            u = acc.create_user(args.username, _read_password(args.password_env), args.role,
                                must_change=not args.no_force_change, created_by="cli")
            print(f"account '{u['username']}' ({u['role']}) created" + ("; they must change the password at first sign-in" if u["must_change_password"] else ""))
        elif c == "list":
            print(_table([{**u, "master": "yes" if u["is_master"] else "", "active": "yes" if u["active"] else "NO",
                           "locked": "LOCKED" if u["locked"] else "", "last_login": u["last_login"] or "never"} for u in acc.list_users()],
                         ["username", "role", "master", "active", "locked", "last_login"]))
        elif c == "set-password":
            acc.set_password(args.username, _read_password(args.password_env), "cli", must_change=args.force_change)
            print("password changed; the user's sessions were signed out")
        elif c in ("disable", "enable"):
            acc.update_user(args.username, active=(c == "enable"), actor="cli")
            print(f"{args.username} {c}d")
        elif c == "unlock":
            acc.unlock(args.username, "cli")
            print(f"{args.username} unlocked")
        elif c == "delete":
            acc.delete_user(args.username, "cli")
            print(f"{args.username} deleted")
        elif c == "token":
            user = acc.get_user(args.username)
            if not user:
                raise auth.PolicyError("no such user")
            print(acc.create_token(user["id"], args.label, args.days))
            print("Copy it now: it is shown only once and stored hashed.", file=sys.stderr)
    except (auth.PolicyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    return 0


def render_dynamic(task: dict) -> str:
    lines = [f"Dynamic task #{task['id']}  status={task['status']}  CAPE task {task['remote_id']}"
             + (f"  error: {task['error']}" if task.get("error") else "")]
    sm = task.get("summary")
    if sm:
        lines.append(f"  score {sm['malscore']}/10  family: {', '.join(sm['families']) or 'none named'}  duration: {sm['duration']}s")
        for sig in sm["signatures"][:8]:
            lines.append(f"  [sev {sig['severity']}] {sig['description'] or sig['name']}")
        for key in ("domains", "urls"):
            for v in sm["network"][key][:6]:
                lines.append(f"  {key[:-1]}: {defang_text(v)}")
        for d in sm["dropped"][:5]:
            lines.append(f"  dropped: {d['name']} {d['sha256']}")
    return "\n".join(lines)


def _detonate(args, report, store) -> str | None:
    cfgc = cape.CapeConfig.from_env()
    if not cfgc.enabled:
        raise ValueError("--detonate needs TOLLGATE_CAPE_URL (see docs/CAPE.md)")
    if store is None or args.no_record:
        raise ValueError("--detonate needs the scan to be recorded (the sandbox result is merged into it); drop --no-record")
    client = cape.CapeClient(cfgc)
    with open(args.path, "rb") as fh:
        data = fh.read()
    task = dynamic_mod.submit(store, client, report.filename, data, report.scan_id, "cli")
    print(f"submitted to CAPE as task #{task['id']} (remote {task['remote_id']})", file=sys.stderr)
    deadline = time.monotonic() + args.wait
    while args.wait and task["status"] not in ("reported", "failed") and time.monotonic() < deadline:
        time.sleep(5)
        task = dynamic_mod.refresh(store, client, task["id"])
    print(render_dynamic(task), file=sys.stderr)
    stored = store.get_scan(report.scan_id) if report.scan_id else None
    if stored and task["status"] == "reported":      # show the merged result, not the static-only one
        report.findings = [Finding(f["rule_id"], f["title"], Severity(f["severity"]), f.get("detail", ""), f.get("category", "general"))
                           for f in stored["findings"]]
        report.score, report.verdict, report.metadata = stored["score"], stored["verdict"], stored["metadata"]
        return stored["verdict"]
    return None


def _dynamic(args, store) -> int:
    if args.dcmd == "list":
        print(_table(store.list_dynamic_tasks(), ["id", "scan_id", "status", "remote_id", "submitted_by", "submitted_at", "error"]))
        return 0
    task = store.get_dynamic_task(args.id)
    if task is None:
        print(f"error: no dynamic task #{args.id}", file=sys.stderr)
        return 3
    if args.dcmd == "refresh":
        cfgc = cape.CapeConfig.from_env()
        if not cfgc.enabled:
            print("error: needs TOLLGATE_CAPE_URL", file=sys.stderr)
            return 3
        try:
            task = dynamic_mod.refresh(store, cape.CapeClient(cfgc), args.id)
        except cape.CapeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
    print(render_dynamic(task))
    return 0
