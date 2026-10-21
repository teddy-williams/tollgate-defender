# Architecture

```
 browser ─► api (FastAPI: UI, accounts, scan, URL, history, intel, rules, sandbox tasks) ──► SQLite (scans, urls, iocs, rules, users, sessions, tokens, audit, dynamic tasks)
              │   ├─ engine: triage → analyzers (PE / LNK / PDF) → extracted artifacts → intel → YARA → score/verdict
              │   ├──► tracer (follows redirects; no DB, no samples) ──► internet
              │   └──► CAPE sandbox (your server; only when an analyst asks) ──► report merged back into the scan
 cli ───────► same engine and database, offline        updater / `intel fetch` ──► feeds (abuse.ch etc.)
```

## Pipeline (`tollgate/engine.py`)
1. **Triage** (`triage.py`): hashes, type from magic bytes, filename tricks, extension/content mismatch.
2. **Intel** (`db.py`): known hash match, "seen before" count.
3. **Analyzers by type:** `pe_analyzer.py` (PE), `lnk_analyzer.py` (shell links, MS-SHLLINK), `pdf_analyzer.py` (objects, streams, actions, JavaScript, embedded files).
   Parsers also return **artifacts**: byte blobs they pulled out (a decoded PowerShell command, an embedded executable, data appended after the structure).
4. **Artifacts** are examined like top-level files (hash intel, YARA, and PE/LNK/PDF analysis up to two levels deep), so a domain hidden in an encoded command or a hash of an embedded dropper is matched.
5. **URLs** found anywhere go through `urlcheck.py` (heuristics + intel).
6. **YARA** (`yara_engine.py`) scans every file.
7. **Scoring** (`scoring.py`): sum of severity weights; decisive findings (`INTEL_*` and `DYN_FAMILY` at critical) force Malicious. The result is stored in history with who ran it.
8. **Dynamic** (optional, `cape.py`, `dynamic.py`): on request the file goes to CAPE; when the report is ready it is summarized, turned into findings (category `dynamic`) and merged into the stored scan, which is re-scored.

Everything produces `Finding(rule_id, title, severity, detail, category)` objects; verdicts are always explainable.

## Modules
| File | Role |
|---|---|
| `triage.py` | hashes, magic-byte type, double extension / RTLO / mismatch checks |
| `pe_analyzer.py`, `lnk_analyzer.py`, `pdf_analyzer.py` | structural analysis; bounded; never execute or render |
| `urlcheck.py` | defang/refang, normalization, URL heuristics, intel match |
| `redirects.py` | SSRF-guarded redirect tracing (`trace_raw` records, `assess` judges) |
| `yara_engine.py` | rule loading per file, scanning, validated rule upload |
| `cape.py`, `dynamic.py`, `fake_cape.py` | CAPE client + defensive report summarizer; task workflow and merge; fake server for demos/tests |
| `db.py` | SQLite store (schema v2 with migration): scans, URLs, IOCs, rules, retro-hunt, export, dynamic tasks |
| `accounts.py`, `auth.py` | users, sessions, API tokens, audit; scrypt hashing and password policy |
| `intel.py` | list/CSV/JSON/ThreatFox feeds, fetch, export/load |
| `api.py`, `tracer_service.py`, `static/` | web API and role guards, tracer microservice, UI (text nodes only; CSP default-src 'self') |
| `cli.py`, `paths.py` | command line (incl. user/dynamic commands), file locations |

## Extending
**New file-type analyzer:** add `tollgate/<type>_analyzer.py` exposing `analyze(data) -> (findings, metadata, artifacts)`, call it from `engine.analyze_bytes` when `triage.detect_type` returns that type, add tests from synthetic bytes.
**New heuristic:** return a `Finding` with a stable `rule_id`; pick severities with the weights in mind.
**New intel type:** add to `db.IOC_TYPES`, `normalize_ioc`, and the matching logic in `db.py`.
**New sandbox backend:** implement the same `submit_file/status/report` shape as `CapeClient` and a summarizer producing the dict `dynamic_findings` expects.
Design rules: analyzers parse bytes only (never execute, never import untrusted content), bound memory and time, and never trust strings from the sample when rendering (the UI uses text nodes only).
