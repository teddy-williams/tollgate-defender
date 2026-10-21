# Using Tollgate

## Signing in
Open http://127.0.0.1:8080 and sign in. If the page says no accounts exist yet, create the owner account with
`docker compose run --rm cli user create-master YOUR-USERNAME` (or `tollgate user create-master YOUR-USERNAME`). Roles, the master account and API tokens are in [ACCOUNTS.md](ACCOUNTS.md).
What you see depends on your role: viewers get History and Intel (read-only); analysts also get Scan and Check a URL; admins also get the intel/rule forms and **Users & audit**.

## Web UI
- **Scan a file:** drag a file onto the drop zone. You get a verdict banner, score, hashes, findings by severity, YARA matches, and a panel for the file type (PE sections and imports, **shortcut structure**, **PDF structure** with scripts, links and embedded files), plus
  a table of everything extracted and examined (decoded commands, embedded files, appended data). Untick "Log this scan" to keep it out of history. If a sandbox is connected, tick **Also detonate in the sandbox** to send the file to CAPE;
  the verdict updates when the run finishes and a **Sandbox run** section shows what happened, with indicators admins can add to intel.
- **Check a URL:** paste a URL, defanged or not. Tick *Trace redirects* to follow the chain (this contacts the URL).
- **History:** every logged scan with who ran it; click a row for the full stored report (including any sandbox run). *Tracked URLs* shows each URL's first/last seen and count.
- **Intel & rules:** stats, search any hash/domain/URL/IP, **Retro-hunt**, and (admins) add indicators, import lists, add regex rules and YARA files.
- **Users & audit (admins):** create accounts, change roles, reset passwords, unlock, disable, delete; read the audit log.
- **Account menu (top right):** change your password and manage your API tokens.

Everything from analysed files is rendered as text, invisible characters in filenames are shown as `\u{202e}`, and URLs are defanged.

## Command line
```bash
tollgate scan FILE [--name ORIGINAL_NAME] [--json] [--no-record] [--detonate [--wait SECONDS]]
tollgate url URL...  [--json] [--no-record]
tollgate trace URL   [--json]                 # follows redirects (network)
tollgate defang TEXT... | tollgate refang TEXT...      # '-' reads stdin
tollgate history [--verdict Malicious] [--name x] [--sha256 H] [--show ID]
tollgate urls | tollgate retro
tollgate intel add sha256 <hash> --family Emotet --source mycase --severity critical
tollgate intel import list.txt --type domain [--column url]       # plain list or CSV
tollgate intel fetch [--config feeds.json] [--every SECONDS]       # feeds; see FEEDS.md
tollgate intel search <value> | stats | remove TYPE VALUE | export [--out f.csv] | load f.csv
tollgate intel rule-add NAME 'regex' --severity high --description "..."
tollgate yara add rule.yar | tollgate yara list
tollgate user create-master|create|list|set-password|disable|enable|unlock|delete|token ...      # see ACCOUNTS.md
tollgate dynamic list | show ID | refresh ID                      # sandbox tasks; see CAPE.md
tollgate serve [--host 127.0.0.1] [--port 8080]
```
Use `--name` when a sample was renamed on disk (for example to its hash) so filename tricks are still detected.
Global option `--db PATH` selects another database. Run `tollgate COMMAND -h` for details. The command line works directly on the database
(no sign-in), so it is for the people who administer the server.

**Exit codes** for `scan`, `url`, `trace`: `0` clean, `1` suspicious, `2` malicious, `3` error. Handy in scripts:
```bash
tollgate scan "$f" --json > report.json; case $? in 2) quarantine "$f";; 1) flag_for_review "$f";; esac
```
PowerShell: `tollgate scan $f; switch ($LASTEXITCODE) { 2 { ... } 1 { ... } }`.

## API
Interactive docs at `/api/docs` (sign in first). Everything except `/api/health`, `/api/auth/status` and `/api/auth/login` needs a login or an API token. For scripts, create a token
(Account menu, or `tollgate user token NAME`) and send it as a bearer token. A token acts with its owner's role:
```bash
export TG=tg_xxxxxxxx
curl -H "Authorization: Bearer $TG" -F "file=@suspect.exe" http://127.0.0.1:8080/api/scan
curl -H "Authorization: Bearer $TG" -F "file=@suspect.exe" -F "detonate=true" http://127.0.0.1:8080/api/scan     # also sandbox (analyst+)
curl -H "Authorization: Bearer $TG" -H 'Content-Type: application/json' -d '{"url":"hxxp://evil[.]example/a"}' http://127.0.0.1:8080/api/url
curl -H "Authorization: Bearer $TG" 'http://127.0.0.1:8080/api/history?verdict=Malicious&limit=20'
curl -H "Authorization: Bearer $TG" http://127.0.0.1:8080/api/retro
curl -H "Authorization: Bearer $TG" http://127.0.0.1:8080/api/dynamic/12                       # sandbox task status/result
```
Admin-role tokens can also add intel and rules (`POST /api/intel/ioc`, `/api/intel/import`, `/api/rules/yara`, `/api/rules/regex`) and manage users.
(On Windows use `curl.exe`, or PowerShell `Invoke-RestMethod`.) Uploads are capped at `TOLLGATE_MAX_UPLOAD_MB` (default 50). Browsers use cookies plus a CSRF header automatically; scripts using tokens need neither.

## Reading a report
Each finding has a **severity**, a **rule id** (for example `NAME_DOUBLE_EXT`, `PE_PACKER`, `YARA_PDF_Launch_Action`,
`INTEL_HASH_MATCH`) and detail. Rule-id prefixes: `NAME_`/`EXT_` filename and type tricks, `PE_` PE structure,
`STR_` PE strings, `LNK_` shortcut structure, `PDF_` PDF structure and JavaScript, `URL_` URL heuristics, `TRACE_` redirect chain, `YARA_` YARA, `RULE_` your regex rules, `INTEL_` threat intel, `DYN_` sandbox behaviour.
Scoring: info 0, low 3, medium 10, high 25, critical 50 (cap 100); **Suspicious at 15+, Malicious at 60+**, and any
critical `INTEL_*` finding (including a `critical` YARA rule) or a sandbox-named malware family (`DYN_FAMILY`) makes the verdict Malicious by itself.
Some benign software legitimately looks like this (installers with large overlays, packed commercial tools): read the
evidence, do not just read the label. Please report false positives (see the issue template).

## Common workflows
**Triage an email attachment:** scan it (`--name` with the real filename), read the filename and type findings first
(these catch most phishing payloads), then YARA and PE findings. Check any linked URLs with `tollgate url`.

**Respond to a new campaign:**
1. Add the indicators: `tollgate intel import hashes.txt --type sha256 --family NewCampaign` (also domains, URLs, IPs, imphash).
2. If the report describes behaviour, write a YARA rule ([RULES.md](RULES.md)) and `tollgate yara add` it.
3. `tollgate retro` (or the UI button): which files you scanned earlier are now flagged? Exit code is 2 if any.

**Share a link safely:** `tollgate defang "http://evil.com/x"` gives `hxxp://evil[.]com/x` for tickets and chat; `refang` reverses it.

**Offline team:** see "Keeping an offline install current" in [INSTALL.md](INSTALL.md).

## Configuration reference
| Variable | Meaning | Default |
|---|---|---|
| `TOLLGATE_HOME` | folder for database, your rules, feeds.json | `~/.tollgate` (`/data` in Docker) |
| `TOLLGATE_DB` | database file | `$TOLLGATE_HOME/tollgate.db` |
| `TOLLGATE_YARA_DIRS` | rule folders (OS path-separator list; last one is writable) | built-in rules + `$TOLLGATE_HOME/rules` |
| `TOLLGATE_FEEDS` | feed config for `intel fetch` | `$TOLLGATE_HOME/feeds.json` |
| `TOLLGATE_MAX_UPLOAD_MB` | upload limit | `50` |
| `TOLLGATE_MASTER_USERNAME` / `_PASSWORD` | optional first-start owner account (forced password change); prefer the CLI | empty |
| `TOLLGATE_COOKIE_SECURE` | `auto`, `1` or `0`: Secure flag on the session cookie | `auto` |
| `TOLLGATE_TRUST_PROXY` | `1` = use X-Forwarded-For (only behind your own proxy) | `0` |
| `TOLLGATE_TRACER_URL` / `TOLLGATE_TRACER_TOKEN` | use a separate tracer service | empty |
| `TOLLGATE_ALLOW_LOCAL_TRACE` | `1` = trace from the API process itself (personal use) | off |
| `TOLLGATE_CAPE_*` | sandbox connection (see [CAPE.md](CAPE.md)) | off |
| `ABUSECH_AUTH_KEY` | read by feed configs that name it (see [FEEDS.md](FEEDS.md)) | empty |
