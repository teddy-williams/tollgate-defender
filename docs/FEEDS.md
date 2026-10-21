# Threat feeds (abuse.ch and your own)

Feeds keep your intel database current without anyone typing indicators. A separate **updater** downloads them on a schedule and merges them into the database. Tollgate then
flags new files and links that match, and **Retro-hunt** shows which past scans are now known-bad.

## Your abuse.ch Auth-Key: where it goes (and where it must NOT go)
abuse.ch's APIs (URLhaus, MalwareBazaar, ThreatFox) require a free key, sent in an `Auth-Key` HTTP header. **One key works for all three.**

| Place | OK? | Why |
|---|---|---|
| `.env` as `ABUSECH_AUTH_KEY=...` | **Yes** | Only the `updater` container receives it; `.env` is git-ignored |
| The Tollgate web UI | **No** | The UI never asks for it and has nowhere to store it. (The old token box in 0.3 was Tollgate's own admin token, not an abuse.ch key. Accounts replace it.) |
| Chat messages, tickets, screenshots, GitHub issues, commits | **No** | Anything pasted there should be treated as exposed |
| `feeds.json` | **No** | That file only names the environment variable; the key itself stays in `.env` |

If a key is ever exposed: revoke it in your abuse.ch account and create a new one; put the new one in `.env`; restart the updater.
The key is sent to abuse.ch over HTTPS only (feeds must be `https://`); it never reaches the browser or the scanning containers.

## Setting it up (Docker)
```bash
cp config/feeds.example.json config/feeds.json        # review it; remove feeds you do not want
# put ABUSECH_AUTH_KEY=... in .env
docker compose run --rm updater intel fetch           # one test run: prints a line per feed (counts, or a clear error)
docker compose --profile updates up -d updater        # then run it every 6 hours in the background
docker compose logs -f updater
```
Without Docker: `ABUSECH_AUTH_KEY=... tollgate intel fetch` (once) or `tollgate intel fetch --every 21600` (repeat; minimum 300 s). The config is read from `$TOLLGATE_HOME/feeds.json`
or `--config`.

## The example feeds
`config/feeds.example.json` ships three abuse.ch feeds: **URLhaus** (recent malware-distribution URLs, severity `high`), **MalwareBazaar** (recent sample hashes with family names,
severity `critical`) and **ThreatFox** (recent IOCs, domains/URLs/IPs/hashes, filtered to confidence 75+, severity `high`). Endpoints and formats follow abuse.ch's public API documentation as of writing;
**verify them** at https://abuse.ch, run one fetch, and read the result lines before scheduling. Respect each provider's terms and rate limits.

Severity decides impact: `critical` matches are **decisive** (the verdict becomes Malicious on their own); `high` and lower add to the score. Community feeds contain mistakes and compromised-but-legitimate sites:
that is why URL feeds default to `high`, and why you should use `intel remove` for false positives.

## Troubleshooting messages
- `environment variable ABUSECH_AUTH_KEY is not set` : the key is missing from `.env`, or the container was not restarted after adding it.
- `HTTP 401 (the API key is missing or wrong)` / `feed reported: unknown_auth_key` : wrong or revoked key.
- `feed did not return JSON` : wrong URL or the provider returned an HTML error page.
- `only https:// feeds are allowed` : a feed URL uses plain http; Tollgate refuses that.
- A feed that errors never stops the others.

## Your own feeds
Add entries to `feeds.json`. Formats: `lines` (a text list or CSV: `type`, optional `column`), `json` (`json_path`, `json_field`, optional `family_field`) and `threatfox`. Options: `method`
(POST when a `body` is given), `body_format` (`form` or `json`), `headers` (non-secret), `headers_from_env` (header name to environment variable), `severity`, `family`, `source`.
No network at the scanner? Fetch elsewhere, then `tollgate intel export` / `intel load` (see INSTALL.md).
