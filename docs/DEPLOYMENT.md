# Deploying Tollgate for a team

Tollgate is built to be **self-hosted**. It parses hostile files, stores scan history and holds accounts, so treat it like any internal security service.

## Do not run an open, public upload site
Even with accounts, an internet-facing instance invites password guessing, abuse as a free scanner, malware storage and denial of service, and (via redirect tracing and the sandbox) outbound
requests. If you want a public demo, run it with fake data and no tracing or sandbox. For real use keep it inside your network or behind your VPN/identity-aware proxy.

## What is built in
- **Accounts and roles** (viewer, analyst, admin, master): sign-in with scrypt-hashed passwords, lockout, server-side sessions, CSRF protection, API tokens, an audit log. See [ACCOUNTS.md](ACCOUNTS.md).
- `api` publishes **127.0.0.1:8080** only. Everything except the sign-in page needs a login or an API token.
- Containers run as a non-root user, read-only root filesystem, all capabilities dropped, memory/PID limits, `no-new-privileges`.
- `tracer` is the only component that follows redirects: no database, no samples, SSRF-guarded (public addresses only, validated IP pinning, TLS verified, limited ports/hops/time).
- `cli` runs with `network_mode: none`. `updater` has network access but mounts no samples and is the only holder of your abuse.ch key.
- The sandbox (CAPE) is **your** server; Tollgate only calls its API when an analyst asks. See [CAPE.md](CAPE.md).

## Add HTTPS in front (recommended)
Terminate TLS at a reverse proxy and publish only the proxy, so passwords and session cookies never cross the network in clear text. Minimal Caddy example (adapt, then test):
```
tollgate.example.org {
    request_body {
        max_size 55MB
    }
    reverse_proxy api:8080
}
```
Run Caddy as another service on the same compose network and remove the `ports:` entry from `api`. Then set in `.env`:
```
TOLLGATE_COOKIE_SECURE=1      # cookies are only sent over HTTPS
TOLLGATE_TRUST_PROXY=1        # use the proxy's X-Forwarded-For for the audit log and login throttle (ONLY if the proxy is yours)
```
You may add proxy-level authentication (SSO, oauth2-proxy, basic auth) as an extra layer; Tollgate's own login still applies.

## Hardening checklist
- [ ] TLS in front of the UI; nothing published on `0.0.0.0` without it; `TOLLGATE_COOKIE_SECURE=1`
- [ ] Your master account created with the CLI (no password left in `.env`); strong unique passwords for everyone; analysts get the least role they need
- [ ] `TOLLGATE_TRACER_TOKEN` is long and random; `.env` is never committed
- [ ] abuse.ch key only in `.env`; rotate it if it ever leaks ([FEEDS.md](FEEDS.md))
- [ ] Run **one** API worker (YARA reload and the login throttle are per process); size memory for your upload limit (default 50 MB)
- [ ] Reverse proxy upload limit matches `TOLLGATE_MAX_UPLOAD_MB`
- [ ] Tracer host: block private/internal ranges at the network layer too (defense in depth), egress via a disposable VPN/proxy
- [ ] CAPE: its API reachable only from the `api` container; guest VMs isolated from real networks; routing chosen deliberately ([CAPE.md](CAPE.md))
- [ ] Host firewall: the `api` container has no outbound code path except the tracer and your CAPE URL, but publishing a port needs network access; restrict egress if you can
- [ ] Back up `./data` (database with accounts, history and intel, plus your rules) on a schedule; it holds hashes, metadata and reports, never samples
- [ ] Review the audit log and who has admin; remove accounts when people leave
- [ ] Keep it updated (Dependabot PRs, new releases); subscribe to the repository's security advisories
- [ ] Analysts know "Clean" is not proof of safety, and that real malware belongs in an isolated VM

## Operating
- Logs: `docker compose logs -f api tracer updater`. Health: `GET /api/health` (open) and the status strip in the UI (signed in).
- Scheduled feed updates: `docker compose --profile updates up -d updater` (needs `config/feeds.json` and your key; see [FEEDS.md](FEEDS.md)).
- Rules without restart: add through the UI/API (`/api/rules/yara`) or `tollgate yara add`; the API reloads on upload. Files dropped straight into `data/rules/` are picked up on the next API restart.
- Upgrading: back up `./data`, `git pull`, `docker compose up -d --build api tracer`. The database upgrades itself on start (see the changelog).
- Scaling: SQLite and a single worker suit a small team. Heavier use is a future PostgreSQL/worker-queue step.
