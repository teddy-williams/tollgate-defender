# Accounts, roles and the master account

Tollgate has built-in accounts. Nothing except the sign-in page, a health check and the "is setup needed?" check works without one.

## Roles
| Role | Can do |
|---|---|
| **viewer** | read history, reports, intel, rules; watch sandbox progress |
| **analyst** | everything a viewer can, plus scan files, check URLs, trace redirects, send a file to the sandbox |
| **admin** | everything an analyst can, plus add/remove intel, rules and YARA, add indicators from sandbox results, manage viewers and analysts, read the audit log |
| **master** | the owner: an admin who can **never** be demoted, disabled or deleted, and the **only** one who can create or change other admins. There is exactly one. |

Nobody can change their own role or delete themselves. Admins cannot touch other admins or the master.

## Creating your master account
Pick one way. The CLI way keeps the password out of files.
```bash
docker compose run --rm cli user create-master YOUR-USERNAME     # Docker (asks for the password twice)
tollgate user create-master YOUR-USERNAME                        # pip install
```
Until a master exists, the sign-in page tells you this command. Account creation is **never** possible from the web page, so nobody
who reaches the site first can take it over.

Alternative for Docker convenience: set `TOLLGATE_MASTER_USERNAME` and `TOLLGATE_MASTER_PASSWORD` in `.env` before the first start. The master
is created once and **must change the password at first sign-in**; then delete the password from `.env`.

## Passwords, lockout, sessions
- Minimum 12 characters (a passphrase works well), maximum 256, no username inside, no very common passwords. Stored as salted **scrypt** (N=2^15).
- 5 wrong passwords lock an account for 15 minutes (and 20 attempts per address per 10 minutes are throttled). Unlock sooner with
  `tollgate user unlock NAME`, or an admin's **Unlock** button. Error messages are the same for unknown users and wrong passwords.
- Sessions are server-side, 12 hours maximum and 4 hours idle, in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` over HTTPS). Every write request also needs a
  per-session CSRF token. Changing or resetting a password, disabling or demoting a user signs them out everywhere.
- Accounts created by an admin (or `user create`) default to **must change password at first sign-in**.

## API tokens
Account menu → **Account & API tokens**. A token (`tg_...`) acts with your role, can expire, and can be revoked. It is shown once and stored hashed.
Use it in scripts and mail gateways: `curl -H "Authorization: Bearer tg_..." ...`. Tokens do not need CSRF tokens.

## Audit log
Admins see the last events in **Users & audit**: sign-ins (including failures and lockouts), account and role changes, password resets, token creation,
intel and rule changes, sandbox submissions, URL traces. Scans are recorded in history with who ran them.

## Command-line management
The CLI works directly on the database (whoever can run it already controls the server):
```
tollgate user create-master NAME      tollgate user create NAME --role analyst|viewer|admin
tollgate user list                    tollgate user set-password NAME [--force-change]
tollgate user disable|enable|unlock|delete NAME
tollgate user token NAME --label ci [--days 90]
```
Use `--password-env VAR` to read a password from an environment variable instead of prompting.

## Lost the master password?
Anyone who can run the CLI on the server can reset it: `docker compose run --rm cli user set-password YOUR-USERNAME`. This is why access to the
host and the `data/` folder must be limited to the people you trust as owners. Back up `data/`.

## Upgrading from 0.3.x
The database upgrades itself on first start (history, intel and rules are kept). The old single admin token (`TOLLGATE_API_TOKEN`) no longer exists:
create your master account with the command above and use roles and API tokens instead.
