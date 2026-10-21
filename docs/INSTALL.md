# Installing Tollgate

Pick the path that matches your situation.

| I want... | Use |
|---|---|
| A web UI for me or my team | [A. Docker Compose](#a-web-app-with-docker-compose) |
| A command-line tool on my laptop/analysis VM | [B. pip / pipx](#b-command-line-with-pip-or-pipx) |
| To install on a machine with **no internet** (Python) | [C. Offline wheelhouse](#c-offline-install-wheelhouse) |
| To run on an **air-gapped** host with Docker | [D. Offline Docker image](#d-offline-docker-image) |

Requirements: Python **3.10+** (options B/C) or Docker with Compose v2 (A/D). Tested on Linux; Windows and macOS work with
Docker or pip but are less tested.

---
## A. Web app with Docker Compose
```bash
git clone https://github.com/teddy-williams/tollgate-defender.git
cd tollgate-defender
cp .env.example .env
```
Edit `.env` and set `TOLLGATE_TRACER_TOKEN` to a long random value (`openssl rand -hex 32`; PowerShell:
`-join ((1..32) | % { '{0:x2}' -f (Get-Random -Max 256) })`). Everything else in `.env` is optional.
```bash
mkdir -p data samples
sudo chown 10001 data           # Linux only: the container runs as uid 10001
docker compose up -d --build api tracer
docker compose ps               # both services should be "running"
docker compose run --rm cli user create-master YOUR-USERNAME     # creates your owner account (asks for a password)
```
Open **http://127.0.0.1:8080** and sign in. It binds to localhost only on purpose; see [DEPLOYMENT.md](DEPLOYMENT.md) before exposing it.
Accounts, roles and the master account are explained in [ACCOUNTS.md](ACCOUNTS.md).

Optional extras: threat feeds with your abuse.ch key ([FEEDS.md](FEEDS.md)) and a sandbox ([CAPE.md](CAPE.md)).

Using a prebuilt release image instead of building: set `TOLLGATE_IMAGE=ghcr.io/teddy-williams/tollgate-defender:<version>`
in `.env`, then `docker compose up -d --no-build api tracer`.

Offline CLI through the same image (no network at all): `docker compose run --rm cli scan /samples/file.bin`.

Stop: `docker compose down` (your data stays in `./data`). Update: `git pull && docker compose up -d --build api tracer`.

---
## B. Command line with pip or pipx
```bash
pipx install "tollgate-defender[all]"      # recommended: isolated install
# or
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install "tollgate-defender[all]"
```
Straight from GitHub (before/without PyPI):
`pipx install "tollgate-defender[all] @ git+https://github.com/teddy-williams/tollgate-defender.git"`

Extras: `[yara]` adds YARA, `[web]` adds the web UI, `[all]` adds both. The core install (just `pefile`) still does triage,
PE analysis, URL checks, intel and history.
```bash
tollgate scan suspicious.exe
tollgate serve                  # web UI on http://127.0.0.1:8080
```
Data lives in `~/.tollgate` (Windows: `C:\Users\<you>\.tollgate`): database in `tollgate.db`, your YARA rules in `rules/`.
Override with `TOLLGATE_HOME`.

Create your owner account once, then start the web UI and sign in:
```bash
tollgate user create-master YOUR-USERNAME        # asks for a password
tollgate serve
```
Enable redirect tracing for personal use: `TOLLGATE_ALLOW_LOCAL_TRACE=1 tollgate serve` (it will contact URLs you trace;
for shared use run the separate tracer, see [DEPLOYMENT.md](DEPLOYMENT.md)).

---
## C. Offline install (wheelhouse)
On a machine **with** internet, download Tollgate and all dependencies:
```bash
# same OS and Python version as the target:
pip download "tollgate-defender[all]" -d wheelhouse

# different target, e.g. Windows x64 + Python 3.12 (binary wheels only):
pip download "tollgate-defender[all]" -d wheelhouse --platform win_amd64 --python-version 3.12 --only-binary=:all: --implementation cp
# Linux x86_64:  --platform manylinux2014_x86_64      macOS Apple Silicon:  --platform macosx_11_0_arm64
```
Or from a repository checkout, one command: `scripts/make-offline-bundle.sh --platform win_amd64 --python 3.12` produces
`tollgate-offline-<version>-<platform>.tar.gz`. Release pages also publish ready-made wheelhouses for Linux and Windows (Python 3.12).

Copy the folder to the offline machine, then:
```bash
python -m venv .venv && . .venv/bin/activate
pip install --no-index --find-links wheelhouse "tollgate-defender[all]"
tollgate yara list
```

---
## D. Offline Docker image
On a connected machine:
```bash
docker pull ghcr.io/teddy-williams/tollgate-defender:<version>     # or build it: docker build -t tollgate:<version> .
docker save ghcr.io/teddy-williams/tollgate-defender:<version> | gzip > tollgate-image.tar.gz
```
(Releases also attach `tollgate-image-v<version>.tar.gz`.) On the air-gapped host:
```bash
gunzip -c tollgate-image.tar.gz | docker load
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp -v "$PWD/data:/data" -v "$PWD/samples:/samples:ro" \
  ghcr.io/teddy-williams/tollgate-defender:<version> scan /samples/suspect.bin
```
For the web UI offline, copy `docker-compose.yml` and `.env`, set `TOLLGATE_IMAGE`, and run `docker compose up -d --no-build api`
(skip `tracer`; tracing needs the internet).

---
## What works offline
| Feature | Offline? |
|---|---|
| File scans, PE analysis, YARA, history, retro-hunt, web UI | Yes |
| URL checks (heuristics + threat-intel lookup) | Yes |
| Redirect tracing | **No** (contacts the URL) |
| Sandbox (CAPE) | Only if your CAPE server is reachable from Tollgate |
| Feed download (`intel fetch`) | **No** (network) |

## Keeping an offline install current
On a connected machine collect intel (`tollgate intel fetch`, see [FEEDS.md](FEEDS.md), or `tollgate intel import` of feed files), then:
```bash
tollgate intel export --out intel-2026-10-16.csv          # connected machine
tollgate intel load intel-2026-10-16.csv                  # offline machine (after moving the file)
tollgate retro                                            # what in my history is now known-bad?
```
Move new YARA rules the same way: copy `.yar` files into `~/.tollgate/rules/` (or `/data/rules` in Docker), or `tollgate yara add rule.yar`.
Feed list format: copy `config/feeds.example.json` to `feeds.json` (default location `$TOLLGATE_HOME/feeds.json`), use real feed URLs,
and check each feed's terms and any API key requirement first.

## Upgrading
Back up your data first (`~/.tollgate` or `./data`). pip: `pip install -U "tollgate-defender[all]"`. Docker: rebuild or pull the
new image and restart. There are no database migrations yet: the schema is created automatically, and the [changelog](../CHANGELOG.md) will call out
any schema change.

## Troubleshooting
- **`tollgate: command not found` after pipx:** run `pipx ensurepath` and open a new terminal.
- **`the web UI needs extra packages`:** install with `[web]` or `[all]`.
- **YARA shows 0 rules / `yara-python is not installed`:** install `[yara]`. On unusual platforms it may need a C toolchain.
- **Docker: `set TOLLGATE_TRACER_TOKEN in .env`:** `.env` is missing or the token is empty.
- **"No accounts exist yet" on the sign-in page:** run the `create-master` command above.
- **Locked out / forgot the master password:** `docker compose run --rm cli user set-password YOUR-USERNAME` (see [ACCOUNTS.md](ACCOUNTS.md)).
- **Docker, Linux: database permission errors:** `sudo chown 10001 data`.
- **Port 8080 busy:** change `127.0.0.1:8080:8080` in `docker-compose.yml`, or `tollgate serve --port 8081`.
- **Antivirus quarantines the project folder:** the rule files contain suspicious-looking strings by design. Exclude only the Tollgate folder, never your samples.
