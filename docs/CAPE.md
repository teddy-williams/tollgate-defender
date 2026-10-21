# Dynamic analysis with CAPE Sandbox

Static analysis reads a file; a **sandbox** runs it in an isolated Windows VM and records what it does (processes, network, dropped files, injected
code, configuration of known malware families). Tollgate connects to a [CAPEv2](https://github.com/kevoreilly/CAPEv2) server **that you run and control**,
sends a file when an analyst explicitly asks, and folds the behaviour into the same verdict and report.

## What Tollgate does and does not do
- It is a **client** of CAPE's REST API. It does not install or run CAPE, and Tollgate never executes samples itself.
- A file is sent **only** when an analyst ticks *Also detonate in the sandbox* (UI), uses `--detonate` (CLI) or `detonate=true` (API). Never automatically.
  It is recorded in the audit log with the file's hash.
- Where the sample's network traffic goes (nowhere, a fake internet, or the real one) is decided **inside CAPE**, not by Tollgate. Configure that deliberately.
- Results are merged into the stored scan: the verdict and score are re-computed with the sandbox findings. A sandbox-named family or a match against your
  threat intel (traffic to a known-bad domain, a dropped file with a known hash) is decisive.

## Setting up CAPE
CAPE needs its own host (Linux with KVM) and Windows guest VMs. Follow the official docs at https://capev2.readthedocs.io for installation and for enabling the REST API
and token authentication (`api.conf`). Keep it on an isolated network segment; allow only Tollgate's API container to reach CAPE's API port, and keep the guest VMs
away from your real network. **Treat detonating real malware as a hazardous activity**: use the network routing options in CAPE that suit your risk (for example no
route, or a simulated internet) and never route live malware traffic through a network you care about.

## Connecting Tollgate
Set these for the `api` service (in `.env` for Docker; environment variables for `tollgate serve`):

| Variable | Meaning | Default |
|---|---|---|
| `TOLLGATE_CAPE_URL` | base URL of CAPE, e.g. `https://cape.internal:8000` (http or https) | empty = dynamic analysis off |
| `TOLLGATE_CAPE_TOKEN` | CAPE API token (sent as `Authorization: Token ...`) | empty |
| `TOLLGATE_CAPE_TOKEN_KEYWORD` | header keyword if your CAPE uses another (`Bearer`) | `Token` |
| `TOLLGATE_CAPE_TIMEOUT` | analysis time in seconds | `120` |
| `TOLLGATE_CAPE_OPTIONS` | raw CAPE `options=` string (for example `route=inetsim`) | empty |
| `TOLLGATE_CAPE_PACKAGE` / `_MACHINE` / `_PLATFORM` | CAPE analysis package / VM / platform | CAPE's defaults |
| `TOLLGATE_CAPE_VERIFY_TLS` | `0` disables certificate checks (lab use only) | `1` |
| `TOLLGATE_CAPE_CA` | path to a CA bundle for a private CA | system CAs |

## Using it
- **UI:** Scan tab → tick *Also detonate in the sandbox* → the static result appears at once; a progress line follows; when CAPE finishes, the verdict updates and a **Sandbox run**
  section shows score, family, behaviours, processes and indicators. Admins can tick indicators and **Add selected to threat intel**.
  The sandbox also sees harmless traffic, so review before adding.
- **CLI:** `tollgate scan FILE --detonate --wait 600` (needs the scan to be recorded); `tollgate dynamic list|show ID|refresh ID`.
- **API:** `POST /api/scan` with `detonate=true`; poll `GET /api/dynamic/{task_id}`; `POST /api/dynamic/{task_id}/iocs` to add indicators (admin).

Polling is lazy: results are fetched when someone looks (the UI polls while open). Tasks that never finish are marked failed after 2 hours.

## Try it without CAPE: the FAKE server
`python -m tollgate.fake_cape --port 8090 --token demo-token` (or `docker compose --profile demo up -d fake-cape`) serves **canned** CAPE-shaped data and executes nothing. Point
`TOLLGATE_CAPE_URL=http://fake-cape:8090` and `TOLLGATE_CAPE_TOKEN=demo-token` at it. A file whose name contains `malware` gets a "bad" report; others a benign one.
Use it to learn the workflow. Never use it as an actual verdict.

## Honest limits
- The client and report reader are written to CAPE's documented REST API and tested against a fake that mimics it, **not against a live CAPE**. CAPE versions differ; the
  summarizer treats every field as optional so a different shape gives less detail instead of an error. Report problems with the CAPE version you use.
- Files are limited by Tollgate's upload limit and by CAPE's own limit.
- Sandboxes can be evaded by malware that detects them; a quiet run is not proof of safety.
