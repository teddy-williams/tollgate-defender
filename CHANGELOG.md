# Changelog

All notable changes are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/);
versions follow [Semantic Versioning](https://semver.org/) (while below 1.0, minor versions may change behaviour).

## [Unreleased]

## [0.4.0] - 2026-10-17
### Added
- **User accounts:** viewer / analyst / admin roles and a protected **master** (owner) account; scrypt password hashing and policy, lockout and login throttling, server-side sessions with CSRF protection, API tokens, audit log, users admin screen, password-change flow. CLI: `tollgate user ...`.
- **LNK structural analyzer** (MS-SHLLINK): target, arguments, padding/newline hiding, encoded PowerShell decoding, decoy icons, remote/WebDAV paths, appended payloads, creation machine/MAC.
- **PDF structural analyzer:** objects, streams, filters, object streams, auto-run JavaScript and indicators, `/Launch`, remote GoTo, links, embedded-file extraction, appended data, obfuscated names, decompression-bomb limits.
- **Artifact scanning:** decoded commands, embedded files and appended data are examined like top-level files (intel, YARA, PE/LNK/PDF analysis).
- **Dynamic analysis with CAPE:** explicit per-scan detonation, task tracking, report summarizer, findings merged into the verdict, add sandbox indicators to intel; a FAKE CAPE server for demos and tests.
- **abuse.ch-style feeds:** JSON and POST feeds, ThreatFox mapping, clear key diagnostics, scheduled `intel fetch --every`, an `updater` service holding the key.
- UI: sign-in, role-aware tabs, account menu, user and audit screens, sandbox progress panel, LNK/PDF/artifact sections.
### Changed
- The single admin token (`TOLLGATE_API_TOKEN`) is **removed**: use accounts and API tokens. Create your master account with `tollgate user create-master`.
- Database schema v2: upgrades automatically on first start; history, intel and rules are kept; scans now record who ran them.
- The PDF/LNK YARA starter rules are now medium severity (the structural parsers are authoritative; the rules are a backstop).
- Python `safe()` text helper no longer adds "..." to text that was not truncated.
### Upgrade notes
Back up `data/` first. Start the new version, run `docker compose run --rm cli user create-master YOUR-USERNAME`, sign in. Remove `TOLLGATE_API_TOKEN` from `.env`.

## [0.3.0] - 2026-10-16
First public release.
### Added
- File triage: real type from content, double extensions (including hidden `.lnk`/`.pif`/`.scf`/`.url`), RTLO/bidi/invisible characters, extension/content mismatch, hashes.
- PE static analysis: entropy, RWX and packer sections, entry-point anomalies, import clusters, resources, overlays, suspicious strings, imphash.
- YARA engine with starter rules (PDF, LNK, embedded/base64 PE, script cradles); per-file rule isolation; validated rule upload.
- Threat-intel database (sha256/md5/sha1/imphash/domain/url/ip), list/CSV import, feed fetch, export/load for offline transfer, regex string rules.
- Scan history, URL tracking, and retro-hunt of past scans against current intel.
- URL analysis: defang/refang, heuristics, intel lookup; SSRF-guarded redirect tracing in an isolated tracer service.
- Web UI and REST API (FastAPI), CLI (`tollgate`), Docker Compose deployment, pip packaging with optional extras.
- Offline install options (wheelhouse, Docker image tarball) and GitHub release automation.
### Known limitations
- Score weights are not yet calibrated; LNK/PDF have YARA/triage coverage but no structural parsers; Authenticode not verified; no dynamic analysis.
