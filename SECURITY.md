# Security policy

## Reporting a vulnerability in Tollgate
Please **do not open a public issue** for security problems. Use GitHub's private reporting:
**Security tab → "Report a vulnerability"** on this repository, or email williamsmavuso@gmail.com.
Include what you found, how to reproduce it (a synthetic file or request is ideal; never send live malware), and the impact.
You will get an acknowledgement within a few days; please allow reasonable time for a fix before public disclosure.

## In scope
Vulnerabilities in Tollgate itself, for example: crashes, hangs or memory blow-ups triggered by a crafted file or URL
(parser denial of service); authentication, session or CSRF bypass; privilege escalation between roles (viewer, analyst, admin, master); weaknesses in password storage, lockout or API tokens; leaking of secrets (abuse.ch key, CAPE token) to clients or logs; SSRF or filter bypass in the redirect
tracer (reaching non-public addresses); stored or reflected XSS in the UI; path traversal or code execution through rule or
file upload; the CAPE client sending data anywhere other than the configured server; secrets exposure; container escape caused by our configuration.

## Out of scope
Detection quality (missed malware, false positives): please use the false-positive issue template. Findings that need
an already-compromised host, or that assume the web UI was deliberately exposed to the internet without authentication
against the guidance in `docs/DEPLOYMENT.md`.

## Know the risks of running it
Tollgate parses hostile input. It never executes samples, but parsers can have bugs. Run it in the provided container
(non-root, read-only, no capabilities, no network for scanning) or a VM, keep it updated, and do not expose it unauthenticated.
Redirect tracing contacts attacker-controlled servers; use a disposable host or VPN. It is a triage aid, not a sandbox or an antivirus.

## Supported versions
Security fixes are made on the latest release only while the project is in beta.
