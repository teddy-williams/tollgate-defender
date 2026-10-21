"""URL handling: defang/refang, normalization, offline heuristics, threat-intel lookup.

Nothing here makes a network request. URLs are only ever treated as text.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .models import Finding, Severity as S
from .scoring import compute_score, compute_verdict

NON_NET_SCHEMES = ("javascript:", "data:", "vbscript:", "mailto:", "file:")

_REFANG = [
    (re.compile(r"\[\s*://\s*\]|\(\s*://\s*\)"), "://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*@\s*\]|\[\s*at\s*\]", re.I), "@"),
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
]
_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>]+")

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "mov",
                   "icu", "cyou", "rest", "buzz", "loan", "work"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"}
DYNAMIC_DNS = {"duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org", "serveo.net",
               "ngrok.io", "ngrok-free.app", "trycloudflare.com"}
LURE_WORDS = {"login", "signin", "verify", "secure", "account", "update", "password",
              "wallet", "bank", "confirm", "invoice"}
_PAYLOAD_EXT = re.compile(r"\.(exe|scr|js|jse|vbs|vbe|ps1|hta|jar|msi|iso|img|lnk|bat|cmd|dll|cpl|wsf)$", re.I)


# --- defang / refang -------------------------------------------------------

def refang(text: str) -> str:
    out = text.strip()
    for pattern, repl in _REFANG:
        out = pattern.sub(repl, out)
    return out


def defang(url: str) -> str:
    """hxxps://evil[.]com/path - safe to paste into chat, tickets and reports."""
    t = url.strip()
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$", t, re.S)
    scheme, rest = (m.group(1), m.group(2)) if m else (None, t)
    authority, tail = re.match(r"^([^/?#]*)(.*)$", rest, re.S).groups()
    authority = authority.replace("[.]", ".").replace("[@]", "@").replace(".", "[.]").replace("@", "[@]")
    if scheme:
        scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme.lower(), scheme)
        return f"{scheme}://{authority}{tail}"
    return authority + tail


def defang_text(text: str) -> str:
    """Defang every URL found inside free text (used for all report output)."""
    return _URL_IN_TEXT.sub(lambda m: defang(m.group(0)), text)


# --- normalization -----------------------------------------------------------

def _prepare(raw: str) -> str | None:
    t = refang(raw).strip()
    if not t:
        return None
    if t.lower().startswith(NON_NET_SCHEMES):
        return t
    return t if "://" in t else "http://" + t


def normalize_url(raw: str) -> str | None:
    """Canonical form used for storage and threat-intel matching."""
    t = _prepare(raw)
    if t is None:
        return None
    if t.lower().startswith(NON_NET_SCHEMES):
        return t[:2048]
    try:
        p = urlsplit(t)
        host, port = p.hostname, p.port
    except ValueError:
        return None
    if not host:
        return None
    scheme = p.scheme.lower()
    try:
        ahost = host.encode("idna").decode("ascii")
    except UnicodeError:
        ahost = host
    if ":" in ahost:
        ahost = f"[{ahost}]"
    default = {"http": 80, "https": 443}.get(scheme)
    hostport = ahost if port in (None, default) else f"{ahost}:{port}"
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{hostport}{p.path or '/'}{query}"


# --- analysis ----------------------------------------------------------------

@dataclass
class UrlReport:
    original: str
    normalized: str | None
    defanged: str
    host: str | None
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "Clean"
    intel: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original": self.original, "normalized": self.normalized, "defanged": self.defanged,
            "host": self.host, "verdict": self.verdict, "score": self.score,
            "findings": [f.to_dict() for f in self.findings], "intel": self.intel,
        }


def _host_in(host: str, domains: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _script_check(host: str) -> Finding | None:
    try:
        uhost = host.encode("ascii").decode("idna")
    except UnicodeError:
        uhost = host
    if all(ord(c) < 128 for c in uhost):
        return None
    scripts = set()
    for ch in uhost:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch, "UNKNOWN").split()[0])
    shown = uhost.encode("unicode_escape").decode("ascii")
    if len(scripts) > 1:
        return Finding("URL_HOMOGRAPH", "Host mixes writing scripts (homograph attack)", S.HIGH,
                       f"Scripts: {', '.join(sorted(scripts))}. Host: {shown}", "url")
    return Finding("URL_IDN", "Internationalized (non-ASCII) host name", S.MEDIUM,
                   f"Host: {shown}. Check it is not imitating a known brand.", "url")


def analyze_url(raw: str, store=None) -> UrlReport:
    """Offline heuristics plus (optionally) a threat-intel lookup through `store`."""
    prepared = _prepare(raw)
    norm = normalize_url(raw)
    if norm is None or prepared is None:
        f = [Finding("URL_INVALID", "Could not parse URL", S.LOW, "", "url")]
        return UrlReport(raw, None, defang(raw), None, f, compute_score(f), "Clean")

    findings: list[Finding] = []
    low = prepared.lower()
    if low.startswith(NON_NET_SCHEMES):
        scheme = low.split(":", 1)[0]
        sev = S.HIGH if scheme in ("javascript", "data", "vbscript") else S.LOW
        findings.append(Finding("URL_SCHEME", f"Non-web URL scheme '{scheme}:'", sev,
                                "Script/data URLs execute or embed content instead of navigating.", "url"))
        score = compute_score(findings)
        return UrlReport(raw, norm, defang(norm), None, findings, score, compute_verdict(score, findings))

    p = urlsplit(prepared)
    host = p.hostname or ""
    path = p.path or "/"
    port = p.port

    if p.scheme.lower() == "ftp":
        findings.append(Finding("URL_FTP", "FTP URL", S.LOW, "Unencrypted file transfer.", "url"))
    if p.username is not None:
        findings.append(Finding(
            "URL_USERINFO", "URL contains credentials/userinfo before the host", S.HIGH,
            "'http://trusted.com@evil.com' really goes to evil.com. Classic phishing trick.", "url"))

    try:
        ipaddress.ip_address(host)
        findings.append(Finding("URL_RAW_IP", "Host is a raw IP address", S.MEDIUM,
                                "Legitimate services rarely link by bare IP.", "url"))
    except ValueError:
        try:
            socket.inet_aton(host)
            findings.append(Finding("URL_OBFUSCATED_IP", "Host is an obfuscated numeric IP", S.HIGH,
                                    f"'{host}' is decimal/hex/octal notation for an IPv4 address.", "url"))
        except OSError:
            pass

    f = _script_check(host)
    if f:
        findings.append(f)
    if "xn--" in host and not f:
        findings.append(Finding("URL_PUNYCODE", "Punycode (xn--) host", S.MEDIUM, f"Host: {host}", "url"))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding("URL_TLD", f"Frequently abused TLD (.{tld})", S.LOW, "", "url"))
    if _host_in(host, SHORTENERS):
        findings.append(Finding("URL_SHORTENER", "URL shortener hides the real destination", S.LOW,
                                "Live redirect resolution is not performed (offline analysis).", "url"))
    if _host_in(host, DYNAMIC_DNS):
        findings.append(Finding("URL_DYNDNS", "Dynamic DNS / tunnelling service", S.LOW,
                                "Common for C2 and short-lived phishing infrastructure.", "url"))
    if host.count(".") >= 4:
        findings.append(Finding("URL_SUBDOMAINS", "Unusually deep subdomain nesting", S.LOW, host, "url"))
    if host.count("-") >= 4:
        findings.append(Finding("URL_HYPHENS", "Many hyphens in host name", S.LOW, host, "url"))
    if port not in (None, 80, 443):
        findings.append(Finding("URL_PORT", f"Non-standard port {port}", S.LOW, "", "url"))
    if len(prepared) > 200:
        findings.append(Finding("URL_LONG", "Very long URL", S.LOW, f"{len(prepared)} characters", "url"))
    if _PAYLOAD_EXT.search(path):
        findings.append(Finding("URL_PAYLOAD_EXT", "URL points directly at an executable/script/disk image",
                                S.MEDIUM, f"Path: {path[:120]}", "url"))
    lures = {w for w in LURE_WORDS if w in host or w in path.lower()}
    if len(lures) >= 2:
        findings.append(Finding("URL_LURE_WORDS", "Credential-lure keywords in URL", S.LOW,
                                ", ".join(sorted(lures)), "url"))
    if _host_in(host, {"discord.com", "discordapp.com"}) and path.startswith("/api/webhooks/"):
        findings.append(Finding("URL_EXFIL_WEBHOOK", "Discord webhook (common exfiltration channel)", S.HIGH, "", "url"))
    if host == "api.telegram.org" and path.startswith("/bot"):
        findings.append(Finding("URL_EXFIL_TELEGRAM", "Telegram bot API (common C2/exfiltration channel)", S.HIGH, "", "url"))
    if _host_in(host, {"pastebin.com", "transfer.sh", "anonfiles.com"}):
        findings.append(Finding("URL_PASTE_HOST", "Anonymous paste/file hosting", S.MEDIUM, host, "url"))

    matches: list[dict] = []
    if store is not None:
        ascii_host = urlsplit(norm).hostname or ""
        matches = store.match_url(norm, ascii_host)
        for row in matches:
            findings.append(Finding(
                "INTEL_URL_MATCH", f"Threat-intel match ({row['ioc_type']})", S(row["severity"]),
                f"{defang_text(row['value'])} | family={row['family'] or 'unknown'} | source={row['source']}",
                "intel"))

    score = compute_score(findings)
    return UrlReport(raw, norm, defang(norm), host, findings, score,
                     compute_verdict(score, findings), matches)
