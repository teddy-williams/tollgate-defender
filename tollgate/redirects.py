"""Safe redirect-chain tracing.

This is the only module that talks to the internet about a suspect URL, so it is built defensively:
  * http/https only, on a short list of web ports
  * every hop is resolved first and refused if ANY address is non-public (loopback, RFC1918,
    link-local/cloud metadata, CGNAT, ...). Redirects into internal networks are reported, never followed.
  * the connection goes to the IP we validated (no second DNS lookup, so no DNS-rebinding window)
  * TLS certificates are always verified; failure ends the trace
  * GET with no cookies/credentials/referer; only headers (plus <=16 KB of HTML to spot meta-refresh) are read
  * hop, per-request and overall time limits
Tracing still contacts attacker-controlled servers: run it from a disposable host/VPN, and remember that
cloaking sites may show scanners something different from what victims see.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from .models import SEVERITY_ORDER, Finding, Severity as S
from .scoring import compute_score, compute_verdict
from .urlcheck import analyze_url, defang, normalize_url

ALLOWED_PORTS = {80, 443, 8080, 8443}
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_BODY = 16 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; Tollgate-URLTrace/0.3)"
DOWNLOAD_TYPES = ("application/x-msdownload", "application/x-msdos-program", "application/x-dosexec",
                  "application/vnd.microsoft.portable-executable", "application/x-iso9660-image",
                  "application/java-archive", "application/x-ms-shortcut", "application/hta",
                  "application/octet-stream", "application/zip", "application/x-zip-compressed")
_PAYLOAD_NAME = re.compile(r"\.(exe|scr|js|jse|vbs|vbe|ps1|hta|jar|msi|iso|img|lnk|bat|cmd|dll|cpl|wsf)\b", re.I)


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


def _printable(text: str | None, limit: int = 120) -> str | None:
    if text is None:
        return None
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]


@dataclass
class Hop:
    url: str
    status: int | None = None
    ip: str | None = None
    kind: str = "http"            # http | meta-refresh
    location: str | None = None
    content_type: str | None = None
    server: str | None = None
    download: bool = False
    filename: str | None = None
    note: str | None = None
    error: str | None = None
    blocked: str | None = None
    elapsed_ms: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["url_defanged"] = defang(self.url)
        return d


@dataclass
class TraceResult:
    start: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    completed: bool = False
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "Clean"

    def to_dict(self, raw: bool = False) -> dict:
        d = {"start": self.start, "start_defanged": defang(self.start), "hops": [h.to_dict() for h in self.hops],
             "final_url": self.final_url, "final_defanged": defang(self.final_url) if self.final_url else None,
             "completed": self.completed, "reason": self.reason}
        if not raw:
            d.update(verdict=self.verdict, score=self.score, findings=[f.to_dict() for f in self.findings])
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "TraceResult":
        fields = Hop.__dataclass_fields__
        hops = [Hop(**{k: v for k, v in h.items() if k in fields}) for h in d.get("hops", [])]
        return cls(d.get("start", ""), hops, d.get("final_url"), bool(d.get("completed")), d.get("reason", ""))


def _fetch_hop(url: str, timeout: float, resolver, allow_private: bool) -> Hop:
    hop = Hop(url=url)
    p = urlsplit(url)
    host, scheme = p.hostname or "", p.scheme
    port = p.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        hop.blocked = f"port {port} is not on the allowed list"
        return hop
    try:
        ips = resolver(host, port)
    except OSError as exc:
        hop.error = f"DNS lookup failed ({exc.__class__.__name__})"
        return hop
    if not ips:
        hop.error = "host did not resolve"
        return hop
    if not allow_private:
        bad = [ip for ip in ips if not is_public_ip(ip)]
        if bad:
            hop.blocked = f"resolves to non-public address {bad[0]}"
            return hop
    hop.ip = ips[0]
    started = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((hop.ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        conn.request("GET", target, headers={
            "Host": p.netloc, "User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5",
            "Accept-Encoding": "identity", "Connection": "close"})
        resp = conn.getresponse()
        hop.status = resp.status
        hop.server = _printable(resp.getheader("Server"), 80)
        ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
        hop.content_type = _printable(ctype, 80)
        disp = resp.getheader("Content-Disposition") or ""
        loc = resp.getheader("Location")
        if resp.status in REDIRECT_CODES and loc:
            hop.location = loc.strip()[:2048]
        elif resp.status < 400:
            if "attachment" in disp.lower() or ctype in DOWNLOAD_TYPES:
                hop.download = True
                m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", disp, re.I)
                hop.filename = _printable(m.group(1) if m else None, 100)
            elif ctype in ("text/html", "application/xhtml+xml"):
                body = resp.read(MAX_BODY).decode("utf-8", "ignore")
                for tag in re.findall(r"<meta\b[^>]*>", body, re.I):
                    if re.search(r"http-equiv\s*=\s*[\"']?refresh", tag, re.I):
                        m = re.search(r"url\s*=\s*[\"']?([^\"'>\s;]+)", tag, re.I)
                        if m:
                            hop.location, hop.kind = m.group(1)[:2048], "meta-refresh"
                            break
                if not hop.location and re.search(r"(window|document|top)\.location|location\.(href|replace)\s*[=(]", body):
                    hop.note = "page contains a JavaScript redirect (not followed)"
    except ssl.SSLCertVerificationError as exc:
        hop.error = f"TLS certificate verification failed: {_printable(getattr(exc, 'verify_message', None) or 'invalid', 80)}"
    except ssl.SSLError as exc:
        hop.error = f"TLS error ({exc.__class__.__name__})"
    except (TimeoutError, socket.timeout):
        hop.error = "timed out"
    except (OSError, http.client.HTTPException) as exc:
        hop.error = f"connection failed ({exc.__class__.__name__})"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        hop.elapsed_ms = int((time.monotonic() - started) * 1000)
    return hop


def trace_raw(url: str, max_hops: int = 8, timeout: float = 6.0, deadline: float = 25.0,
              resolver=None, allow_private: bool = False) -> TraceResult:
    """Follow the chain and record it. No verdict yet (see `assess`)."""
    resolver = resolver or _default_resolver
    start = normalize_url(url)
    res = TraceResult(start=url)
    if not start or not start.startswith(("http://", "https://")):
        res.reason = "only http(s) URLs can be traced"
        return res
    res.start = start
    current, seen, t0 = start, set(), time.monotonic()
    for _ in range(max_hops + 1):
        if current in seen:
            res.reason = "redirect loop"
            break
        seen.add(current)
        if time.monotonic() - t0 > deadline:
            res.reason = "overall time limit reached"
            break
        hop = _fetch_hop(current, timeout, resolver, allow_private)
        res.hops.append(hop)
        res.final_url = current
        if hop.blocked:
            res.reason = f"stopped: {hop.blocked}"
            break
        if hop.error:
            res.reason = f"stopped: {hop.error}"
            break
        if not hop.location:
            res.reason, res.completed = "final destination reached", True
            break
        nxt = urljoin(current, hop.location)
        norm = normalize_url(nxt)
        if not norm or not norm.startswith(("http://", "https://")):
            scheme = nxt.split(":", 1)[0].lower()[:20]
            res.hops.append(Hop(url=_printable(nxt, 200) or "", blocked=f"redirect to non-web scheme '{scheme}:'"))
            res.reason = f"stopped: redirect to non-web scheme '{scheme}:'"
            break
        current = norm
    else:
        res.reason = f"hop limit ({max_hops}) reached"
    return res


def assess(res: TraceResult, store=None) -> TraceResult:
    """Turn a recorded chain into findings, using URL heuristics and threat intel on every hop."""
    f: list[Finding] = []
    redirects = [h for h in res.hops if h.location]
    hosts = {urlsplit(h.url).hostname for h in res.hops if h.url.startswith("http")}
    if len(redirects) >= 5:
        f.append(Finding("TRACE_LONG_CHAIN", f"Very long redirect chain ({len(redirects)} redirects)", S.MEDIUM,
                         "Long chains are used to launder reputation and dodge URL filters.", "trace"))
    elif len(redirects) >= 3:
        f.append(Finding("TRACE_CHAIN", f"Redirect chain with {len(redirects)} redirects", S.LOW, "", "trace"))
    if len(hosts) >= 3:
        f.append(Finding("TRACE_CROSS_HOST", f"Chain crosses {len(hosts)} different hosts", S.LOW,
                         ", ".join(defang(h) for h in sorted(h for h in hosts if h)[:6]), "trace"))
    if any(h.kind == "meta-refresh" for h in res.hops):
        f.append(Finding("TRACE_META_REFRESH", "HTML meta-refresh redirect", S.LOW,
                         "Common in phishing kits and cloaking pages.", "trace"))
    for h in res.hops:
        if h.note:
            f.append(Finding("TRACE_JS_REDIRECT", "JavaScript redirect present", S.LOW, f"{defang(h.url)}: {h.note}", "trace"))
        if h.blocked and "non-public" in h.blocked:
            f.append(Finding("TRACE_INTERNAL_TARGET", "Chain points at an internal/non-public address (not followed)",
                             S.HIGH, f"{defang(h.url)}: {h.blocked}", "trace"))
        elif h.blocked and "non-web scheme" in h.blocked:
            sev = S.HIGH if re.search(r"'(javascript|data|vbscript):'", h.blocked) else S.LOW
            f.append(Finding("TRACE_NONWEB_SCHEME", "Chain ends in a non-web URL", sev, h.blocked, "trace"))
        elif h.blocked:
            f.append(Finding("TRACE_BLOCKED", "Hop not followed", S.LOW, f"{defang(h.url)}: {h.blocked}", "trace"))
        if h.error and "TLS certificate" in h.error:
            f.append(Finding("TRACE_BAD_TLS", "Invalid TLS certificate on a hop", S.MEDIUM, f"{defang(h.url)}: {h.error}", "trace"))
        if h.download:
            risky = bool(_PAYLOAD_NAME.search(h.filename or "") or _PAYLOAD_NAME.search(urlsplit(h.url).path))
            f.append(Finding("TRACE_DOWNLOAD", "Destination delivers a file download", S.HIGH if risky else S.MEDIUM,
                             f"{defang(h.url)} ({h.content_type}{', ' + h.filename if h.filename else ''})", "trace"))
    if len(res.hops) >= 2 and res.hops[0].url.startswith("https://") and res.final_url and res.final_url.startswith("http://"):
        f.append(Finding("TRACE_DOWNGRADE", "Chain downgrades from HTTPS to HTTP", S.LOW, "", "trace"))

    known, odd = [], []
    for h in res.hops:
        if not h.url.startswith("http"):
            continue
        if store:
            store.track_url(h.url, None, "redirect")
        ur = analyze_url(h.url, store)
        if ur.intel:
            known.append((h, ur))
        elif ur.verdict != "Clean":
            top = sorted(ur.findings, key=lambda x: SEVERITY_ORDER.index(x.severity))[0]
            odd.append(f"{defang(h.url)} ({top.title})")
    if known:
        worst = min((S(r["severity"]) for _, ur in known for r in ur.intel), key=SEVERITY_ORDER.index)
        f.append(Finding("INTEL_URL_MATCH", "A hop in the chain matches threat intel", worst,
                         "; ".join(f"{defang(h.url)} -> " + ", ".join(f"{r['ioc_type']}:{r['family'] or r['source']}" for r in ur.intel)
                                   for h, ur in known[:5]), "intel"))
    if odd:
        f.append(Finding("TRACE_HOP_SUSPICIOUS", f"{len(odd)} hop(s) look suspicious on their own", S.MEDIUM,
                         "; ".join(odd[:5]), "trace"))
    res.findings = f
    res.score = compute_score(f)
    res.verdict = compute_verdict(res.score, f)
    return res


def trace(url: str, store=None, **kwargs) -> TraceResult:
    return assess(trace_raw(url, **kwargs), store)
