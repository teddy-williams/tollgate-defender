"""CAPE Sandbox (CAPEv2) client and report summarizer. Network code uses only the standard library.

Tollgate only talks to the CAPE REST API you configure (TOLLGATE_CAPE_URL). It uploads a sample ONLY when an analyst
explicitly asks for detonation, and it never runs anything itself. Where the sample's network traffic goes (nowhere,
a fake internet, or the real one) is decided inside CAPE, not here.

The report summarizer reads CAPE's JSON defensively: every key is optional, so a different CAPE version degrades to
less detail instead of failing.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Finding, Severity as S
from .textutil import safe

MAX_REPORT = 64 * 1024 * 1024
_URL_RE = re.compile(r"^(?:https?|ftp)://[^\s\"'<>]{4,300}$", re.I)
_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
# Noise the sandbox's own guest OS produces. Not "safe", just not worth suggesting as indicators.
BENIGN_SUFFIXES = ("windowsupdate.com", "microsoft.com", "windows.com", "msftncsi.com", "msftconnecttest.com", "digicert.com",
                   "verisign.com", "symcd.com", "ocsp.int-x3.letsencrypt.org", "in-addr.arpa", "ip6.arpa", "local", "localhost")


class CapeError(Exception):
    pass


@dataclass
class CapeConfig:
    url: str = ""
    token: str = ""
    token_keyword: str = "Token"
    verify_tls: bool = True
    ca_bundle: str = ""
    analysis_timeout: int = 120
    options: str = ""
    package: str = ""
    machine: str = ""
    platform: str = ""
    http_timeout: int = 30

    @classmethod
    def from_env(cls) -> "CapeConfig":
        e = os.environ.get
        return cls(url=e("TOLLGATE_CAPE_URL", "").rstrip("/"), token=e("TOLLGATE_CAPE_TOKEN", ""),
                   token_keyword=e("TOLLGATE_CAPE_TOKEN_KEYWORD", "Token"),
                   verify_tls=e("TOLLGATE_CAPE_VERIFY_TLS", "1").lower() not in ("0", "false", "no"),
                   ca_bundle=e("TOLLGATE_CAPE_CA", ""), analysis_timeout=int(e("TOLLGATE_CAPE_TIMEOUT", "120")),
                   options=e("TOLLGATE_CAPE_OPTIONS", ""), package=e("TOLLGATE_CAPE_PACKAGE", ""),
                   machine=e("TOLLGATE_CAPE_MACHINE", ""), platform=e("TOLLGATE_CAPE_PLATFORM", ""))

    @property
    def enabled(self) -> bool:
        return bool(self.url) and urlsplit(self.url).scheme in ("http", "https")


class CapeClient:
    def __init__(self, cfg: CapeConfig):
        if not cfg.enabled:
            raise CapeError("CAPE is not configured (set TOLLGATE_CAPE_URL to an http(s) URL)")
        self.cfg = cfg

    def _context(self):
        if not self.cfg.url.lower().startswith("https"):
            return None
        ctx = ssl.create_default_context(cafile=self.cfg.ca_bundle or None)
        if not self.cfg.verify_tls:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, body: bytes | None = None, content_type: str | None = None) -> dict:
        headers = {"Accept": "application/json", "User-Agent": "tollgate-cape/0.4"}
        if self.cfg.token:
            headers["Authorization"] = f"{self.cfg.token_keyword} {self.cfg.token}"
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.cfg.url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.http_timeout, context=self._context()) as resp:  # noqa: S310 - operator-configured
                raw = resp.read(MAX_REPORT + 1)
        except urllib.error.HTTPError as exc:
            raise CapeError(f"CAPE returned HTTP {exc.code}" + (" (check TOLLGATE_CAPE_TOKEN)" if exc.code in (401, 403) else "")) from None
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise CapeError(f"cannot reach CAPE ({exc.__class__.__name__})") from None
        if len(raw) > MAX_REPORT:
            raise CapeError("CAPE response is larger than 64 MB")
        try:
            return json.loads(raw)
        except ValueError:
            raise CapeError("CAPE returned something that is not JSON") from None

    def ping(self) -> dict:
        return self._request("GET", "/apiv2/cuckoo/status/")

    def submit_file(self, name: str, data: bytes) -> int:
        fields = {"timeout": str(self.cfg.analysis_timeout)}
        for key, val in (("options", self.cfg.options), ("package", self.cfg.package), ("machine", self.cfg.machine),
                         ("platform", self.cfg.platform)):
            if val:
                fields[key] = val
        boundary = "----tollgate" + secrets.token_hex(12)
        parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
        safe_name = re.sub(r'[\r\n"\\]', "_", name)[:200] or "sample.bin"
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n".encode() + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        j = self._request("POST", "/apiv2/tasks/create/file/", b"".join(parts), f"multipart/form-data; boundary={boundary}")
        d = j.get("data") if isinstance(j, dict) else None
        ids = (d.get("task_ids") or ([d["task_id"]] if "task_id" in d else [])) if isinstance(d, dict) else []
        if j.get("error") or not ids:
            raise CapeError("CAPE rejected the submission: " + safe(str(j.get("error_value") or j.get("errors") or j)[:200]))
        return int(ids[0])

    def status(self, task_id) -> str:
        j = self._request("GET", f"/apiv2/tasks/status/{int(task_id)}/")
        d = j.get("data")
        if isinstance(d, dict):
            d = d.get("status") or d.get("state")
        if j.get("error") or not isinstance(d, str):
            raise CapeError("CAPE could not report the task status: " + safe(str(j.get("error_value") or j)[:200]))
        return d

    def report(self, task_id) -> dict:
        j = self._request("GET", f"/apiv2/tasks/get/report/{int(task_id)}/")
        if not isinstance(j, dict) or j.get("error"):
            raise CapeError("CAPE could not return the report: " + safe(str(j.get("error_value") if isinstance(j, dict) else j)[:200]))
        return j


# ----------------------------------------------------------------------------- report summary

def _list(x) -> list:
    return x if isinstance(x, list) else []


def _dict(x) -> dict:
    return x if isinstance(x, dict) else {}


def _walk_strings(obj, out: list, depth: int = 0) -> None:
    if depth > 6 or len(out) > 500:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_strings(v, out, depth + 1)


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _benign_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in BENIGN_SUFFIXES)


def summarize_report(report: dict) -> dict:
    info, behavior, net = _dict(report.get("info")), _dict(report.get("behavior")), _dict(report.get("network"))
    cape = _dict(report.get("CAPE"))

    sigs = []
    for s in _list(report.get("signatures")):
        s = _dict(s)
        sev = s.get("severity") if isinstance(s.get("severity"), int) else 1
        sigs.append({"name": safe(s.get("name"), 80), "description": safe(s.get("description"), 200), "severity": sev,
                     "ttps": [safe(t, 16) for t in _list(s.get("ttp"))][:6],
                     "families": [safe(f, 40) for f in _list(s.get("families"))][:4]})
    sigs.sort(key=lambda x: -x["severity"])

    procs = [{"name": safe(p.get("process_name"), 60), "pid": p.get("process_id"), "ppid": p.get("parent_id"),
              "command_line": safe(p.get("command_line"), 240)} for p in map(_dict, _list(behavior.get("processes")))][:40]
    summary_b = _dict(behavior.get("summary"))
    commands = [safe(c, 240) for c in _list(summary_b.get("executed_commands"))][:30]
    mutexes = [safe(m, 100) for m in _list(summary_b.get("mutexes"))][:30]

    domains, ips, urls = [], [], []
    for d in map(_dict, _list(net.get("domains"))):
        if isinstance(d.get("domain"), str):
            domains.append(d["domain"].lower())
    for d in map(_dict, _list(net.get("dns"))):
        if isinstance(d.get("request"), str):
            domains.append(d["request"].lower())
    for h in _list(net.get("hosts")):
        ip = h if isinstance(h, str) else _dict(h).get("ip")
        if isinstance(ip, str):
            ips.append(ip)
    for h in map(_dict, _list(net.get("http"))):
        u = h.get("uri") if isinstance(h.get("uri"), str) else None
        if u is None and h.get("host"):
            u = f"http://{h['host']}{h.get('path', '/')}"
        if u and _URL_RE.match(u):
            urls.append(u)
    for kind in ("tcp", "udp"):
        for c in map(_dict, _list(net.get(kind))):
            if isinstance(c.get("dst"), str):
                ips.append(c["dst"])

    configs, families, c2 = [], [], []
    for cfg in _list(cape.get("configs")):
        for fam, body in _dict(cfg).items():
            families.append(safe(fam, 60))
            strings: list = []
            _walk_strings(body, strings)
            for s in strings:
                s = s.strip()
                m = _IP_RE.match(s)
                if _URL_RE.match(s) or (m and _is_public_ip(m.group(1))) or _DOMAIN_RE.match(s):
                    c2.append(safe(s, 300))
            configs.append({"family": safe(fam, 60), "keys": [safe(k, 40) for k in list(_dict(body))[:15]]})
    if report.get("malfamily"):
        families.insert(0, safe(report["malfamily"], 60))
    for s in sigs:
        families += s["families"]

    dropped = [{"name": safe(d.get("name"), 100), "sha256": safe(d.get("sha256"), 64), "size": d.get("size"), "type": safe(d.get("type"), 80)}
               for d in map(_dict, _list(report.get("dropped")) + _list(cape.get("payloads"))) if isinstance(d.get("sha256"), str)][:50]
    ttps = sorted({t for s in sigs for t in s["ttps"] if re.match(r"^T\d{4}", t)} |
                  {safe(_dict(t).get("ttp"), 16) for t in _list(report.get("ttps")) if isinstance(_dict(t).get("ttp"), str)})[:40]
    alerts = [{"signature": safe(a.get("signature"), 160), "category": safe(a.get("category"), 80), "severity": a.get("severity")}
              for a in map(_dict, _list(_dict(report.get("suricata")).get("alerts")))][:20]

    pub_domains = sorted({d for d in domains if _DOMAIN_RE.match(d) and not _benign_domain(d)})[:100]
    pub_ips = sorted({i for i in ips if _is_public_ip(i)})[:100]
    uniq_urls = list(dict.fromkeys(urls))[:100]
    target = _dict(_dict(report.get("target")).get("file"))
    return {
        "malscore": report.get("malscore") if isinstance(report.get("malscore"), (int, float)) else None,
        "families": list(dict.fromkeys(f for f in families if f))[:10], "duration": info.get("duration"),
        "machine": safe(_dict(info.get("machine")).get("name"), 60) or None, "target_sha256": target.get("sha256"),
        "signatures": sigs[:40], "processes": procs, "commands": commands, "mutexes": mutexes,
        "network": {"domains": pub_domains, "ips": pub_ips, "urls": uniq_urls},
        "c2_candidates": list(dict.fromkeys(c2))[:30], "configs": configs[:10], "dropped": dropped, "ttps": ttps, "alerts": alerts,
    }


def dynamic_findings(summary: dict, store=None) -> list[Finding]:
    """Turn a summary into findings (category 'dynamic'). Intel hits on observed network/dropped files are decisive."""
    f: list[Finding] = []

    def add(rule, title, sev, detail=""):
        f.append(Finding(rule, title, sev, safe(detail, 400), "dynamic"))

    if summary["families"]:
        add("DYN_FAMILY", f"Sandbox identified malware family: {', '.join(summary['families'][:3])}", S.CRITICAL,
            "A signature or configuration extractor in CAPE named the family.")
    score = summary.get("malscore")
    if score is not None:
        sev = S.HIGH if score >= 8 else S.MEDIUM if score >= 5 else S.LOW if score >= 3 else S.INFO
        add("DYN_MALSCORE", f"Sandbox score {score}/10", sev, "CAPE's own behaviour score for this run.")
    high = [s for s in summary["signatures"] if s["severity"] >= 3]
    for s in high[:8]:
        add(f"DYN_SIG_{s['name']}", f"Behaviour: {s['description'] or s['name']}", S.HIGH, "TTPs: " + ", ".join(s["ttps"]) if s["ttps"] else "")
    mid = [s for s in summary["signatures"] if s["severity"] == 2]
    if mid:
        add("DYN_SIGNATURES_MEDIUM", f"{len(mid)} medium-severity behaviour(s)", S.MEDIUM, "; ".join(s["description"] or s["name"] for s in mid[:6]))
    if summary["alerts"]:
        add("DYN_NETWORK_ALERTS", f"{len(summary['alerts'])} network IDS alert(s) during the run", S.HIGH,
            "; ".join(a["signature"] for a in summary["alerts"][:4]))
    if store is not None:
        net = summary["network"]
        seen = set()
        for kind, values in (("domain", net["domains"]), ("ip", net["ips"]), ("url", net["urls"] + summary["c2_candidates"])):
            for v in values:
                host = urlsplit(v).hostname if "://" in v else v
                for row in store.match_url(v if "://" in v else f"http://{v}/", host or ""):
                    key = (row["ioc_type"], row["value"])
                    if key not in seen:
                        seen.add(key)
                        f.append(Finding("INTEL_URL_MATCH", f"Sandbox saw traffic to a known-bad {row['ioc_type']}", S(row["severity"]),
                                         f"{safe(v, 120)} matches {row['ioc_type']}:{row['value']} | family={row['family'] or 'unknown'} | source={row['source']}",
                                         "dynamic"))
        for d in summary["dropped"]:
            row = store.lookup_ioc("sha256", str(d["sha256"]).lower())
            if row:
                f.append(Finding("INTEL_HASH_MATCH", f"Sandbox saw a dropped file that is known malware ({row['family'] or 'unknown'})",
                                 S(row["severity"]), f"{d['name']} sha256 {d['sha256']} | source={row['source']}", "dynamic"))
    return f
