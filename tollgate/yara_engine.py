"""YARA integration: load rule files from one or more directories, scan any file type.

Each rule file is validated on its own, so one broken file never disables the rest.
Rule meta keys used: description, severity (critical|high|medium|low), family.
A rule with severity "critical" yields an INTEL_* finding, which is decisive (Malicious).
"""
from __future__ import annotations

import os
import re
import tempfile

from . import paths
from .models import Finding, Severity as S

try:  # YARA is optional: Tollgate still works without it
    import yara
except ImportError:  # pragma: no cover
    yara = None

MAX_RULE_BYTES = 256 * 1024
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_INCLUDE_RE = re.compile(r"^\s*include\b", re.M)
_SEVS = {"critical", "high", "medium", "low"}


def available() -> bool:
    return yara is not None


def _identifier(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


class YaraEngine:
    def __init__(self, dirs: list[str]):
        self.dirs = [d for d in dirs if d]
        self.rules = None
        self.loaded: list[str] = []
        self.errors: list[dict] = []
        self.reload()

    def reload(self) -> None:
        self.rules, self.loaded, self.errors = None, [], []
        if yara is None:
            return
        valid: dict[str, str] = {}
        for i, d in enumerate(self.dirs):
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if not fn.lower().endswith((".yar", ".yara")):
                    continue
                path = os.path.join(d, fn)
                try:
                    yara.compile(filepath=path)
                    valid[f"d{i}_{_identifier(fn)}"] = path
                except yara.Error as exc:
                    self.errors.append({"file": path, "error": str(exc)[:300]})
        if valid:
            self.rules = yara.compile(filepaths=valid)
            self.loaded = sorted(valid.values())

    def rule_count(self) -> int:
        return sum(1 for _ in self.rules) if self.rules else 0

    def scan(self, data: bytes) -> tuple[list[Finding], list[dict]]:
        if not self.rules:
            return [], []
        try:
            matches = self.rules.match(data=data, timeout=30)
        except yara.TimeoutError:
            return [Finding("YARA_TIMEOUT", "YARA scan timed out", S.LOW, "", "yara")], []
        except yara.Error as exc:
            return [Finding("YARA_ERROR", "YARA scan failed", S.LOW, str(exc)[:200], "yara")], []
        findings, summary = [], []
        for m in matches:
            meta = m.meta or {}
            sev = str(meta.get("severity", "high")).lower()
            sev = sev if sev in _SEVS else "high"
            prefix = "INTEL_YARA_" if sev == "critical" else "YARA_"
            ids = []
            for sm in m.strings or []:
                ident = getattr(sm, "identifier", None) or (sm[1] if isinstance(sm, tuple) else "?")
                offs = [i.offset for i in sm.instances[:1]] if hasattr(sm, "instances") else [sm[0]]
                ids.append(f"{ident}@{hex(offs[0])}" if offs else str(ident))
            detail = f"rule {m.rule} [{m.namespace}]" + (f" | family={meta['family']}" if meta.get("family") else "") \
                + (f" | strings: {', '.join(ids[:5])}" if ids else "")
            findings.append(Finding(f"{prefix}{m.rule}", str(meta.get("description") or m.rule), S(sev), detail, "yara"))
            summary.append({"rule": m.rule, "namespace": m.namespace, "severity": sev, "tags": list(m.tags)})
        return findings, summary


def validate_source(text: str) -> None:
    """Raise ValueError unless `text` is an acceptable, compilable YARA rule file."""
    if yara is None:
        raise ValueError("yara-python is not installed")
    if len(text.encode("utf-8", "ignore")) > MAX_RULE_BYTES:
        raise ValueError(f"rule file larger than {MAX_RULE_BYTES} bytes")
    if _INCLUDE_RE.search(text):
        raise ValueError("'include' is not allowed in uploaded rules")
    try:
        yara.compile(source=text)
    except yara.Error as exc:
        raise ValueError(f"rule does not compile: {exc}") from None


def add_rule_file(name: str, text: str, dest_dir: str) -> str:
    """Validate and save a rule file, replacing any file of the same name. Returns the path."""
    base = name[:-4] if name.lower().endswith(".yar") else name
    if not _NAME_RE.match(base):
        raise ValueError("rule file name must be 1-64 chars of letters, digits, _ . -")
    validate_source(text)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, base + ".yar")
    fd, tmp = tempfile.mkstemp(dir=dest_dir, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)  # atomic: a scan never sees a half-written rule file
    return path


def dirs_from_env() -> list[str]:
    """Built-in rules first, then the user's own rules dir (the last entry is where new rules are written)."""
    env = os.environ.get("TOLLGATE_YARA_DIRS")
    return env.split(os.pathsep) if env else [paths.builtin_rules_dir(), paths.user_rules_dir()]


def user_rules_dir() -> str:
    return dirs_from_env()[-1]


_default: YaraEngine | None = None


def default_engine() -> YaraEngine | None:
    global _default
    if yara is None:
        return None
    if _default is None:
        _default = YaraEngine(dirs_from_env())
    return _default
