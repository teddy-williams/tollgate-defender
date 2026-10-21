"""Step 1: triage. Hashes, true file type from content, filename trickery.

Nothing in here executes or renders the sample. It only reads bytes.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .models import Finding, Severity as S

# --- extension knowledge ---------------------------------------------------

EXECUTABLE_EXTS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "hta", "msi", "jar", "dll", "cpl", "lnk", "reg",
    "msc", "url", "scf", "shs",
}
# Windows never displays these extensions, even with "show extensions" on.
AUTO_HIDDEN_EXTS = {"lnk", "pif", "scf", "url", "shs"}
SCRIPT_EXTS = {"vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "hta", "bat", "cmd"}
# Extensions a victim expects to be harmless.
DECOY_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
    "png", "gif", "bmp", "mp3", "mp4", "avi", "zip", "rar", "rtf", "csv",
}
# What the content type should be for a given extension.
EXT_EXPECTED = {
    "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"}, "sys": {"pe"}, "cpl": {"pe"},
    "pdf": {"pdf"}, "lnk": {"lnk"}, "rtf": {"rtf"},
    "doc": {"ole", "rtf", "zip", "text"}, "xls": {"ole", "zip", "text"},
    "ppt": {"ole", "zip"},
    "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "zip": {"zip"}, "jar": {"zip"},
    "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "png": {"png"}, "gif": {"gif"},
}
EXECUTABLE_TYPES = {"pe", "dos-mz", "elf", "lnk"}

BIDI_CHARS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")
INVISIBLE_CHARS = set("\u200b\u200c\u200d\u2060\ufeff\u00ad")

LNK_MAGIC = bytes.fromhex("4C0000000114020000000000C000000000000046")
OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")


# --- content-based type detection -----------------------------------------

def detect_type(data: bytes) -> str:
    """Identify the real file type from content, ignoring the filename."""
    if not data:
        return "empty"
    if data[:2] == b"MZ":
        if len(data) >= 0x40:
            off = int.from_bytes(data[0x3C:0x40], "little")
            if 0 < off <= len(data) - 4 and data[off:off + 4] == b"PE\x00\x00":
                return "pe"
        return "dos-mz"
    if data.startswith(LNK_MAGIC):
        return "lnk"
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data.startswith(OLE_MAGIC):
        return "ole"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:5] == b"{\\rtf":
        return "rtf"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:2] == b"#!":
        return "script"
    if _looks_like_text(data[:4096]):
        return "text"
    return "unknown"


def _looks_like_text(sample: bytes) -> bool:
    if not sample or b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(sample) > 0.95


# --- filename analysis -------------------------------------------------------

def extensions_of(name: str) -> list[str]:
    """Extensions the way Windows sees them (trailing dots/spaces stripped)."""
    core = name.rstrip(" .")
    parts = core.split(".")
    return [p.strip().lower() for p in parts[1:]]


def analyze_filename(name: str) -> list[Finding]:
    findings: list[Finding] = []
    escaped = name.encode("unicode_escape").decode("ascii")

    if "\u202e" in name:
        findings.append(Finding(
            "NAME_RTLO", "Right-to-left override (U+202E) in filename", S.CRITICAL,
            f"The displayed name can be visually reversed to fake an extension. Raw: {escaped}",
            "filename"))
    elif any(c in BIDI_CHARS for c in name):
        findings.append(Finding(
            "NAME_BIDI", "Bidirectional control characters in filename", S.HIGH,
            f"Raw: {escaped}", "filename"))

    if any(c in INVISIBLE_CHARS for c in name):
        findings.append(Finding(
            "NAME_INVISIBLE", "Invisible/zero-width characters in filename", S.MEDIUM,
            f"Raw: {escaped}", "filename"))

    if any(ord(c) < 32 for c in name):
        findings.append(Finding(
            "NAME_CONTROL", "Control characters in filename", S.HIGH,
            f"Raw: {escaped}", "filename"))

    if re.search(r" {4,}", name):
        findings.append(Finding(
            "NAME_PADDING", "Long run of spaces in filename", S.HIGH,
            "Padding can push the real extension out of view in file listings.", "filename"))

    if name.endswith((" ", ".")):
        findings.append(Finding(
            "NAME_TRAILING", "Trailing space or dot in filename", S.MEDIUM,
            "Windows strips these, which can hide the true file type.", "filename"))

    exts = extensions_of(name)
    if len(exts) >= 2 and exts[-1] in EXECUTABLE_EXTS and exts[-2] in DECOY_EXTS:
        last, prev = exts[-1], exts[-2]
        hidden = last in AUTO_HIDDEN_EXTS
        detail = f"'.{prev}.{last}' looks like a .{prev} file but is an executable type (.{last})."
        if hidden:
            detail += f" Windows never shows '.{last}', so the victim sees only '.{prev}'."
        findings.append(Finding(
            "NAME_DOUBLE_EXT", "Double extension: executable disguised as a document/media file",
            S.CRITICAL if hidden else S.HIGH, detail, "filename"))
    elif exts and exts[-1] in SCRIPT_EXTS:
        findings.append(Finding(
            "NAME_SCRIPT_EXT", f"Script-type file (.{exts[-1]})", S.LOW,
            "Script content analysis is not implemented yet in this version.", "filename"))

    return findings


def check_type_vs_extension(name: str, detected: str) -> list[Finding]:
    exts = extensions_of(name)
    if not exts or detected in ("empty",):
        return []
    ext = exts[-1]
    expected = EXT_EXPECTED.get(ext)
    if expected is None or detected in expected:
        return []

    if detected in EXECUTABLE_TYPES and ext not in EXECUTABLE_EXTS:
        return [Finding(
            "EXT_SPOOF", f"Executable content disguised as .{ext}", S.CRITICAL,
            f"Extension says .{ext} but the content is '{detected}'.", "filename")]
    if ext in EXECUTABLE_EXTS:
        sev = S.LOW if detected == "dos-mz" else S.MEDIUM
        return [Finding(
            "EXT_MISMATCH", f".{ext} file is not a valid PE executable", sev,
            f"Content detected as '{detected}'. Corrupt, renamed, or crafted to evade parsers.",
            "filename")]
    return [Finding(
        "EXT_MISMATCH", f"Content does not match .{ext} extension", S.MEDIUM,
        f"Content detected as '{detected}', expected one of {sorted(expected)}.", "filename")]


# --- entry point -------------------------------------------------------------

@dataclass
class TriageResult:
    hashes: dict
    detected_type: str
    findings: list[Finding] = field(default_factory=list)


def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def run(data: bytes, name: str) -> TriageResult:
    detected = detect_type(data)
    findings = analyze_filename(name)
    findings += check_type_vs_extension(name, detected)
    if detected == "empty":
        findings.append(Finding("FILE_EMPTY", "File is empty", S.INFO, "", "general"))
    return TriageResult(compute_hashes(data), detected, findings)
