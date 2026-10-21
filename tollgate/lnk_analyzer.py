"""Structural analysis of Windows Shell Link (.lnk) files (MS-SHLLINK).

Parses the header, link target ID list, LinkInfo, string data and extra-data blocks, then looks for how
shortcuts are abused: launching script hosts, padded/obfuscated arguments, decoy icons, remote targets,
payloads appended after the structure. Bytes are only parsed, never executed. Every read is bounds-checked.
"""
from __future__ import annotations

import base64
import datetime as dt
import re
import struct
import uuid

from .models import Finding, Severity as S
from .textutil import safe
from . import triage

HEADER_SIZE = 0x4C
LINK_FLAGS = {0: "HasLinkTargetIDList", 1: "HasLinkInfo", 2: "HasName", 3: "HasRelativePath", 4: "HasWorkingDir",
              5: "HasArguments", 6: "HasIconLocation", 7: "IsUnicode", 8: "ForceNoLinkInfo", 9: "HasExpString",
              10: "RunInSeparateProcess", 12: "HasDarwinID", 13: "RunAsUser", 14: "HasExpIcon"}
SHOW_COMMANDS = {1: "normal", 3: "maximized", 7: "minimized"}
EXTRA_BLOCKS = {0xA0000001: "EnvironmentVariable", 0xA0000002: "Console", 0xA0000003: "Tracker", 0xA0000004: "ConsoleFE",
                0xA0000005: "SpecialFolder", 0xA0000006: "Darwin", 0xA0000007: "IconEnvironment", 0xA0000008: "Shim",
                0xA0000009: "PropertyStore", 0xA000000B: "KnownFolder", 0xA000000C: "VistaAndAboveIDList"}
LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe", "forfiles.exe", "curl.exe",
           "installutil.exe", "msbuild.exe", "schtasks.exe", "conhost.exe", "cmstp.exe", "pcalua.exe"}
DECOY_ICON_HINTS = ("shell32.dll", "imageres.dll", "winword.exe", "excel.exe", "powerpnt.exe", "acrord", "acrobat",
                    "notepad.exe", "explorer.exe", ".pdf", ".doc", ".xls", ".ppt", ".txt", ".jpg", ".png", ".zip")
MAX_APPENDED_ARTIFACT = 5 * 1024 * 1024

_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>^|&]+", re.I)
_ENC_RE = re.compile(r"(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm"
                     r"|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{12,})", re.I)

# (rule id, regex, severity, title)
ARG_PATTERNS = [
    ("LNK_ARG_PS_HIDDEN", r"-w(?:indowstyle)?\s+(?:hidden|1)\b|-nop(?:rofile)?\b|-ep\s+bypass|-executionpolicy\s+bypass",
     S.MEDIUM, "PowerShell stealth flags (hidden window / no profile / policy bypass)"),
    ("LNK_ARG_PS_DOWNLOAD", r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b",
     S.HIGH, "PowerShell download cradle"),
    ("LNK_ARG_PS_EXEC", r"\biex\b|invoke-expression|frombase64string|\[convert\]::", S.MEDIUM, "PowerShell dynamic execution"),
    ("LNK_ARG_MSHTA", r"mshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)", S.HIGH, "mshta runs remote or inline script"),
    ("LNK_ARG_CERTUTIL", r"certutil[^\r\n]{0,40}-(?:urlcache|decode|f\s)", S.HIGH, "certutil used to download or decode a payload"),
    ("LNK_ARG_BITSADMIN", r"bitsadmin[^\r\n]{0,30}/transfer", S.HIGH, "bitsadmin transfer (download)"),
    ("LNK_ARG_CURL", r"\bcurl(?:\.exe)?\b[^\r\n]{0,80}https?://", S.MEDIUM, "curl downloads from a URL"),
    ("LNK_ARG_REGSVR", r"regsvr32[^\r\n]{0,40}/i:(?:https?:|\\\\)|scrobj\.dll", S.HIGH, "regsvr32 remote scriptlet (Squiblydoo)"),
    ("LNK_ARG_RUNDLL_JS", r"rundll32[^\r\n]{0,20}(?:javascript:|url\.dll,\s*FileProtocolHandler)", S.HIGH, "rundll32 script/URL launch"),
    ("LNK_ARG_WSH_SCRIPT", r"(?:wscript|cscript)(?:\.exe)?\s+(?://e:\w+\s+|//b\s+)?[^\r\n]{0,60}\.(?:js|jse|vbs|vbe|wsf)\b",
     S.MEDIUM, "Windows Script Host runs a script file"),
    ("LNK_ARG_CMD_CHAIN", r"cmd(?:\.exe)?\s+/[ckv]\s+.*(?:&&|&|\|)", S.MEDIUM, "cmd chains several commands"),
    ("LNK_ARG_USER_WRITABLE_EXEC", r"%(?:temp|appdata|localappdata|programdata|public)%[^\s\"']*\.(?:exe|dll|js|vbs|ps1|bat|cmd|hta)",
     S.MEDIUM, "Runs a file from a user-writable folder"),
]
_ARG_COMPILED = [(r, re.compile(rx, re.I), sev, t) for r, rx, sev, t in ARG_PATTERNS]


class LnkError(ValueError):
    pass


def _cstr(buf: bytes, off: int, unicode: bool = False) -> str:
    if off <= 0 or off >= len(buf):
        return ""
    if unicode:
        end = off
        while end + 1 < len(buf) and buf[end:end + 2] != b"\x00\x00":
            end += 2
        return buf[off:end].decode("utf-16le", "replace")
    end = buf.find(b"\x00", off)
    return buf[off:len(buf) if end < 0 else end].decode("cp1252", "replace")


def _filetime(value: int) -> str | None:
    if not value:
        return None
    try:
        return (dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError):
        return "invalid"


def _guid_v1(raw: bytes) -> tuple[str | None, str | None]:
    try:
        u = uuid.UUID(bytes_le=raw)
    except ValueError:
        return None, None
    if u.version != 1:
        return None, None
    node = ":".join(f"{(u.node >> s) & 0xFF:02x}" for s in range(40, -8, -8))
    ts = dt.datetime(1582, 10, 15, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=u.time // 10)
    return node, ts.isoformat()


def _idlist_path(idlist: bytes) -> tuple[str, list[str]]:
    """Best-effort target path from shell items (drive + folder/file entries)."""
    parts, strings, i = [], [], 0
    while i + 2 <= len(idlist) and len(parts) < 64:
        size = struct.unpack_from("<H", idlist, i)[0]
        if size < 3 or i + size > len(idlist):
            break
        item = idlist[i + 2:i + size]
        i += size
        kind = item[0]
        if kind & 0x70 == 0x20:                       # drive
            name = item[1:].split(b"\x00")[0].decode("cp1252", "replace")
        elif kind & 0x70 == 0x30 and len(item) > 12:  # file/folder entry
            if kind & 0x04:
                name = item[12:].decode("utf-16le", "replace").split("\x00")[0]
            else:
                name = item[12:].split(b"\x00")[0].decode("cp1252", "replace")
            longest = max(re.findall(rb"(?:[\x20-\x7e]\x00){4,}", item) or [b""], key=len)
            if longest:
                name = longest.decode("utf-16le", "replace")
        else:
            continue
        if name:
            parts.append(name)
            strings.append(name)
    path = ""
    for p in parts:
        path = p if not path else (path + p if path.endswith("\\") else path + "\\" + p)
    return path, strings[:20]


def parse(data: bytes) -> tuple[dict, list[str]]:
    """Return (info, warnings). Raises LnkError only if this is not a shell link at all."""
    if len(data) < HEADER_SIZE or struct.unpack_from("<I", data, 0)[0] != HEADER_SIZE:
        raise LnkError("not a shell link header")
    warnings: list[str] = []
    flags_raw, attrs = struct.unpack_from("<II", data, 20)
    ctime, atime, wtime = struct.unpack_from("<QQQ", data, 28)
    file_size, icon_index, show = struct.unpack_from("<IiI", data, 52)
    info: dict = {
        "flags": [n for b, n in LINK_FLAGS.items() if flags_raw >> b & 1], "show_command": SHOW_COMMANDS.get(show, str(show)),
        "file_size": file_size, "icon_index": icon_index,
        "times": {"created": _filetime(ctime), "accessed": _filetime(atime), "written": _filetime(wtime)},
        "target": None, "network_target": None, "relative_path": None, "working_dir": None, "arguments": None,
        "icon_location": None, "name": None, "idlist_path": None, "env_target": None, "extra_blocks": [], "tracker": None,
    }
    is_unicode = bool(flags_raw >> 7 & 1)
    pos = HEADER_SIZE

    if flags_raw & 1:                                                        # LinkTargetIDList
        if pos + 2 > len(data):
            warnings.append("truncated before IDList")
            return _finish(info, pos, data, warnings)
        size = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + size > len(data):
            warnings.append("IDList larger than file")
            return _finish(info, len(data), data, warnings)
        info["idlist_path"], _ = _idlist_path(data[pos:pos + size])
        pos += size

    if flags_raw >> 1 & 1 and not flags_raw >> 8 & 1:                       # LinkInfo
        if pos + 4 > len(data):
            warnings.append("truncated before LinkInfo")
            return _finish(info, pos, data, warnings)
        li_size = struct.unpack_from("<I", data, pos)[0]
        if li_size < 0x1C or pos + li_size > len(data):
            warnings.append("LinkInfo size is invalid")
            return _finish(info, len(data), data, warnings)
        li = data[pos:pos + li_size]
        hdr_size, li_flags, _vol, base_off, net_off, suffix_off = struct.unpack_from("<IIIIII", li, 4)
        base = suffix = ""
        if li_flags & 1:
            base = _cstr(li, base_off)
            if hdr_size >= 0x24 and len(li) >= 0x24:
                b_uni, s_uni = struct.unpack_from("<II", li, 0x1C)
                base = _cstr(li, b_uni, True) or base
                suffix = _cstr(li, s_uni, True)
        suffix = suffix or _cstr(li, suffix_off)
        if li_flags & 2 and 0 < net_off < len(li) - 20:
            net = li[net_off:]
            name_off = struct.unpack_from("<I", net, 8)[0]
            info["network_target"] = _cstr(net, name_off)
            base = base or info["network_target"]
        info["target"] = (base + ("\\" + suffix if suffix and base and not base.endswith("\\") else suffix)) or None
        pos += li_size

    string_fields = [(2, "name"), (3, "relative_path"), (4, "working_dir"), (5, "arguments"), (6, "icon_location")]
    for bit, key in string_fields:
        if not flags_raw >> bit & 1:
            continue
        if pos + 2 > len(data):
            warnings.append(f"truncated before {key}")
            return _finish(info, len(data), data, warnings)
        count = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        nbytes = count * 2 if is_unicode else count
        if pos + nbytes > len(data):
            warnings.append(f"{key} runs past the end of the file")
            return _finish(info, len(data), data, warnings)
        raw = data[pos:pos + nbytes]
        info[key] = raw.decode("utf-16le", "replace") if is_unicode else raw.decode("cp1252", "replace")
        pos += nbytes

    while True:                                                              # ExtraData
        if pos + 4 > len(data):
            break
        bsize = struct.unpack_from("<I", data, pos)[0]
        if bsize < 4:
            pos += 4                                                         # TerminalBlock
            break
        if bsize < 8 or pos + bsize > len(data):
            warnings.append("extra-data block is truncated or invalid")
            break
        sig = struct.unpack_from("<I", data, pos + 4)[0]
        name = EXTRA_BLOCKS.get(sig, f"0x{sig:08x}")
        info["extra_blocks"].append(name)
        block = data[pos:pos + bsize]
        if sig == 0xA0000003 and bsize >= 0x60:
            machine = block[16:32].split(b"\x00")[0].decode("ascii", "replace")
            mac, created = _guid_v1(block[48:64])
            info["tracker"] = {"machine_id": safe(machine, 16), "file_guid_mac": mac, "file_guid_time": created}
        elif sig == 0xA0000001 and bsize >= 0x314:
            ansi = block[8:268].split(b"\x00")[0].decode("cp1252", "replace")
            uni = block[268:788].decode("utf-16le", "replace").split("\x00")[0]
            info["env_target"] = uni or ansi
        pos += bsize
    return _finish(info, pos, data, warnings)


def _finish(info: dict, end: int, data: bytes, warnings: list[str]) -> tuple[dict, list[str]]:
    info["structure_end"] = end
    info["trailing"] = data[end:]
    return info, warnings


def _decode_powershell(args: str) -> str | None:
    m = _ENC_RE.search(args)
    if not m:
        return None
    b64 = m.group(1)
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
    except ValueError:
        return None
    for enc in ("utf-16le", "utf-8"):
        text = raw.decode(enc, "ignore")
        if len(text) >= 4 and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.9:
            return text
    return None


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").rstrip("\\").split("\\")[-1].lower()


def analyze(data: bytes) -> tuple[list[Finding], dict, list[tuple[str, bytes]]]:
    """Return (findings, metadata, artifacts). Artifacts are extra byte blobs (decoded commands, appended data) for YARA/intel."""
    findings: list[Finding] = []
    artifacts: list[tuple[str, bytes]] = []
    try:
        info, warnings = parse(data)
    except LnkError as exc:
        return [Finding("LNK_MALFORMED", "Shortcut header is invalid", S.MEDIUM, str(exc), "lnk")], {}, []
    except (struct.error, IndexError) as exc:  # defensive: any parser slip must not break the scan
        return [Finding("LNK_MALFORMED", "Shortcut could not be parsed", S.MEDIUM, safe(str(exc)), "lnk")], {}, []
    if warnings:
        findings.append(Finding("LNK_MALFORMED", "Shortcut structure is damaged or crafted", S.MEDIUM, "; ".join(warnings), "lnk"))

    target = info["target"] or info["idlist_path"] or info["env_target"] or info["relative_path"] or ""
    exe = _basename(target)
    args = info["arguments"] or ""
    is_lolbin = exe in LOLBINS
    emitted: set[str] = set()

    def add(rule, title, sev, detail=""):
        if rule not in emitted:
            emitted.add(rule)
            findings.append(Finding(rule, title, sev, safe(detail, 400), "lnk"))

    if is_lolbin:
        add("LNK_LOLBIN_TARGET", f"Shortcut launches {exe} (a system tool often abused by malware)", S.MEDIUM,
            f"Target: {safe(target, 200)}")
        if info["show_command"] == "minimized" and exe in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "mshta.exe"}:
            add("LNK_HIDDEN_WINDOW", "Starts minimized (no visible window)", S.LOW, "")
    if "RunAsUser" in info["flags"] and is_lolbin:
        add("LNK_RUN_AS", "Shortcut requests to run as another user / elevated", S.LOW, "")

    if len(args) > 260:
        add("LNK_ARG_LONG", f"Very long arguments ({len(args)} characters)", S.MEDIUM,
            "Windows shows only the first ~260 characters in the Properties dialog.")
    if re.search(r"\s{80,}", args):
        add("LNK_ARG_PADDING", "Arguments padded with whitespace to hide the real command", S.HIGH,
            "A long run of spaces pushes the payload out of view in the Properties dialog.")
    if re.search(r"[\r\n]", args):
        add("LNK_ARG_NEWLINE", "Line breaks inside the arguments", S.HIGH, "Used to hide commands from the Properties dialog.")

    scan_text = args
    decoded = _decode_powershell(args)
    if decoded:
        add("LNK_ARG_PS_ENCODED", "PowerShell -EncodedCommand payload", S.HIGH, f"Decoded: {safe(decoded, 250)}")
        artifacts.append(("decoded PowerShell command", decoded.encode("utf-8", "replace")[:MAX_APPENDED_ARTIFACT]))
        scan_text = args + "\n" + decoded
    for rule, rx, sev, title in _ARG_COMPILED:
        m = rx.search(scan_text)
        if m:
            add(rule, title, sev, f"Matched: {m.group(0)[:100]}")
    if args.count("^") >= 8:
        add("LNK_ARG_CARET_OBFUSCATION", "cmd caret (^) obfuscation", S.MEDIUM, "")
    if re.search(r"%[A-Za-z0-9_]+:~-?\d+(?:,-?\d+)?%", args):
        add("LNK_ARG_ENV_SUBSTRING", "Environment-variable substring obfuscation", S.MEDIUM, "")
    if re.search(r"(?:'[^']{1,5}'\s*\+\s*){4,}", args):
        add("LNK_ARG_STRING_CONCAT", "String-concatenation obfuscation", S.MEDIUM, "")

    icon = (info["icon_location"] or "").lower()
    if icon.startswith("\\\\") or icon.startswith("http"):
        add("LNK_REMOTE_ICON", "Icon is loaded from a remote host (forces network authentication)", S.HIGH,
            f"Icon: {safe(info['icon_location'], 150)}")
    elif is_lolbin and any(h in icon for h in DECOY_ICON_HINTS):
        add("LNK_ICON_SPOOF", "Document-style icon on a script/command launcher", S.MEDIUM,
            f"Icon: {safe(info['icon_location'], 150)} while the target is {exe}")
    for label, path in (("target", target), ("working directory", info["working_dir"] or ""), ("relative path", info["relative_path"] or "")):
        p = path.lower()
        if p.startswith("\\\\") and ("@ssl" in p or re.search(r"@\d+\\", p) or "davwwwroot" in p):
            add("LNK_WEBDAV", f"Shortcut {label} points at a WebDAV share", S.HIGH, safe(path, 150))
        elif p.startswith(("http://", "https://", "file://")):
            add("LNK_REMOTE_PATH", f"Shortcut {label} is a URL", S.HIGH, safe(path, 150))
        elif p.startswith("\\\\"):
            add("LNK_REMOTE_PATH", f"Shortcut {label} is a network (UNC) path", S.MEDIUM, safe(path, 150))

    names = {_basename(p) for p in (info["target"], info["idlist_path"], info["env_target"]) if p}
    if len(names) > 1:
        add("LNK_TARGET_MISMATCH", "Target fields disagree with each other (crafted shortcut)", S.MEDIUM,
            "Names found: " + ", ".join(sorted(safe(n, 40) for n in names)))

    trailing = info["trailing"]
    extra = trailing.rstrip(b"\x00")
    if len(extra) > 64:
        kind = triage.detect_type(extra[:4096])
        add("LNK_APPENDED_DATA", f"{len(extra)} bytes of data appended after the shortcut structure", S.HIGH,
            f"Appended content looks like: {kind}. Shortcuts normally end at the terminal block; this hides a payload.")
        artifacts.append(("data appended to shortcut", extra[:MAX_APPENDED_ARTIFACT]))
    t = info["times"]
    if not any(t.values()):
        add("LNK_NO_TIMESTAMPS", "Timestamps are all zero (typical of tool-generated shortcuts)", S.LOW, "")
    if not info["tracker"]:
        pass  # absence is common and not informative on its own

    urls = list(dict.fromkeys(_URL_RE.findall(scan_text)))[:15]
    meta = {
        "target": safe(info["target"], 300), "idlist_path": safe(info["idlist_path"], 300), "env_target": safe(info["env_target"], 300),
        "relative_path": safe(info["relative_path"], 300), "working_dir": safe(info["working_dir"], 300),
        "arguments": safe(args, 2000), "icon_location": safe(info["icon_location"], 300), "name": safe(info["name"], 200),
        "show_command": info["show_command"], "flags": info["flags"], "times": info["times"], "file_size_field": info["file_size"],
        "extra_blocks": info["extra_blocks"], "tracker": info["tracker"], "appended_bytes": len(extra), "urls": urls,
        "decoded_command": safe(decoded, 1000) if decoded else None,
    }
    return findings, meta, artifacts
