"""Step 2: static analysis of Windows PE files (.exe/.dll/.scr/...).

Pure parsing with pefile. The sample is never loaded or executed.
Findings are heuristics: each one is evidence, not proof.
"""
from __future__ import annotations

import datetime as dt
import math
import re
from collections import Counter

import pefile

from .models import Finding, Severity as S

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_READ = 0x40000000
DIR_SECURITY = 4
DIR_COM_DESCRIPTOR = 14
MAX_STRING_SCAN = 32 * 1024 * 1024
MAX_RESOURCE_BLOBS = 200

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc",
    ".pdata", ".xdata", ".tls", ".crt", ".didat", ".gfids", ".00cfg", ".sdata",
    ".retplne", ".voltbl", ".mrdata", ".shared", ".detourc", ".detourd", ".orpc",
    "code", "data", "bss", "idata", "text", "rsrc", "reloc", "init", ".init", ".fini",
}

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".petite": "Petite",
    "mpress1": "MPRESS", "mpress2": "MPRESS", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".packed": "generic packer",
    ".yp": "Yoda's Protector", ".pec1": "PECompact", "pec2": "PECompact",
}

# (title, api names lowercase, [(min distinct hits, severity), ...] ascending)
API_GROUPS = {
    "injection": (
        "Process-injection API cluster",
        {"virtualallocex", "writeprocessmemory", "createremotethread",
         "createremotethreadex", "ntunmapviewofsection", "zwunmapviewofsection",
         "queueuserapc", "setthreadcontext", "ntwritevirtualmemory",
         "rtlcreateuserthread", "ntcreatethreadex", "ntmapviewofsection"},
        [(1, S.LOW), (2, S.MEDIUM), (3, S.HIGH)],
    ),
    "hooking": (
        "Keylogging / input-hook APIs",
        {"setwindowshookexa", "setwindowshookexw", "getasynckeystate",
         "getkeyboardstate", "registerrawinputdevices"},
        [(1, S.LOW), (2, S.MEDIUM)],
    ),
    "download": (
        "Network download APIs",
        {"urldownloadtofilea", "urldownloadtofilew", "urldownloadtocachefilea",
         "urldownloadtocachefilew", "internetreadfile", "internetopenurla",
         "internetopenurlw"},
        [(2, S.LOW)],
    ),
    "anti_debug": (
        "Anti-debugging APIs",
        {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
         "outputdebugstringa", "ntsetinformationthread", "zwsetinformationthread"},
        [(1, S.LOW), (3, S.MEDIUM)],
    ),
    "crypto": (
        "Crypto API cluster (ransomware-style capability, also common in benign software)",
        {"cryptencrypt", "cryptacquirecontexta", "cryptacquirecontextw", "cryptgenkey",
         "cryptimportkey", "cryptderivekey", "bcryptencrypt", "bcryptgeneratesymmetrickey"},
        [(3, S.LOW)],
    ),
}
EXEC_APIS = {"winexec", "shellexecutea", "shellexecutew", "shellexecuteexa",
             "shellexecuteexw", "createprocessa", "createprocessw"}

# (rule id, regex, severity, title)
STRING_PATTERNS = [
    ("STR_VSS_DELETE", r"vssadmin(\.exe)?\s+delete\s+shadows", S.HIGH,
     "Shadow-copy deletion command (ransomware behaviour)"),
    ("STR_BCDEDIT", r"bcdedit[^\n]{0,40}(recoveryenabled|bootstatuspolicy)", S.HIGH,
     "Boot recovery tampering command (ransomware behaviour)"),
    ("STR_WMIC_SHADOW", r"wmic[^\n]{0,40}shadowcopy[^\n]{0,20}delete", S.HIGH,
     "WMIC shadow-copy deletion"),
    ("STR_CERTUTIL_DL", r"certutil[^\n]{0,30}-urlcache", S.HIGH,
     "certutil used as a downloader (LOLBin)"),
    ("STR_DISCORD_WEBHOOK", r"discord(app)?\.com/api/webhooks/", S.HIGH,
     "Discord webhook URL (common exfiltration channel)"),
    ("STR_TELEGRAM_BOT", r"api\.telegram\.org/bot", S.HIGH,
     "Telegram bot API URL (common C2/exfiltration channel)"),
    ("STR_POWERSHELL_EVASION",
     r"powershell(\.exe)?[^\n]{0,80}(-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|-nop|bypass|downloadstring|iex)",
     S.MEDIUM, "PowerShell with evasion/download flags"),
    ("STR_RUN_KEY", r"software\\microsoft\\windows\\currentversion\\run", S.MEDIUM,
     "Registry Run key reference (persistence)"),
    ("STR_SCHTASKS", r"schtasks[^\n]{0,20}/create", S.MEDIUM,
     "Scheduled task creation (persistence)"),
    ("STR_MSHTA", r"mshta(\.exe)?\s", S.MEDIUM, "mshta invocation (LOLBin)"),
    ("STR_BITSADMIN", r"bitsadmin[^\n]{0,30}/transfer", S.MEDIUM,
     "bitsadmin transfer (LOLBin downloader)"),
    ("STR_ONION", r"\b[a-z2-7]{16,56}\.onion\b", S.MEDIUM, "Tor .onion address"),
    ("STR_PASTE_SITE", r"(pastebin\.com/raw|transfer\.sh|anonfiles)", S.MEDIUM,
     "Anonymous file/paste hosting reference"),
    ("STR_RAW_IP_URL", r"https?://\d{1,3}(\.\d{1,3}){3}", S.LOW, "URL pointing at a raw IP address"),
    ("STR_CMD_C", r"cmd(\.exe)?\s+/c", S.LOW, "cmd /c command execution"),
    ("STR_WSCRIPT", r"\b(wscript|cscript)(\.exe)?\s", S.LOW, "Windows Script Host invocation"),
]
_COMPILED_PATTERNS = [(rid, re.compile(rx, re.I), sev, title) for rid, rx, sev, title in STRING_PATTERNS]
_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,200}")


# --- helpers ---------------------------------------------------------------

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _perm_string(chars: int) -> str:
    return (("R" if chars & IMAGE_SCN_MEM_READ else "-")
            + ("W" if chars & IMAGE_SCN_MEM_WRITE else "-")
            + ("X" if chars & IMAGE_SCN_MEM_EXECUTE else "-"))


def _clean_name(raw: bytes) -> str:
    text = raw.rstrip(b"\x00").decode("latin-1")
    return "".join(c if c.isprintable() else "?" for c in text)


def _sev_for(hits: int, thresholds):
    sev = None
    for min_hits, s in thresholds:
        if hits >= min_hits:
            sev = s
    return sev


# --- pure, individually testable checks ------------------------------------

def classify_imports(names) -> list[Finding]:
    original = {n.lower(): n for n in names}
    found = set(original)
    findings: list[Finding] = []
    for key, (title, apis, thresholds) in API_GROUPS.items():
        hit = sorted(found & apis)
        sev = _sev_for(len(hit), thresholds)
        if sev:
            findings.append(Finding(
                f"PE_API_{key.upper()}", title, sev,
                "Imports: " + ", ".join(original[h] for h in hit), "pe-imports"))
    dl_hit = found & API_GROUPS["download"][1]
    exec_hit = found & EXEC_APIS
    if dl_hit and exec_hit:
        findings.append(Finding(
            "PE_API_DOWNLOAD_EXEC", "Download-and-execute capability", S.MEDIUM,
            "Imports: " + ", ".join(original[h] for h in sorted(dl_hit | exec_hit)),
            "pe-imports"))
    return findings


def scan_strings(data: bytes, extra_rules=None) -> tuple[list[Finding], list[str]]:
    buf = data[:MAX_STRING_SCAN]
    parts = [s.decode("ascii") for s in _ASCII_RE.findall(buf)]
    parts += [s.decode("utf-16le", errors="ignore") for s in _UTF16_RE.findall(buf)]
    text = "\n".join(parts)[:8_000_000]
    findings = []
    for rule_id, pattern, sev, title in _COMPILED_PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append(Finding(rule_id, title, sev, f"Matched: {m.group(0)[:100]!r}", "pe-strings"))
    for rule in extra_rules or []:  # analyst-defined rules from the intel database
        try:
            m = re.search(rule["regex"], text, re.I)
        except re.error:
            continue
        if m:
            findings.append(Finding(
                f"RULE_{rule['name']}", rule.get("description") or rule["name"],
                S(rule.get("severity", "high")), f"Matched: {m.group(0)[:100]!r}", "custom-rule"))
    urls = list(dict.fromkeys(_URL_RE.findall(text)))[:15]
    return findings, urls


# --- PE inspection ---------------------------------------------------------

def analyze(data: bytes, extra_rules=None) -> tuple[list[Finding], dict]:
    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as exc:
        return [Finding(
            "PE_MALFORMED", "PE header could not be parsed", S.MEDIUM,
            f"{exc}. Corrupt, or crafted to break analysis tools.", "pe")], {}
    findings: list[Finding] = []
    meta: dict = {}
    try:
        _header_checks(pe, findings, meta)
        _section_checks(pe, findings, meta)
        _import_checks(pe, findings, meta)
        _resource_checks(pe, findings, meta)
        _overlay_checks(pe, data, findings, meta)
        str_findings, urls = scan_strings(data, extra_rules)
        findings += str_findings
        meta["urls"] = urls
    finally:
        pe.close()
    return findings, meta


def _datadir(pe, index):
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return dirs[index] if len(dirs) > index else None


def _header_checks(pe, findings, meta):
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    is_dll = bool(fh.Characteristics & 0x2000)
    com = _datadir(pe, DIR_COM_DESCRIPTOR)
    meta["is_dll"] = is_dll
    meta["is_dotnet"] = bool(com and com.VirtualAddress)
    meta["machine"] = pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))
    meta["subsystem"] = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, oh.Subsystem)
    meta["entry_point_rva"] = hex(oh.AddressOfEntryPoint)
    ts = fh.TimeDateStamp
    meta["compile_time"] = (dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat() if ts else None)
    warnings = pe.get_warnings()
    meta["parser_warnings"] = len(warnings)

    if meta["is_dotnet"]:
        findings.append(Finding(
            "PE_DOTNET", ".NET managed assembly", S.INFO,
            "Native-PE checks apply, but managed (IL) analysis is not implemented yet.", "pe"))
    if ts and dt.datetime.fromtimestamp(ts, dt.timezone.utc) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1):
        findings.append(Finding(
            "PE_TIMESTAMP_FUTURE", "Compile timestamp is in the future", S.LOW,
            "Forged timestamp, or a reproducible-build hash (common with MSVC /Brepro).", "pe"))
    if len(warnings) >= 5:
        findings.append(Finding(
            "PE_PARSER_WARNINGS", "Many structural anomalies in PE headers", S.LOW,
            f"{len(warnings)} parser warnings; first: {warnings[0][:120]}", "pe"))
    if oh.CheckSum and not pe.verify_checksum():
        findings.append(Finding(
            "PE_BAD_CHECKSUM", "Header checksum does not match file contents", S.LOW,
            "File may have been patched or modified after it was built.", "pe"))

    sec = _datadir(pe, DIR_SECURITY)
    signed = bool(sec and sec.VirtualAddress and sec.Size)
    meta["authenticode_present"] = signed
    findings.append(Finding(
        "PE_SIGNATURE", "Authenticode signature present (NOT verified)" if signed else "No Authenticode signature",
        S.INFO, "Signature chain/revocation validation is not implemented yet; presence proves nothing.", "pe"))


def _section_checks(pe, findings, meta):
    sections = []
    packer_hits, odd_names = set(), []
    last = len(pe.sections) - 1
    for i, s in enumerate(pe.sections):
        name = _clean_name(s.Name)
        raw = s.get_data()
        ent = entropy(raw) if len(raw) >= 512 else 0.0
        chars = s.Characteristics
        is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        sections.append({"name": name, "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                         "entropy": round(ent, 2), "perms": _perm_string(chars)})
        lname = name.lower()
        if lname in PACKER_SECTIONS:
            packer_hits.add(PACKER_SECTIONS[lname])
        elif lname not in STANDARD_SECTIONS and not name.startswith("/"):
            odd_names.append(name)
        if is_exec and ent >= 7.0:
            findings.append(Finding(
                "PE_SECTION_ENTROPY", f"High-entropy executable section '{name}'", S.MEDIUM,
                f"Entropy {ent:.2f}/8.0 suggests packed or encrypted code.", "pe-sections"))
        elif not is_exec and ent >= 7.5 and s.SizeOfRawData >= 16384 and lname != ".rsrc":
            findings.append(Finding(
                "PE_DATA_ENTROPY", f"High-entropy data section '{name}'", S.LOW,
                f"Entropy {ent:.2f}/8.0; compressed or encrypted payload data.", "pe-sections"))
        if is_exec and chars & IMAGE_SCN_MEM_WRITE:
            findings.append(Finding(
                "PE_SECTION_RWX", f"Section '{name}' is writable and executable", S.MEDIUM,
                "Self-modifying or unpacking code; legitimate software rarely needs this.", "pe-sections"))
        if is_exec and s.SizeOfRawData == 0 and s.Misc_VirtualSize >= 0x1000:
            findings.append(Finding(
                "PE_SECTION_EMPTY_EXEC", f"Executable section '{name}' has no raw data", S.MEDIUM,
                "Code is created at runtime (classic packer unpacking space).", "pe-sections"))
    meta["sections"] = sections

    if packer_hits:
        findings.append(Finding(
            "PE_PACKER", "Packer/protector section names", S.MEDIUM,
            "Detected: " + ", ".join(sorted(packer_hits)) + ". Packers are also used by legitimate software.",
            "pe-sections"))
    if odd_names:
        findings.append(Finding(
            "PE_ODD_SECTIONS", "Non-standard section names", S.LOW,
            ", ".join(odd_names[:10]), "pe-sections"))

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep == 0:
        if not meta["is_dll"]:
            findings.append(Finding("PE_EP_ZERO", "Executable has no entry point", S.MEDIUM, "", "pe"))
        return
    sec = pe.get_section_by_rva(ep)
    if sec is None:
        findings.append(Finding(
            "PE_EP_OUTSIDE", "Entry point is outside every section", S.HIGH,
            f"RVA {hex(ep)}. Typical of corrupted, infected or hand-crafted binaries.", "pe"))
        return
    idx = list(pe.sections).index(sec)
    if idx == last and last > 0:
        findings.append(Finding(
            "PE_EP_LAST_SECTION", "Entry point is in the last section", S.MEDIUM,
            "Common for packers and file infectors.", "pe"))
    if not sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
        findings.append(Finding(
            "PE_EP_NONEXEC", "Entry point is in a non-executable section", S.MEDIUM, "", "pe"))


def _import_checks(pe, findings, meta):
    names, dlls, ordinals = [], set(), 0
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, []):
            dll = (entry.dll or b"").decode("latin-1").lower()
            dlls.add(dll)
            for imp in entry.imports:
                if imp.name:
                    names.append(imp.name.decode("latin-1"))
                else:
                    ordinals += 1
    try:
        imphash = pe.get_imphash()
    except Exception:  # noqa: BLE001 - malformed import tables
        imphash = ""
    meta["imports"] = {"count": len(names), "ordinal_only": ordinals,
                       "dlls": sorted(dlls)[:50], "imphash": imphash}

    if not meta["is_dotnet"]:
        if not names and not ordinals:
            findings.append(Finding(
                "PE_NO_IMPORTS", "No import table", S.MEDIUM,
                "Either packed, or resolves every API at runtime (loader/shellcode pattern).", "pe-imports"))
        elif 0 < len(names) <= 6:
            findings.append(Finding(
                "PE_FEW_IMPORTS", f"Very few imports ({len(names)})", S.MEDIUM,
                "Often means the real imports are resolved at runtime after unpacking.", "pe-imports"))
    findings.extend(classify_imports(names))


def _walk_resources(pe):
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return

    def walk(entries, path):
        for e in entries:
            label = e.name.decode("latin-1") if getattr(e, "name", None) else e.id
            if hasattr(e, "directory"):
                yield from walk(e.directory.entries, path + [label])
            elif hasattr(e, "data"):
                try:
                    blob = pe.get_data(e.data.struct.OffsetToData, e.data.struct.Size)
                except Exception:  # noqa: BLE001
                    continue
                yield path + [label], blob

    yield from walk(root.entries, [])


def _resource_checks(pe, findings, meta):
    count = 0
    embedded_exe = high_entropy = None
    try:
        for path, blob in _walk_resources(pe):
            count += 1
            if count > MAX_RESOURCE_BLOBS:
                break
            top = path[0] if path else None
            label = "/".join(str(p) for p in path)
            if len(blob) >= 64 and blob[:2] == b"MZ" and embedded_exe is None:
                embedded_exe = f"{label} ({len(blob)} bytes)"
            elif (isinstance(top, str) or top == 10) and len(blob) >= 4096 and entropy(blob) >= 7.5 \
                    and high_entropy is None:
                high_entropy = f"{label} ({len(blob)} bytes)"
    except Exception:  # noqa: BLE001 - malformed resource tree is itself noteworthy but not fatal
        findings.append(Finding("PE_RSRC_MALFORMED", "Resource directory is malformed", S.LOW, "", "pe-resources"))
    meta["resource_blobs"] = min(count, MAX_RESOURCE_BLOBS)
    if embedded_exe:
        findings.append(Finding(
            "PE_RSRC_EXE", "Executable embedded in resources", S.HIGH,
            f"Resource {embedded_exe}. Classic dropper layout.", "pe-resources"))
    if high_entropy:
        findings.append(Finding(
            "PE_RSRC_ENCRYPTED", "High-entropy custom/RCDATA resource", S.MEDIUM,
            f"Resource {high_entropy}: likely an encrypted or compressed payload.", "pe-resources"))


def _overlay_checks(pe, data, findings, meta):
    start = pe.get_overlay_data_start_offset()
    meta["overlay_size"] = 0
    if start is None or start >= len(data):
        return
    end = len(data)
    sec = _datadir(pe, DIR_SECURITY)
    if sec and sec.VirtualAddress and sec.Size and start <= sec.VirtualAddress < end:
        end = sec.VirtualAddress  # the certificate table is not "extra" data
    overlay = data[start:end]
    meta["overlay_size"] = len(overlay)
    if not overlay:
        return
    if overlay[:2] == b"MZ":
        findings.append(Finding(
            "PE_OVERLAY_EXE", "Executable appended after the PE image", S.HIGH,
            f"{len(overlay)} bytes of overlay start with an MZ header.", "pe-overlay"))
    elif overlay[:4] == b"PK\x03\x04":
        findings.append(Finding(
            "PE_OVERLAY_ZIP", "ZIP archive appended after the PE image", S.MEDIUM,
            "Self-extractor or dropper layout.", "pe-overlay"))
    elif len(overlay) >= 4096 and entropy(overlay[:1 << 20]) >= 7.2:
        findings.append(Finding(
            "PE_OVERLAY_ENTROPY", "Large high-entropy overlay", S.MEDIUM,
            f"{len(overlay)} bytes. Encrypted payload, or a legitimate installer/SFX archive.", "pe-overlay"))
