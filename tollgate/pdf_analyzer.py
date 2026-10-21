"""Structural analysis of PDF files: objects, streams, actions, JavaScript, embedded files, appended data.

Written from scratch as a bounded scanner (in the spirit of pdfid/pdf-parser). It never renders the PDF or runs any
script: JavaScript is only *read* and matched against indicator patterns. Decompression is capped to defeat bombs.
"""
from __future__ import annotations

import base64
import hashlib
import re
import zlib
from collections import Counter

from . import triage
from .models import Finding, Severity as S
from .textutil import safe

MAX_SCAN = 32 * 1024 * 1024
MAX_OBJECTS = 20000
MAX_STREAM_OUT = 8 * 1024 * 1024
MAX_ARTIFACT = 5 * 1024 * 1024
MAX_SCRIPTS = 20
MAX_EMBEDDED = 10

OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,10})[ \t\r\n]+(\d{1,5})[ \t\r\n]+obj\b")
STREAM_RE = re.compile(rb">>\s*stream(?:\r\n|\n|\r)")
HASH_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
NAME_RE = re.compile(rb"/([^\s/\[\]<>()%{}]{1,64})")
INTERESTING = {"JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "URI", "SubmitForm",
               "ImportData", "GoToR", "GoToE", "RichMedia", "XFA", "AcroForm", "Encrypt", "ObjStm", "JBIG2Decode", "Flash",
               "Movie", "Sound", "Names", "XObject"}
EXEC_EXTS = {"exe", "scr", "com", "pif", "dll", "cpl", "msi", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "ps1", "hta", "jar", "lnk"}
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>\\^|]+", re.I)

# JavaScript indicators (matched as text only; nothing is executed)
EXPLOIT_APIS = [r"util\.printf", r"util\.printd", r"Collab\.collectEmailInfo", r"Collab\.getIcon", r"media\.newPlayer",
                r"spell\.customDictionaryOpen", r"getAnnots", r"this\.getPageNthWord", r"doc\.syncAnnotScan", r"app\.launchURL",
                r"this\.exportDataObject", r"this\.importDataObject", r"this\.submitForm", r"app\.mailMsg", r"Net\.HTTP"]
_EXPLOIT_RE = re.compile("|".join(EXPLOIT_APIS), re.I)


# ----------------------------------------------------------------------------- low-level helpers

def _unhash(name: bytes) -> bytes:
    return HASH_RE.sub(lambda m: bytes([int(m.group(1), 16)]), name)


def read_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    """Read a PDF literal ( ... ) or hex < ... > string starting at `pos`. Returns (value, next position)."""
    n = len(buf)
    if pos >= n:
        return b"", pos
    if buf[pos] == 0x28:
        out, depth, i = bytearray(), 1, pos + 1
        esc = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
        while i < n and len(out) < 2_000_000:
            c = buf[i]
            if c == 0x5C:
                i += 1
                if i >= n:
                    break
                e = buf[i]
                if e in esc:
                    out.append(esc[e]); i += 1
                elif 0x30 <= e <= 0x37:
                    val = cnt = 0
                    while i < n and cnt < 3 and 0x30 <= buf[i] <= 0x37:
                        val, i, cnt = val * 8 + buf[i] - 0x30, i + 1, cnt + 1
                    out.append(val & 0xFF)
                elif e in (10, 13):
                    i += 1
                    if e == 13 and i < n and buf[i] == 10:
                        i += 1
                else:
                    out.append(e); i += 1
                continue
            if c == 0x28:
                depth += 1
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    return bytes(out), i + 1
            out.append(c)
            i += 1
        return bytes(out), i
    if buf[pos] == 0x3C and buf[pos:pos + 2] != b"<<":
        end = buf.find(b">", pos + 1)
        end = min(len(buf), pos + 1 + 400_000) if end < 0 else end
        digits = re.sub(rb"[^0-9A-Fa-f]", b"", buf[pos + 1:end])
        digits += b"0" * (len(digits) % 2)
        return bytes.fromhex(digits.decode()), end + 1
    return b"", pos


def _text(raw: bytes) -> str:
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16be", "replace")
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16le", "replace")
    return raw.decode("utf-8", "replace") if b"\x00" not in raw else raw.decode("latin-1", "replace")


def _inflate(data: bytes, limit: int) -> tuple[bytes, bool]:
    """Decompress zlib data, capped at `limit` bytes. Returns (output, hit_limit). Salvages output from damaged streams."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, limit + 1)
        return out[:limit], len(out) > limit
    except zlib.error:
        d, out = zlib.decompressobj(), bytearray()
        try:
            for i in range(0, len(data), 512):
                out += d.decompress(data[i:i + 512], max(0, limit - len(out)) + 1)
                if len(out) > limit:
                    return bytes(out[:limit]), True
        except zlib.error:
            pass
        return bytes(out), False


def decode_stream(raw: bytes, filters: list[str]) -> tuple[bytes | None, str]:
    """Apply a filter chain. Returns (data or None, note). note is '' | 'limit' | 'unsupported:<name>' | 'error'."""
    data, note = raw, ""
    for name in filters:
        try:
            if name in ("FlateDecode", "Fl"):
                data, hit = _inflate(data, MAX_STREAM_OUT)
                note = "limit" if hit else note
            elif name in ("ASCIIHexDecode", "AHx"):
                digits = re.sub(rb"[^0-9A-Fa-f]", b"", data.split(b">")[0])
                data = bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode())
            elif name in ("ASCII85Decode", "A85"):
                s = data.strip()
                s = s[2:] if s.startswith(b"<~") else s
                end = s.find(b"~>")
                data = base64.a85decode(s[:end] if end >= 0 else s)
            elif name in ("RunLengthDecode", "RL"):
                out, i = bytearray(), 0
                while i < len(data) and len(out) < MAX_STREAM_OUT:
                    n = data[i]
                    if n == 128:
                        break
                    if n < 128:
                        out += data[i + 1:i + 2 + n]; i += 2 + n
                    else:
                        out += data[i + 1:i + 2] * (257 - n); i += 2
                data = bytes(out)
            else:
                return None, f"unsupported:{name}"
        except (ValueError, zlib.error):
            return None, "error"
    return data, note


class Obj:
    __slots__ = ("num", "dict", "norm", "stream", "filters", "from_objstm")

    def __init__(self, num: int, dict_bytes: bytes, stream: bytes | None, from_objstm: bool = False):
        self.num, self.dict, self.stream, self.from_objstm = num, dict_bytes, stream, from_objstm
        self.norm = _unhash(dict_bytes)
        m = re.search(rb"/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)", self.norm)
        self.filters = [f.decode() for f in re.findall(rb"/([A-Za-z0-9]+)", m.group(1))] if m else []


# ----------------------------------------------------------------------------- JavaScript indicators

def analyze_js(code: str) -> list[Finding]:
    f: list[Finding] = []
    if re.search(r"(?:%u[0-9a-fA-F]{4}){12,}|(?:\\u[0-9a-fA-F]{4}){12,}", code):
        f.append(Finding("PDF_JS_SHELLCODE_ESCAPES", "JavaScript contains long %u/\\u escape runs (shellcode / heap-spray pattern)",
                         S.HIGH, "", "pdf"))
    if re.search(r"unescape\s*\(", code, re.I) and re.search(r"eval\s*\(", code, re.I):
        f.append(Finding("PDF_JS_EVAL_UNESCAPE", "JavaScript decodes and evaluates hidden code (eval + unescape)", S.HIGH, "", "pdf"))
    elif re.search(r"\beval\s*\(", code):
        f.append(Finding("PDF_JS_EVAL", "JavaScript uses eval()", S.MEDIUM, "", "pdf"))
    hits = sorted({m.group(0).lower() for m in _EXPLOIT_RE.finditer(code)})
    if hits:
        f.append(Finding("PDF_JS_EXPLOIT_API", "JavaScript calls APIs historically abused to exploit or exfiltrate", S.HIGH,
                         "APIs: " + ", ".join(hits[:8]), "pdf"))
    if len(re.findall(r"String\.fromCharCode", code)) >= 5 or len(re.findall(r"\\x[0-9a-fA-F]{2}", code)) >= 50:
        f.append(Finding("PDF_JS_OBFUSCATED", "JavaScript looks obfuscated (fromCharCode / hex escapes)", S.MEDIUM, "", "pdf"))
    return f


# ----------------------------------------------------------------------------- main analysis

def analyze(data: bytes) -> tuple[list[Finding], dict, list[tuple[str, bytes]]]:
    findings: list[Finding] = []
    artifacts: list[tuple[str, bytes]] = []
    emitted: set[str] = set()

    def add(rule, title, sev, detail=""):
        if rule not in emitted:
            emitted.add(rule)
            findings.append(Finding(rule, title, sev, safe(detail, 400), "pdf"))

    truncated = len(data) > MAX_SCAN
    buf = data[:MAX_SCAN]
    meta: dict = {"version": None, "objects": 0, "streams": 0, "pages": 0, "keywords": {}, "obfuscated_names": [], "uris": [],
                  "urls": [], "scripts": [], "embedded": [], "info": {}, "eof_count": 0, "appended_bytes": 0,
                  "header_offset": None, "encrypted": False, "filter_chains": 0, "truncated_scan": truncated}
    if truncated:
        add("PDF_LARGE", "Only the first 32 MB of a very large PDF were analysed", S.LOW)

    hdr = buf.find(b"%PDF-")
    if hdr >= 0:
        meta["header_offset"] = hdr
        meta["version"] = safe(buf[hdr + 5:hdr + 8].decode("latin-1"), 5)
        if hdr > 8:
            add("PDF_JUNK_BEFORE_HEADER", "Data before the %PDF header (polyglot / evasion)", S.MEDIUM, f"{hdr} bytes precede the header")

    # --- objects
    objs: dict[int, Obj] = {}
    ordered: list[Obj] = []
    for m in OBJ_RE.finditer(buf):
        if len(ordered) >= MAX_OBJECTS:
            add("PDF_OBJECT_LIMIT", f"More than {MAX_OBJECTS} objects; analysis truncated", S.LOW)
            break
        start = m.end()
        end = buf.find(b"endobj", start)
        end = len(buf) if end < 0 else end
        body = buf[start:end]
        sm = STREAM_RE.search(body)
        if sm:
            stream_end = body.rfind(b"endstream")
            raw = body[sm.end():stream_end if stream_end >= sm.end() else len(body)]
            obj = Obj(int(m.group(1)), body[:sm.start() + 2], raw)
            meta["streams"] += 1
        else:
            obj = Obj(int(m.group(1)), body, None)
        objs[obj.num] = obj
        ordered.append(obj)
    meta["objects"] = len(ordered)

    budget = {"decoded": 0, "limit": False}

    def decoded(o: Obj) -> bytes | None:
        if o.stream is None:
            return None
        out, note = decode_stream(o.stream, o.filters)
        if note == "limit":
            budget["limit"] = True
        if out is not None:
            budget["decoded"] += len(out)
        return out

    # --- object streams: expand into sub-objects so hidden actions are seen
    for o in list(ordered):
        if b"/ObjStm" in o.norm and o.stream is not None:
            body = decoded(o)
            nm, fm = re.search(rb"/N\s+(\d+)", o.norm), re.search(rb"/First\s+(\d+)", o.norm)
            if not body or not nm or not fm:
                continue
            n, first = min(int(nm.group(1)), 5000), int(fm.group(1))
            pairs = [int(x) for x in re.findall(rb"\d+", body[:first])][:2 * n]
            nums, offs = pairs[0::2], pairs[1::2]
            for idx, (num, off) in enumerate(zip(nums, offs)):
                stop = first + offs[idx + 1] if idx + 1 < len(offs) else len(body)
                sub = Obj(num, body[first + off:stop], None, from_objstm=True)
                objs.setdefault(num, sub)
                ordered.append(sub)

    # --- keywords (names normalised so /J#61vaScript counts as /JavaScript)
    counts: Counter = Counter()
    obfuscated: list[str] = []
    for o in ordered:
        for raw_name in NAME_RE.findall(o.dict):
            name = _unhash(raw_name).decode("latin-1")
            counts[name] += 1
            if b"#" in raw_name and name in INTERESTING and len(obfuscated) < 10:
                obfuscated.append(f"/{raw_name.decode('latin-1')} -> /{name}")
    if not ordered:
        for raw_name in NAME_RE.findall(buf[:4_000_000]):
            counts[_unhash(raw_name).decode("latin-1")] += 1
    meta["keywords"] = {k: counts[k] for k in sorted(INTERESTING) if counts[k]}
    meta["obfuscated_names"] = [safe(x, 80) for x in obfuscated]
    meta["pages"] = sum(len(re.findall(rb"/Type\s*/Page\b", o.norm)) for o in ordered)
    meta["encrypted"] = counts["Encrypt"] > 0
    if obfuscated:
        add("PDF_OBFUSCATED_NAMES", "Keywords hidden with #xx name escapes", S.HIGH, "; ".join(obfuscated[:4]))

    # --- JavaScript
    scripts: list[tuple[str, str, bool]] = []     # (origin, code, hidden_in_objstm)

    def resolve(norm: bytes, pos: int) -> str | None:
        while pos < len(norm) and norm[pos] in b" \t\r\n":
            pos += 1
        if norm[pos:pos + 1] in (b"(", b"<") and norm[pos:pos + 2] != b"<<":
            return _text(read_string(norm, pos)[0])
        rm = re.match(rb"(\d+)\s+\d+\s+R", norm[pos:pos + 30])
        if rm and int(rm.group(1)) in objs:
            target = objs[int(rm.group(1))]
            if target.stream is not None:
                body = decoded(target)
                return _text(body) if body is not None else None
            first = re.search(rb"[(<]", target.norm)
            if first and target.norm[first.start():first.start() + 2] != b"<<":
                return _text(read_string(target.norm, first.start())[0])
        return None

    for o in ordered:
        for m in re.finditer(rb"/JS\b", o.norm):
            if len(scripts) >= MAX_SCRIPTS:
                break
            code = resolve(o.norm, m.end())
            if code:
                scripts.append((f"object {o.num}", code[:256 * 1024], o.from_objstm))
    for o in ordered:                                                     # XFA form scripts
        for m in re.finditer(rb"/XFA\s*(?:\[([^\]]*)\]|(\d+)\s+\d+\s+R)", o.norm):
            refs = re.findall(rb"(\d+)\s+\d+\s+R", m.group(1) or b"") or ([m.group(2)] if m.group(2) else [])
            for ref in refs[:8]:
                target = objs.get(int(ref))
                body = decoded(target) if target is not None else None
                for sm in re.finditer(rb"<script[^>]*>(.*?)</script>", body or b"", re.S | re.I):
                    if len(scripts) < MAX_SCRIPTS:
                        scripts.append((f"XFA object {target.num}", _text(sm.group(1))[:256 * 1024], False))
    has_js = bool(scripts) or counts["JavaScript"] > 0 or counts["JS"] > 0
    for n, (origin, code, hidden) in enumerate(scripts, 1):
        meta["scripts"].append({"origin": origin, "size": len(code), "sha256": hashlib.sha256(code.encode("utf-8", "replace")).hexdigest(),
                                "preview": safe(code[:200], 200)})
        artifacts.append((f"PDF JavaScript #{n} ({origin})", code.encode("utf-8", "replace")))
        for finding in analyze_js(code):
            add(finding.rule_id, finding.title, finding.severity, finding.detail)
        meta["urls"].extend(_URL_RE.findall(code))
        if hidden:
            add("PDF_ACTIVE_IN_OBJSTM", "Script hidden inside an object stream", S.MEDIUM,
                "Active content is stored where simple scanners do not look.")
    if has_js:
        add("PDF_JAVASCRIPT", "PDF contains JavaScript", S.MEDIUM, f"{len(scripts)} script(s) extracted")
        if counts["OpenAction"] or counts["AA"]:
            add("PDF_AUTO_JS", "JavaScript is wired to run automatically (OpenAction / AA)", S.HIGH, "")
    if counts["Encrypt"] and has_js:
        add("PDF_ENCRYPTED_ACTIVE", "Encrypted PDF that also contains JavaScript (evasion)", S.MEDIUM, "")

    # --- other active content
    launch = []
    for o in ordered:
        if b"/Launch" in o.norm:
            window = o.norm[o.norm.find(b"/Launch"):][:800]
            for sm in re.finditer(rb"/(?:F|P|Win|UF)\s*\(", window):
                launch.append(_text(read_string(window, sm.end() - 1)[0]))
            if o.from_objstm:
                add("PDF_ACTIVE_IN_OBJSTM", "Script hidden inside an object stream", S.MEDIUM, "Launch action stored in an object stream")
    if counts["Launch"]:
        add("PDF_LAUNCH", "PDF can launch a program (/Launch action)", S.HIGH, "Command: " + safe(" ".join(launch[:3]) or "unknown", 200))
    for key, rule, title, sev in (("RichMedia", "PDF_RICHMEDIA", "Embedded rich media / Flash", S.MEDIUM),
                                  ("Flash", "PDF_RICHMEDIA", "Embedded rich media / Flash", S.MEDIUM),
                                  ("XFA", "PDF_XFA", "XFA forms (frequently abused)", S.LOW),
                                  ("SubmitForm", "PDF_SUBMITFORM", "Form data can be sent to a remote server", S.MEDIUM),
                                  ("ImportData", "PDF_IMPORTDATA", "ImportData action", S.MEDIUM),
                                  ("JBIG2Decode", "PDF_JBIG2", "JBIG2 image decoder in use (historic exploit target)", S.LOW)):
        if counts[key]:
            add(rule, title, sev, f"/{key} x{counts[key]}")
    for o in ordered:
        if b"/GoToR" in o.norm or b"/GoToE" in o.norm:
            fm = re.search(rb"/F\s*\(", o.norm)
            target = _text(read_string(o.norm, fm.end() - 1)[0]) if fm else ""
            unc = target.startswith("\\\\") or target.lower().startswith(("http", "file:"))
            add("PDF_GOTO_REMOTE", "Action jumps to a remote or external document", S.HIGH if unc else S.MEDIUM,
                f"Target: {safe(target, 150)}" if target else "")

    # --- links
    uris = []
    for o in ordered:
        for m in re.finditer(rb"/URI\s*[(<]", o.norm):
            uri = _text(read_string(o.norm, m.end() - 1)[0]).strip()
            if uri and uri not in uris:
                uris.append(uri)
    meta["uris"] = [safe(u, 300) for u in uris[:50]]
    meta["urls"] = list(dict.fromkeys(uris + meta["urls"]))[:15]

    # --- embedded files
    embedded_streams: dict[int, str] = {}
    for o in ordered:
        em = re.search(rb"/EF\s*<<\s*/(?:F|UF)\s+(\d+)\s+\d+\s+R", o.norm)
        if em:
            name = ""
            for key in (rb"/UF\s*[(<]", rb"/F\s*[(<]"):
                nm = re.search(key, o.norm)
                if nm:
                    name = _text(read_string(o.norm, nm.end() - 1)[0])
                    break
            embedded_streams[int(em.group(1))] = name
    for o in ordered:
        if o.stream is not None and rb"/EmbeddedFile" in o.norm and o.num not in embedded_streams:
            embedded_streams[o.num] = ""
    for num, name in list(embedded_streams.items())[:MAX_EMBEDDED]:
        target = objs.get(num)
        body = decoded(target) if target is not None else None
        if body is None:
            continue
        kind = triage.detect_type(body[:4096])
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        info = {"name": safe(name, 100), "size": len(body), "type": kind, "sha256": hashlib.sha256(body).hexdigest()}
        meta["embedded"].append(info)
        artifacts.append((f"embedded file '{safe(name or f'object {num}', 60)}'", body[:MAX_ARTIFACT]))
        if kind in ("pe", "dos-mz", "elf", "lnk"):
            add("PDF_EMBEDDED_EXEC", "PDF carries an embedded executable or shortcut", S.HIGH, f"{safe(name, 80)} ({kind}, {len(body)} bytes)")
        elif ext in EXEC_EXTS or kind == "script":
            add("PDF_EMBEDDED_SCRIPT", "PDF carries an embedded script or executable-type file", S.HIGH, f"{safe(name, 80)} ({kind})")
        elif kind in ("zip", "ole"):
            add("PDF_EMBEDDED_ARCHIVE", "PDF carries an embedded archive or Office document", S.MEDIUM, f"{safe(name, 80)} ({kind})")
        else:
            add("PDF_EMBEDDED_FILE", "PDF carries an embedded file", S.LOW, f"{safe(name, 80)} ({kind})")

    # --- structure
    chains = [o for o in ordered if len(o.filters) >= 3]
    meta["filter_chains"] = len(chains)
    if chains:
        add("PDF_FILTER_CHAIN", "Streams use three or more stacked filters (evasion)", S.MEDIUM, f"e.g. object {chains[0].num}: {'+'.join(chains[0].filters)}")
    if budget["limit"]:
        add("PDF_DECOMP_LIMIT", "A stream hit the decompression limit (possible zip bomb)", S.MEDIUM, f"cap {MAX_STREAM_OUT // 1024 // 1024} MB per stream")
    eofs = [m.start() for m in re.finditer(rb"%%EOF", buf)]
    meta["eof_count"] = len(eofs)
    if eofs:
        tail = buf[eofs[-1] + 5:].strip(b"\r\n\t \x00")
        meta["appended_bytes"] = len(tail)
        if len(tail) > 1024:
            add("PDF_DATA_AFTER_EOF", f"{len(tail)} bytes of data after the final %%EOF", S.HIGH,
                f"Appended content looks like: {triage.detect_type(tail[:4096])}")
            artifacts.append(("data appended after PDF end", tail[:MAX_ARTIFACT]))
        elif len(tail) > 64:
            add("PDF_BYTES_AFTER_EOF", f"{len(tail)} bytes after the final %%EOF", S.MEDIUM, "")
    elif hdr >= 0:
        add("PDF_NO_EOF", "No %%EOF marker (truncated or damaged)", S.LOW)
    n_end = buf.count(b"endobj")
    top_level = sum(1 for o in ordered if not o.from_objstm)
    if hdr >= 0 and not ordered:
        add("PDF_NO_OBJECTS", "No PDF objects could be parsed", S.MEDIUM, "Damaged, encrypted container, or deliberately malformed.")
    elif abs(top_level - n_end) > max(2, n_end // 20):
        add("PDF_STRUCTURE_BROKEN", "Object and endobj counts disagree", S.LOW, f"{top_level} obj / {n_end} endobj")

    for key, tag in (("Producer", "producer"), ("Creator", "creator"), ("Title", "title"), ("Author", "author")):
        for o in ordered[:2000]:
            m = re.search(rb"/" + key.encode() + rb"\s*[(<]", o.norm)
            if m:
                meta["info"][tag] = safe(_text(read_string(o.norm, m.end() - 1)[0]), 120)
                break
    return findings, meta, artifacts
