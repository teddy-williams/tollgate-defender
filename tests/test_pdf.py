import os
import random
import zlib

from tollgate import pdf_analyzer as P
from tollgate.models import Severity
from tests.helpers import CODE, benign_pdf, build_pdf, build_pe, pdf_stream

CATALOG = b"<< /Type /Catalog /Pages 2 0 R %s >>"
PAGES = {2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", 3: b"<< /Type /Page /Parent 2 0 R >>"}


def doc(catalog_extra=b"", **extra):
    objs = {1: CATALOG % catalog_extra, **PAGES}
    objs.update(extra)
    return objs


def ids(findings):
    return {f.rule_id for f in findings}


def run(data):
    return P.analyze(data)


def test_benign_pdf_is_quiet():
    f, meta, art = run(benign_pdf())
    assert f == [] and art == []
    assert meta["pages"] == 1 and meta["info"]["producer"] == "Test Producer" and meta["version"] == "1.7"


def test_inline_javascript_with_openaction():
    pdf = build_pdf({1: CATALOG % b"/OpenAction 4 0 R", **PAGES, 4: b"<< /S /JavaScript /JS (app.alert\\(1\\)) >>"})
    f, meta, art = run(pdf)
    assert {"PDF_JAVASCRIPT", "PDF_AUTO_JS"} <= ids(f)
    assert meta["scripts"][0]["size"] == len("app.alert(1)") and art[0][1] == b"app.alert(1)"


def test_javascript_in_compressed_stream_by_reference():
    pdf = build_pdf({1: CATALOG % b"/OpenAction 4 0 R", **PAGES, 4: b"<< /S /JavaScript /JS 5 0 R >>",
                     5: pdf_stream(data=b"eval(unescape('%61%6c%65%72%74'))")})
    f, meta, art = run(pdf)
    assert "PDF_JS_EVAL_UNESCAPE" in ids(f) and b"eval" in art[0][1]


def test_obfuscated_names():
    pdf = build_pdf({1: CATALOG % b"/OpenAct#69on 4 0 R", **PAGES, 4: b"<< /S /J#61vaScript /J#53 (x=1;) >>"})
    f, meta, _ = run(pdf)
    assert "PDF_OBFUSCATED_NAMES" in ids(f)
    assert meta["keywords"].get("JavaScript") == 1 and meta["keywords"].get("OpenAction") == 1
    assert "PDF_AUTO_JS" in ids(f)


def test_script_hidden_in_object_stream():
    inner = b"<< /S /JavaScript /JS (app.launchURL\\('http://evil.example/x'\\)) >>"
    header = b"7 0 "
    objstm = pdf_stream(extra=b"/Type /ObjStm /N 1 /First %d" % len(header), data=header + inner)
    pdf = build_pdf({1: CATALOG % b"/OpenAction 7 0 R", **PAGES, 6: objstm})
    f, meta, _ = run(pdf)
    assert {"PDF_JAVASCRIPT", "PDF_ACTIVE_IN_OBJSTM", "PDF_JS_EXPLOIT_API"} <= ids(f)
    assert any("evil.example" in u for u in meta["urls"])


def test_embedded_executable():
    pe = build_pe([(".text", b"\x90" * 300, CODE)])
    pdf = build_pdf(doc(b"/Names << /EmbeddedFiles << /Names [(update.exe) 5 0 R] >> >>", **{
        "5": b"<< /Type /Filespec /F (update.exe) /UF (update.exe) /EF << /F 6 0 R >> >>",
        "6": pdf_stream(extra=b"/Type /EmbeddedFile", data=pe)}))
    f, meta, art = run(pdf)
    top = next(x for x in f if x.rule_id == "PDF_EMBEDDED_EXEC")
    assert top.severity == Severity.HIGH
    assert meta["embedded"][0]["type"] == "pe" and meta["embedded"][0]["name"] == "update.exe"
    assert any(b == pe for _, b in art)


def test_embedded_script_by_name_only():
    pdf = build_pdf(doc(**{"5": b"<< /Type /Filespec /F (run.vbs) /EF << /F 6 0 R >> >>",
                           "6": pdf_stream(extra=b"/Type /EmbeddedFile", data=b"WScript.Echo 1\n")}))
    f, _, _ = run(pdf)
    assert "PDF_EMBEDDED_SCRIPT" in ids(f)


def test_launch_uri_and_remote_goto():
    pdf = build_pdf({1: CATALOG % b"/OpenAction 4 0 R", **PAGES,
                     4: b"<< /S /Launch /Win << /F (cmd.exe) /P (/c calc) >> >>",
                     5: b"<< /Subtype /Link /A << /S /URI /URI (http://evil.example/login) >> >>",
                     6: b"<< /S /GoToR /F (\\\\\\\\attacker.example\\\\share\\\\x.pdf) /D [0 /Fit] >>"})
    f, meta, _ = run(pdf)
    sev = {x.rule_id: x.severity for x in f}
    assert sev["PDF_LAUNCH"] == Severity.HIGH and sev["PDF_GOTO_REMOTE"] == Severity.HIGH
    assert any("cmd.exe" in x.detail for x in f if x.rule_id == "PDF_LAUNCH")
    assert meta["uris"] == ["http://evil.example/login"] and "http://evil.example/login" in meta["urls"]


def test_appended_data_after_eof_and_junk_header():
    pe = build_pe([(".text", b"\x90" * 2000, CODE)])
    f, meta, art = run(benign_pdf() + pe)
    assert "PDF_DATA_AFTER_EOF" in ids(f) and art[-1][1].startswith(b"MZ") and meta["appended_bytes"] > 1024
    assert "PDF_DATA_AFTER_EOF" not in ids(run(benign_pdf() + b"\r\n\r\n")[0])     # trailing newlines are normal
    f, _, _ = run(b"X" * 40 + benign_pdf())
    assert "PDF_JUNK_BEFORE_HEADER" in ids(f)


def test_filter_chain_and_decompression_limit():
    chained = build_pdf(doc(**{"5": pdf_stream(data=b"BT ET", filters=[b"/ASCIIHexDecode", b"/FlateDecode", b"/ASCII85Decode"], flate=False)}))
    assert "PDF_FILTER_CHAIN" in ids(run(chained)[0])
    bomb = zlib.compress(b"\x00" * (20 * 1024 * 1024), 9)
    pdf = build_pdf(doc(**{"5": b"<< /Type /Filespec /F (a.bin) /EF << /F 6 0 R >> >>",
                           "6": b"<< /Type /EmbeddedFile /Filter /FlateDecode /Length %d >>\nstream\n" % len(bomb) + bomb + b"\nendstream"}))
    f, meta, art = run(pdf)
    assert "PDF_DECOMP_LIMIT" in ids(f) and len(art[0][1]) <= P.MAX_ARTIFACT


def test_javascript_indicators():
    shell = "var s = unescape('" + "%u9090" * 20 + "'); "
    assert "PDF_JS_SHELLCODE_ESCAPES" in ids(P.analyze_js(shell))
    assert "PDF_JS_EXPLOIT_API" in ids(P.analyze_js("util.printf('%45000f', 1)"))
    assert "PDF_JS_OBFUSCATED" in ids(P.analyze_js("String.fromCharCode(1);" * 6))
    assert P.analyze_js("app.alert('hello');") == []


def test_encrypted_with_javascript():
    pdf = build_pdf({1: CATALOG % b"/Encrypt 9 0 R /OpenAction 4 0 R", **PAGES, 4: b"<< /S /JavaScript /JS (x) >>"})
    assert "PDF_ENCRYPTED_ACTIVE" in ids(run(pdf)[0])


def test_xfa_script_extracted():
    xml = b"<xdp><template><script contentType='application/x-javascript'>eval(unescape('%41'));</script></template></xdp>"
    pdf = build_pdf({1: CATALOG % b"/AcroForm 4 0 R", **PAGES, 4: b"<< /XFA 5 0 R >>", 5: pdf_stream(data=xml)})
    f, meta, _ = run(pdf)
    assert {"PDF_XFA", "PDF_JAVASCRIPT", "PDF_JS_EVAL_UNESCAPE"} <= ids(f)


def test_garbage_never_crashes():
    rng = random.Random(1234)
    base = benign_pdf()
    for _ in range(60):
        data = bytearray(base)
        for _ in range(rng.randint(1, 40)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        P.analyze(bytes(data[:rng.randint(20, len(data))]))
    P.analyze(b"%PDF-1.4\n" + os.urandom(5000))
    f, _, _ = P.analyze(b"%PDF-1.4\n")
    assert "PDF_NO_OBJECTS" in ids(f)


def test_engine_scans_embedded_files_and_javascript():
    from tollgate.db import Store
    from tollgate.engine import analyze_bytes
    pe = build_pe([(".text", b"\x90" * 300, CODE)])
    pdf = build_pdf(doc(b"/OpenAction 4 0 R", **{
        "4": b"<< /S /JavaScript /JS (var u='http://c2.badhost.example/x';) >>",
        "5": b"<< /Type /Filespec /F (update.exe) /EF << /F 6 0 R >> >>",
        "6": pdf_stream(extra=b"/Type /EmbeddedFile", data=pe)}))
    store = Store(":memory:")
    r = analyze_bytes(pdf, "statement.pdf", store)
    assert r.verdict in ("Suspicious", "Malicious") and "pdf" in r.metadata
    assert {"PDF_EMBEDDED_EXEC", "PDF_AUTO_JS"} <= {f.rule_id for f in r.findings}
    assert any(a["type"] == "pe" for a in r.metadata["artifacts"])
    # the embedded file's hash is later added to intel: a rescan is decisive, with the reason shown
    store.add_ioc("sha256", __import__("hashlib").sha256(pe).hexdigest(), family="DropperX", source="unit")
    r2 = analyze_bytes(pdf, "statement.pdf", store)
    hit = next(f for f in r2.findings if f.rule_id == "INTEL_HASH_MATCH")
    assert r2.verdict == "Malicious" and "update.exe" in hit.title
    # a domain that appears only inside the PDF's JavaScript is matched too
    store.add_ioc("domain", "badhost.example", family="DropperX", source="unit")
    assert "INTEL_URL_MATCH" in {f.rule_id for f in analyze_bytes(pdf, "statement.pdf", store).findings}
