import os

import pytest

from tollgate import yara_engine
from tollgate.engine import analyze_bytes
from tests.helpers import CODE, build_pe

pytestmark = pytest.mark.skipif(not yara_engine.available(), reason="yara-python not installed")
ROOT = os.path.dirname(os.path.dirname(__file__))
STARTER = os.path.join(ROOT, "tollgate", "rules")


def ids(report):
    return {f.rule_id for f in report.findings}


def test_starter_rules_compile_and_load():
    eng = yara_engine.YaraEngine([STARTER])
    assert eng.errors == [] and eng.rule_count() >= 8


def test_starter_pdf_and_lnk_rules():
    eng = yara_engine.YaraEngine([STARTER])
    pdf = b"%PDF-1.7\n1 0 obj<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>endobj\n"
    assert "YARA_PDF_JavaScript_AutoAction" in ids(analyze_bytes(pdf, "a.pdf", yara_engine=eng))
    assert "YARA_PDF_Launch_Action" in ids(analyze_bytes(b"%PDF-1.4\n<< /Launch << /Win >> >>", "b.pdf", yara_engine=eng))
    lnk = (bytes.fromhex("4C0000000114020000000000C000000000000046") + b"\0" * 40
           + "powershell -w hidden -enc AAAA".encode("utf-16le"))
    r = analyze_bytes(lnk, "invoice.pdf.lnk", yara_engine=eng)
    assert {"YARA_LNK_Script_Host_Command", "NAME_DOUBLE_EXT"} <= ids(r)
    assert r.verdict == "Malicious"          # hidden .lnk double extension (50) + YARA high (25)


def test_embedded_exe_and_benign_pdf():
    eng = yara_engine.YaraEngine([STARTER])
    pe = build_pe([(".text", b"\x90" * 300, CODE)])
    assert "YARA_Embedded_Windows_Executable" not in ids(analyze_bytes(pe, "a.exe", yara_engine=eng))  # a PE is fine
    stub = b"hello" + b"This program cannot be run in DOS mode" + b"x"
    assert "YARA_Embedded_Windows_Executable" in ids(analyze_bytes(stub, "readme.txt", yara_engine=eng))
    assert not any(i.startswith("YARA_") for i in ids(analyze_bytes(b"%PDF-1.4\nplain text pdf", "ok.pdf", yara_engine=eng)))


def test_bad_rule_file_is_isolated(tmp_path):
    (tmp_path / "good.yar").write_text('rule good { strings: $a = "marker_good" condition: $a }')
    (tmp_path / "bad.yar").write_text("rule broken { condition: nonsense }")
    eng = yara_engine.YaraEngine([str(tmp_path)])
    assert len(eng.errors) == 1 and eng.rule_count() == 1
    assert "YARA_good" in ids(analyze_bytes(b"xx marker_good xx", "f.bin", yara_engine=eng))


def test_critical_rule_is_decisive_and_add_rule_file(tmp_path):
    src = ('rule ZetaLoader { meta: severity = "critical" family = "Zeta" description = "ZetaLoader"\n'
           ' strings: $a = "zeta_c2_beacon" condition: $a }')
    path = yara_engine.add_rule_file("zeta", src, str(tmp_path))
    assert path.endswith("zeta.yar")
    eng = yara_engine.YaraEngine([str(tmp_path)])
    r = analyze_bytes(b"...zeta_c2_beacon...", "x.bin", yara_engine=eng)
    assert r.verdict == "Malicious" and "INTEL_YARA_ZetaLoader" in ids(r)
    assert r.metadata["yara"]["matches"][0]["rule"] == "ZetaLoader"


def test_rule_upload_validation(tmp_path):
    with pytest.raises(ValueError):
        yara_engine.add_rule_file("x", "rule a { condition: nope }", str(tmp_path))
    with pytest.raises(ValueError):
        yara_engine.add_rule_file("x", 'include "/etc/passwd"\nrule a { condition: true }', str(tmp_path))
    with pytest.raises(ValueError):
        yara_engine.add_rule_file("../evil", "rule a { condition: true }", str(tmp_path))
    assert os.listdir(tmp_path) == []
