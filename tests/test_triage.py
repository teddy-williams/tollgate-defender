from tollgate import triage
from tollgate.models import Severity
from tests.helpers import CODE, build_pe


def ids(findings):
    return {f.rule_id for f in findings}


def sev(findings, rule_id):
    return next(f.severity for f in findings if f.rule_id == rule_id)


PE = build_pe([(".text", b"\x90" * 600, CODE)])


def test_detect_types():
    assert triage.detect_type(PE) == "pe"
    assert triage.detect_type(b"MZ" + b"\0" * 100) == "dos-mz"
    assert triage.detect_type(b"%PDF-1.7\n%...") == "pdf"
    assert triage.detect_type(triage.LNK_MAGIC + b"\0" * 100) == "lnk"
    assert triage.detect_type(b"hello world\n") == "text"
    assert triage.detect_type(b"") == "empty"


def test_double_extension_exe_is_high():
    f = triage.analyze_filename("invoice.pdf.exe")
    assert sev(f, "NAME_DOUBLE_EXT") == Severity.HIGH


def test_double_extension_lnk_is_critical():
    f = triage.analyze_filename("invoice.pdf.lnk")
    assert sev(f, "NAME_DOUBLE_EXT") == Severity.CRITICAL


def test_rtlo():
    f = triage.analyze_filename("report\u202egpj.exe")
    assert sev(f, "NAME_RTLO") == Severity.CRITICAL


def test_space_padding_and_trailing():
    assert "NAME_PADDING" in ids(triage.analyze_filename("invoice.pdf" + " " * 20 + ".exe"))
    assert "NAME_TRAILING" in ids(triage.analyze_filename("photo.jpg "))


def test_benign_names_are_quiet():
    for name in ("holiday.jpg", "report.final.docx", "setup.v2.exe", "notes.txt"):
        assert triage.analyze_filename(name) == [], name


def test_exe_disguised_as_pdf():
    r = triage.run(PE, "statement.pdf")
    assert sev(r.findings, "EXT_SPOOF") == Severity.CRITICAL


def test_real_pdf_is_quiet():
    r = triage.run(b"%PDF-1.4\n1 0 obj\n", "a.pdf")
    assert not ids(r.findings) & {"EXT_SPOOF", "EXT_MISMATCH"}


def test_exe_extension_but_not_pe():
    r = triage.run(b"just some text here\n", "tool.exe")
    assert "EXT_MISMATCH" in ids(r.findings)
