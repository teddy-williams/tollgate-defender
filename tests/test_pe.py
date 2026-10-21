import os

from tollgate import pe_analyzer
from tollgate.engine import analyze_bytes
from tollgate.models import Severity
from tests.helpers import CODE, DATA, RWX, build_pe

FILLER = (b"\x55\x8b\xec\x90\x90\xc3" * 200)


def ids(findings):
    return {f.rule_id for f in findings}


def test_calm_pe_has_no_packing_indicators():
    findings, meta = pe_analyzer.analyze(build_pe([(".text", FILLER, CODE), (".data", FILLER, DATA)]))
    assert not ids(findings) & {"PE_SECTION_ENTROPY", "PE_PACKER", "PE_SECTION_RWX", "PE_EP_LAST_SECTION"}
    assert meta["sections"][0]["name"] == ".text"


def test_high_entropy_code_section():
    findings, _ = pe_analyzer.analyze(build_pe([(".text", os.urandom(8192), CODE)]))
    assert "PE_SECTION_ENTROPY" in ids(findings)


def test_packer_names_and_rwx():
    findings, _ = pe_analyzer.analyze(build_pe([("UPX0", b"", RWX), ("UPX1", FILLER, RWX)], entry_section=1))
    assert {"PE_PACKER", "PE_SECTION_RWX", "PE_SECTION_EMPTY_EXEC"} <= ids(findings)


def test_entry_point_in_last_section():
    findings, _ = pe_analyzer.analyze(
        build_pe([(".text", FILLER, CODE), (".data", FILLER, DATA)], entry_section=1))
    assert {"PE_EP_LAST_SECTION", "PE_EP_NONEXEC"} <= ids(findings)


def test_overlay_with_embedded_exe():
    inner = build_pe([(".text", FILLER, CODE)])
    findings, meta = pe_analyzer.analyze(build_pe([(".text", FILLER, CODE)], overlay=inner))
    assert "PE_OVERLAY_EXE" in ids(findings)
    assert meta["overlay_size"] == len(inner)


def test_malformed_pe():
    data = b"MZ" + b"\0" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\0\0" + b"\xff" * 10
    findings, _ = pe_analyzer.analyze(data)
    assert "PE_MALFORMED" in ids(findings)


def test_import_classification():
    f = pe_analyzer.classify_imports(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])
    assert f[0].rule_id == "PE_API_INJECTION" and f[0].severity == Severity.HIGH
    assert pe_analyzer.classify_imports(["CreateFileW", "ReadFile", "ExitProcess"]) == []
    combo = pe_analyzer.classify_imports(["URLDownloadToFileW", "ShellExecuteW"])
    assert "PE_API_DOWNLOAD_EXEC" in ids(combo)


def test_string_patterns():
    findings, urls = pe_analyzer.scan_strings(
        b"junk\x00vssadmin delete shadows /all /quiet\x00http://10.1.2.3/payload.bin\x00")
    assert {"STR_VSS_DELETE", "STR_RAW_IP_URL"} <= ids(findings)
    assert urls == ["http://10.1.2.3/payload.bin"]


def test_end_to_end_spoofed_pe_is_flagged():
    report = analyze_bytes(build_pe([("UPX0", b"", RWX), ("UPX1", FILLER, RWX)], entry_section=1),
                           "invoice.pdf.exe")
    assert report.verdict in ("Suspicious", "Malicious")
    assert report.to_dict()["findings"]
