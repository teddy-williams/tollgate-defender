import os

import pytest

from tollgate import cape, cli, fake_cape
from tollgate.accounts import Accounts, AuthError
from tollgate.db import Store
from tests.helpers import CODE, build_pe

PW = "correct horse battery staple"


def run(args, monkeypatch=None, env=None, capsys=None):
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    code = cli.main(args)
    out = capsys.readouterr() if capsys else None
    return code, out


def test_user_commands(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "u.db")
    c, out = run(["--db", db, "user", "create-master", "owner1", "--password-env", "PW"], monkeypatch, {"PW": PW}, capsys)
    assert c == 0 and "master account" in out.out
    c, out = run(["--db", db, "user", "create-master", "second", "--password-env", "PW"], monkeypatch, capsys=capsys)
    assert c == 3 and "already exists" in out.err
    assert run(["--db", db, "user", "create", "ana", "--role", "analyst", "--password-env", "PW"], capsys=capsys)[0] == 0
    c, out = run(["--db", db, "user", "create", "weak", "--password-env", "SHORT"], monkeypatch, {"SHORT": "tiny"}, capsys)
    assert c == 3 and "at least 12" in out.err
    c, out = run(["--db", db, "user", "list"], capsys=capsys)
    assert "owner1" in out.out and "yes" in out.out and "ana" in out.out and "analyst" in out.out and "password" not in out.out.lower()
    assert run(["--db", db, "user", "disable", "ana"], capsys=capsys)[0] == 0
    assert run(["--db", db, "user", "disable", "owner1"], capsys=capsys)[0] == 3            # master is protected
    assert run(["--db", db, "user", "delete", "owner1"], capsys=capsys)[0] == 3
    c, out = run(["--db", db, "user", "token", "ana", "--label", "ci"], capsys=capsys)
    assert c == 0 and out.out.strip().startswith("tg_") and "only once" in out.err
    assert run(["--db", db, "user", "set-password", "ana", "--password-env", "PW2", "--force-change"], monkeypatch, {"PW2": "another long passphrase!"}, capsys=capsys)[0] == 0
    acc = Accounts(Store(db))
    with pytest.raises(AuthError):
        acc.authenticate("ana", "another long passphrase!")                  # still disabled
    assert run(["--db", db, "user", "enable", "ana"], capsys=capsys)[0] == 0
    user = acc.authenticate("ana", "another long passphrase!")
    assert user["must_change_password"] == 1                                  # --force-change was honoured


def test_user_set_password_interactive(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "i.db")
    answers = iter([PW, PW])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["--db", db, "user", "create-master", "teddy-owner"]) == 0
    answers2 = iter([PW, "different"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers2))
    assert cli.main(["--db", db, "user", "create", "bob"]) == 3                              # mismatch is rejected
    assert "did not match" in capsys.readouterr().err


def test_scan_detonate_and_dynamic_commands(tmp_path, monkeypatch, capsys):
    server, url = fake_cape.start()
    try:
        db = str(tmp_path / "d.db")
        sample = tmp_path / "malware-sample.exe"
        sample.write_bytes(build_pe([(".text", b"\x55\x8b\xec\x90\xc3" * 200, CODE)]))
        monkeypatch.setenv("TOLLGATE_YARA_DIRS", str(tmp_path / "norules"))
        assert cli.main(["--db", db, "scan", str(sample), "--detonate"]) == 3                 # CAPE not configured
        assert "TOLLGATE_CAPE_URL" in capsys.readouterr().err
        monkeypatch.setenv("TOLLGATE_CAPE_URL", url)
        monkeypatch.setattr("time.sleep", lambda s: None)
        assert cli.main(["--db", db, "scan", str(sample), "--detonate", "--wait", "60", "--no-record"]) == 3   # needs history to track
        capsys.readouterr()
        code = cli.main(["--db", db, "scan", str(sample), "--detonate", "--wait", "60"])
        out = capsys.readouterr()
        assert code == 2 and "FakeFamily" in out.err and "MALICIOUS" in out.out.upper()      # merged verdict drives the exit code
        assert cli.main(["--db", db, "dynamic", "list"]) == 0 and "reported" in capsys.readouterr().out
        assert cli.main(["--db", db, "dynamic", "show", "1"]) == 0 and "FakeFamily" in capsys.readouterr().out
        assert cli.main(["--db", db, "dynamic", "show", "99"]) == 3
        assert Store(db).history()[0]["verdict"] == "Malicious"
    finally:
        server.shutdown()


def test_fetch_every_floor(tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "f.db"), "intel", "fetch", "--every", "10"]) == 3
    assert "at least 300" in capsys.readouterr().err
    assert cape.CapeConfig.from_env().enabled in (True, False)
    assert isinstance(os.environ, os._Environ)
