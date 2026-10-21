import pytest

from tollgate import auth


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Real deployments use N=2**15; tests use a tiny cost so the suite stays fast."""
    monkeypatch.setattr(auth, "SCRYPT_N", 2 ** 10)
