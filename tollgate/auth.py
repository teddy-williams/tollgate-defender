"""Password hashing, password policy and role helpers. Standard library only (scrypt)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1            # ~32 MiB per hash
_MAXMEM = 128 * 1024 * 1024
ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")
MIN_PASSWORD = 12
MAX_PASSWORD = 256
_COMMON = {"password1234", "passwordpassword", "123456789012", "1234567890123", "qwertyuiop12", "qwertyuiopas",
           "letmein12345", "administrator", "welcome12345", "iloveyou1234", "changeme1234", "abcdefghijkl",
           "password12345", "tollgate12345", "malwareanalyst", "securitytest1"}


class PolicyError(ValueError):
    pass


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=_MAXMEM, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        want = base64.b64decode(expected)
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=_MAXMEM, dklen=len(want))
        return hmac.compare_digest(got, want)
    except (ValueError, TypeError):
        return False


_dummy: str | None = None


def burn_time(password: str) -> None:
    """Spend the same effort as a real check so unknown usernames are not distinguishable by timing."""
    global _dummy
    _dummy = _dummy or hash_password("tollgate-timing-dummy")
    verify_password(password, _dummy)


def check_password_policy(password: str, username: str = "") -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise PolicyError(f"password must be at least {MIN_PASSWORD} characters (a passphrase of several words works well)")
    if len(password) > MAX_PASSWORD:
        raise PolicyError(f"password must be at most {MAX_PASSWORD} characters")
    low = password.lower()
    if username and username.lower() in low:
        raise PolicyError("password must not contain the username")
    if low in _COMMON or len(set(password)) < 5:
        raise PolicyError("password is too common or too repetitive")


def check_username(username: str) -> str:
    if not USERNAME_RE.match(username or ""):
        raise PolicyError("username must be 3-64 characters: letters, digits, _ . @ -")
    return username


def rank(role: str) -> int:
    return ROLE_RANK.get(role, 0)
