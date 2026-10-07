"""口令散列与令牌生成。

- 口令使用 PBKDF2-HMAC-SHA256，随机盐，格式: pbkdf2$<iterations>$<salt_hex>$<hash_hex>
- 校验使用 hmac.compare_digest 防时序侧信道。
- 令牌使用 secrets.token_urlsafe，具备密码学随机性。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGO = "pbkdf2"
_ITERATIONS = 120_000
_SALT_BYTES = 16
_DKLEN = 32


def hash_password(password: str, *, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS, dklen=_DKLEN
    )
    return f"{_ALGO}${_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, expected = stored.split("$")
        if algo != _ALGO:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations), dklen=_DKLEN
        )
        return hmac.compare_digest(dk.hex(), expected)
    except (ValueError, AttributeError):
        return False


def generate_token() -> str:
    return secrets.token_urlsafe(32)
