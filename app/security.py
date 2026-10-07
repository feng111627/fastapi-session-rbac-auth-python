"""口令散列与随机令牌生成。"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 120_000


def hash_password(password: str, *, salt: str | None = None) -> str:
    """对口令做 PBKDF2 加盐散列，返回 "salt$hex" 形式的可存储字符串。"""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS
    )
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """校验口令是否与存储的散列匹配（常数时间比较）。"""
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hash_password(password, salt=salt)
    return hmac.compare_digest(candidate, stored)


def new_token() -> str:
    """生成密码学安全的随机令牌（URL 安全）。"""
    return secrets.token_urlsafe(32)
