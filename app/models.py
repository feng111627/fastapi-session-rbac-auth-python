"""核心数据模型定义（骨架）。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PermissionGrant:
    """一条权限授予/拒绝记录。"""
    effect: Effect
    subject: str          # "role:admin" / "user:alice"
    permission: str       # 如 "document:read"
    resource: str = "*"   # 具体资源 id 或 "*"


@dataclass
class Role:
    name: str
    parents: tuple[str, ...] = ()   # 继承的父角色
    permissions: frozenset[str] = frozenset()


@dataclass
class User:
    username: str
    password_hash: str
    roles: frozenset[str] = frozenset()
    disabled: bool = False


@dataclass
class Session:
    token: str
    username: str
    created_at: float
    expires_at: float
    csrf_token: str

    def is_expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at
