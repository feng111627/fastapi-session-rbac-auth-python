"""核心数据模型定义（骨架：仅类型定义）。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    """账号主体。"""

    username: str
    password_hash: str
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Role:
    """角色：可继承父角色，拥有一组权限。"""

    name: str
    permissions: frozenset[str] = frozenset()
    parents: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccessRule:
    """针对特定主体/资源的显式允许或拒绝规则。"""

    subject: str          # 用户名或 "role:<角色名>"
    permission: str
    effect: str           # "allow" | "deny"
    resource: str | None = None  # None 表示对所有资源生效


@dataclass
class Session:
    """服务端会话。"""

    session_id: str
    username: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    revoked: bool = False
    csrf_token: str = ""
