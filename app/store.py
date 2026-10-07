"""线程安全的内存数据存储。

所有读写都在同一把可重入锁内完成，保证并发请求下
用户/角色/权限授予视图一致。
"""
from __future__ import annotations

import threading

from .models import PermissionGrant, Role, User


class Store:
    """用户、角色、权限授予的集中存储，所有访问持锁。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._roles: dict[str, Role] = {}
        self._grants: list[PermissionGrant] = []

    # ---- 用户 ----
    def add_user(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    # ---- 角色 ----
    def add_role(self, role: Role) -> None:
        with self._lock:
            self._roles[role.name] = role

    def get_role(self, name: str) -> Role | None:
        with self._lock:
            return self._roles.get(name)

    # ---- 显式授予/拒绝 ----
    def add_grant(self, grant: PermissionGrant) -> None:
        with self._lock:
            self._grants.append(grant)

    def list_grants(self) -> list[PermissionGrant]:
        with self._lock:
            return list(self._grants)
