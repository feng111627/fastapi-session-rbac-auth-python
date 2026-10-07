"""角色继承 + 显式拒绝优先的权限判定。

判定规则（所有入口共用同一函数，保证结论一致）：
1. 未登录（user 为 None）或账号被禁用 -> 拒绝。
2. 展开角色继承链（带环保护），汇总全部有效角色的权限。
3. 收集与用户相关的显式授予记录（user: 与 role: 主体，精确资源或 "*"）。
4. 任一匹配的 DENY 记录 -> 拒绝（显式拒绝优先于一切允许）。
5. 否则，权限在角色权限集合或 ALLOW 记录中 -> 允许；其余拒绝。
"""
from __future__ import annotations

from .models import Effect, User
from .store import Store


def resolve_roles(store: Store, user: User) -> set[str]:
    """展开角色继承链，返回用户全部有效角色名（含自身角色）。"""
    resolved: set[str] = set()
    stack = list(user.roles)
    while stack:
        name = stack.pop()
        if name in resolved:
            continue
        role = store.get_role(name)
        if role is None:
            continue
        resolved.add(name)
        stack.extend(role.parents)
    return resolved


def effective_permissions(store: Store, user: User) -> set[str]:
    """汇总所有有效角色的权限。"""
    perms: set[str] = set()
    for role_name in resolve_roles(store, user):
        role = store.get_role(role_name)
        if role is not None:
            perms.update(role.permissions)
    return perms


def check_permission(
    store: Store,
    user: User | None,
    permission: str,
    resource: str = "*",
) -> bool:
    """判定是否允许。显式 DENY 优先于 ALLOW；user 为 None 视为未登录。"""
    if user is None or user.disabled:
        return False

    roles = resolve_roles(store, user)
    subjects = {f"user:{user.username}"} | {f"role:{r}" for r in roles}

    allowed = permission in effective_permissions(store, user)
    for grant in store.list_grants():
        if grant.subject not in subjects or grant.permission != permission:
            continue
        if grant.resource not in ("*", resource):
            continue
        if grant.effect is Effect.DENY:
            return False  # 显式拒绝优先
        allowed = True
    return allowed
