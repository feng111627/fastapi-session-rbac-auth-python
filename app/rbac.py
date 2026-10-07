"""角色继承与权限判定。"""
from __future__ import annotations

from .models import AccessRule, Role, User


class PermissionChecker:
    """基于角色继承 + 显式允许/拒绝规则的权限判定器。

    判定顺序：显式拒绝 > 显式允许 > 角色继承所得权限。
    """

    def __init__(self, roles: dict[str, Role], rules: list[AccessRule]) -> None:
        self._roles = roles
        self._rules = rules

    def resolve_permissions(self, user: User) -> set[str]:
        """计算用户经角色继承后的全部权限（不含显式规则）。"""
        result: set[str] = set()
        stack = list(user.roles)
        visited: set[str] = set()
        while stack:
            name = stack.pop()
            if name in visited:
                continue
            visited.add(name)
            role = self._roles.get(name)
            if role is None:
                continue
            result.update(role.permissions)
            stack.extend(role.parents)
        return result

    def _rule_matches(self, rule: AccessRule, user: User, permission: str,
                      resource: str | None) -> bool:
        if rule.permission != permission:
            return False
        if rule.resource is not None and rule.resource != resource:
            return False
        if rule.subject.startswith("role:"):
            return rule.subject[5:] in user.roles
        return rule.subject == user.username

    def is_allowed(self, user: User, permission: str,
                   resource: str | None = None) -> bool:
        """判定用户是否拥有某权限；显式拒绝优先于允许。"""
        matched = [
            r for r in self._rules
            if self._rule_matches(r, user, permission, resource)
        ]
        if any(r.effect == "deny" for r in matched):
            return False
        if any(r.effect == "allow" for r in matched):
            return True
        return permission in self.resolve_permissions(user)
