"""FastAPI 依赖：统一 Cookie/Bearer 两种入口的身份解析与权限校验。

- 两种入口解析出同一个 Session/Principal，后续权限判定走同一个
  rbac.check_permission，保证结论一致。
- CSRF：仅对 Cookie 承载的状态变更请求（POST/PUT/PATCH/DELETE）校验
  X-CSRF-Token；Bearer 客户端天然免疫 CSRF，不做该校验，避免误伤。
- 错误原因可区分（unauthenticated / session_invalid / csrf_failed /
  forbidden），且 forbidden 的响应不透露资源是否存在。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse

from .models import Session, User
from .rbac import check_permission

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class Principal:
    user: User
    session: Session
    via: str  # "cookie" | "bearer"


class AuthError(Exception):
    """认证/授权失败，reason 用于区分原因且不泄露资源存在性。"""

    def __init__(self, reason: str, status_code: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


async def auth_error_handler(_request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"reason": exc.reason}},
    )


def _extract_token(request: Request) -> tuple[str, str] | None:
    """返回 (via, token)；优先 Bearer，其次 Cookie。"""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return ("bearer", token)
    cookie_token = request.cookies.get(request.app.state.settings.cookie_name)
    if cookie_token:
        return ("cookie", cookie_token)
    return None


def get_principal(request: Request) -> Principal:
    """解析当前请求身份；未认证或会话失效时抛出 AuthError。"""
    extracted = _extract_token(request)
    if extracted is None:
        raise AuthError("unauthenticated", 401)
    via, token = extracted

    session = request.app.state.sessions.validate(token)
    if session is None:
        raise AuthError("session_invalid", 401)

    if via == "cookie" and request.method not in SAFE_METHODS:
        header = request.headers.get(request.app.state.settings.csrf_header, "")
        if not header or header != session.csrf_token:
            raise AuthError("csrf_failed", 403)

    user = request.app.state.store.get_user(session.username)
    if user is None or user.disabled:
        raise AuthError("session_invalid", 401)
    return Principal(user=user, session=session, via=via)


def require_permission(permission: str, resource: str = "*") -> Callable:
    """生成权限校验依赖。拒绝时统一返回 forbidden，不区分资源不存在与无权。"""

    def dependency(request: Request) -> Principal:
        principal = get_principal(request)
        if not check_permission(
            request.app.state.store, principal.user, permission, resource
        ):
            raise AuthError("forbidden", 403)
        return principal

    return dependency
