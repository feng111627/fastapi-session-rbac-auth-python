"""认证依赖：Cookie 会话 / Bearer 令牌统一入口 + CSRF 校验。

两类入口最终都解析到同一个服务端会话，因此对同一账号、同一资源的
权限结论必然一致。
"""
from __future__ import annotations

from fastapi import Request

from .models import User

SESSION_COOKIE = "session_id"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class AuthError(Exception):
    """认证/授权失败，reason 用于区分原因。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _resolve_session(request: Request):
    """从 Cookie 或 Bearer 令牌解析会话；返回 (session, via_cookie)。"""
    store = request.app.state.sessions
    tokens = request.app.state.tokens

    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        session_id = tokens.get(auth[len("Bearer "):])
        if session_id is not None:
            session = store.get_valid(session_id)
            if session is not None:
                return session, False

    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        session = store.get_valid(session_id)
        if session is not None:
            return session, True
    return None, False


async def get_current_user(request: Request) -> User:
    """从 Cookie 会话或 Bearer 令牌解析当前用户；未认证抛 AuthError。"""
    has_credential = (
        "authorization" in request.headers or SESSION_COOKIE in request.cookies
    )
    session, via_cookie = _resolve_session(request)
    if session is None:
        # 区分"完全未认证"与"凭证已失效"，但不泄露任何资源信息
        raise AuthError("unauthenticated" if not has_credential else "session_invalid")
    if via_cookie and request.method not in SAFE_METHODS:
        _check_csrf(request, session)
    user = request.app.state.users.get(session.username)
    if user is None:
        raise AuthError("session_invalid")
    return user


def _check_csrf(request: Request, session) -> None:
    """Cookie 会话的状态变更请求必须携带匹配的 CSRF 令牌。"""
    token = request.headers.get(CSRF_HEADER)
    if not token or token != session.csrf_token:
        raise AuthError("csrf_failed")


def verify_csrf(request: Request, user: User) -> None:
    """对 Cookie 会话的状态变更请求校验 CSRF 令牌；Bearer 客户端豁免。

    供需要在依赖之外手动校验的场景使用；常规路径已由 get_current_user 覆盖。
    """
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return
    if request.method in SAFE_METHODS:
        return
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return
    session = request.app.state.sessions.get_valid(session_id)
    if session is None:
        raise AuthError("session_invalid")
    _check_csrf(request, session)
