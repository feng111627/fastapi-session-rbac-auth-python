"""FastAPI 应用装配：登录、会话、RBAC 权限控制。"""
from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .auth import AuthError, SESSION_COOKIE, get_current_user
from .models import AccessRule, Role, User
from .ratelimit import LoginGuard
from .rbac import PermissionChecker
from .security import hash_password, new_token, verify_password
from .sessions import SessionStore

# 文档存储：受保护资源
DOCUMENTS: dict[str, dict[str, str]] = {
    "doc-1": {"title": "公开手册", "body": "hello"},
    "doc-9": {"title": "内部备忘录", "body": "secret"},
}


class LoginRequest(BaseModel):
    username: str
    password: str


def create_app(
    *,
    idle_timeout: float = 1800.0,
    max_sessions_per_user: int = 3,
    max_login_failures: int = 5,
    lockout_seconds: float = 300.0,
    cookie_secure: bool = False,
) -> FastAPI:
    app = FastAPI(title="session-rbac-auth")

    # ---- 应用状态：账号、角色、权限规则、会话、令牌、登录保护 ----
    app.state.users = {
        "alice": User("alice", hash_password("alice-pw"), frozenset({"editor"})),
        "bob": User("bob", hash_password("bob-pw"), frozenset({"viewer"})),
    }
    app.state.checker = PermissionChecker(
        roles={
            "viewer": Role("viewer", frozenset({"doc:read"})),
            "editor": Role("editor", frozenset({"doc:write"}), parents=("viewer",)),
        },
        rules=[
            # 显式拒绝：alice 对 doc-9 无写权限，优先于角色允许
            AccessRule("alice", "doc:write", "deny", resource="doc-9"),
        ],
    )
    app.state.sessions = SessionStore(idle_timeout, max_sessions_per_user)
    app.state.tokens: dict[str, str] = {}  # bearer token -> session_id
    app.state.login_guard = LoginGuard(max_login_failures, lockout_seconds)

    # ---- 错误处理：区分原因，但不泄露资源是否存在 ----
    @app.exception_handler(AuthError)
    async def auth_error_handler(_: Request, exc: AuthError) -> JSONResponse:
        status = 403 if exc.reason in ("forbidden", "csrf_failed") else 401
        return JSONResponse({"detail": exc.reason}, status_code=status)

    # ---- 认证接口 ----
    @app.post("/login")
    def login(body: LoginRequest, request: Request):
        guard: LoginGuard = app.state.login_guard
        if guard.is_locked(body.username):
            return JSONResponse({"detail": "locked"}, status_code=429)
        user = app.state.users.get(body.username)
        if user is None or not verify_password(body.password, user.password_hash):
            guard.record_failure(body.username)
            # 不区分"用户不存在"与"口令错误"，避免账号枚举
            return JSONResponse({"detail": "invalid_credentials"}, status_code=401)
        guard.record_success(body.username)
        csrf_token = new_token()
        session = app.state.sessions.create(user.username, csrf_token)
        bearer = new_token()
        app.state.tokens[bearer] = session.session_id
        response = JSONResponse(
            {"token": bearer, "csrf_token": csrf_token, "username": user.username}
        )
        response.set_cookie(
            SESSION_COOKIE,
            session.session_id,
            httponly=True,
            samesite="lax",
            secure=cookie_secure,
            path="/",
        )
        return response

    @app.post("/logout")
    def logout(request: Request, user: User = Depends(get_current_user)):
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id is None:
            auth = request.headers.get("authorization", "")
            token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
            session_id = app.state.tokens.get(token, "")
        app.state.sessions.revoke(session_id)
        for tok, sid in list(app.state.tokens.items()):
            if sid == session_id:
                del app.state.tokens[tok]
        return {"detail": "logged_out"}

    @app.get("/me")
    def me(user: User = Depends(get_current_user)):
        return {
            "username": user.username,
            "roles": sorted(user.roles),
            "permissions": sorted(app.state.checker.resolve_permissions(user)),
        }

    # ---- 受保护资源：直接访问与间接调用共用同一权限判定 ----
    def _get_doc(doc_id: str, user: User, permission: str) -> dict[str, str]:
        # 先鉴权再查资源：未授权时统一 403，不暴露资源是否存在
        if not app.state.checker.is_allowed(user, permission, doc_id):
            raise AuthError("forbidden")
        doc = DOCUMENTS.get(doc_id)
        if doc is None:
            raise HTTPException(status_code=404, detail="not_found")
        return doc

    @app.get("/documents/{doc_id}")
    def read_doc(doc_id: str, user: User = Depends(get_current_user)):
        return _get_doc(doc_id, user, "doc:read")

    @app.get("/documents/{doc_id}/summary")
    def read_doc_summary(doc_id: str, user: User = Depends(get_current_user)):
        doc = _get_doc(doc_id, user, "doc:read")
        return {"title": doc["title"]}

    @app.post("/documents/{doc_id}")
    def write_doc(doc_id: str, user: User = Depends(get_current_user)):
        _get_doc(doc_id, user, "doc:write")
        return {"detail": "written"}

    return app
