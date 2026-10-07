"""应用装配与路由。

路由概览：
- POST /auth/login            账号口令登录，建立服务端会话，下发 Cookie 与令牌
- POST /auth/logout           注销当前会话（Cookie 入口需 CSRF 头）
- GET  /auth/me               当前身份
- GET/POST/DELETE /documents/{doc_id}   受保护资源（doc:read / doc:write / doc:delete）
- GET  /reports/{doc_id}      间接入口：复用同一 doc:read 判定，验证结论一致
"""
from __future__ import annotations

import threading

from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel

from .auth import AuthError, Principal, auth_error_handler, get_principal
from .config import DEFAULT_SETTINGS, Settings
from .models import Role, User
from .ratelimit import LoginGuard
from .security import hash_password, verify_password
from .sessions import SessionManager
from .store import Store


class LoginRequest(BaseModel):
    username: str
    password: str


class DocBody(BaseModel):
    content: str


def seed(store: Store) -> None:
    """初始化角色层级与演示账号。"""
    store.add_role(Role("viewer", permissions=frozenset({"doc:read"})))
    store.add_role(Role("editor", parents=("viewer",), permissions=frozenset({"doc:write"})))
    store.add_role(Role("admin", parents=("editor",), permissions=frozenset({"doc:delete"})))
    store.add_user(User("alice", hash_password("alice-pw"), roles=frozenset({"editor"})))
    store.add_user(User("bob", hash_password("bob-pw"), roles=frozenset({"viewer"})))
    store.add_user(User("carol", hash_password("carol-pw"), roles=frozenset({"admin"})))


def create_app(settings: Settings = DEFAULT_SETTINGS) -> FastAPI:
    app = FastAPI(title="session-rbac-auth")
    app.state.settings = settings
    app.state.store = Store()
    app.state.sessions = SessionManager(settings)
    app.state.login_guard = LoginGuard(settings)
    app.state.documents = {"doc-1": "hello", "doc-2": "world"}
    app.state.documents_lock = threading.Lock()
    app.add_exception_handler(AuthError, auth_error_handler)
    seed(app.state.store)

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    @app.post("/auth/login")
    def login(body: LoginRequest, request: Request):
        guard: LoginGuard = request.app.state.login_guard
        store: Store = request.app.state.store

        if guard.is_locked(body.username):
            raise AuthError("account_locked", 423)

        user = store.get_user(body.username)
        # 用户不存在与口令错误返回同一结果，不暴露账号是否存在
        if user is None or user.disabled or not verify_password(body.password, user.password_hash):
            guard.record_failure(body.username)
            raise AuthError("invalid_credentials", 401)

        guard.record_success(body.username)
        session = request.app.state.sessions.create(user.username)

        from fastapi.responses import JSONResponse

        response = JSONResponse(
            {
                "token": session.token,
                "csrf_token": session.csrf_token,
                "expires_in": settings.session_ttl_seconds,
            }
        )
        response.set_cookie(
            settings.cookie_name,
            session.token,
            httponly=True,
            samesite="lax",
            secure=settings.cookie_secure,
            path="/",
        )
        return response

    @app.post("/auth/logout")
    def logout(request: Request, principal: Principal = Depends(get_principal)):
        request.app.state.sessions.revoke(principal.session.token)
        from fastapi.responses import JSONResponse

        response = JSONResponse({"logged_out": True})
        response.delete_cookie(request.app.state.settings.cookie_name, path="/")
        return response

    @app.get("/auth/me")
    def me(principal: Principal = Depends(get_principal)):
        return {
            "username": principal.user.username,
            "via": principal.via,
            "roles": sorted(principal.user.roles),
        }

    def _get_document(request: Request, doc_id: str) -> str | None:
        with request.app.state.documents_lock:
            return request.app.state.documents.get(doc_id)

    @app.get("/documents/{doc_id}")
    def read_document(doc_id: str, request: Request, principal: Principal = Depends(get_principal)):
        from .rbac import check_permission

        content = _get_document(request, doc_id)
        # 资源不存在与无权限返回同一错误，不暴露资源存在性
        if content is None or not check_permission(
            request.app.state.store, principal.user, "doc:read", doc_id
        ):
            raise AuthError("forbidden", 403)
        return {"id": doc_id, "content": content}

    @app.get("/reports/{doc_id}")
    def read_report(doc_id: str, request: Request, principal: Principal = Depends(get_principal)):
        """间接入口：与 /documents/{id} 使用完全相同的权限判定。"""
        from .rbac import check_permission

        content = _get_document(request, doc_id)
        if content is None or not check_permission(
            request.app.state.store, principal.user, "doc:read", doc_id
        ):
            raise AuthError("forbidden", 403)
        return {"report_for": doc_id, "summary": content.upper()}

    @app.post("/documents/{doc_id}")
    def write_document(
        doc_id: str, body: DocBody, request: Request, principal: Principal = Depends(get_principal)
    ):
        from .rbac import check_permission

        if not check_permission(request.app.state.store, principal.user, "doc:write", doc_id):
            raise AuthError("forbidden", 403)
        with request.app.state.documents_lock:
            request.app.state.documents[doc_id] = body.content
        return {"id": doc_id, "written": True}

    @app.delete("/documents/{doc_id}")
    def delete_document(doc_id: str, request: Request, principal: Principal = Depends(get_principal)):
        from .rbac import check_permission

        exists = _get_document(request, doc_id) is not None
        if not exists or not check_permission(
            request.app.state.store, principal.user, "doc:delete", doc_id
        ):
            raise AuthError("forbidden", 403)
        with request.app.state.documents_lock:
            del request.app.state.documents[doc_id]
        return {"id": doc_id, "deleted": True}

    return app
