"""关键路径测试：登录、权限判定、会话失效、失败锁定、CSRF。"""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client():
    app = create_app(max_login_failures=3, lockout_seconds=60.0)
    with TestClient(app) as c:
        yield c


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def login_ok(client, username="alice"):
    password = {"alice": "alice-pw", "bob": "bob-pw"}[username]
    r = login(client, username, password)
    assert r.status_code == 200, r.text
    return r.json()


# ---------- 登录 ----------

def test_login_success_sets_secure_cookie(client):
    r = login(client, "alice", "alice-pw")
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    print("[PASS] 登录成功，Cookie 带 HttpOnly/SameSite 属性")


def test_login_wrong_password(client):
    r = login(client, "alice", "wrong")
    assert r.status_code == 401 and r.json()["detail"] == "invalid_credentials"
    print("[PASS] 口令错误返回 401 invalid_credentials")


def test_login_unknown_user_same_response(client):
    r = login(client, "nobody", "x")
    assert r.status_code == 401 and r.json()["detail"] == "invalid_credentials"
    print("[PASS] 未知用户与口令错误响应一致，不可枚举账号")


# ---------- 认证与可区分原因 ----------

def test_unauthenticated_rejected(client):
    r = client.get("/documents/doc-1")
    assert r.status_code == 401 and r.json()["detail"] == "unauthenticated"
    print("[PASS] 未认证访问返回 401 unauthenticated")


def test_invalid_session_rejected(client):
    client.cookies.set("session_id", "bogus")
    r = client.get("/documents/doc-1")
    assert r.status_code == 401 and r.json()["detail"] == "session_invalid"
    print("[PASS] 无效会话返回 401 session_invalid，与未认证可区分")


# ---------- Cookie 与 Bearer 一致性 ----------

def test_cookie_and_bearer_same_conclusion(client):
    tokens = login_ok(client, "bob")  # bob 只有 doc:read
    bearer = {"Authorization": f"Bearer {tokens['token']}"}

    r_cookie = client.get("/documents/doc-1")
    r_bearer = client.get("/documents/doc-1", headers=bearer)
    assert r_cookie.status_code == r_bearer.status_code == 200

    csrf = {"x-csrf-token": tokens["csrf_token"]}
    r_cookie = client.post("/documents/doc-1", headers=csrf)
    r_bearer = client.post("/documents/doc-1", headers=bearer)
    assert r_cookie.status_code == r_bearer.status_code == 403
    assert r_cookie.json() == r_bearer.json() == {"detail": "forbidden"}
    print("[PASS] Cookie 与 Bearer 对同一资源权限结论一致")


# ---------- 权限判定：继承、显式拒绝、多入口一致 ----------

def test_role_inheritance_and_deny_override(client):
    tokens = login_ok(client, "alice")  # editor 继承 viewer
    assert client.get("/documents/doc-1").status_code == 200  # 继承的读权限

    csrf = {"x-csrf-token": tokens["csrf_token"]}
    assert client.post("/documents/doc-1", headers=csrf).status_code == 200
    # 显式拒绝优先于角色允许
    r = client.post("/documents/doc-9", headers=csrf)
    assert r.status_code == 403 and r.json()["detail"] == "forbidden"
    print("[PASS] 角色继承生效，显式拒绝优先于允许")


def test_multiple_entries_same_permission(client):
    login_ok(client, "bob")
    r1 = client.get("/documents/doc-1")
    r2 = client.get("/documents/doc-1/summary")
    assert r1.status_code == r2.status_code == 200
    print("[PASS] 直接与间接入口对同一权限判定一致")


def test_forbidden_does_not_leak_existence(client):
    login_ok(client, "bob")  # bob 无写权限
    csrf = {"x-csrf-token": client.post("/login", json={
        "username": "bob", "password": "bob-pw"}).json()["csrf_token"]}
    r_exists = client.post("/documents/doc-1", headers=csrf)
    r_missing = client.post("/documents/no-such", headers=csrf)
    assert r_exists.status_code == r_missing.status_code == 403
    assert r_exists.json() == r_missing.json()
    print("[PASS] 未授权时存在/不存在资源响应一致，不泄露存在性")


# ---------- 会话失效：注销、淘汰、过期 ----------

def test_logout_invalidates_session_and_token(client):
    tokens = login_ok(client)
    bearer = {"Authorization": f"Bearer {tokens['token']}"}
    csrf = {"x-csrf-token": tokens["csrf_token"]}
    r = client.post("/logout", headers=csrf)
    assert r.status_code == 200
    assert client.get("/me").status_code == 401
    r = client.get("/me", headers=bearer)
    assert r.status_code == 401 and r.json()["detail"] == "session_invalid"
    print("[PASS] 注销后 Cookie 会话与 Bearer 令牌同时失效")


def test_concurrent_session_limit_evicts_oldest():
    app = create_app(max_sessions_per_user=2)
    with TestClient(app) as c1, TestClient(app) as c2, TestClient(app) as c3:
        login_ok(c1); login_ok(c2); login_ok(c3)  # 第三个会话淘汰最旧的 c1
        assert c1.get("/me").json()["detail"] == "session_invalid"
        assert c2.get("/me").status_code == 200
        assert c3.get("/me").status_code == 200
    print("[PASS] 并发会话超限时淘汰最旧会话，被淘汰会话判为失效")


def test_idle_timeout_expires_session():
    app = create_app(idle_timeout=0.05)
    with TestClient(app) as c:
        login_ok(c)
        import time
        time.sleep(0.1)
        r = c.get("/me")
        assert r.status_code == 401 and r.json()["detail"] == "session_invalid"
    print("[PASS] 空闲超时后会话失效")


# ---------- 登录失败锁定 ----------

def test_lockout_after_repeated_failures(client):
    for _ in range(3):
        login(client, "alice", "wrong")
    r = login(client, "alice", "alice-pw")  # 锁定期间正确口令也被拒
    assert r.status_code == 429 and r.json()["detail"] == "locked"
    print("[PASS] 连续失败触发锁定，锁定期间正确口令也返回 429 locked")


def test_concurrent_failures_counted_accurately():
    app = create_app(max_login_failures=5, lockout_seconds=60.0)
    with TestClient(app) as c:
        def fail():
            login(c, "alice", "wrong")
        threads = [threading.Thread(target=fail) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert app.state.login_guard.is_locked("alice")
        r = login(c, "alice", "alice-pw")
        assert r.status_code == 429
    print("[PASS] 并发失败计数准确，达到阈值即锁定，无竞争绕过")


def test_success_resets_failure_count(client):
    login(client, "alice", "wrong")
    login(client, "alice", "wrong")
    login_ok(client, "alice")  # 成功清零
    login(client, "alice", "wrong")
    login(client, "alice", "wrong")
    r = login(client, "alice", "alice-pw")
    assert r.status_code == 200  # 未达阈值，未锁定
    print("[PASS] 登录成功清零失败计数")


# ---------- CSRF ----------

def test_csrf_required_for_cookie_state_change(client):
    login_ok(client)
    r = client.post("/documents/doc-1")  # Cookie 会话、无 CSRF 令牌
    assert r.status_code == 403 and r.json()["detail"] == "csrf_failed"
    print("[PASS] Cookie 会话状态变更缺少 CSRF 令牌被拒")


def test_csrf_not_required_for_bearer(client):
    tokens = login_ok(client)
    bearer = {"Authorization": f"Bearer {tokens['token']}"}
    # 脚本客户端只用 Bearer，不带 Cookie、不带 CSRF 令牌
    with TestClient(client.app) as c:
        r = c.post("/documents/doc-1", headers=bearer)
        assert r.status_code == 200
    print("[PASS] Bearer 客户端豁免 CSRF 校验，不被误伤")
