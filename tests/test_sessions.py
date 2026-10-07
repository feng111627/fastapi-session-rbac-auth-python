"""会话：滑动过期、主动注销、并发上限淘汰、失效会话拒绝。"""

import time

from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient
from tests.conftest import login_ok


def test_logout_invalidates_session(client):
    tokens = login_ok(client, "alice", "alice-pw")
    assert client.get("/auth/me").status_code == 200
    r = client.post("/auth/logout", headers={"x-csrf-token": tokens["csrf_token"]})
    assert r.status_code == 200
    # 注销响应会清除浏览器 Cookie；此处显式重放旧 Cookie，验证服务端判定
    r = client.get("/auth/me", cookies={"sid": tokens["token"]})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_invalid"
    print("PASS 注销后会话立即失效，原因可与未认证区分")


def test_revoked_bearer_token_rejected(client):
    """同一会话的 Bearer 令牌在注销后同样失效（两类入口共享会话）。"""
    tokens = login_ok(client, "alice", "alice-pw")
    bearer = {"Authorization": f"Bearer {tokens['token']}"}
    assert client.get("/auth/me", headers=bearer).status_code == 200
    client.post("/auth/logout", headers={"x-csrf-token": tokens["csrf_token"]})
    r = client.get("/auth/me", headers=bearer)
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_invalid"
    print("PASS 注销后 Bearer 令牌同步失效")


def test_concurrent_session_limit_evicts_oldest(settings, app):
    """超过并发上限时淘汰最旧会话，被淘汰会话再请求判为失效。"""
    c1, c2, c3 = TestClient(app), TestClient(app), TestClient(app)
    login_ok(c1, "alice", "alice-pw")
    login_ok(c2, "alice", "alice-pw")
    login_ok(c3, "alice", "alice-pw")  # 上限=2，淘汰 c1
    assert c1.get("/auth/me").status_code == 401
    assert c1.get("/auth/me").json()["detail"]["reason"] == "session_invalid"
    assert c2.get("/auth/me").status_code == 200
    assert c3.get("/auth/me").status_code == 200
    print("PASS 并发会话超限淘汰最旧会话，被淘汰会话判为失效")


def test_sliding_expiration_extends_session():
    """滑动过期：活跃访问续期，闲置超时失效。"""
    app = create_app(Settings(session_ttl_seconds=0.3, max_sessions_per_user=5))
    client = TestClient(app)
    login_ok(client, "alice", "alice-pw")
    for _ in range(3):  # 每 0.15s 访问一次，始终不过期
        time.sleep(0.15)
        assert client.get("/auth/me").status_code == 200
    time.sleep(0.4)  # 闲置超过 ttl
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_invalid"
    print("PASS 滑动过期: 活跃续期、闲置失效")


def test_garbage_token_rejected(client):
    r = client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_invalid"
    print("PASS 伪造令牌判为 session_invalid")
