"""CSRF：Cookie 状态变更需令牌；Bearer 客户端豁免。"""

from tests.conftest import login_ok


def test_cookie_state_change_without_csrf_rejected(client):
    login_ok(client, "alice", "alice-pw")
    r = client.post("/documents/doc-1", json={"content": "x"})
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "csrf_failed"
    print("PASS Cookie 入口缺少 CSRF 令牌的状态变更被拒绝")


def test_cookie_state_change_with_wrong_csrf_rejected(client):
    login_ok(client, "alice", "alice-pw")
    r = client.post("/documents/doc-1", json={"content": "x"}, headers={"x-csrf-token": "bad"})
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "csrf_failed"
    print("PASS 错误 CSRF 令牌被拒绝")


def test_cookie_state_change_with_csrf_allowed(client):
    tokens = login_ok(client, "alice", "alice-pw")
    r = client.post(
        "/documents/doc-1",
        json={"content": "updated"},
        headers={"x-csrf-token": tokens["csrf_token"]},
    )
    assert r.status_code == 200
    assert client.get("/documents/doc-1").json()["content"] == "updated"
    print("PASS 携带正确 CSRF 令牌的 Cookie 请求放行")


def test_bearer_client_exempt_from_csrf(client):
    """Bearer 令牌无法被跨站表单携带，合法非浏览器客户端不被误伤。"""
    tokens = login_ok(client, "alice", "alice-pw")
    r = client.post(
        "/documents/doc-1",
        json={"content": "via-bearer"},
        headers={"Authorization": f"Bearer {tokens['token']}"},
    )
    assert r.status_code == 200
    print("PASS Bearer 客户端免 CSRF 校验")


def test_cookie_safe_methods_do_not_require_csrf(client):
    login_ok(client, "alice", "alice-pw")
    assert client.get("/documents/doc-1").status_code == 200
    print("PASS 安全方法（GET）无需 CSRF 令牌")
