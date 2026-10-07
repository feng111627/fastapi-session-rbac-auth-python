"""登录路径：成功/失败/未认证的可区分结果。"""

from tests.conftest import login, login_ok


def test_login_success_sets_cookie_and_returns_token(client):
    r = login(client, "alice", "alice-pw")
    assert r.status_code == 200
    body = r.json()
    assert body["token"] and body["csrf_token"]
    cookie = r.headers.get("set-cookie", "")
    assert "sid=" in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    print("PASS 登录成功: 下发 Cookie + 令牌 + CSRF 令牌")


def test_login_wrong_password(client):
    r = login(client, "alice", "wrong")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_credentials"
    print("PASS 口令错误: 401 invalid_credentials")


def test_login_unknown_user_same_response(client):
    """未知用户与口令错误响应一致，不暴露账号是否存在。"""
    r_unknown = login(client, "nobody", "x")
    r_wrongpw = login(client, "alice", "wrong")
    assert r_unknown.status_code == r_wrongpw.status_code == 401
    assert r_unknown.json() == r_wrongpw.json()
    print("PASS 未知用户与口令错误响应一致")


def test_unauthenticated_rejected(client):
    r = client.get("/documents/doc-1")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "unauthenticated"
    print("PASS 未认证访问受保护资源: 401 unauthenticated")


def test_cookie_and_bearer_same_identity(client, app):
    """Cookie 与 Bearer 两种入口对同一账号得出同一身份与权限结论。"""
    tokens = login_ok(client, "alice", "alice-pw")
    bearer = {"Authorization": f"Bearer {tokens['token']}"}

    r_cookie = client.get("/auth/me")
    r_bearer = client.get("/auth/me", headers=bearer)
    assert r_cookie.status_code == r_bearer.status_code == 200
    assert r_cookie.json()["username"] == r_bearer.json()["username"] == "alice"
    assert {r_cookie.json()["via"], r_bearer.json()["via"]} == {"cookie", "bearer"}

    d_cookie = client.get("/documents/doc-1")
    d_bearer = client.get("/documents/doc-1", headers=bearer)
    assert d_cookie.status_code == d_bearer.status_code == 200
    assert d_cookie.json() == d_bearer.json()
    print("PASS Cookie 与 Bearer 入口身份/权限结论一致")
