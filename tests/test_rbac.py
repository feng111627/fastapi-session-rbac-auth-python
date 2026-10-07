"""权限判定：角色继承、显式拒绝优先、多入口一致、不暴露资源存在性。"""

from app.models import Effect, PermissionGrant
from tests.conftest import login_ok


def test_role_inheritance_allows_and_denies(client):
    """editor 继承 viewer 的读权限，但没有 delete 权限。"""
    tokens = login_ok(client, "alice", "alice-pw")  # editor
    assert client.get("/documents/doc-1").status_code == 200
    r = client.delete("/documents/doc-1", headers={"x-csrf-token": tokens["csrf_token"]})
    assert r.status_code == 403
    print("PASS 角色继承: editor 可读、不可删")


def test_viewer_cannot_write(client):
    tokens = login_ok(client, "bob", "bob-pw")  # viewer
    r = client.post(
        "/documents/doc-1",
        json={"content": "x"},
        headers={"x-csrf-token": tokens["csrf_token"]},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "forbidden"
    print("PASS 权限不足: 403 forbidden（与未认证 401 可区分）")


def test_explicit_deny_overrides_role_allow(client, app):
    """对特定资源的显式 DENY 优先于角色继承来的 ALLOW。"""
    app.state.store.add_grant(
        PermissionGrant(Effect.DENY, "user:alice", "doc:read", "doc-1")
    )
    login_ok(client, "alice", "alice-pw")
    assert client.get("/documents/doc-1").status_code == 403
    assert client.get("/documents/doc-2").status_code == 200  # 其他资源不受影响
    print("PASS 显式拒绝优先于允许，且只作用于指定资源")


def test_direct_and_indirect_entries_consistent(client, app):
    """/documents/{id} 与 /reports/{id} 对同一权限判定结论一致。"""
    app.state.store.add_grant(
        PermissionGrant(Effect.DENY, "role:editor", "doc:read", "doc-2")
    )
    login_ok(client, "alice", "alice-pw")
    assert client.get("/documents/doc-2").status_code == 403
    assert client.get("/reports/doc-2").status_code == 403
    assert client.get("/documents/doc-1").status_code == 200
    assert client.get("/reports/doc-1").status_code == 200
    print("PASS 直接与间接入口权限结论一致")


def test_forbidden_does_not_leak_existence(client):
    """资源不存在与无权限返回完全一致的响应。"""
    login_ok(client, "bob", "bob-pw")  # viewer 有 doc:read，无 doc:write
    tokens = client.post(
        "/auth/login", json={"username": "bob", "password": "bob-pw"}
    ).json()
    headers = {"x-csrf-token": tokens["csrf_token"]}
    r_missing = client.post("/documents/no-such-doc", json={"content": "x"}, headers=headers)
    r_noperm = client.post("/documents/doc-1", json={"content": "x"}, headers=headers)
    # viewer 对已存在的 doc-1 无写权限；no-such-doc 不存在 —— 两者响应必须一致
    assert r_missing.status_code == r_noperm.status_code == 403
    assert r_missing.json() == r_noperm.json()
    print("PASS 无权与资源不存在响应一致，不暴露存在性")


def test_admin_inherits_all_and_can_delete(client):
    tokens = login_ok(client, "carol", "carol-pw")  # admin
    r = client.delete("/documents/doc-2", headers={"x-csrf-token": tokens["csrf_token"]})
    assert r.status_code == 200
    print("PASS admin 继承链完整，可删除文档")
