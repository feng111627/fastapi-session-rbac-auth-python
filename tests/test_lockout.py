"""连续失败锁定：阈值、可区分结果、并发计数准确性、成功清零。"""

from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
from tests.conftest import login, login_ok


def test_lockout_after_threshold(client, settings):
    for _ in range(settings.login_max_failures - 1):
        r = login(client, "alice", "wrong")
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "invalid_credentials"
    # 达到阈值的那一次仍返回 invalid_credentials
    assert login(client, "alice", "wrong").status_code == 401
    # 之后即使口令正确也被锁定
    r = login(client, "alice", "alice-pw")
    assert r.status_code == 423
    assert r.json()["detail"]["reason"] == "account_locked"
    print("PASS 连续失败达阈值后锁定，锁定/失败结果可区分")


def test_success_resets_failure_count(client, settings):
    for _ in range(settings.login_max_failures - 1):
        login(client, "alice", "wrong")
    login_ok(client, "alice", "alice-pw")  # 成功清零
    for _ in range(settings.login_max_failures - 1):
        login(client, "alice", "wrong")
    r = login(client, "alice", "alice-pw")  # 未达阈值，不应被锁
    assert r.status_code == 200
    print("PASS 登录成功清零失败计数")


def test_concurrent_failures_counted_accurately(app, settings):
    """并发失败请求下计数不丢失：恰好阈值次失败后必须锁定。"""
    client = TestClient(app)
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda _: login(client, "alice", "wrong"), range(settings.login_max_failures)))
    r = login(client, "alice", "alice-pw")
    assert r.status_code == 423
    assert r.json()["detail"]["reason"] == "account_locked"
    print("PASS 并发失败计数准确，锁定不被竞争绕过")


def test_lockout_is_per_user(client):
    for _ in range(3):
        login(client, "alice", "wrong")
    assert login(client, "alice", "alice-pw").status_code == 423
    assert login(client, "bob", "bob-pw").status_code == 200  # 其他账号不受影响
    print("PASS 锁定按账号隔离")
