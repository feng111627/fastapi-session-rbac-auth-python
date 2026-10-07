import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        session_ttl_seconds=60.0,
        max_sessions_per_user=2,
        login_max_failures=3,
        login_lockout_seconds=60.0,
    )


@pytest.fixture()
def app(settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    # 每个用例独立 client，避免 Cookie 串扰
    return TestClient(app)


def login(client: TestClient, username: str, password: str):
    return client.post("/auth/login", json={"username": username, "password": password})


def login_ok(client: TestClient, username: str, password: str) -> dict:
    r = login(client, username, password)
    assert r.status_code == 200, r.text
    return r.json()
