import pytest
from dashboard.app import create_app
from werkzeug.security import generate_password_hash

ANALYST_PASSWORD = "analyst-test-pass"
ADMIN_PASSWORD = "admin-test-pass"


@pytest.fixture
def app():
    application = create_app()
    application.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        DASHBOARD_USERS={
            "analyst1": {
                "password_hash": generate_password_hash(ANALYST_PASSWORD),
                "role": "analyst",
            },
            "admin1": {
                "password_hash": generate_password_hash(ADMIN_PASSWORD),
                "role": "admin",
            },
        },
    )
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def analyst_client(client):
    with client.session_transaction() as sess:
        sess["username"] = "analyst1"
        sess["role"] = "analyst"
    return client


@pytest.fixture
def admin_client(client):
    with client.session_transaction() as sess:
        sess["username"] = "admin1"
        sess["role"] = "admin"
    return client


@pytest.fixture
def mock_api(monkeypatch):
    """Stub out dashboard.api_client so route tests never hit the network."""
    calls = {"get": [], "post": [], "patch": []}

    def fake_get(path, params=None):
        calls["get"].append((path, params))
        return {}

    def fake_post(path, payload=None):
        calls["post"].append((path, payload))
        return {"note": "ok"}

    def fake_patch(path, payload=None):
        calls["patch"].append((path, payload))
        return {"note": "ok"}

    monkeypatch.setattr("dashboard.api_client.get", fake_get)
    monkeypatch.setattr("dashboard.api_client.post", fake_post)
    monkeypatch.setattr("dashboard.api_client.patch", fake_patch)
    return calls
