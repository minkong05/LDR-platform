# Must match the hashes the `app` fixture in conftest.py builds for these users.
ANALYST_PASSWORD = "analyst-test-pass"
ADMIN_PASSWORD = "admin-test-pass"


def test_unauthenticated_request_redirects_to_login(client):
    resp = client.get("/alerts/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_health_endpoint_is_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_login_page_is_public(client):
    resp = client.get("/login")
    assert resp.status_code == 200


def test_login_success_sets_session(client):
    resp = client.post("/login", data={"username": "analyst1", "password": ANALYST_PASSWORD})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess["username"] == "analyst1"
        assert sess["role"] == "analyst"


def test_login_success_sets_session_admin(client):
    resp = client.post("/login", data={"username": "admin1", "password": ADMIN_PASSWORD})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess["username"] == "admin1"
        assert sess["role"] == "admin"


def test_login_invalid_credentials_rejected(client):
    resp = client.post("/login", data={"username": "analyst1", "password": "wrong"})
    assert resp.status_code == 401
    with client.session_transaction() as sess:
        assert "username" not in sess


def test_login_unknown_user_rejected(client):
    resp = client.post("/login", data={"username": "nobody", "password": "whatever"})
    assert resp.status_code == 401


def test_logout_clears_session(admin_client):
    resp = admin_client.post("/logout")
    assert resp.status_code == 302
    with admin_client.session_transaction() as sess:
        assert "username" not in sess


def test_analyst_forbidden_from_block(analyst_client, mock_api):
    resp = analyst_client.post("/entities/ip/1.2.3.4/block", data={})
    assert resp.status_code == 403
    assert mock_api["post"] == []


def test_analyst_forbidden_from_unblock(analyst_client, mock_api):
    resp = analyst_client.post("/entities/ip/1.2.3.4/unblock", data={})
    assert resp.status_code == 403
    assert mock_api["post"] == []


def test_admin_allowed_to_block(admin_client, mock_api):
    resp = admin_client.post("/entities/ip/1.2.3.4/block", data={})
    assert resp.status_code == 302
    assert mock_api["post"]
    assert mock_api["post"][0][0] == "/v1/response/block"


def test_admin_allowed_to_unblock(admin_client, mock_api):
    resp = admin_client.post("/entities/ip/1.2.3.4/unblock", data={})
    assert resp.status_code == 302
    assert mock_api["post"]
    assert mock_api["post"][0][0] == "/v1/response/unblock/1.2.3.4"


def test_analyst_forbidden_from_audit_verify(analyst_client, mock_api):
    resp = analyst_client.get("/response/audit/verify")
    assert resp.status_code == 403
    assert mock_api["get"] == []


def test_admin_allowed_to_audit_verify(admin_client, mock_api):
    resp = admin_client.get("/response/audit/verify")
    assert resp.status_code == 302
    assert mock_api["get"]
    assert mock_api["get"][0][0] == "/v1/response/audit-log/verify"
