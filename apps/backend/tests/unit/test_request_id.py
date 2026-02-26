from app.main import app
from fastapi.testclient import TestClient


def test_request_id_header_added():
    client = TestClient(app)
    r = client.get("/v1/health")
    assert r.status_code == 200
    assert "X-Request-Id" in r.headers
