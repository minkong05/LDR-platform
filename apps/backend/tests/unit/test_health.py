from app.main import app
from fastapi.testclient import TestClient


def test_health_ok():
    client = TestClient(app)
    r = client.get("/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
