from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_events_route_registered():
    """Verify /v1/events endpoint exists and responds (not 404)."""
    r = client.get("/v1/events")
    assert r.status_code != 404
