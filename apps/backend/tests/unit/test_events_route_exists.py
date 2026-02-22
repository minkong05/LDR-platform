from app.main import app


def test_events_route_registered():
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/v1/events" in paths
