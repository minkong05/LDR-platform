from app.main import app


def _all_paths(routes):
    """Recursively collect all route paths from nested routers."""
    paths = set()
    for r in routes:
        path = getattr(r, "path", None)
        if path:
            paths.add(path)
        subroutes = getattr(r, "routes", None)
        if subroutes:
            paths |= _all_paths(subroutes)
    return paths


def test_events_route_registered():
    paths = _all_paths(app.routes)
    # Depending on FastAPI version, the route is stored as "/v1/events" or "/events"
    assert "/v1/events" in paths or "/events" in paths
