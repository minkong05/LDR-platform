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
    assert "/v1/events" in paths
