import os

import pytest
from app.main import app
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_db_ping():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    client = TestClient(app)
    r = client.get("/v1/db/ping")
    assert r.status_code == 200
    assert r.json() == {"db": "ok"}
