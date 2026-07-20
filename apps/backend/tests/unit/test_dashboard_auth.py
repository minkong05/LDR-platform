from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_alerts_list_rejects_missing_token():
    r = client.get("/v1/alerts")
    assert r.status_code == 401


def test_entities_ip_summary_rejects_missing_token():
    r = client.get("/v1/entities/ip/203.0.113.55")
    assert r.status_code == 401


def test_response_block_status_rejects_missing_token():
    r = client.get("/v1/response/block-status/203.0.113.55")
    assert r.status_code == 401


def test_response_audit_log_rejects_missing_token():
    r = client.get("/v1/response/audit-log")
    assert r.status_code == 401
