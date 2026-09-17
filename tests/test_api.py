from fastapi.testclient import TestClient

from queryguard.api import create_app
from queryguard.quota import QuotaLimits, QuotaStore
from queryguard.service import QueryGuardService


def client():
    return TestClient(create_app(QueryGuardService(quota=QuotaStore(QuotaLimits(requests=10)))))


def test_health_and_analyze():
    c = client()
    assert c.get("/v1/health").status_code == 200
    response = c.post("/v1/analyze", json={"sql": "SELECT * FROM users"})
    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_execute_masks_schema_pii():
    c = client()
    response = c.post("/v1/execute", json={
        "sql": "SELECT id, email FROM users", "schema": {
            "tables": [{"name": "users", "columns": [
                {"name": "id", "data_type": "INTEGER"},
                {"name": "email", "data_type": "TEXT"}]}]
        }
    })
    assert response.status_code == 200
    assert response.json()["masked_columns"] == ["email"]


def test_read_only_rejects_write():
    assert client().post("/v1/execute", json={"sql": "DELETE FROM users"}).status_code == 400


def test_high_risk_read_is_blocked():
    assert client().post("/v1/execute", json={"sql": "SELECT * FROM users"}).status_code == 400


def test_read_only_rejects_mutating_cte():
    assert client().post("/v1/execute", json={
        "sql": "WITH doomed AS (SELECT 1) DELETE FROM users"
    }).status_code == 400
