from fastapi.testclient import TestClient

from services.model_api.app import create_app
from services.model_api.monitoring import QueryMonitor


def test_api_fails_closed_without_key():
    client = TestClient(create_app(api_key=None))
    response = client.post("/predict", json={"features": [5.1, 3.5, 1.4, 0.2], "client_id": "demo"})
    assert response.status_code == 503


def test_api_auth_rate_limit_and_no_raw_payload_logging():
    application = create_app(api_key="test-secret", rate_limit=1, output_mode="rounded")
    client = TestClient(application)
    payload = {"features": [5.1, 3.5, 1.4, 0.2], "client_id": "demo"}
    unauthorized = client.post("/predict", json=payload)
    assert unauthorized.status_code == 401
    accepted = client.post("/predict", json=payload, headers={"x-api-key": "test-secret"})
    assert accepted.status_code == 200
    limited = client.post("/predict", json=payload, headers={"x-api-key": "test-secret"})
    assert limited.status_code == 429
    event = application.state.monitor.events[0]
    assert "features" not in event
    assert "input_fingerprint" in event
    assert accepted.json()["confidence"] == round(accepted.json()["confidence"], 2)


def test_query_monitor_hashes_client_and_input():
    event = QueryMonitor().record("r1", "client", "v1", [1.0, 2.0], 0, 0.9)
    assert event["client_hash"] != "client"
    assert event["input_fingerprint"]
