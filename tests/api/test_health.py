"""Tests for the health endpoint."""

from fastapi.testclient import TestClient


def test_health_returns_expected_payload(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "cloud-security-control-plane",
    }
