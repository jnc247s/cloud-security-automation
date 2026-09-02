"""Application startup smoke test."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_application_starts_and_exposes_openapi() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Cloud Security Control Plane"
