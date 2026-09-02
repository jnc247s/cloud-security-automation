"""Tests for the readiness endpoint."""

from fastapi.testclient import TestClient
from pytest import MonkeyPatch
from sqlalchemy.exc import SQLAlchemyError

from app.api.routes import health


def test_ready_when_database_connection_succeeds(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(health, "check_database_connection", lambda: None)

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "service": "cloud-security-control-plane",
        "checks": {"database": "ready"},
    }


def test_not_ready_when_database_connection_fails(
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    def unavailable_database() -> None:
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(health, "check_database_connection", unavailable_database)

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "service": "cloud-security-control-plane",
        "checks": {"database": "unavailable"},
    }
