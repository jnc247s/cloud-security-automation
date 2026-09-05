"""HTTP contract tests for the asynchronous scan boundary."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.errors import scan_submission_error_handler
from app.api.routes.scans import get_scan_executor, router
from app.database.session import get_db
from app.security.authentication import Principal, get_current_principal
from app.services.scan_service import ScanSubmissionError


class RecordingExecutor:
    def __init__(self, *, reject: bool = False) -> None:
        self.scan_ids = []
        self.reject = reject

    def submit(self, scan_id) -> None:
        self.scan_ids.append(scan_id)
        if self.reject:
            raise RuntimeError("non-public executor detail")

    def shutdown(self, *, wait: bool = True) -> None:
        pass


@pytest.fixture
def scan_api() -> Iterator[tuple[TestClient, RecordingExecutor]]:
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    executor = RecordingExecutor()
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    application.add_exception_handler(ScanSubmissionError, scan_submission_error_handler)

    def database_override() -> Iterator[Session]:
        with factory() as session:
            yield session

    application.dependency_overrides[get_db] = database_override
    application.dependency_overrides[get_scan_executor] = lambda: executor
    application.dependency_overrides[get_current_principal] = lambda: Principal(
        subject="api-admin",
        role_names=frozenset({"ADMIN"}),
        issuer="test",
    )
    with TestClient(application) as client:
        yield client, executor
    engine.dispose()


def test_post_scan_returns_202_before_execution_and_supports_reads(scan_api) -> None:
    client, executor = scan_api

    response = client.post("/api/v1/scans", json={"region": "us-west-2"})

    assert response.status_code == 202
    document = response.json()
    assert document["status"] == "RUNNING"
    assert document["aws_account_id"] is None
    assert document["inventory_sha256"] is None
    assert document["requested_regions"] == ["us-west-2"]
    assert [str(scan_id) for scan_id in executor.scan_ids] == [document["scan_id"]]
    detail = client.get(f"/api/v1/scans/{document['scan_id']}")
    assert detail.status_code == 200
    assert detail.json()["scan_id"] == document["scan_id"]
    listing = client.get("/api/v1/scans")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1


def test_post_scan_rejects_caller_supplied_account_identity(scan_api) -> None:
    client, executor = scan_api

    response = client.post(
        "/api/v1/scans",
        json={"region": "us-west-2", "aws_account_id": "999999999999"},
    )

    assert response.status_code == 422
    assert executor.scan_ids == []


def test_rejected_submission_returns_durable_failed_scan_id(scan_api) -> None:
    client, executor = scan_api
    executor.reject = True

    response = client.post("/api/v1/scans", json={"region": "us-west-2"})

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["code"] == "scan_submission_failed"
    assert detail["scan_id"] == str(executor.scan_ids[0])
    stored = client.get(f"/api/v1/scans/{detail['scan_id']}")
    assert stored.status_code == 200
    assert stored.json()["status"] == "FAILED"
    assert "non-public executor detail" not in response.text


def test_unauthenticated_post_is_rejected_before_executor_lookup() -> None:
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")

    with TestClient(application) as client:
        response = client.post("/api/v1/scans", json={"region": "us-west-2"})

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "authentication_required"
