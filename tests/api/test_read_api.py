"""Authenticated HTTP coverage for Sprint 4 read endpoints."""

from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.errors import entity_not_found_handler
from app.api.routes.assessments import router as assessments_router
from app.api.routes.controls import router as controls_router
from app.api.routes.exceptions import router as exceptions_router
from app.api.routes.findings import router as findings_router
from app.api.routes.frameworks import router as frameworks_router
from app.api.routes.resources import router as resources_router
from app.database.base import Base
from app.database.persistence import persist_scan_result
from app.database.session import get_db
from app.models.assessment import ControlAssessment
from app.models.control import Framework
from app.models.finding import Finding
from app.models.resource import Resource
from app.services.errors import EntityNotFoundError
from tests.unit.database.factories import scan_bundle

AUTHORIZATION = {"Authorization": "Bearer local-development"}


@pytest.fixture
def api_session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


@pytest.fixture
def read_client(api_session: Session) -> Iterator[TestClient]:
    application = FastAPI()
    versioned_router = APIRouter(prefix="/api/v1")
    for route_router in (
        resources_router,
        assessments_router,
        findings_router,
        controls_router,
        frameworks_router,
        exceptions_router,
    ):
        versioned_router.include_router(route_router)
    application.include_router(versioned_router)
    application.add_exception_handler(EntityNotFoundError, entity_not_found_handler)

    def override_database() -> Iterator[Session]:
        yield api_session

    application.dependency_overrides[get_db] = override_database
    with TestClient(application) as client:
        yield client


def _persist_fixture(db_session: Session) -> None:
    persist_scan_result(db_session, **scan_bundle())
    db_session.commit()


def test_read_routes_require_authentication(read_client: TestClient) -> None:
    response = read_client.get("/api/v1/resources")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "authentication_required"


def test_read_routes_expose_machine_readable_provenance(
    read_client: TestClient,
    api_session: Session,
) -> None:
    _persist_fixture(api_session)
    resource_id = api_session.scalars(select(Resource.resource_id)).one()
    assessment_id = api_session.scalars(select(ControlAssessment.assessment_id)).one()
    finding_id = api_session.scalars(select(Finding.finding_id)).one()
    control_id = api_session.scalars(select(ControlAssessment.control_id)).one()
    framework_id = api_session.scalars(select(Framework.framework_id)).one()

    resource_page = read_client.get(
        "/api/v1/resources",
        headers=AUTHORIZATION,
        params={"service": "ec2"},
    )
    history = read_client.get(
        f"/api/v1/resources/{resource_id}/history",
        headers=AUTHORIZATION,
    )
    assessment = read_client.get(
        f"/api/v1/assessments/{assessment_id}",
        headers=AUTHORIZATION,
    )
    finding = read_client.get(
        f"/api/v1/findings/{finding_id}",
        headers=AUTHORIZATION,
    )
    control = read_client.get(
        f"/api/v1/controls/{control_id}",
        headers=AUTHORIZATION,
    )
    framework = read_client.get(
        f"/api/v1/frameworks/{framework_id}",
        headers=AUTHORIZATION,
    )
    exceptions = read_client.get("/api/v1/exceptions", headers=AUTHORIZATION)
    list_responses = {
        "assessments": read_client.get(
            "/api/v1/assessments",
            headers=AUTHORIZATION,
            params={"result": "FAIL"},
        ),
        "findings": read_client.get(
            "/api/v1/findings",
            headers=AUTHORIZATION,
            params={"status": "OPEN"},
        ),
        "controls": read_client.get("/api/v1/controls", headers=AUTHORIZATION),
        "frameworks": read_client.get("/api/v1/frameworks", headers=AUTHORIZATION),
    }

    assert resource_page.status_code == 200
    assert resource_page.json()["items"][0]["resource_id"] == str(resource_id)
    assert history.status_code == 200
    assert history.json()["items"][0]["scan_id"]
    assert assessment.status_code == 200
    assert assessment.json()["assessment_result"] == "FAIL"
    assert assessment.json()["evidence"]
    assert assessment.json()["framework_mappings"]
    assert finding.status_code == 200
    assert finding.json()["occurrences"][0]["assessment_id"] == str(assessment_id)
    assert control.status_code == 200
    assert control.json()["versions"][0]["framework_mappings"]
    assert framework.status_code == 200
    assert any(item["control_mappings"] for item in framework.json()["references"])
    assert exceptions.status_code == 200
    assert exceptions.json()["total"] == 0
    assert all(response.status_code == 200 for response in list_responses.values())
    assert all(response.json()["total"] >= 1 for response in list_responses.values())


def test_read_routes_enforce_bounds_and_translate_missing_entities(
    read_client: TestClient,
) -> None:
    invalid_page = read_client.get(
        "/api/v1/resources",
        headers=AUTHORIZATION,
        params={"limit": 101},
    )
    missing = read_client.get(
        f"/api/v1/resources/{uuid4()}",
        headers=AUTHORIZATION,
    )

    assert invalid_page.status_code == 422
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "entity_not_found"
    assert UUID(missing.json()["detail"]["identifier"])
