"""Authenticated HTTP coverage for generic evidence-graph reads."""

from collections.abc import Iterator
from uuid import uuid4

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.errors import entity_not_found_handler
from app.api.routes.relationships import router as relationships_router
from app.api.routes.source_outcomes import router as source_outcomes_router
from app.config import Settings, get_settings
from app.database.base import Base
from app.database.persistence import persist_scan_result
from app.database.session import get_db
from app.security.authentication import DEVELOPMENT_BEARER_MARKER
from app.services.errors import EntityNotFoundError
from tests.unit.database.factories import graph_scan_bundle

AUTHORIZATION = {"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"}


@pytest.fixture
def graph_api_session() -> Iterator[Session]:
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
def graph_client(graph_api_session: Session) -> Iterator[TestClient]:
    application = FastAPI()
    versioned_router = APIRouter(prefix="/api/v1")
    versioned_router.include_router(relationships_router)
    versioned_router.include_router(source_outcomes_router)
    application.include_router(versioned_router)
    application.add_exception_handler(EntityNotFoundError, entity_not_found_handler)

    def override_database() -> Iterator[Session]:
        yield graph_api_session

    application.dependency_overrides[get_db] = override_database
    application.dependency_overrides[get_settings] = lambda: Settings(
        app_env="test",
        auth_mode="development",
        dev_identity_subject="evidence-reader",
        dev_identity_roles="VIEWER",
    )
    with TestClient(application) as client:
        yield client


def _persist_fixture(session: Session) -> dict:
    bundle = graph_scan_bundle()
    persist_scan_result(session, **bundle)
    session.commit()
    return bundle


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/relationships",
        "/api/v1/source-outcomes",
    ],
)
def test_evidence_graph_routes_require_real_bearer_authentication(
    graph_client: TestClient,
    path: str,
) -> None:
    missing = graph_client.get(path)
    invalid = graph_client.get(path, headers={"Authorization": "Bearer invalid"})

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert missing.json()["detail"]["code"] == "authentication_required"
    assert invalid.json()["detail"]["code"] == "authentication_required"


def test_relationship_routes_support_read_auth_filters_pagination_and_detail(
    graph_client: TestClient,
    graph_api_session: Session,
) -> None:
    bundle = _persist_fixture(graph_api_session)
    graph = bundle["snapshot"].evidence_graph
    relationship = graph.relationships[0]

    page = graph_client.get(
        "/api/v1/relationships",
        headers=AUTHORIZATION,
        params={
            "scan_id": str(bundle["snapshot"].scan_id),
            "relationship_type": "attached_to_security_group",
            "resolution": "RESOLVED",
            "source_resource_id": str(relationship.source.stable_resource_id),
            "target_resource_id": str(relationship.target.stable_resource_id),
            "limit": 1,
            "offset": 0,
        },
    )
    detail = graph_client.get(
        f"/api/v1/relationships/{relationship.observation_id}",
        headers=AUTHORIZATION,
    )

    assert page.status_code == 200
    assert page.json()["total"] == 1
    assert page.json()["limit"] == 1
    assert page.json()["items"][0]["observation_id"] == str(relationship.observation_id)
    assert detail.status_code == 200
    assert detail.json()["relationship_id"] == str(relationship.relationship_id)
    assert detail.json()["source_outcome_id"] == str(graph.source_outcomes[0].source_outcome_id)
    assert detail.json()["provenance"]["evidence_reference"].startswith("normalized://")


def test_source_outcome_routes_filter_and_return_the_sanitized_artifact(
    graph_client: TestClient,
    graph_api_session: Session,
) -> None:
    bundle = _persist_fixture(graph_api_session)
    graph = bundle["snapshot"].evidence_graph
    outcome = graph.source_outcomes[0]

    page = graph_client.get(
        "/api/v1/source-outcomes",
        headers=AUTHORIZATION,
        params={
            "scan_id": str(bundle["snapshot"].scan_id),
            "contract_key": "ec2.instance-security-groups",
            "collector": "SecurityGroupCollector",
            "phase": "DISCOVERY",
            "evidence_kind": "ec2.instance-security-groups",
            "state": "PRESENT",
            "limit": 1,
        },
    )
    detail = graph_client.get(
        f"/api/v1/source-outcomes/{outcome.source_outcome_id}",
        headers=AUTHORIZATION,
    )

    assert page.status_code == 200
    assert page.json()["total"] == 1
    assert page.json()["items"][0]["source_outcome_id"] == str(outcome.source_outcome_id)
    assert detail.status_code == 200
    assert detail.json()["artifact"]["evidence_sha256"] == outcome.evidence_sha256
    assert detail.json()["artifact"]["normalized_payload"] == {
        "instance_id": "i-evidence-graph",
        "security_group_ids": ["sg-history"],
    }


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/relationships",
        "/api/v1/source-outcomes",
    ],
)
def test_evidence_graph_routes_enforce_pagination_bounds(
    graph_client: TestClient,
    path: str,
) -> None:
    response = graph_client.get(path, headers=AUTHORIZATION, params={"limit": 101})

    assert response.status_code == 422


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/relationships",
        "/api/v1/source-outcomes",
    ],
)
def test_evidence_graph_routes_translate_missing_ids(
    graph_client: TestClient,
    path: str,
) -> None:
    response = graph_client.get(f"{path}/{uuid4()}", headers=AUTHORIZATION)

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "entity_not_found"
