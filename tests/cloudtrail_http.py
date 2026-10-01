"""6F.1 acceptance through real authentication, HTTP, executor and persistence."""

import json
from threading import Event
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database import session as database_session
from app.main import create_app
from app.models import AuditEvent, ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot
from app.models.enums import AuditEventType
from app.security.authentication import DEVELOPMENT_BEARER_MARKER
from app.services.scan_executor import InProcessScanExecutor
from tests.cloudtrail_fixtures import cloudtrail_provider, logging_profile
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _poll_terminal_scan,
)


def exercise_logging_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = logging_profile()
    path = tmp_path / "cloudtrail-http-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.11.0",
                "profile": profile.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASSESSMENT_PROFILE_FILE", str(path))
    monkeypatch.setenv("ASSESSMENT_PROFILE_VERSION", profile.version)
    headers = {"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"}
    entered, release = Event(), Event()
    calls = []

    def provider(region):
        calls.append(region)
        fake = cloudtrail_provider(region)
        client = fake._clients[("cloudtrail", region)]
        pages = client._paginators["list_trails"][0].pages
        client._paginators["list_trails"][0] = _CollectionGatePaginator(
            pages, entered=entered, release=release
        )
        return fake

    try:
        for role in ("ANALYST", "ADMIN"):
            settings = _development_settings(
                monkeypatch, engine, subject="logging-operator", role=role
            )
            app = create_app(
                executor_factory=lambda settings=settings: InProcessScanExecutor(
                    session_factory=factory, settings=settings, provider_factory=provider
                )
            )
            assert app.dependency_overrides == {}
            with TestClient(app) as client:
                if role == "ANALYST":
                    assert (
                        client.post("/api/v1/scans", json={"region": "us-east-1"}).status_code
                        == 401
                    )
                    assert (
                        client.post(
                            "/api/v1/scans", headers=headers, json={"region": "us-east-1"}
                        ).status_code
                        == 403
                    )
                    assert not calls
                    continue
                try:
                    response = client.post(
                        "/api/v1/scans", headers=headers, json={"region": "us-east-1"}
                    )
                    assert response.status_code == 202, response.text
                    scan_id = UUID(response.json()["scan_id"])
                    assert entered.wait(timeout=10)
                    assert not release.is_set(), "HTTP must return before collection finishes"
                finally:
                    release.set()
                terminal = _poll_terminal_scan(client, scan_id, headers)
                assert terminal["status"] == "COMPLETED", terminal
                assert calls == ["us-east-1"]

                def get(route):
                    response = client.get(f"/api/v1/{route}", headers=headers)
                    assert response.status_code == 200, response.text
                    return response.json()

                assert get(f"scans/{scan_id}")["scan_id"] == str(scan_id)
                listing = get(f"assessments?scan_id={scan_id}")["items"]
                relationships = get(f"relationships?scan_id={scan_id}")["items"]
                assert len(relationships) == 1
                relationship = relationships[0]
                assert relationship["relationship_type"] == "delivers_to_bucket"
                assert relationship["resolution"] == "TARGET_IDENTITY_INCOMPLETE"
                assert relationship["target"]["identity_state"] == "unresolved"
                assert relationship["target"]["scope"] == "regional"
                assert relationship["target"]["region"] is None
                assert relationship["target"]["aws_account_id"] is None
                assert relationship["target"]["stable_resource_id"] is None
                assert get(f"relationships/{relationship['observation_id']}") == relationship
                with Session(engine) as session:
                    rows = session.scalars(
                        select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
                    ).all()
                    assert len(rows) == len(listing) == 2
                    assert {str(row.assessment_id) for row in rows} == {
                        row["assessment_id"] for row in listing
                    }
                    for row in rows:
                        control_key = get(f"controls/{row.control_id}")["control_key"]
                        detail = get(f"assessments/{row.assessment_id}")
                        assert detail["assessment_result"] == "FAIL"
                        target = session.get(ResourceSnapshot, row.resource_snapshot_id)
                        assert detail["resource_snapshot_id"] == str(target.snapshot_id)
                        assert target.resource.resource_type == (
                            "aws_account" if control_key == "LOG-002" else "cloudtrail_trail"
                        )
                        assert get(f"resources/{target.resource_id}")["resource_id"] == str(
                            target.resource_id
                        )
                        assert any(
                            entry["snapshot_id"] == str(target.snapshot_id)
                            and entry["scan_id"] == str(scan_id)
                            for entry in get(f"resources/{target.resource_id}/history")["items"]
                        )
                        artifact = session.scalars(
                            select(EvidenceArtifact).where(
                                EvidenceArtifact.assessment_id == row.assessment_id
                            )
                        ).one()
                        evidence = detail["evidence"][0]
                        assert evidence["evidence_id"] == str(artifact.evidence_id)
                        assert evidence["payload"]["evaluation_version"] == "1.0.0"
                        proof = evidence["payload"]["source_proof"]
                        assert proof["schema_version"] == "1.8.0"
                        assert proof["scan_id"] == str(scan_id)
                        assert proof["relationship_observation_ids"] == []
                        assert len(proof["cloudtrail"]["trails"]) == 1
                        for citation in proof["sources"]:
                            source = get(f"source-outcomes/{citation['source_outcome_id']}")
                            assert source["scan_id"] == str(scan_id)
                            assert source["artifact"]["artifact_id"] == citation["artifact_id"]
                            assert (
                                source["artifact"]["evidence_sha256"] == citation["evidence_sha256"]
                            )
                        finding = session.get(Finding, UUID(detail["finding_id"]))
                        assert finding.resource_id == target.resource_id
                        assert get(f"findings/{finding.finding_id}")["finding_id"] == str(
                            finding.finding_id
                        )
                        assert control_key in profile.enabled_controls
                        mapping = detail["framework_mappings"][0]
                        assert mapping["framework_version"] == "2.0+subset.10"
                        assert mapping["reference_key"] == (
                            "PR.PS-04" if control_key == "LOG-002" else "PR.DS-01"
                        )
                        assert get(f"frameworks/{mapping['framework_id']}")["version"] == (
                            "2.0+subset.10"
                        )
                    events = session.scalars(
                        select(AuditEvent).where(AuditEvent.target_id == scan_id)
                    ).all()
                    assert any(
                        event.event_type is AuditEventType.SCAN_STARTED
                        and event.actor_id == "logging-operator"
                        for event in events
                    )
                    assert any(
                        event.event_type is AuditEventType.SCAN_COMPLETED for event in events
                    )
    finally:
        release.set()
        get_settings.cache_clear()
