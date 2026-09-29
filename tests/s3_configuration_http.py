"""6E.1 real HTTP acceptance with deterministic offline AWS only."""

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
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _poll_terminal_scan,
)
from tests.s3_configuration_fixtures import failing_provider, s3_profile


def exercise_s3_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = s3_profile()
    path = tmp_path / "s3-http-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.8.0",
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
        fake = failing_provider(region)
        client = fake._clients[("s3", region)]
        pages = client._paginators["list_buckets"][0].pages
        client._paginators["list_buckets"][0] = _CollectionGatePaginator(
            pages, entered=entered, release=release
        )
        return fake

    try:
        for role in ("ANALYST", "ADMIN"):
            settings = _development_settings(monkeypatch, engine, subject="s3-operator", role=role)
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
                    assert entered.wait(timeout=10), "executor did not reach fake AWS"
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
                with Session(engine) as session:
                    rows = session.scalars(
                        select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
                    ).all()
                    assert len(rows) == len(listing) == 2
                    assert {str(a.assessment_id) for a in rows} == {
                        a["assessment_id"] for a in listing
                    }
                    for row in rows:
                        control_key = get(f"controls/{row.control_id}")["control_key"]
                        detail = get(f"assessments/{row.assessment_id}")
                        assert detail["assessment_result"] == "FAIL"
                        target = session.get(ResourceSnapshot, row.resource_snapshot_id)
                        assert detail["resource_snapshot_id"] == str(target.snapshot_id)
                        assert get(f"resources/{target.resource_id}")["resource_id"] == str(
                            target.resource_id
                        )
                        history = get(f"resources/{target.resource_id}/history")["items"]
                        assert any(
                            h["snapshot_id"] == str(target.snapshot_id)
                            and h["scan_id"] == str(scan_id)
                            for h in history
                        )
                        artifact = session.scalars(
                            select(EvidenceArtifact).where(
                                EvidenceArtifact.assessment_id == row.assessment_id
                            )
                        ).one()
                        assert detail["evidence"][0]["evidence_id"] == str(artifact.evidence_id)
                        proof = detail["evidence"][0]["payload"]["source_proof"]
                        assert proof["scan_id"] == str(scan_id)
                        for citation in proof["sources"]:
                            source = get(f"source-outcomes/{citation['source_outcome_id']}")
                            assert source["scan_id"] == str(scan_id)
                            assert source["artifact"]["artifact_id"] == citation["artifact_id"]
                            assert (
                                source["artifact"]["evidence_sha256"] == citation["evidence_sha256"]
                            )
                        assert proof["relationship_observation_ids"] == []
                        finding = session.get(Finding, UUID(detail["finding_id"]))
                        assert finding.resource_id == target.resource_id
                        assert get(f"findings/{finding.finding_id}")["finding_id"] == str(
                            finding.finding_id
                        )
                        assert control_key in profile.enabled_controls
                        mapping = detail["framework_mappings"][0]
                        version = "2.0+subset.7"
                        assert mapping["framework_version"] == version
                        assert mapping["reference_key"] == (
                            "PR.AA-05" if control_key == "S3-001" else "PR.DS-02"
                        )
                        assert get(f"frameworks/{mapping['framework_id']}")["version"] == version
                    events = session.scalars(
                        select(AuditEvent).where(AuditEvent.target_id == scan_id)
                    ).all()
                    assert any(
                        e.event_type is AuditEventType.SCAN_STARTED and e.actor_id == "s3-operator"
                        for e in events
                    )
                    assert any(e.event_type is AuditEventType.SCAN_COMPLETED for e in events)
    finally:
        release.set()
        get_settings.cache_clear()
