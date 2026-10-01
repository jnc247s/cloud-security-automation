"""Real authenticated 6F.2 HTTP execution/readback; only AWS responses are offline."""

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
from tests.cloudtrail_destination_fixtures import destination_profile, destination_provider
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _poll_terminal_scan,
)
from tests.s3_exposure_fixtures import policy_response, statement


def exercise_destination_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = destination_profile()
    path = tmp_path / "destination-http-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.12.0",
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
        fake = destination_provider(
            region,
            policy_response=policy_response(statement()),
            policy_status_response={"PolicyStatus": {"IsPublic": True}},
        )
        client = fake._clients[("cloudtrail", region)]
        pages = client._paginators["list_trails"][0].pages
        client._paginators["list_trails"][0] = _CollectionGatePaginator(
            pages, entered=entered, release=release
        )
        return fake

    try:
        for role in ("ANALYST", "ADMIN"):
            settings = _development_settings(
                monkeypatch, engine, subject="destination-operator", role=role
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
                    assert not release.is_set()
                finally:
                    release.set()
                terminal = _poll_terminal_scan(client, scan_id, headers)
                assert terminal["status"] == "COMPLETED", terminal
                assert calls == ["us-east-1"]

                def get(route):
                    response = client.get(f"/api/v1/{route}", headers=headers)
                    assert response.status_code == 200, response.text
                    return response.json()

                listing = get(f"assessments?scan_id={scan_id}")["items"]
                assert len(listing) == 2
                relationships = get(f"relationships?scan_id={scan_id}")["items"]
                edge = next(
                    r for r in relationships if r["relationship_type"] == "delivers_to_bucket"
                )
                assert edge["resolution"] == "RESOLVED"
                assert get(f"relationships/{edge['observation_id']}") == edge
                with Session(engine) as session:
                    rows = session.scalars(
                        select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
                    ).all()
                    details = {
                        get(f"controls/{r.control_id}")["control_key"]: get(
                            f"assessments/{r.assessment_id}"
                        )
                        for r in rows
                    }
                    assert set(details) == {"LOG-004", "S3-002"}
                    assert all(d["assessment_result"] == "FAIL" for d in details.values())
                    log = details["LOG-004"]
                    proof = log["evidence"][0]["payload"]["source_proof"]
                    assert proof["schema_version"] == "1.9.0"
                    assert proof["relationship_observation_ids"] == [edge["observation_id"]]
                    dependency = proof["destination_dependency"]
                    assert (
                        dependency["resource_snapshot_id"]
                        == details["S3-002"]["resource_snapshot_id"]
                    )
                    assert (
                        dependency["resource_snapshot_id"] == edge["target"]["resource_snapshot_id"]
                    )
                    assert dependency["profile_checksum"] == profile.content_checksum
                    assert (
                        dependency["evidence"][0]["evidence_id"]
                        == details["S3-002"]["evidence"][0]["evidence_id"]
                    )
                    for row in rows:
                        detail = get(f"assessments/{row.assessment_id}")
                        target = session.get(ResourceSnapshot, row.resource_snapshot_id)
                        assert get(f"resources/{target.resource_id}")["resource_id"] == str(
                            target.resource_id
                        )
                        assert any(
                            h["snapshot_id"] == str(target.snapshot_id)
                            for h in get(f"resources/{target.resource_id}/history")["items"]
                        )
                        evidence = session.scalars(
                            select(EvidenceArtifact).where(
                                EvidenceArtifact.assessment_id == row.assessment_id
                            )
                        ).one()
                        assert detail["evidence"][0]["evidence_id"] == str(evidence.evidence_id)
                        finding = session.get(Finding, UUID(detail["finding_id"]))
                        assert get(f"findings/{finding.finding_id}")["finding_id"] == str(
                            finding.finding_id
                        )
                    for citation in proof["sources"]:
                        source = get(f"source-outcomes/{citation['source_outcome_id']}")
                        assert source["artifact"]["evidence_sha256"] == citation["evidence_sha256"]
                        assert source["artifact"]["artifact_id"] == citation["artifact_id"]
                    mapping = log["framework_mappings"][0]
                    assert mapping["reference_key"] == "PR.AA-05"
                    assert (
                        get(f"frameworks/{mapping['framework_id']}")["version"] == "2.0+subset.11"
                    )
                    events = session.scalars(
                        select(AuditEvent).where(AuditEvent.target_id == scan_id)
                    ).all()
                    assert any(
                        e.event_type is AuditEventType.SCAN_STARTED
                        and e.actor_id == "destination-operator"
                        for e in events
                    )
                    assert any(e.event_type is AuditEventType.SCAN_COMPLETED for e in events)
    finally:
        release.set()
        get_settings.cache_clear()
