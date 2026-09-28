"""6C real HTTP/auth/executor/persistence acceptance; only AWS responses are fake."""

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
from tests.ec2_fixtures import ec2_client, ec2_profile
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _empty_provider,
    _poll_terminal_scan,
)


def install_ec2_client(provider, region, client):
    existing = provider._clients[("ec2", region)]
    existing._paginators.update(client._paginators)
    existing._responses.update(client._responses)


def exercise_ec2_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = ec2_profile()
    path = tmp_path / "ec2-http-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.5.0",
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
        fake = _empty_provider(region)
        client = ec2_client()
        pages = client._paginators["describe_instances"][0].pages
        client._paginators["describe_instances"][0] = _CollectionGatePaginator(
            pages, entered=entered, release=release
        )
        install_ec2_client(fake, region, client)
        return fake

    try:
        for role in ("ANALYST", "ADMIN"):
            settings = _development_settings(monkeypatch, engine, subject="ec2-operator", role=role)
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
                    assert len(rows) == len(listing) == 4
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
                        if control_key == "EC2-004":
                            assert target.region == "us-east-1" and target.scope.value == "regional"
                            assert target.resource.resource_type == "aws_account"
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
                        finding = session.get(Finding, UUID(detail["finding_id"]))
                        assert finding.resource_id == target.resource_id
                        assert get(f"findings/{finding.finding_id}")["finding_id"] == str(
                            finding.finding_id
                        )
                        assert control_key in profile.enabled_controls
                        mapping = detail["framework_mappings"][0]
                        assert mapping["framework_version"] == "2.0+subset.4"
                        assert (
                            mapping["reference_key"]
                            == {
                                "EC2-001": "PR.PS-01",
                                "EC2-002": "PR.IR-01",
                                "EC2-003": "PR.DS-01",
                                "EC2-004": "PR.DS-01",
                            }[control_key]
                        )
                        assert (
                            get(f"frameworks/{mapping['framework_id']}")["version"]
                            == "2.0+subset.4"
                        )
                    events = session.scalars(
                        select(AuditEvent).where(AuditEvent.target_id == scan_id)
                    ).all()
                    assert any(
                        e.event_type is AuditEventType.SCAN_STARTED and e.actor_id == "ec2-operator"
                        for e in events
                    )
                    assert any(e.event_type is AuditEventType.SCAN_COMPLETED for e in events)
    finally:
        release.set()
        get_settings.cache_clear()
