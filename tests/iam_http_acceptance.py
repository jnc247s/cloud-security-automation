"""Real bearer/capability, executor, collector, rule, persistence and public read acceptance."""

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
from tests.iam_credentials_fixtures import iam_client, iam_profile
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _empty_provider,
    _poll_terminal_scan,
)


def exercise_iam_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = iam_profile(version="6.1.0")
    policy_path = tmp_path / "iam-acceptance-policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.3.0",
                "profile": profile.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASSESSMENT_PROFILE_FILE", str(policy_path))
    monkeypatch.setenv("ASSESSMENT_PROFILE_VERSION", profile.version)
    headers = {"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"}
    entered, release = Event(), Event()
    calls = []

    def provider(region):
        calls.append(region)
        fake = _empty_provider(region)
        # Fixed ancient dates ensure these failures do not depend on the current second.
        client = iam_client(age=730, unused=730)
        pages = client._paginators["list_users"][0].pages
        client._paginators["list_users"][0] = _CollectionGatePaginator(
            pages, entered=entered, release=release
        )
        fake._clients[("iam", region)] = client
        return fake

    try:
        analyst = _development_settings(monkeypatch, engine, subject="iam-analyst", role="ANALYST")
        app = create_app(
            executor_factory=lambda: InProcessScanExecutor(
                session_factory=factory,
                settings=analyst,
                provider_factory=provider,
            )
        )
        assert app.dependency_overrides == {}
        with TestClient(app) as client:
            assert client.post("/api/v1/scans", json={"region": "us-east-1"}).status_code == 401
            assert (
                client.post(
                    "/api/v1/scans", headers=headers, json={"region": "us-east-1"}
                ).status_code
                == 403
            )
        assert calls == []

        admin = _development_settings(monkeypatch, engine, subject="iam-admin", role="ADMIN")
        app = create_app(
            executor_factory=lambda: InProcessScanExecutor(
                session_factory=factory,
                settings=admin,
                provider_factory=provider,
            )
        )
        assert app.dependency_overrides == {}
        with TestClient(app) as client:
            # Release within the lifespan on assertion failure, allowing clean shutdown.
            try:
                response = client.post(
                    "/api/v1/scans", headers=headers, json={"region": "us-east-1"}
                )
                assert response.status_code == 202, response.text
                scan_id = UUID(response.json()["scan_id"])
                assert entered.wait(timeout=10), "executor never entered the fake AWS boundary"
                assert not release.is_set()  # HTTP returned before AWS collection could finish.
            finally:
                release.set()
            scan = _poll_terminal_scan(client, scan_id, headers)
            assert scan["status"] == "COMPLETED", scan
            assert calls == ["us-east-1"]

            def get(path):
                response = client.get(f"/api/v1/{path}", headers=headers)
                assert response.status_code == 200, response.text
                return response.json()

            listing = get(f"assessments?scan_id={scan_id}")["items"]
            assert len(listing) == 4
            with Session(engine) as session:
                stored = session.scalars(
                    select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
                ).all()
                assert {str(a.assessment_id) for a in stored} == {
                    a["assessment_id"] for a in listing
                }
                for assessment in stored:
                    detail = get(f"assessments/{assessment.assessment_id}")
                    assert detail["assessment_result"] == "FAIL"
                    target = session.get(ResourceSnapshot, assessment.resource_snapshot_id)
                    assert detail["resource_snapshot_id"] == str(target.snapshot_id)
                    resource = get(f"resources/{target.resource_id}")
                    assert resource["resource_id"] == str(target.resource_id)
                    history = get(f"resources/{target.resource_id}/history")["items"]
                    assert any(
                        h["snapshot_id"] == str(target.snapshot_id) and h["scan_id"] == str(scan_id)
                        for h in history
                    )
                    evidence = session.scalars(
                        select(EvidenceArtifact).where(
                            EvidenceArtifact.assessment_id == assessment.assessment_id
                        )
                    ).one()
                    assert detail["evidence"][0]["evidence_id"] == str(evidence.evidence_id)
                    proof = detail["evidence"][0]["payload"]["source_proof"]
                    assert proof["scan_id"] == str(scan_id)
                    for citation in proof["sources"]:
                        source = get(f"source-outcomes/{citation['source_outcome_id']}")
                        assert source["scan_id"] == str(scan_id)
                        assert source["artifact"]["artifact_id"] == citation["artifact_id"]
                        assert source["artifact"]["evidence_sha256"] == citation["evidence_sha256"]
                    for edge_id in proof["relationship_observation_ids"]:
                        edge = get(f"relationships/{edge_id}")
                        assert edge["scan_id"] == str(scan_id)
                        assert edge["source"]["resource_snapshot_id"] == str(target.snapshot_id)
                        child = get(f"resources/{edge['target']['stable_resource_id']}/history")
                        assert any(
                            h["snapshot_id"] == edge["target"]["resource_snapshot_id"]
                            for h in child["items"]
                        )
                    finding = session.get(Finding, UUID(detail["finding_id"]))
                    assert finding.resource_id == target.resource_id
                    assert get(f"findings/{finding.finding_id}")["finding_id"] == str(
                        finding.finding_id
                    )
                    control = get(f"controls/{assessment.control_id}")
                    mapping = detail["framework_mappings"][0]
                    assert mapping["framework_version"] == "2.0+subset.2"
                    assert mapping["reference_key"] == (
                        "PR.AA-03" if control["control_key"] == "IAM-006" else "PR.AA-01"
                    )
                    framework = get(f"frameworks/{mapping['framework_id']}")
                    assert framework["version"] == mapping["framework_version"]
                events = session.scalars(
                    select(AuditEvent).where(AuditEvent.target_id == scan_id)
                ).all()
                assert any(
                    e.event_type is AuditEventType.SCAN_STARTED and e.actor_id == "iam-admin"
                    for e in events
                )
                assert any(e.event_type is AuditEventType.SCAN_COMPLETED for e in events)
    finally:
        release.set()
        get_settings.cache_clear()
