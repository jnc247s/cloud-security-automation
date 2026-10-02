"""Real authenticated GOV-001 scan execution and generic readback; only AWS is offline."""

import json
from threading import Event
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database import session as database_session
from app.main import create_app
from app.models import AuditEvent, ControlAssessment, ResourceSnapshot
from app.models.enums import AuditEventType
from app.security.authentication import DEVELOPMENT_BEARER_MARKER
from app.services.scan_executor import InProcessScanExecutor
from tests.governance_fixtures import governance_profile, governance_provider
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _poll_terminal_scan,
)


def exercise_governance_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = governance_profile()
    path = tmp_path / "governance-http-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.13.0",
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
        fake = governance_provider(region, tags={"s3_bucket": {}})
        ec2 = fake._clients[("ec2", region)]
        ec2._paginators["describe_instances"][0] = _CollectionGatePaginator(
            ec2._paginators["describe_instances"][0].pages,
            entered=entered,
            release=release,
        )
        return fake

    try:
        for role in ("ANALYST", "ADMIN"):
            settings = _development_settings(
                monkeypatch, engine, subject="governance-operator", role=role
            )
            app = create_app(
                executor_factory=lambda settings=settings: InProcessScanExecutor(
                    session_factory=factory,
                    settings=settings,
                    provider_factory=provider,
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
                    assert entered.wait(10)
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

                assert len(get(f"assessments?scan_id={scan_id}")["items"]) == 11
                assert client.get("/api/v1/controls?category=governance").status_code == 401
                controls = get(
                    "controls?category=governance&severity=MEDIUM&catalog_key=aws-cloud-security-controls"
                )
                assert controls["total"] == 1
                control = controls["items"][0]
                assert control["control_key"] == "GOV-001"
                version = control["versions"][0]
                assert version["catalog_version"] == "0.13.0"
                assert version["category"] == "governance"
                assert version["execution_contract"]["schema_version"] == "1.10.0"
                for kind in profile.governed_resource_types:
                    page = get(f"controls?category=governance&resource_type={kind}")
                    assert (
                        page["total"] == 1
                        and page["items"][0]["control_id"] == control["control_id"]
                    )
                assert get("controls?category=governance&resource_type=iam_group")["total"] == 0
                assert get("controls?category=network")["total"] > 0
                assert get("controls?category=governance&offset=1")["items"] == []
                with Session(engine) as session:
                    rows = session.scalars(
                        select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
                    ).all()
                    for row in rows:
                        detail = get(f"assessments/{row.assessment_id}")
                        target = session.get(ResourceSnapshot, row.resource_snapshot_id)
                        assert detail["assessment_result"] == (
                            "FAIL" if target.resource.resource_type == "s3_bucket" else "PASS"
                        )
                        proof = detail["evidence"][0]["payload"]["source_proof"]
                        assert proof["schema_version"] == "1.10.0"
                        assert proof["profile_checksum"] == profile.content_checksum
                        assert proof["relationship_observation_ids"] == []
                        assert get(f"controls/{row.control_id}") == control
                        assert get(f"resources/{target.resource_id}")["resource_id"] == str(
                            target.resource_id
                        )
                        assert any(
                            h["snapshot_id"] == str(target.snapshot_id)
                            for h in get(f"resources/{target.resource_id}/history")["items"]
                        )
                        for citation in proof["sources"]:
                            source = get(f"source-outcomes/{citation['source_outcome_id']}")
                            assert source["artifact"]["artifact_id"] == citation["artifact_id"]
                            assert (
                                source["artifact"]["evidence_sha256"] == citation["evidence_sha256"]
                            )
                        mapping = detail["framework_mappings"][0]
                        assert mapping["reference_key"] == "ID.AM-02"
                        assert (
                            get(f"frameworks/{mapping['framework_id']}")["version"]
                            == "2.0+subset.12"
                        )
                        if target.resource.resource_type == "s3_bucket":
                            assert get(f"findings/{detail['finding_id']}")["status"] == "OPEN"
                        else:
                            assert detail["finding_id"] is None
                    events = session.scalars(
                        select(AuditEvent).where(AuditEvent.target_id == scan_id)
                    ).all()
                    assert any(
                        e.event_type is AuditEventType.SCAN_STARTED
                        and e.actor_id == "governance-operator"
                        for e in events
                    )
                    assert any(e.event_type is AuditEventType.SCAN_COMPLETED for e in events)
    finally:
        release.set()
        get_settings.cache_clear()
