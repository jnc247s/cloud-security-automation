"""All supported controls through real bearer-authenticated HTTP; only AWS is offline."""

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database import session as database_session
from app.database.governance import create_finding_exception
from app.main import create_app
from app.models import AuditEvent, ControlAssessment
from app.models.enums import AuditEventType
from app.security.authentication import DEVELOPMENT_BEARER_MARKER
from app.services.scan_executor import InProcessScanExecutor
from tests.governance_fixtures import governance_provider
from tests.integration.test_persistence_postgres import (
    _CollectionGatePaginator,
    _development_settings,
    _poll_terminal_scan,
)
from tests.sprint6_fixtures import CATALOG_ID, SUPPORTED_IDS, sprint6_profile


def exercise_sprint6_http(engine, monkeypatch, tmp_path):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    profile = sprint6_profile()
    path = tmp_path / "sprint6-http-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": CATALOG_ID,
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
        fake = governance_provider(region)
        ec2 = fake._clients[("ec2", region)]
        ec2._paginators["describe_instances"][0] = _CollectionGatePaginator(
            ec2._paginators["describe_instances"][0].pages, entered=entered, release=release
        )
        return fake

    try:
        for role in ("ANALYST", "ADMIN"):
            settings = _development_settings(
                monkeypatch, engine, subject="sprint6-operator", role=role
            )
            app = create_app(
                executor_factory=lambda settings=settings: InProcessScanExecutor(
                    session_factory=factory, settings=settings, provider_factory=provider
                )
            )
            assert app.dependency_overrides == {}
            with TestClient(app) as client:
                if role == "ANALYST":
                    assert client.get("/api/v1/controls", headers=headers).status_code == 200
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
                    assert entered.wait(10), "real worker did not reach the offline AWS boundary"
                    assert not release.is_set()
                finally:
                    release.set()
                terminal = _poll_terminal_scan(client, scan_id, headers)
                assert terminal["status"] == "COMPLETED", terminal
                assert terminal["control_catalog_version"] == "0.13.0"
                assert terminal["assessment_profile_checksum"] == profile.content_checksum
                assert set(terminal["scope"]["enabled_controls"]) == SUPPORTED_IDS
                assert calls == ["us-east-1"]

                def get(route):
                    response = client.get(f"/api/v1/{route}", headers=headers)
                    assert response.status_code == 200, response.text
                    return response.json()

                def page(route):
                    items, offset = [], 0
                    separator = "&" if "?" in route else "?"
                    while True:
                        result = get(f"{route}{separator}limit=100&offset={offset}")
                        items.extend(result["items"])
                        if len(items) == result["total"]:
                            return items
                        assert result["items"] and len(items) < result["total"] and offset < 1000
                        offset += len(result["items"])

                for route in (
                    "controls",
                    "resources",
                    "assessments",
                    "findings",
                    "source-outcomes",
                    "relationships",
                    "frameworks",
                    "exceptions",
                ):
                    assert client.get(f"/api/v1/{route}").status_code == 401
                controls = {c["control_id"]: c for c in page("controls")}
                assert {c["control_key"] for c in controls.values()} == SUPPORTED_IDS
                assessments = page(f"assessments?scan_id={scan_id}")
                assert len(assessments) == 39
                assert {a["control_id"] for a in assessments} == set(controls)
                assert Counter(a["assessment_result"] for a in assessments) == {
                    "PASS": 21,
                    "FAIL": 17,
                    "NOT_APPLICABLE": 1,
                }
                relationships = {
                    r["observation_id"]: r for r in page(f"relationships?scan_id={scan_id}")
                }
                sources = {
                    s["source_outcome_id"]: s for s in page(f"source-outcomes?scan_id={scan_id}")
                }
                details, source_details, framework_details = {}, {}, {}
                for assessment in assessments:
                    detail = get(f"assessments/{assessment['assessment_id']}")
                    assert {k: detail[k] for k in assessment} == assessment
                    key = controls[detail["control_id"]]["control_key"]
                    details.setdefault(key, []).append(detail)
                    assert get(f"controls/{detail['control_id']}") == controls[detail["control_id"]]
                    resource = get(f"resources/{detail['resource_id']}")
                    assert (
                        resource["latest_snapshot"]["snapshot_id"] == detail["resource_snapshot_id"]
                    )
                    assert any(
                        h["snapshot_id"] == detail["resource_snapshot_id"]
                        for h in page(f"resources/{detail['resource_id']}/history")
                    )
                    for evidence in detail["evidence"]:
                        assert evidence["assessment_id"] == detail["assessment_id"]
                        assert evidence["scan_id"] == str(scan_id)
                        assert evidence["resource_snapshot_id"] == detail["resource_snapshot_id"]
                        assert evidence["control_version_id"] == detail["control_version_id"]
                        encoded = json.dumps(
                            evidence["payload"],
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                            allow_nan=False,
                        ).encode("utf-8")
                        assert hashlib.sha256(encoded).hexdigest() == evidence["payload_sha256"]
                        proof = evidence["payload"].get("source_proof")
                        if proof is not None:
                            assert proof["scan_id"] == str(scan_id)
                            if key in {"S3-002", "GOV-001"}:
                                assert proof["profile_checksum"] == profile.content_checksum
                            else:
                                # Earlier proof schemas intentionally do not add this field.
                                assert "profile_checksum" not in proof
                            for citation in proof["sources"]:
                                identity = citation["source_outcome_id"]
                                assert identity in sources
                                if identity not in source_details:
                                    source_details[identity] = get(f"source-outcomes/{identity}")
                                source = source_details[identity]
                                assert source["scan_id"] == str(scan_id)
                                assert source["artifact"]["artifact_id"] == citation["artifact_id"]
                                assert (
                                    source["artifact"]["evidence_sha256"]
                                    == citation["evidence_sha256"]
                                )
                            for identity in proof["relationship_observation_ids"]:
                                assert identity in relationships
                                assert get(f"relationships/{identity}") == relationships[identity]
                    for mapping in detail["framework_mappings"]:
                        identity = mapping["framework_id"]
                        if identity not in framework_details:
                            framework_details[identity] = get(f"frameworks/{identity}")
                        framework = framework_details[identity]
                        assert framework["version"] == mapping["framework_version"]
                        assert any(
                            r["reference_key"] == mapping["reference_key"]
                            for r in framework["references"]
                        )
                    assert detail["framework_mappings"]
                    if detail["assessment_result"] == "FAIL":
                        finding = get(f"findings/{detail['finding_id']}")
                        assert finding["status"] == "OPEN"
                        assert any(
                            o["assessment_id"] == detail["assessment_id"]
                            and o["scan_id"] == str(scan_id)
                            for o in finding["occurrences"]
                        )
                    else:
                        assert detail["finding_id"] is None
                assert set(details) == SUPPORTED_IDS
                log, destination = details["LOG-004"][0], details["S3-002"][0]
                dependency = log["evidence"][0]["payload"]["source_proof"]["destination_dependency"]
                assert log["assessment_result"] == destination["assessment_result"] == "PASS"
                assert dependency["resource_snapshot_id"] == destination["resource_snapshot_id"]
                assert dependency["profile_checksum"] == profile.content_checksum
                assert (
                    dependency["evidence"][0]["evidence_id"]
                    == destination["evidence"][0]["evidence_id"]
                )

                # Existing governance service changes handling, never technical truth/evidence.
                failed = details["S3-001"][0]
                now = datetime.now(UTC)
                with Session(engine) as session, session.begin():
                    exception = create_finding_exception(
                        session,
                        finding_id=UUID(failed["finding_id"]),
                        reason="Bounded acceptance exception",
                        approved_by="sprint6-approver",
                        created_at=now,
                        expires_at=now + timedelta(hours=1),
                    )
                    exception_id = str(exception.exception_id)
                assert get(f"assessments/{failed['assessment_id']}") == failed
                finding = get(f"findings/{failed['finding_id']}")
                assert finding["status"] == "OPEN" and finding["active_exception_ids"] == [
                    exception_id
                ]
                assert (
                    page(f"exceptions?finding_id={failed['finding_id']}")[0]["exception_id"]
                    == exception_id
                )
                with Session(engine) as session:
                    persisted = session.scalars(
                        select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
                    ).all()
                    assert {str(a.assessment_id) for a in persisted} == {
                        a["assessment_id"] for a in assessments
                    }
                    events = session.scalars(
                        select(AuditEvent).where(AuditEvent.target_id == scan_id)
                    ).all()
                    assert any(
                        e.event_type is AuditEventType.SCAN_STARTED
                        and e.actor_id == "sprint6-operator"
                        for e in events
                    )
                    assert any(e.event_type is AuditEventType.SCAN_COMPLETED for e in events)
    finally:
        release.set()
        get_settings.cache_clear()
