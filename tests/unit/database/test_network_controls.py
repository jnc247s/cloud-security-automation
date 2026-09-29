"""6D.1 history, atomic proof rejection, finding lifecycle and exact-policy recovery."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.assessment.models import AssessmentResult
from app.assessment.models import EvidenceArtifact as ArtifactInput
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.ec2_fixtures import OBSERVED, ec2_bundle
from tests.network_control_fixtures import network_bundle, network_client, network_profile
from tests.unit.collectors.test_security_group_evidence import _security_group
from tests.unit.database.factories import scan_bundle


def exercise_network_history(engine):
    bundles = (scan_bundle(), ec2_bundle(), network_bundle())
    with Session(engine) as session, session.begin():
        for bundle in bundles:
            persist_scan_result(session, **bundle)
    current = bundles[-1]
    with Session(engine) as session:
        for bundle in bundles:
            verify_control_catalog(session, bundle["catalog"])
        profile = load_assessment_profile(
            session,
            profile_id=current["profile"].profile_id,
            version=current["profile"].version,
            expected_checksum=current["profile"].content_checksum,
        )
        catalog, registry = resolve_catalog(current["catalog"].catalog_id, "0.6.0")
        assert (
            RuleEngine(registry, catalog=catalog).assess(current["snapshot"], profile)
            == current["assessments"]
        )
        rows = session.scalars(
            select(ControlAssessment).where(
                ControlAssessment.scan_id == current["snapshot"].scan_id
            )
        ).all()
        assert len(rows) == 3
        for row in rows:
            assert row.assessment_result is AssessmentResult.FAIL
            target = session.get(ResourceSnapshot, row.resource_snapshot_id)
            assert target.scan_id == current["snapshot"].scan_id
            assert target.resource.resource_type == "security_group"
            artifact = session.scalars(
                select(EvidenceArtifact).where(EvidenceArtifact.assessment_id == row.assessment_id)
            ).one()
            assert artifact.payload["source_proof"]["scan_id"] == str(target.scan_id)
            assert len(artifact.payload["source_proof"]["relationship_observation_ids"]) == 1
            assert (
                session.scalar(
                    select(Finding).where(
                        Finding.resource_id == target.resource_id,
                        Finding.control_id == row.control_id,
                    )
                )
                is not None
            )


def exercise_network_rejection(engine, kind):
    bundle = network_bundle()
    first, *rest = bundle["assessments"]
    if kind in {"na", "pass"}:
        first = first.model_copy(
            update={
                "result": AssessmentResult.NOT_APPLICABLE
                if kind == "na"
                else AssessmentResult.PASS,
                "evidence_artifacts": () if kind == "na" else first.evidence_artifacts,
            }
        )
    elif kind == "policy":
        # N/A is legitimate under empty port policy, but not this retained profile.
        bundle = network_bundle(profile=network_profile(high_risk_public_tcp_ports=()))
        nonempty = network_profile()
        bundle["profile"] = nonempty
        bundle["scope"] = bundle["scope"].model_copy(
            update={"assessment_profile_checksum": nonempty.content_checksum}
        )
        bundle["assessments"] = tuple(
            a.model_copy(update={"profile_checksum": nonempty.content_checksum})
            for a in bundle["assessments"]
        )
    else:
        artifact = first.evidence_artifacts[0]
        document = artifact.model_dump(exclude={"evidence_id", "payload_sha256"})
        proof = document["payload"]["source_proof"]
        if kind == "edge":
            proof["relationship_observation_ids"] = [str(uuid4())]
        elif kind == "source":
            proof["sources"][0]["artifact_id"] = str(uuid4())
        else:
            proof["security_group"]["configuration"]["ingress_rules"] = []
        first = first.model_copy(
            update={"evidence_artifacts": (ArtifactInput.for_assessment(**document),)}
        )
    if kind != "policy":
        bundle["assessments"] = (first, *rest)
    with (
        Session(engine) as session,
        pytest.raises(ScanPersistenceError, match="assessment source evidence is invalid"),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_network_empty_policy(engine):
    for options in (
        {"groups": []},
        {"profile": network_profile(high_risk_public_tcp_ports=(), version="6.4.1")},
    ):
        bundle = network_bundle(**options)
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            stored = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).all()
            assert len(stored) == 3
            assert sum(r.assessment_result is AssessmentResult.NOT_APPLICABLE for r in stored) == (
                3 if "groups" in options else 1
            )


def exercise_network_recovery(engine, tmp_path, *, flow_logs=False):
    from app.config import Settings
    from app.schemas.scan import ScanCreateRequest
    from app.services.scan_executor import InProcessScanExecutor
    from app.services.scan_service import ScanService
    from tests.ec2_http_acceptance import install_ec2_client
    from tests.integration.test_persistence_postgres import _empty_provider, _RecordingExecutor

    profile = network_profile()
    if flow_logs:
        from tests.flow_log_fixtures import flow_profile

        profile = flow_profile()
    version = "0.7.0" if flow_logs else "0.6.0"
    path = tmp_path / "network-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": version,
                "profile": profile.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=str(path),
        assessment_profile_version=profile.version,
    )
    with Session(engine) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="network-recovery"
        )
    calls = []

    def provider(region):
        calls.append(region)
        fake = _empty_provider(region)
        install_ec2_client(fake, region, network_client())
        return fake

    restart = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=None,
        assessment_profile_version="1.0.0",
    )
    executor = InProcessScanExecutor(
        session_factory=sessionmaker(bind=engine), settings=restart, provider_factory=provider
    )
    try:
        executor._execute(pending.scan_id)
    finally:
        executor.shutdown()
    assert calls == ["us-east-1"]
    with Session(engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.control_catalog_version == version
        assert scan.assessment_profile_checksum == profile.content_checksum
        rows = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == scan.scan_id)
        ).all()
        assert len(rows) == (1 if flow_logs else 3)
        assert {r.assessment_result for r in rows} == {AssessmentResult.FAIL}


def test_network_history(migrated_engine):
    exercise_network_history(migrated_engine)


@pytest.mark.parametrize("kind", ["na", "pass", "source", "edge", "facts", "policy"])
def test_network_rejection(migrated_engine, kind):
    exercise_network_rejection(migrated_engine, kind)


def test_network_empty_policy(migrated_engine):
    exercise_network_empty_policy(migrated_engine)


def test_network_recovery(migrated_engine, tmp_path):
    exercise_network_recovery(migrated_engine, tmp_path)


def exercise_network_lifecycle(engine):
    from tests.fakes import client_error

    group = _security_group()
    group.update(IpPermissions=[], IpPermissionsEgress=[])
    bundles = (
        network_bundle(),
        network_bundle(
            groups=[group],
            observed=OBSERVED + timedelta(days=1),
            flow_error=client_error("AccessDenied", "offline"),
        ),
        network_bundle(groups=[group], observed=OBSERVED + timedelta(days=2)),
    )
    identities = None
    for index, bundle in enumerate(bundles):
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            findings = session.scalars(select(Finding)).all()
            assert len(findings) == 3
            current = {f.finding_id for f in findings}
            if identities is None:
                identities = current
            assert current == identities
            assert {f.status for f in findings} == {
                FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN
            }


def test_network_lifecycle(migrated_engine):
    exercise_network_lifecycle(migrated_engine)
