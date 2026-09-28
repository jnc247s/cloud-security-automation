"""IAM-004 history, atomic proof enforcement and exact restart; shared with PostgreSQL."""

import json

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.assessment.models import AssessmentResult
from app.assessment.models import EvidenceArtifact as ArtifactInput
from app.config import Settings
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import Control, ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor
from app.services.scan_service import ScanService
from tests.iam_credentials_fixtures import iam_bundle
from tests.iam_policy_fixtures import policy_bundle, policy_client, policy_profile
from tests.integration.test_persistence_postgres import _empty_provider, _RecordingExecutor
from tests.unit.database.factories import scan_bundle


def exercise_policy_history(engine):
    bundles = (scan_bundle(), iam_bundle(), policy_bundle(profile=policy_profile(version="3.0.0")))
    with Session(engine) as session, session.begin():
        for bundle in bundles:
            persist_scan_result(session, **bundle)
    new = bundles[-1]
    with Session(engine) as session:
        for bundle in bundles:
            verify_control_catalog(session, bundle["catalog"])
        profile = load_assessment_profile(
            session,
            profile_id=new["profile"].profile_id,
            version=new["profile"].version,
            expected_checksum=new["profile"].content_checksum,
        )
        catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.4.0")
        assert (
            RuleEngine(registry, catalog=catalog).assess(new["snapshot"], profile)
            == new["assessments"]
        )
        stored = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == new["snapshot"].scan_id)
        ).all()
        assert len(stored) == 4 and {a.assessment_result for a in stored} == {AssessmentResult.FAIL}
        for a in stored:
            snapshot = session.get(ResourceSnapshot, a.resource_snapshot_id)
            artifact = session.scalars(
                select(EvidenceArtifact).where(EvidenceArtifact.assessment_id == a.assessment_id)
            ).one()
            fact = artifact.payload["source_proof"]["iam_policy_document"]
            assert fact["document_sha256"] == snapshot.normalized_configuration["document_sha256"]
            assert fact["resource_snapshot_id"] == str(snapshot.snapshot_id)
            assert session.scalar(
                select(Finding).where(
                    Finding.resource_id == snapshot.resource_id, Finding.control_id == a.control_id
                )
            )


def exercise_policy_forgery(engine):
    bundle = policy_bundle()
    first, *rest = bundle["assessments"]
    artifact = first.evidence_artifacts[0]
    values = artifact.model_dump(exclude={"evidence_id", "payload_sha256"})
    values["payload"]["source_proof"]["iam_policy_document"]["document_sha256"] = "0" * 64
    forged = ArtifactInput.for_assessment(**values)
    bundle["assessments"] = (first.model_copy(update={"evidence_artifacts": (forged,)}), *rest)
    with Session(engine) as session, pytest.raises(ScanPersistenceError), session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 0


def exercise_policy_recovery(engine, tmp_path):
    profile = policy_profile(version="6.2.0")
    path = tmp_path / "policy-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.4.0",
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
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="policy-recovery"
        )
    calls = []

    def provider(region):
        calls.append(region)
        fake = _empty_provider(region)
        fake._clients[("iam", region)] = policy_client()
        return fake

    restarted = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=None,
        assessment_profile_version="1.0.0",
    )
    executor = InProcessScanExecutor(
        session_factory=sessionmaker(bind=engine), settings=restarted, provider_factory=provider
    )
    try:
        executor._execute(pending.scan_id)
    finally:
        executor.shutdown()
    assert calls == ["us-east-1"]
    with Session(engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.control_catalog_version == "0.4.0"
        assert scan.assessment_profile_checksum == profile.content_checksum
        stored = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == scan.scan_id)
        ).all()
        assert len(stored) == 4
        assert {session.get(Control, a.control_id).control_key for a in stored} == {"IAM-004"}


def test_policy_history(migrated_engine):
    exercise_policy_history(migrated_engine)


def test_policy_forgery_is_atomic(migrated_engine):
    exercise_policy_forgery(migrated_engine)


def test_policy_pending_recovery(migrated_engine, tmp_path):
    exercise_policy_recovery(migrated_engine, tmp_path)


def exercise_policy_version_history(engine):
    first = policy_bundle()
    second = policy_bundle(
        local_version="v2",
        aws_version="v6",
        document={"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
    )
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **first)
        persist_scan_result(session, **second)
    with Session(engine) as session:
        for bundle, expected in ((first, AssessmentResult.FAIL), (second, AssessmentResult.PASS)):
            stored = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).all()
            assert len(stored) == 4 and {a.assessment_result for a in stored} == {expected}
            for a in stored:
                artifact = session.scalars(
                    select(EvidenceArtifact).where(
                        EvidenceArtifact.assessment_id == a.assessment_id
                    )
                ).one()
                original = next(
                    c
                    for c in bundle["assessments"]
                    if c.resource_snapshot_id == a.resource_snapshot_id
                )
                assert artifact.payload == original.evidence_artifacts[0].payload
                snapshot = session.get(ResourceSnapshot, a.resource_snapshot_id)
                if snapshot.resource.resource_type == "iam_inline_policy":
                    assert (
                        session.scalar(
                            select(func.count())
                            .select_from(ResourceSnapshot)
                            .where(ResourceSnapshot.resource_id == snapshot.resource_id)
                        )
                        == 2
                    )
                if snapshot.resource.resource_type == "iam_managed_policy_version" and (
                    snapshot.resource.aws_account_id == bundle["snapshot"].account_id
                ):
                    assert snapshot.normalized_configuration["version_id"] == (
                        "v1" if bundle is first else "v2"
                    )


def test_policy_version_history(migrated_engine):
    exercise_policy_version_history(migrated_engine)
