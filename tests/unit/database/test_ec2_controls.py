"""6C history, scope and atomic rejection, shared with disposable PostgreSQL tests."""

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.assessment.models import AssessmentResult
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import Control, ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.ec2_fixtures import ec2_bundle, ec2_client, ec2_profile
from tests.iam_credentials_fixtures import iam_bundle
from tests.iam_policy_fixtures import policy_bundle, policy_profile
from tests.unit.database.factories import scan_bundle


def exercise_ec2_history(engine):
    legacy, iam, policy, new = (
        scan_bundle(),
        iam_bundle(),
        policy_bundle(profile=policy_profile(version="6.2.0")),
        ec2_bundle(),
    )
    with Session(engine) as session, session.begin():
        for bundle in (legacy, iam, policy, new):
            persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for bundle in (legacy, iam, policy, new):
            verify_control_catalog(session, bundle["catalog"])
        profile = load_assessment_profile(
            session,
            profile_id=new["profile"].profile_id,
            version=new["profile"].version,
            expected_checksum=new["profile"].content_checksum,
        )
        catalog, registry = resolve_catalog(new["catalog"].catalog_id, "0.5.0")
        assert (
            RuleEngine(registry, catalog=catalog).assess(new["snapshot"], profile)
            == new["assessments"]
        )
        rows = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == new["snapshot"].scan_id)
        ).all()
        assert len(rows) == 4
        assert {a.assessment_result for a in rows} == {AssessmentResult.FAIL}
        assert len({a.resource_snapshot_id for a in rows}) == 3
        for row in rows:
            target = session.get(ResourceSnapshot, row.resource_snapshot_id)
            assert target.scan_id == new["snapshot"].scan_id
            artifact = session.scalars(
                select(EvidenceArtifact).where(EvidenceArtifact.assessment_id == row.assessment_id)
            ).one()
            assert artifact.payload["source_proof"]["scan_id"] == str(target.scan_id)
            assert session.scalar(
                select(Finding).where(
                    Finding.resource_id == target.resource_id, Finding.control_id == row.control_id
                )
            )
            if session.get(Control, row.control_id).control_key == "EC2-004":
                assert target.region == "us-east-1"
                assert target.scope.value == "regional"
                assert target.resource.resource_type == "aws_account"
                assert not any(r.resource_type == "aws_account" for r in new["snapshot"].resources)


def exercise_ec2_rejection(engine, kind):
    bundle = ec2_bundle()
    first, *rest = bundle["assessments"]
    if kind == "na":
        first = first.model_copy(
            update={"result": AssessmentResult.NOT_APPLICABLE, "evidence_artifacts": ()}
        )
    elif kind == "region":
        first = first.model_copy(update={"region": "us-west-2"})
    else:
        from app.assessment.models import EvidenceArtifact as ArtifactInput

        artifact = first.evidence_artifacts[0]
        document = artifact.model_dump(exclude={"evidence_id", "payload_sha256"})
        if kind == "source":
            document["payload"]["source_proof"]["sources"][0]["artifact_id"] = str(uuid4())
        else:
            document["payload"]["metadata_options"]["http_tokens"] = "required"
        forged = ArtifactInput.for_assessment(**document)
        first = first.model_copy(update={"evidence_artifacts": (forged,)})
    bundle["assessments"] = (first, *rest)
    expected_error = ValidationError if kind == "region" else ScanPersistenceError
    with Session(engine) as session, pytest.raises(expected_error), session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_ec2_regions_and_empty(engine):
    bundles = [
        ec2_bundle(instances=False, volumes=False, region=region)
        for region in ("us-east-1", "us-west-2")
    ]
    with Session(engine) as session, session.begin():
        for bundle in bundles:
            persist_scan_result(session, **bundle)
    with Session(engine) as session:
        settings = session.scalars(
            select(ControlAssessment)
            .join(Control, Control.control_id == ControlAssessment.control_id)
            .where(Control.control_key == "EC2-004")
        ).all()
        assert len(settings) == 2
        assert {a.assessment_result for a in settings} == {AssessmentResult.FAIL}
        targets = [session.get(ResourceSnapshot, a.resource_snapshot_id) for a in settings]
        assert len({t.resource_id for t in targets}) == 2
        assert {t.region for t in targets} == {"us-east-1", "us-west-2"}
        assert (
            session.scalar(
                select(func.count())
                .select_from(ControlAssessment)
                .where(ControlAssessment.assessment_result == AssessmentResult.NOT_APPLICABLE)
            )
            == 6
        )


def exercise_ec2_recovery(engine, tmp_path):
    from app.config import Settings
    from app.schemas.scan import ScanCreateRequest
    from app.services.scan_executor import InProcessScanExecutor
    from app.services.scan_service import ScanService
    from tests.integration.test_persistence_postgres import _empty_provider, _RecordingExecutor

    profile = ec2_profile()
    path = tmp_path / "ec2-recovery.json"
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
    settings = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=str(path),
        assessment_profile_version=profile.version,
    )
    with Session(engine) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="ec2-recovery"
        )
    calls = []

    def provider(region):
        calls.append(region)
        fake = _empty_provider(region)
        # The EC2 client also supplies the unchanged security-group/network collectors.
        from tests.ec2_http_acceptance import install_ec2_client

        install_ec2_client(fake, region, ec2_client())
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
        assert scan.control_catalog_version == "0.5.0"
        assert scan.assessment_profile_checksum == profile.content_checksum
        rows = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == scan.scan_id)
        ).all()
        assert len(rows) == 4
        assert {a.assessment_result for a in rows} == {AssessmentResult.FAIL}


def test_ec2_history(migrated_engine):
    exercise_ec2_history(migrated_engine)


@pytest.mark.parametrize("kind", ["na", "region", "source", "facts"])
def test_ec2_rejection_is_atomic(migrated_engine, kind):
    exercise_ec2_rejection(migrated_engine, kind)


def test_ec2_regions_and_empty(migrated_engine):
    exercise_ec2_regions_and_empty(migrated_engine)


def test_ec2_recovery(migrated_engine, tmp_path):
    exercise_ec2_recovery(migrated_engine, tmp_path)
