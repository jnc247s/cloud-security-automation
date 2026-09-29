"""S3-002 immutable policy history, atomic proof verification and real HTTP acceptance."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.assessment.extended_profiles import canonical_profile_document
from app.assessment.models import AssessmentResult as R
from app.assessment.models import EvidenceArtifact as ArtifactInput
from app.config import Settings
from app.database.catalogs import (
    VersionContentConflictError,
    ensure_assessment_profile,
    load_assessment_profile,
    verify_control_catalog,
)
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor
from app.services.scan_service import ScanService
from tests.ec2_fixtures import OBSERVED
from tests.fakes import client_error
from tests.integration.test_persistence_postgres import _RecordingExecutor
from tests.s3_configuration_fixtures import s3_bundle
from tests.s3_configuration_http import exercise_s3_http
from tests.s3_exposure_fixtures import exposure_bundle, exposure_profile, failing_provider
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine
FORGERIES = (
    "pass",
    "na",
    "insufficient",
    "source",
    "policy",
    "profile",
    "identity",
    "decision",
    "version",
)


def exercise_history(engine):
    bundles = (
        s3_bundle(),
        exposure_bundle(provider=failing_provider()),
        exposure_bundle(
            provider=failing_provider(),
            profile=exposure_profile(public=True, policy_version="1.0.1", version="6.6.2"),
        ),
    )
    assert [b["assessments"][0].result for b in bundles[1:]] == [R.FAIL, R.PASS]
    for bundle in bundles:
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for bundle in bundles:
            verify_control_catalog(session, bundle["catalog"])
            profile = load_assessment_profile(
                session,
                profile_id=bundle["profile"].profile_id,
                version=bundle["profile"].version,
                expected_checksum=bundle["profile"].content_checksum,
            )
            assert canonical_profile_document(profile) == canonical_profile_document(
                bundle["profile"]
            )
            assert profile.content_checksum == bundle["profile"].content_checksum
            catalog, registry = resolve_catalog(
                bundle["catalog"].catalog_id, bundle["catalog"].version
            )
            assert (
                RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], profile)
                == bundle["assessments"]
            )
            rows = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).all()
            assert len(rows) == len(bundle["assessments"])
            for row in rows:
                assert (
                    session.get(ResourceSnapshot, row.resource_snapshot_id).scan_id == row.scan_id
                )


def exercise_rejection(engine, kind):
    bundle = exposure_bundle(provider=failing_provider())
    (original,) = bundle["assessments"]
    if kind in {"pass", "na", "insufficient"}:
        forged = original.model_copy(
            update={
                "result": {
                    "pass": R.PASS,
                    "na": R.NOT_APPLICABLE,
                    "insufficient": R.INSUFFICIENT_EVIDENCE,
                }[kind],
                "evidence_artifacts": original.evidence_artifacts if kind == "pass" else (),
                "missing_evidence": ("s3.required",) if kind == "insufficient" else (),
            }
        )
    else:
        document = original.evidence_artifacts[0].model_dump(
            exclude={"evidence_id", "payload_sha256"}
        )
        proof = document["payload"]["source_proof"]
        if kind == "source":
            proof["sources"][0]["artifact_id"] = str(uuid4())
        elif kind == "policy":
            proof["approval_policy"]["content_checksum"] = "0" * 64
        elif kind == "profile":
            proof["profile_checksum"] = "0" * 64
        elif kind == "identity":
            proof["s3_exposure"]["bucket_identity"]["bucket_region"] = "eu-west-1"
        elif kind == "decision":
            proof["exposure_decision"]["policy_channel"] = "APPROVED_EXPOSURE"
        else:
            document["payload"]["evaluation_version"] = "9.0.0"
        forged = original.model_copy(
            update={"evidence_artifacts": (ArtifactInput.for_assessment(**document),)}
        )
    bundle["assessments"] = (forged,)
    with (
        Session(engine) as session,
        pytest.raises(ScanPersistenceError, match="assessment source evidence is invalid"),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_lifecycle(engine):
    bundles = (
        exposure_bundle(provider=failing_provider()),
        exposure_bundle(
            tag_response=client_error("AccessDenied", "GetBucketTagging"),
            observed=OBSERVED + timedelta(days=1),
        ),
        exposure_bundle(observed=OBSERVED + timedelta(days=2)),
    )
    finding_id = None
    for index, bundle in enumerate(bundles):
        assert bundle["assessments"][0].result is (R.FAIL if index == 0 else R.PASS)
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            finding = session.scalars(select(Finding)).one()
            finding_id = finding_id or finding.finding_id
            assert finding.finding_id == finding_id
            assert finding.status is (FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN)


def exercise_policy_substitution(engine):
    original = exposure_profile()
    replacement = exposure_profile(public=True, version="6.6.2")
    with Session(engine) as session, session.begin():
        ensure_assessment_profile(session, original)
    with (
        Session(engine) as session,
        pytest.raises(VersionContentConflictError),
        session.begin(),
    ):
        ensure_assessment_profile(session, replacement)
    with Session(engine) as session:
        retained = load_assessment_profile(
            session,
            profile_id=original.profile_id,
            version=original.version,
            expected_checksum=original.content_checksum,
        )
        assert retained.s3_exposure_approvals == original.s3_exposure_approvals


def test_policy_substitution(migrated_engine):
    exercise_policy_substitution(migrated_engine)


def exercise_recovery(engine, tmp_path):
    profile = exposure_profile()
    path = tmp_path / "exposure-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.9.0",
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
            ScanCreateRequest(region="us-east-1"),
            _RecordingExecutor(),
            actor_id="exposure-recovery",
        )
    restart = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=None,
        assessment_profile_version="1.0.0",
    )
    executor = InProcessScanExecutor(
        session_factory=sessionmaker(bind=engine),
        settings=restart,
        provider_factory=failing_provider,
    )
    try:
        executor._execute(pending.scan_id)
    finally:
        executor.shutdown()
    with Session(engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.assessment_profile_checksum == profile.content_checksum
        row = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == scan.scan_id)
        ).one()
        assert row.assessment_result is R.FAIL


def test_history(migrated_engine):
    exercise_history(migrated_engine)


@pytest.mark.parametrize("kind", FORGERIES)
def test_rejection(migrated_engine, kind):
    exercise_rejection(migrated_engine, kind)


def test_lifecycle(migrated_engine):
    exercise_lifecycle(migrated_engine)


def test_recovery(migrated_engine, tmp_path):
    exercise_recovery(migrated_engine, tmp_path)


def test_http(monkeypatch, tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, event

    from tests.integration.test_persistence_postgres import migration_config

    engine = create_engine(f"sqlite:///{(tmp_path / 'exposure-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_s3_http(engine, monkeypatch, tmp_path, exposure=True)
    finally:
        engine.dispose()
