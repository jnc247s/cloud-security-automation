"""S3-004 classifier history, proof tamper rejection, recovery and HTTP acceptance."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.assessment.extended_profiles import canonical_profile_document
from app.assessment.models import AssessmentResult as R
from app.assessment.models import EvidenceArtifact as ArtifactInput
from app.assessment.sensitive_buckets import SensitiveBucketClassifier, SensitiveBucketTagRule
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
from tests.s3_configuration_http import exercise_s3_http
from tests.s3_exposure_fixtures import exposure_bundle
from tests.s3_sensitive_kms_fixtures import (
    KEY_ARN,
    encryption_rule,
    key_response,
    sensitive_kms_bundle,
    sensitive_kms_profile,
    sensitive_kms_provider,
)
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine
FORGERIES = (
    "fail",
    "na",
    "insufficient",
    "source",
    "classifier",
    "profile",
    "identity",
    "classification",
    "matches",
    "key",
    "relationship",
    "version",
)


def exercise_history(engine):
    changed = sensitive_kms_profile(
        version="6.7.2",
        classifier=SensitiveBucketClassifier.create(
            version="1.0.1",
            sensitive_tag_rules=(SensitiveBucketTagRule(key="DataClassification", value="Secret"),),
        ),
    )
    bundles = (
        exposure_bundle(),
        sensitive_kms_bundle(),
        sensitive_kms_bundle(profile=changed),
        sensitive_kms_bundle(
            encryption_rules=[encryption_rule(reference=KEY_ARN)],
            kms_responses={"us-east-1": [key_response()]},
        ),
    )
    assert [b["assessments"][0].result for b in bundles[1:]] == [R.FAIL, R.NOT_APPLICABLE, R.PASS]
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
            catalog, registry = resolve_catalog(
                bundle["catalog"].catalog_id, bundle["catalog"].version
            )
            assert (
                RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], profile)
                == bundle["assessments"]
            )
            row = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).one()
            assert row.assessment_result is bundle["assessments"][0].result
            assert session.get(ResourceSnapshot, row.resource_snapshot_id).scan_id == row.scan_id
            # N/A still retains exact historical classifier through its immutable scan/profile.
            scan = session.get(Scan, row.scan_id)
            assert scan.assessment_profile_checksum == profile.content_checksum


def exercise_rejection(engine, kind):
    bundle = sensitive_kms_bundle(
        encryption_rules=[encryption_rule(reference=KEY_ARN)],
        kms_responses={"us-east-1": [key_response()]},
    )
    (original,) = bundle["assessments"]
    assert original.result is R.PASS
    if kind in {"fail", "na", "insufficient"}:
        forged = original.model_copy(
            update={
                "result": {
                    "fail": R.FAIL,
                    "na": R.NOT_APPLICABLE,
                    "insufficient": R.INSUFFICIENT_EVIDENCE,
                }[kind],
                "evidence_artifacts": original.evidence_artifacts if kind == "fail" else (),
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
        elif kind == "classifier":
            proof["classifier"]["content_checksum"] = "0" * 64
        elif kind == "profile":
            proof["profile_checksum"] = "0" * 64
        elif kind == "identity":
            proof["s3_sensitive_kms"]["bucket_identity"]["bucket_region"] = "eu-west-1"
        elif kind == "classification":
            proof["classification"]["reason"] = "explicit_sensitive_bucket"
        elif kind == "matches":
            proof["classification"]["matched_tag_rules"] = []
        elif kind == "key":
            proof["s3_sensitive_kms"]["keys"][KEY_ARN]["key"]["key_manager"] = "AWS"
        elif kind == "relationship":
            proof["relationship_observation_ids"] = []
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
        sensitive_kms_bundle(),
        sensitive_kms_bundle(
            encryption_rules=[encryption_rule()],
            versioning_response=client_error("AccessDenied", "GetBucketVersioning"),
            observed=OBSERVED + timedelta(days=1),
        ),
        sensitive_kms_bundle(
            encryption_rules=[encryption_rule()], observed=OBSERVED + timedelta(days=2)
        ),
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


def exercise_false_pass(engine, state):
    options = {
        "failed": {},
        "non-sensitive": {"tag_response": {"TagSet": []}},
        "unknown": {"tag_response": client_error("AccessDenied", "GetBucketTagging")},
    }[state]
    bundle = sensitive_kms_bundle(**options)
    original = bundle["assessments"][0]
    # A rehashed decisive proof from this scan must not promote FAIL/N/A/unknown to PASS.
    from app.assessment.evidence_reader import AssessmentEvidenceReader
    from app.rules.s3_sensitive_kms import S3SensitiveKMSRule

    rule = S3SensitiveKMSRule()
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    target = next(r for r in bundle["snapshot"].resources if r.resource_type == "s3_bucket")
    proof = reader.proof(rule.contract.execution_contract, target)
    forged = rule.assessment_for_resource(
        bundle["snapshot"],
        bundle["profile"],
        target,
        result=R.PASS,
        evidence={"source_proof": proof, "evaluation_version": "1.0.0"},
        reason="Forged promotion",
        collector="s3_evidence",
        source_api="s3:GetEncryptionConfiguration",
    )
    assert original.result is not R.PASS
    bundle["assessments"] = (
        original.model_copy(
            update={
                "result": R.PASS,
                "evidence_artifacts": forged.evidence_artifacts,
                "missing_evidence": (),
            }
        ),
    )
    with (
        Session(engine) as session,
        pytest.raises(ScanPersistenceError, match="assessment source evidence is invalid"),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 0


def exercise_policy_substitution(engine):
    original = sensitive_kms_profile()
    replacement = sensitive_kms_profile(
        version="6.7.2",
        classifier=SensitiveBucketClassifier.create(
            version="1.0.0",
            sensitive_name_patterns=("offline-*",),
        ),
    )
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
        assert retained.sensitive_bucket_classifier == original.sensitive_bucket_classifier


def exercise_recovery(engine, tmp_path):
    profile = sensitive_kms_profile()
    path = tmp_path / "sensitive-kms-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.10.0",
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
            actor_id="kms-recovery",
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
        provider_factory=sensitive_kms_provider,
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


@pytest.mark.parametrize("state", ["failed", "non-sensitive", "unknown"])
def test_false_pass(migrated_engine, state):
    exercise_false_pass(migrated_engine, state)


def test_policy_substitution(migrated_engine):
    exercise_policy_substitution(migrated_engine)


def test_recovery(migrated_engine, tmp_path):
    exercise_recovery(migrated_engine, tmp_path)


def test_http(monkeypatch, tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, event

    from tests.integration.test_persistence_postgres import migration_config

    engine = create_engine(f"sqlite:///{(tmp_path / 'sensitive-kms-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_s3_http(engine, monkeypatch, tmp_path, sensitive_kms=True)
    finally:
        engine.dispose()
