"""Retained 6F.1 history, atomic proof rejection, lifecycle, recovery and real HTTP."""

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
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor
from app.services.scan_service import ScanService
from tests.cloudtrail_fixtures import cloudtrail_provider, logging_bundle, logging_profile
from tests.cloudtrail_http import exercise_logging_http
from tests.ec2_fixtures import OBSERVED
from tests.fakes import client_error
from tests.integration.test_persistence_postgres import _RecordingExecutor
from tests.s3_sensitive_kms_fixtures import sensitive_kms_bundle
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine
FORGERIES = ("fail", "na", "insufficient", "source", "identity", "fact", "version", "scan")
BOOLEAN_PROOF_PATHS = (
    ("LOG-002", ("cloudtrail", "empty_population")),
    ("LOG-003", ("cloudtrail", "empty_population")),
    ("LOG-002", ("cloudtrail", "trails", 0, "is_multi_region_trail")),
    ("LOG-002", ("cloudtrail", "trails", 0, "is_organization_trail")),
    ("LOG-002", ("cloudtrail", "trails", 0, "is_logging")),
    ("LOG-003", ("cloudtrail", "trails", 0, "log_file_validation_enabled")),
    (
        "LOG-002",
        (
            "cloudtrail",
            "trails",
            0,
            "event_selectors",
            "basic_selectors",
            0,
            "include_management_events",
        ),
    ),
    (
        "LOG-002",
        (
            "cloudtrail",
            "trails",
            0,
            "event_selectors",
            "basic_selectors",
            0,
            "raw_presence",
            "include_management_events",
        ),
    ),
)


def exercise_history(engine):
    bundles = (
        sensitive_kms_bundle(),
        logging_bundle(),
        logging_bundle(specs=[{}]),
        logging_bundle(
            profile=logging_profile(version="6.8.2", enabled_controls=("LOG-003",)), empty=True
        ),
    )
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
                == (bundle["assessments"])
            )
            rows = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).all()
            assert {row.assessment_result for row in rows} == {
                candidate.result for candidate in bundle["assessments"]
            }
            assert len(rows) == len(bundle["assessments"])
            for row in rows:
                assert (
                    session.get(ResourceSnapshot, row.resource_snapshot_id).scan_id == row.scan_id
                )
            assert session.get(Scan, bundle["snapshot"].scan_id).assessment_profile_checksum == (
                profile.content_checksum
            )


def exercise_rejection(engine, control_id, kind):
    bundle = logging_bundle(specs=[{}])
    original = next(a for a in bundle["assessments"] if a.control_id == control_id)
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
                "missing_evidence": ("cloudtrail.required",) if kind == "insufficient" else (),
            }
        )
    else:
        document = original.evidence_artifacts[0].model_dump(
            exclude={"evidence_id", "payload_sha256"}
        )
        proof = document["payload"]["source_proof"]
        if kind == "source":
            proof["sources"][0]["artifact_id"] = str(uuid4())
        elif kind == "identity":
            proof["cloudtrail"]["trails"][0]["home_region"] = "eu-west-1"
        elif kind == "fact":
            trail = proof["cloudtrail"]["trails"][0]
            trail[
                "is_multi_region_trail"
                if control_id == "LOG-002"
                else "log_file_validation_enabled"
            ] = False
        elif kind == "scan":
            proof["scan_id"] = str(uuid4())
        else:
            document["payload"]["evaluation_version"] = "9.0.0"
        forged = original.model_copy(
            update={"evidence_artifacts": (ArtifactInput.for_assessment(**document),)}
        )
    bundle["assessments"] = tuple(
        forged if a.control_id == control_id else a for a in bundle["assessments"]
    )
    with (
        Session(engine) as session,
        pytest.raises(ScanPersistenceError, match="assessment source evidence is invalid"),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_false_pass(engine, control_id, state):
    options = {
        "failed": {},
        "empty": {"empty": True},
        "unknown": {"specs": [{"omit": ["IsMultiRegionTrail", "LogFileValidationEnabled"]}]},
    }[state]
    bundle = logging_bundle(**options)
    original = next(a for a in bundle["assessments"] if a.control_id == control_id)
    assert original.result is not R.PASS
    artifacts = original.evidence_artifacts or (
        ArtifactInput.for_assessment(
            **{
                field: getattr(original, field)
                for field in (
                    "resource_snapshot_id",
                    "scan_id",
                    "control_id",
                    "account_id",
                    "service",
                    "resource_type",
                    "aws_resource_id",
                    "arn",
                    "scope",
                    "region",
                )
            },
            collector="cloudtrail_evidence",
            source="normalized-inventory",
            source_api="cloudtrail:GetTrail",
            collected_at=bundle["snapshot"].collected_at,
            schema_name=f"control.{control_id.lower()}.evidence",
            schema_version="1.0.0",
            payload={"source_proof": {}, "evaluation_version": "1.0.0"},
        ),
    )
    bundle["assessments"] = tuple(
        original.model_copy(
            update={"result": R.PASS, "missing_evidence": (), "evidence_artifacts": artifacts}
        )
        if a.control_id == control_id
        else a
        for a in bundle["assessments"]
    )
    with (
        Session(engine) as session,
        pytest.raises(
            ScanPersistenceError,
            match="empty target set requires an explicit N/A or insufficient result"
            if state == "empty" and control_id == "LOG-003"
            else "assessment source evidence is invalid",
        ),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 0


def exercise_numeric_proof_rejection(engine, control_id, path, numeric_type):
    bundle = logging_bundle(specs=[{}])
    original = next(a for a in bundle["assessments"] if a.control_id == control_id)
    assert original.result is R.PASS
    document = original.evidence_artifacts[0].model_dump(exclude={"evidence_id", "payload_sha256"})
    node = document["payload"]["source_proof"]
    for segment in path[:-1]:
        node = node[segment]
    assert type(node[path[-1]]) is bool
    node[path[-1]] = numeric_type(node[path[-1]])
    artifact = ArtifactInput.for_assessment(**document)
    assert artifact.verify_integrity()
    forged = original.model_copy(update={"evidence_artifacts": (artifact,)})
    bundle["assessments"] = tuple(
        forged if a.control_id == control_id else a for a in bundle["assessments"]
    )
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
        logging_bundle(),
        logging_bundle(
            specs=[{}],
            tag_error=client_error("AccessDenied", "ListTags"),
            observed=OBSERVED + timedelta(days=1),
        ),
        logging_bundle(specs=[{}], observed=OBSERVED + timedelta(days=2)),
    )
    finding_ids = None
    for index, bundle in enumerate(bundles):
        assert {a.result for a in bundle["assessments"]} == {R.FAIL if index == 0 else R.PASS}
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            findings = session.scalars(select(Finding)).all()
            assert len(findings) == 2
            ids = {finding.finding_id for finding in findings}
            finding_ids = finding_ids or ids
            assert finding_ids == ids
            assert {finding.status for finding in findings} == {
                FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN
            }


def exercise_recovery(engine, tmp_path):
    profile = logging_profile()
    path = tmp_path / "logging-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.11.0",
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
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="logging-recovery"
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
        provider_factory=cloudtrail_provider,
    )
    try:
        executor._execute(pending.scan_id)
    finally:
        executor.shutdown()
    with Session(engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.assessment_profile_checksum == profile.content_checksum
        rows = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == scan.scan_id)
        ).all()
        assert len(rows) == 2
        assert {row.assessment_result for row in rows} == {R.FAIL}


def test_history(migrated_engine):
    exercise_history(migrated_engine)


@pytest.mark.parametrize("control_id", ["LOG-002", "LOG-003"])
@pytest.mark.parametrize("kind", FORGERIES)
def test_rejection(migrated_engine, control_id, kind):
    exercise_rejection(migrated_engine, control_id, kind)


@pytest.mark.parametrize("control_id", ["LOG-002", "LOG-003"])
@pytest.mark.parametrize("state", ["failed", "empty", "unknown"])
def test_false_pass(migrated_engine, control_id, state):
    exercise_false_pass(migrated_engine, control_id, state)


@pytest.mark.parametrize("control_id,path", BOOLEAN_PROOF_PATHS)
@pytest.mark.parametrize("numeric_type", [int, float])
def test_numeric_proof_rejection(migrated_engine, control_id, path, numeric_type):
    exercise_numeric_proof_rejection(migrated_engine, control_id, path, numeric_type)


def test_lifecycle(migrated_engine):
    exercise_lifecycle(migrated_engine)


def test_recovery(migrated_engine, tmp_path):
    exercise_recovery(migrated_engine, tmp_path)


def test_http(monkeypatch, tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, event

    from tests.integration.test_persistence_postgres import migration_config

    engine = create_engine(f"sqlite:///{(tmp_path / 'cloudtrail-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_logging_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
