"""6E.1 persisted history, recovery, atomic result validation and real HTTP acceptance."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

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
from tests.ec2_fixtures import OBSERVED
from tests.fakes import client_error
from tests.integration.test_persistence_postgres import _RecordingExecutor
from tests.network_control_fixtures import network_bundle
from tests.s3_configuration_fixtures import failing_provider, s3_bundle, s3_profile
from tests.s3_configuration_http import exercise_s3_http
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine


def exercise_s3_history(engine):
    bundles = (
        network_bundle(),
        s3_bundle(provider=failing_provider()),
        s3_bundle(profile=s3_profile(version="6.5.2", enabled_controls=("S3-003",))),
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


def exercise_s3_rejection(engine, kind):
    bundle = s3_bundle()
    original = bundle["assessments"][0]
    if kind in {"na", "fail", "insufficient"}:
        forged = original.model_copy(
            update={
                "result": {
                    "na": R.NOT_APPLICABLE,
                    "fail": R.FAIL,
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
        elif kind == "facts":
            proof["s3_configuration"]["observations"]["s3.account-public-access-block"]["state"] = (
                "EXPECTED_ABSENCE"
            )
        else:
            document["payload"]["evaluation_version"] = "9.0.0"
        forged = original.model_copy(
            update={"evidence_artifacts": (ArtifactInput.for_assessment(**document),)}
        )
    bundle["assessments"] = (forged, *bundle["assessments"][1:])
    with (
        Session(engine) as session,
        pytest.raises(ScanPersistenceError, match="assessment source evidence is invalid"),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_s3_lifecycle(engine):
    bundles = (
        s3_bundle(provider=failing_provider()),
        s3_bundle(
            tag_response=client_error("AccessDenied", "GetBucketTagging"),
            observed=OBSERVED + timedelta(days=1),
        ),
        s3_bundle(observed=OBSERVED + timedelta(days=2)),
    )
    ids = None
    for index, bundle in enumerate(bundles):
        assert {a.result for a in bundle["assessments"]} == ({R.FAIL} if index == 0 else {R.PASS})
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            findings = session.scalars(select(Finding)).all()
            assert len(findings) == 2
            current = {f.finding_id for f in findings}
            ids = ids or current
            assert current == ids
            assert {f.status for f in findings} == {
                FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN
            }


def exercise_s3_recovery(engine, tmp_path):
    profile = s3_profile()
    path = tmp_path / "s3-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.8.0",
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
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="s3-recovery"
        )
    restart = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=None,
        assessment_profile_version="1.0.0",
    )
    calls = []

    def provider(region):
        calls.append(region)
        return failing_provider(region)

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
        assert scan.assessment_profile_checksum == profile.content_checksum
        rows = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == scan.scan_id)
        ).all()
        assert len(rows) == 2
        assert {a.assessment_result for a in rows} == {R.FAIL}


def test_s3_history(migrated_engine):
    exercise_s3_history(migrated_engine)


@pytest.mark.parametrize("kind", ["na", "fail", "insufficient", "source", "facts", "version"])
def test_s3_rejection(migrated_engine, kind):
    exercise_s3_rejection(migrated_engine, kind)


def test_s3_lifecycle(migrated_engine):
    exercise_s3_lifecycle(migrated_engine)


def test_s3_recovery(migrated_engine, tmp_path):
    exercise_s3_recovery(migrated_engine, tmp_path)


def test_s3_http(monkeypatch, tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, event

    from tests.integration.test_persistence_postgres import migration_config

    engine = create_engine(f"sqlite:///{(tmp_path / 's3-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_s3_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
