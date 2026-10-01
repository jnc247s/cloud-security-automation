"""6F.2 atomic dependency validation, immutable history, lifecycle and recovery."""

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
from app.database.persistence import persist_scan_result
from app.models import ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor
from app.services.scan_service import ScanService
from tests.cloudtrail_destination_fixtures import (
    assert_mixed_destination_bindings,
    destination_bundle,
    destination_profile,
    destination_provider,
    mixed_destination_provider,
)
from tests.cloudtrail_fixtures import logging_bundle
from tests.ec2_fixtures import OBSERVED
from tests.fakes import client_error
from tests.integration.test_persistence_postgres import _RecordingExecutor
from tests.s3_exposure_fixtures import policy_response, statement
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine
FORGERIES = (
    "result",
    "na",
    "insufficient",
    "source",
    "edge",
    "snapshot",
    "scan",
    "profile",
    "catalog",
    "policy",
    "dependency_digest",
    "version",
    "numeric",
    "owner",
    "region",
)
PREREQUISITE_FORGERIES = (
    "result",
    "scan",
    "snapshot",
    "profile",
    "catalog",
    "inventory",
    "name",
    "numeric",
    "owner",
    "region",
)


def assert_empty(engine):
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_rejection(engine, kind, *, prerequisite=False):
    bundle = (
        destination_bundle(provider=mixed_destination_provider())
        if kind in {"owner", "region"}
        else destination_bundle()
    )
    control_id = "S3-002" if prerequisite else "LOG-004"
    original = next(a for a in bundle["assessments"] if a.control_id == control_id)
    if kind in {"result", "na", "insufficient"}:
        result = {
            "result": R.FAIL,
            "na": R.NOT_APPLICABLE,
            "insufficient": R.INSUFFICIENT_EVIDENCE,
        }[kind]
        forged = original.model_copy(
            update={
                "result": result,
                "evidence_artifacts": original.evidence_artifacts if kind == "result" else (),
                "missing_evidence": ("missing",) if kind == "insufficient" else (),
            }
        )
    elif prerequisite and kind != "numeric":
        field = {
            "scan": "scan_id",
            "snapshot": "resource_snapshot_id",
            "profile": "profile_checksum",
            "catalog": "control_catalog_sha256",
            "inventory": "inventory_sha256",
            "name": "name",
            "owner": "account_id",
            "region": "region",
        }[kind]
        value = (
            uuid4()
            if kind in {"scan", "snapshot"}
            else "111122223333"
            if kind == "owner"
            else ("us-east-1" if original.region == "eu-west-1" else "eu-west-1")
            if kind == "region"
            else "f" * 64
        )
        forged = original.model_copy(update={field: value})
    else:
        document = original.evidence_artifacts[0].model_dump(
            exclude={"evidence_id", "payload_sha256"}
        )
        proof = document["payload"]["source_proof"]
        dependency = proof.get("destination_dependency")
        if kind == "source":
            proof["sources"][0]["artifact_id"] = str(uuid4())
        elif kind == "edge":
            proof["relationship_observation_ids"] = [str(uuid4())]
        elif kind in {"snapshot", "scan", "profile", "catalog"}:
            field = {
                "snapshot": "resource_snapshot_id",
                "scan": "scan_id",
                "profile": "profile_checksum",
                "catalog": "control_catalog_sha256",
            }[kind]
            dependency[field] = str(uuid4()) if kind in {"snapshot", "scan"} else "f" * 64
        elif kind == "policy":
            dependency["approval_policy"]["version"] = "9.9.9"
        elif kind == "dependency_digest":
            dependency["evidence"][0]["payload_sha256"] = "f" * 64
        elif kind in {"owner", "region"}:
            dependency["bucket_identity"][
                "aws_account_id" if kind == "owner" else "bucket_region"
            ] = (
                "111122223333"
                if kind == "owner"
                else "us-east-1"
                if dependency["bucket_identity"]["bucket_region"] == "eu-west-1"
                else "eu-west-1"
            )
        elif kind == "version":
            document["payload"]["evaluation_version"] = "9.9.9"
        elif prerequisite:
            proof["s3_exposure"]["empty_population"] = 0
        else:
            proof["cloudtrail"]["empty_population"] = 0
        artifact = ArtifactInput.for_assessment(**document)
        assert artifact.verify_integrity()
        forged = original.model_copy(update={"evidence_artifacts": (artifact,)})
    bundle["assessments"] = tuple(
        forged if a is original else a for a in reversed(bundle["assessments"])
    )
    with Session(engine) as session, pytest.raises(ValueError), session.begin():
        persist_scan_result(session, **bundle)
    assert_empty(engine)


def exercise_mixed_destinations(engine, monkeypatch):
    from app.assessment import identities

    bundle = destination_bundle(provider=mixed_destination_provider())
    assert_mixed_destination_bindings(bundle)
    bundle["assessments"] = tuple(reversed(bundle["assessments"]))
    calls = []
    original = identities.inventory_sha256

    def record(snapshot):
        calls.append(snapshot)
        return original(snapshot)

    monkeypatch.setattr(identities, "inventory_sha256", record)
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    assert len(calls) == 1  # One sealed persistence reader, not once per trail.
    with Session(engine) as session:
        expected = {
            a.resource_snapshot_id: a for a in bundle["assessments"] if a.control_id == "LOG-004"
        }
        rows = session.scalars(
            select(ControlAssessment).where(
                ControlAssessment.resource_snapshot_id.in_(expected),
                ControlAssessment.scan_id == bundle["snapshot"].scan_id,
            )
        ).all()
        assert len(rows) == 3
        for row in rows:
            candidate = expected[row.resource_snapshot_id]
            assert row.assessment_result == candidate.result
            assert len(row.evidence_artifacts) == 1
            assert row.evidence_artifacts[0].payload == candidate.evidence_artifacts[0].payload
            assert (
                row.evidence_artifacts[0].evidence_id == candidate.evidence_artifacts[0].evidence_id
            )


def exercise_history(engine):
    bundles = [
        logging_bundle(),
        destination_bundle(),
        destination_bundle(
            profile=destination_profile(version="6.9.2", enabled_controls=("LOG-004",)), specs=[]
        ),
    ]
    for bundle in bundles:
        bundle["assessments"] = tuple(reversed(bundle["assessments"]))
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
            replayed = RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], profile)
            assert replayed == tuple(sorted(bundle["assessments"], key=lambda a: a.identity))
            count = session.scalar(
                select(func.count())
                .select_from(ControlAssessment)
                .where(ControlAssessment.scan_id == bundle["snapshot"].scan_id)
            )
            assert count == len(bundle["assessments"])


def exercise_lifecycle(engine):
    bundles = [
        destination_bundle(
            policy_response=policy_response(statement()),
            policy_status_response={"PolicyStatus": {"IsPublic": True}},
        ),
        destination_bundle(
            observed=OBSERVED + timedelta(days=1),
            trail_options={"tag_error": client_error("AccessDeniedException", "ListTags")},
        ),
        destination_bundle(observed=OBSERVED + timedelta(days=2)),
    ]
    identities = None
    for index, bundle in enumerate(bundles):
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            findings = session.scalars(select(Finding)).all()
            assert len(findings) == 2
            ids = {f.finding_id for f in findings}
            identities = identities or ids
            assert ids == identities
            assert {f.status for f in findings} == {
                FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN
            }
            failed = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundles[0]["snapshot"].scan_id
                )
            ).all()
            assert {a.assessment_result for a in failed} == {R.FAIL}


def exercise_recovery(engine, tmp_path):
    profile = destination_profile()
    path = tmp_path / "destination-recovery.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.12.0",
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
            actor_id="destination-recovery",
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
        provider_factory=destination_provider,
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
        assert len(rows) == 2 and {r.assessment_result for r in rows} == {R.PASS}


@pytest.mark.parametrize("kind", FORGERIES)
def test_rejection(migrated_engine, kind):
    exercise_rejection(migrated_engine, kind)


@pytest.mark.parametrize("kind", PREREQUISITE_FORGERIES)
def test_prerequisite_rejection(migrated_engine, kind):
    exercise_rejection(migrated_engine, kind, prerequisite=True)


def test_history(migrated_engine):
    exercise_history(migrated_engine)


def test_mixed_destinations(migrated_engine, monkeypatch):
    exercise_mixed_destinations(migrated_engine, monkeypatch)


def test_lifecycle(migrated_engine):
    exercise_lifecycle(migrated_engine)


def test_recovery(migrated_engine, tmp_path):
    exercise_recovery(migrated_engine, tmp_path)


def test_http(monkeypatch, tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, event

    from tests.cloudtrail_destination_http import exercise_destination_http
    from tests.integration.test_persistence_postgres import migration_config

    engine = create_engine(f"sqlite:///{(tmp_path / 'destination-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_destination_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
