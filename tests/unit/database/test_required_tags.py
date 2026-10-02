"""GOV-001 atomic source-proof validation, retained policies/history and finding lifecycle."""

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
from app.database.governance import create_finding_exception
from app.database.persistence import persist_scan_result
from app.models import (
    ControlAssessment,
    EvidenceArtifact,
    Finding,
    FindingOccurrence,
    ResourceSnapshot,
    Scan,
)
from app.models.enums import FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor
from app.services.scan_service import ScanService
from tests.cloudtrail_destination_fixtures import destination_bundle
from tests.ec2_fixtures import OBSERVED
from tests.governance_fixtures import governance_bundle, governance_profile, governance_provider
from tests.integration.test_persistence_postgres import _RecordingExecutor
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine
FORGERIES = (
    "result",
    "na",
    "insufficient",
    "source_id",
    "source_hash",
    "source_outcome",
    "edge",
    "scan",
    "profile",
    "tags",
    "applicability_type",
    "empty_type",
    "version",
    "owner",
    "region",
    "omitted_target",
    "duplicate_target",
)
COVERAGE_FORGERIES = (
    "omitted_account",
    "account_na",
    "account_pass",
    "account_service",
    "account_owner",
    "unneeded_account",
)


def exercise_coverage_rejection(engine, kind):
    bundle = governance_bundle(
        profile=governance_profile(governed_resource_types=("s3_bucket",)),
        error_operation=("s3", "list_buckets"),
    )
    account = next(a for a in bundle["assessments"] if a.resource_type == "aws_account")
    assert account.result is R.INSUFFICIENT_EVIDENCE
    assert {a.result for a in bundle["assessments"] if a is not account} == {R.NOT_APPLICABLE}
    if kind == "omitted_account":
        bundle["assessments"] = tuple(a for a in bundle["assessments"] if a is not account)
    elif kind == "unneeded_account":
        # An account result cannot accompany genuinely observed governed targets.
        complete = governance_bundle(profile=bundle["profile"])
        account = account.model_copy(
            update={
                "scan_id": complete["snapshot"].scan_id,
                "inventory_sha256": complete["assessments"][0].inventory_sha256,
                "result": R.NOT_APPLICABLE,
                "missing_evidence": (),
            }
        )
        bundle = complete
        bundle["assessments"] += (account,)
    else:
        update = {
            "account_na": {"result": R.NOT_APPLICABLE, "missing_evidence": ()},
            "account_pass": {"result": R.PASS, "missing_evidence": ()},
            "account_service": {"service": "cloudtrail"},
            "account_owner": {"account_id": "111122223333", "aws_resource_id": "111122223333"},
        }[kind]
        forged = account.model_copy(update=update)
        bundle["assessments"] = tuple(forged if a is account else a for a in bundle["assessments"])
    with Session(engine) as session, pytest.raises(ValueError), session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_coverage_history(engine):
    for index, failed in enumerate((True, False)):
        bundle = governance_bundle(
            profile=governance_profile(governed_resource_types=("s3_bucket",)),
            observed=OBSERVED + timedelta(days=index),
            **(
                {"error_operation": ("s3", "list_buckets")}
                if failed
                else {"empty_family": "s3_bucket"}
            ),
        )
        account = next(a for a in bundle["assessments"] if a.resource_type == "aws_account")
        expected = R.INSUFFICIENT_EVIDENCE if failed else R.NOT_APPLICABLE
        assert account.result is expected
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            rows = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).all()
            assert len(rows) == len(bundle["assessments"]) == 11
            assert sum(r.assessment_result is expected for r in rows) == (1 if failed else 11)
            assert not any(r.evidence_artifacts for r in rows)
            assert session.scalar(select(func.count()).select_from(Finding)) == 0


def exercise_population_cost(engine, monkeypatch, instance_count):
    from collections import Counter

    from app.assessment import governance_evidence
    from app.assessment.evidence_reader import AssessmentEvidenceReader

    bundle = governance_bundle(instance_count=instance_count)
    calls, indexes = [], []
    original = governance_evidence._population
    original_index = AssessmentEvidenceReader.governance_resource_families

    def population(reader, family, target, citations):
        calls.append((reader, family.resource_type))
        return original(reader, family, target, citations)

    def index(reader):
        if reader._governance_resource_families is None:
            indexes.append(reader)
        return original_index(reader)

    monkeypatch.setattr(governance_evidence, "_population", population)
    monkeypatch.setattr(AssessmentEvidenceReader, "governance_resource_families", index)
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    assert len(calls) == 11
    assert set(Counter(calls).values()) == {1}
    assert len(indexes) == len(set(indexes)) == 1
    with Session(engine) as session:
        rows = session.scalars(select(ControlAssessment)).all()
        assert len(rows) == instance_count + 10 and {r.assessment_result for r in rows} == {R.PASS}


def exercise_rejection(engine, kind):
    bundle = governance_bundle()
    original = next(a for a in bundle["assessments"] if a.resource_type == "s3_bucket")
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
    elif kind in {"owner", "region"}:
        forged = original.model_copy(
            update={
                "account_id" if kind == "owner" else "region": "111122223333"
                if kind == "owner"
                else "eu-west-1",
            }
        )
    elif kind in {"omitted_target", "duplicate_target"}:
        forged = original
    else:
        document = original.evidence_artifacts[0].model_dump(
            exclude={"evidence_id", "payload_sha256"}
        )
        proof = document["payload"]["source_proof"]
        if kind in {"source_id", "source_hash", "source_outcome"}:
            proof["sources"][0][
                {
                    "source_id": "artifact_id",
                    "source_hash": "evidence_sha256",
                    "source_outcome": "source_outcome_id",
                }[kind]
            ] = "f" * 64 if kind == "source_hash" else str(uuid4())
        elif kind == "edge":
            proof["relationship_observation_ids"] = [str(uuid4())]
        elif kind == "scan":
            proof["scan_id"] = str(uuid4())
        elif kind == "profile":
            proof["profile_checksum"] = "f" * 64
        elif kind == "tags":
            proof["governance"]["tags"][0]["value_utf8_hex"] = b"forged".hex()
        elif kind == "applicability_type":
            proof["governance"]["applicable"] = 1
        elif kind == "empty_type":
            proof["governance"]["empty_population"] = 0
        else:
            document["payload"]["evaluation_version"] = "9.9.9"
        artifact = ArtifactInput.for_assessment(**document)
        assert artifact.verify_integrity()
        forged = original.model_copy(update={"evidence_artifacts": (artifact,)})
    bundle["assessments"] = tuple(
        forged if a is original else a for a in reversed(bundle["assessments"])
    )
    if kind == "omitted_target":
        bundle["assessments"] = tuple(a for a in bundle["assessments"] if a is not original)
    elif kind == "duplicate_target":
        bundle["assessments"] += (original,)
    with Session(engine) as session, pytest.raises(ValueError), session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_history(engine):
    bundles = [
        destination_bundle(),
        governance_bundle(),
        governance_bundle(empty=True, profile=governance_profile(version="6.10.1")),
        governance_bundle(
            profile=governance_profile(version="6.10.2", governed_resource_types=("s3_bucket",))
        ),
        governance_bundle(
            tags={"s3_bucket": {"Owner": " Platform \t", "Environment": "Production "}}
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
            # Accepted storage canonicalizes set-like policy tuples; compare exact
            # canonical content/checksum rather than incidental input tuple order.
            assert canonical_profile_document(profile) == canonical_profile_document(
                bundle["profile"]
            )
            assert profile.content_checksum == bundle["profile"].content_checksum
            catalog, registry = resolve_catalog(
                bundle["catalog"].catalog_id, bundle["catalog"].version
            )
            assert RuleEngine(registry, catalog=catalog).assess(
                bundle["snapshot"], profile
            ) == tuple(sorted(bundle["assessments"], key=lambda a: a.identity))
            rows = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).all()
            assert len(rows) == len(bundle["assessments"])
            expected = {a.resource_snapshot_id: a for a in bundle["assessments"]}
            for row in rows:
                candidate = expected[row.resource_snapshot_id]
                assert row.assessment_result == candidate.result
                assert len(row.evidence_artifacts) == len(candidate.evidence_artifacts)
                for artifact, input_artifact in zip(
                    row.evidence_artifacts, candidate.evidence_artifacts, strict=True
                ):
                    assert artifact.payload == input_artifact.payload
                    assert artifact.payload_sha256 == input_artifact.payload_sha256
                    assert artifact.evidence_id == input_artifact.evidence_id
        target = next(
            r for r in bundles[-1]["snapshot"].resources if r.resource_type == "s3_bucket"
        )
        snapshot = session.get(
            ResourceSnapshot,
            next(
                a.resource_snapshot_id
                for a in bundles[-1]["assessments"]
                if a.resource_type == "s3_bucket"
            ),
        )
        assert (
            snapshot.tags == target.tags == {"Owner": " Platform \t", "Environment": "Production "}
        )


def exercise_lifecycle(engine):
    bundles = [
        governance_bundle(tags={"s3_bucket": {}}),
        governance_bundle(
            observed=OBSERVED + timedelta(days=1), error_operation=("s3", "get_bucket_tagging")
        ),
        governance_bundle(observed=OBSERVED + timedelta(days=2)),
    ]
    identity = None
    for index, bundle in enumerate(bundles):
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            finding = session.scalars(select(Finding)).one()
            identity = identity or finding.finding_id
            assert finding.finding_id == identity
            assert finding.status is (FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN)
            failed = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundles[0]["snapshot"].scan_id,
                    ControlAssessment.assessment_result == R.FAIL,
                )
            ).one()
            occurrence = session.scalars(
                select(FindingOccurrence).where(
                    FindingOccurrence.assessment_id == failed.assessment_id
                )
            ).one()
            assert occurrence.finding_id == identity
            if index == 0:
                original = failed.evidence_artifacts[0].payload_sha256
                exception = create_finding_exception(
                    session,
                    finding_id=identity,
                    reason="Temporary approved ownership investigation",
                    approved_by="governance-approver",
                    created_at=OBSERVED + timedelta(hours=1),
                    expires_at=OBSERVED + timedelta(hours=12),
                )
                session.commit()
                assert exception.finding_id == identity
                assert failed.assessment_result is R.FAIL
                assert failed.evidence_artifacts[0].payload_sha256 == original


def exercise_recovery(engine, tmp_path):
    profile = governance_profile()
    path = tmp_path / "governance-recovery.json"
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
            actor_id="governance-recovery",
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
        provider_factory=governance_provider,
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
        assert len(rows) == 11 and {r.assessment_result for r in rows} == {R.PASS}


@pytest.mark.parametrize("kind", FORGERIES)
def test_atomic_rejection(migrated_engine, kind):
    exercise_rejection(migrated_engine, kind)


@pytest.mark.parametrize("kind", COVERAGE_FORGERIES)
def test_coverage_atomic_rejection(migrated_engine, kind):
    exercise_coverage_rejection(migrated_engine, kind)


def test_coverage_history(migrated_engine):
    exercise_coverage_history(migrated_engine)


@pytest.mark.parametrize("instance_count", [1, 2, 4, 8, 16])
def test_population_cost(migrated_engine, monkeypatch, instance_count):
    exercise_population_cost(migrated_engine, monkeypatch, instance_count)


def test_history(migrated_engine):
    exercise_history(migrated_engine)


def test_lifecycle(migrated_engine):
    exercise_lifecycle(migrated_engine)


def test_recovery(migrated_engine, tmp_path):
    exercise_recovery(migrated_engine, tmp_path)


def test_http(monkeypatch, tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, event

    from tests.governance_http import exercise_governance_http
    from tests.integration.test_persistence_postgres import migration_config

    engine = create_engine(f"sqlite:///{(tmp_path / 'governance-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_governance_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
