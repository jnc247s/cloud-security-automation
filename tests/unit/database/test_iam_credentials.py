"""6B.1 transactional history and proof enforcement, also exercised on PostgreSQL."""

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assessment.extended_profiles import canonical_profile_document
from app.assessment.models import AssessmentResult
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import FindingStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.iam_credentials_fixtures import iam_bundle
from tests.unit.database.factories import scan_bundle


def exercise_iam_history(engine):
    legacy = scan_bundle()
    new = iam_bundle()
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **legacy)
        persist_scan_result(session, **new)
    with Session(engine) as session:
        verify_control_catalog(session, legacy["catalog"])
        verify_control_catalog(session, new["catalog"])
        loaded = load_assessment_profile(
            session,
            profile_id=new["profile"].profile_id,
            version=new["profile"].version,
            expected_checksum=new["profile"].content_checksum,
        )
        assert canonical_profile_document(loaded) == canonical_profile_document(new["profile"])
        assert loaded.content_checksum == new["profile"].content_checksum
        catalog, registry = resolve_catalog(new["catalog"].catalog_id, new["catalog"].version)
        assert (
            RuleEngine(registry, catalog=catalog).assess(new["snapshot"], loaded)
            == new["assessments"]
        )
        assessments = session.scalars(
            select(ControlAssessment).where(ControlAssessment.scan_id == new["snapshot"].scan_id)
        ).all()
        assert len(assessments) == 4
        assert {a.assessment_result for a in assessments} == {AssessmentResult.FAIL}
        for assessment in assessments:
            snapshot = session.get(ResourceSnapshot, assessment.resource_snapshot_id)
            assert snapshot.scan_id == new["snapshot"].scan_id
            evidence = session.scalars(
                select(EvidenceArtifact).where(
                    EvidenceArtifact.assessment_id == assessment.assessment_id
                )
            ).one()
            assert evidence.payload["source_proof"]["scan_id"] == str(snapshot.scan_id)
            assert (
                session.scalar(
                    select(Finding).where(
                        Finding.resource_id == snapshot.resource_id,
                        Finding.control_id == assessment.control_id,
                    )
                ).status
                is FindingStatus.OPEN
            )


def exercise_iam_forged_proof(engine):
    bundle = iam_bundle()
    first, *rest = bundle["assessments"]
    artifact = first.evidence_artifacts[0]
    payload = dict(artifact.payload)
    proof = dict(payload["source_proof"])
    proof["relationship_observation_ids"] = []
    payload["source_proof"] = proof
    # Recompute the artifact's own digest: rejection must be about the false graph proof.
    from app.assessment.models import EvidenceArtifact as ArtifactInput

    values = artifact.model_dump(exclude={"evidence_id", "payload_sha256"})
    values["payload"] = payload
    forged = ArtifactInput.for_assessment(**values)
    bundle["assessments"] = (first.model_copy(update={"evidence_artifacts": (forged,)}), *rest)
    with Session(engine) as session, pytest.raises(ScanPersistenceError), session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 0


def exercise_iam_empty_history(engine):
    bundle = iam_bundle(keys=False)
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        results = session.scalars(select(ControlAssessment.assessment_result)).all()
        assert results.count(AssessmentResult.NOT_APPLICABLE) == 2
        assert session.scalar(select(func.count()).select_from(Finding)) == 2


def test_iam_history(migrated_engine):
    exercise_iam_history(migrated_engine)


def test_forged_iam_proof_is_rejected_atomically(migrated_engine):
    exercise_iam_forged_proof(migrated_engine)


def test_empty_keys_persist_without_fabricated_evidence(migrated_engine):
    exercise_iam_empty_history(migrated_engine)


def exercise_iam_recovery(engine, tmp_path):
    """A pending new-catalog scan must not inherit the restarted legacy deployment policy."""
    import json

    from sqlalchemy.orm import sessionmaker

    from app.config import Settings
    from app.models.enums import ScanStatus
    from app.schemas.scan import ScanCreateRequest
    from app.services.scan_executor import InProcessScanExecutor
    from app.services.scan_service import ScanService
    from tests.iam_credentials_fixtures import iam_client, iam_profile
    from tests.integration.test_persistence_postgres import _empty_provider, _RecordingExecutor

    profile = iam_profile(version="6.1.0", max_unused_access_key_days=1)
    path = tmp_path / "iam-recovery-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.3.0",
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
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="recovery-test"
        )

    calls = []

    def provider(region):
        calls.append(region)
        fake = _empty_provider(region)
        fake._clients[("iam", region)] = iam_client(age=730, unused=730)
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
        assert scan.control_catalog_version == "0.3.0"
        assert scan.assessment_profile_checksum == profile.content_checksum
        artifacts = session.scalars(
            select(EvidenceArtifact).where(EvidenceArtifact.scan_id == scan.scan_id)
        ).all()
        assert len(artifacts) == 4
        assert sorted(
            a.payload["threshold_days"] for a in artifacts if "threshold_days" in a.payload
        ) == [1, 90]


def test_pending_iam_scan_recovers_exact_policy(migrated_engine, tmp_path):
    exercise_iam_recovery(migrated_engine, tmp_path)
