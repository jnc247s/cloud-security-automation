"""Whole-sprint retained history and actual supported-release restart acceptance."""

import json
from datetime import timedelta

import pytest
from alembic import command
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.assessment.extended_profiles import canonical_profile_document
from app.assessment.models import AssessmentResult as R
from app.config import Settings
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import persist_scan_result
from app.models import ControlAssessment, Scan, SourceEvidenceArtifact
from app.models.enums import ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor
from app.services.scan_service import ScanService
from tests.ec2_fixtures import OBSERVED
from tests.governance_fixtures import governance_provider
from tests.integration.test_persistence_postgres import _RecordingExecutor, migration_config
from tests.sprint6_fixtures import CATALOG_CHECKSUMS, CATALOG_ID, sprint6_bundle, sprint6_profile
from tests.unit.database.conftest import migrated_engine as _migrated_engine

migrated_engine = _migrated_engine


@pytest.fixture
def threaded_engine(tmp_path):
    """Use independent connections for the real worker; never an in-memory StaticPool."""
    engine = create_engine(f"sqlite:///{(tmp_path / 'sprint6.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        yield engine
    finally:
        engine.dispose()


def exercise_release_history(engine):
    bundles = []
    for index, version in enumerate(CATALOG_CHECKSUMS):
        bundle = sprint6_bundle(catalog_version=version, observed=OBSERVED + timedelta(days=index))
        # Persistence must be independent of assessment arrival order.
        bundle["assessments"] = tuple(reversed(bundle["assessments"]))
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        bundles.append(bundle)

    # Read every old result after the newest catalog/profile has been registered.
    with Session(engine) as session:
        for bundle in bundles:
            scan_id = bundle["snapshot"].scan_id
            scan = session.get(Scan, scan_id)
            assert scan.status is ScanStatus.COMPLETED
            assert scan.control_catalog_version == bundle["catalog"].version
            assert scan.assessment_profile_checksum == bundle["profile"].content_checksum
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
            if bundle["catalog"].version == "0.2.1":
                assert "schema_version" not in canonical_profile_document(profile)
            catalog, registry = resolve_catalog(CATALOG_ID, bundle["catalog"].version)
            assert RuleEngine(registry, catalog=catalog).assess(
                bundle["snapshot"], profile
            ) == tuple(sorted(bundle["assessments"], key=lambda a: a.identity))
            rows = session.scalars(
                select(ControlAssessment).where(ControlAssessment.scan_id == scan_id)
            ).all()
            expected = {(a.control_id, a.resource_snapshot_id): a for a in bundle["assessments"]}
            assert len(rows) == len(expected)
            for row in rows:
                candidate = expected[
                    (row.control_version.control.control_key, row.resource_snapshot_id)
                ]
                assert row.assessment_result is candidate.result
                assert row.reason == candidate.reason
                assert row.assessment_profile.content_checksum == profile.content_checksum
                assert {a.evidence_id for a in row.evidence_artifacts} == {
                    a.evidence_id for a in candidate.evidence_artifacts
                }
                for artifact in row.evidence_artifacts:
                    original = next(
                        a
                        for a in candidate.evidence_artifacts
                        if a.evidence_id == artifact.evidence_id
                    )
                    assert artifact.payload == original.payload
                    assert artifact.payload_sha256 == original.payload_sha256
                    assert artifact.scan_id == scan_id
                assert (row.finding_occurrence is not None) is (candidate.result is R.FAIL)
                assert row.control_version.framework_mappings
            artifacts = session.scalars(
                select(SourceEvidenceArtifact).where(SourceEvidenceArtifact.scan_id == scan_id)
            ).all()
            originals = {a.artifact_id: a for a in bundle["snapshot"].evidence_graph.artifacts}
            assert {a.artifact_id for a in artifacts} == set(originals)
            for artifact in artifacts:
                assert artifact.evidence_sha256 == originals[artifact.artifact_id].evidence_sha256
                assert (
                    artifact.normalized_payload
                    == originals[artifact.artifact_id].model_dump(mode="json")["normalized_payload"]
                )
        latest = session.get(Scan, bundles[-1]["snapshot"].scan_id)
        assert len(latest.assessments) == 39


def exercise_release_recovery(engine, tmp_path, version):
    profile = sprint6_profile(version)
    path = tmp_path / "sprint6-pending-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": CATALOG_ID,
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
            ScanCreateRequest(region="us-east-1"), _RecordingExecutor(), actor_id="sprint6-recovery"
        )
        assert session.get(Scan, pending.scan_id).status is ScanStatus.RUNNING
    # Neither current deployment policy nor the default catalog may replace retained intent.
    path.unlink()
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
        return governance_provider(region)

    executor = InProcessScanExecutor(
        session_factory=sessionmaker(bind=engine),
        settings=restart,
        provider_factory=provider,
        max_workers=1,
        max_outstanding=1,
    )
    try:
        assert executor.resume_pending() == 1
    finally:
        executor.shutdown(wait=True)
    assert calls == ["us-east-1"]
    with Session(engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.control_catalog_version == version
        assert scan.assessment_profile_checksum == profile.content_checksum
        assert scan.result_checksum and scan.inventory_sha256
        assert {a.control_version.control.control_key for a in scan.assessments} == set(
            profile.enabled_controls
        )
        assert all(
            a.assessment_profile.content_checksum == profile.content_checksum
            for a in scan.assessments
        )
        if version == "0.13.0":
            assert len(scan.assessments) == 39
            assert sum(a.assessment_result is R.FAIL for a in scan.assessments) == 17
        # A completed job must not collect again during a second public restart pass.
    second = InProcessScanExecutor(
        session_factory=sessionmaker(bind=engine), settings=restart, provider_factory=provider
    )
    try:
        assert second.resume_pending() == 0
    finally:
        second.shutdown(wait=True)
    assert calls == ["us-east-1"]


def test_release_history(migrated_engine):
    exercise_release_history(migrated_engine)


@pytest.mark.parametrize("version", CATALOG_CHECKSUMS)
def test_release_recovery(threaded_engine, tmp_path, version):
    exercise_release_recovery(threaded_engine, tmp_path, version)


def test_whole_sprint_http(threaded_engine, monkeypatch, tmp_path):
    from tests.sprint6_http import exercise_sprint6_http

    exercise_sprint6_http(threaded_engine, monkeypatch, tmp_path)
