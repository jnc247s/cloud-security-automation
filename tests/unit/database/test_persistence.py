"""Historical integrity and finding lifecycle tests against migrated databases."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.assessment.identities import inventory_sha256
from app.assessment.models import AssessmentResult
from app.database.integrity import canonical_json_sha256
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import (
    AuditEvent,
    ControlAssessment,
    EvidenceArtifact,
    Finding,
    FindingOccurrence,
    Resource,
    ResourceSnapshot,
    Scan,
    ScanScopeManifest,
)
from app.models.enums import FindingStatus, ScanStatus
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import ResourceScope
from tests.unit.database.factories import scan_bundle


def count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model))


def test_later_scan_preserves_exact_historical_state_and_evidence(db_session: Session) -> None:
    old = scan_bundle(tags={"Owner": "old"})
    new = scan_bundle(
        public_ssh=False,
        tags={"Owner": "new"},
        observed_at=old["snapshot"].collected_at + timedelta(days=1),
    )
    persist_scan_result(db_session, **old)
    db_session.commit()
    persist_scan_result(db_session, **new)
    db_session.commit()

    assert count(db_session, Resource) == 1
    assert count(db_session, Scan) == 2
    snapshots = db_session.scalars(
        select(ResourceSnapshot).order_by(ResourceSnapshot.observed_at)
    ).all()
    assert len(snapshots) == 2
    assert snapshots[0].tags == {"Owner": "old"}
    assert snapshots[1].tags == {"Owner": "new"}
    assert snapshots[0].normalized_configuration["ingress_rules"]
    assert snapshots[1].normalized_configuration["ingress_rules"] == []
    assert snapshots[0].state_sha256 != snapshots[1].state_sha256
    assert "raw_configuration" not in snapshots[0].__table__.columns
    assert count(db_session, EvidenceArtifact) == 2
    finding = db_session.scalar(select(Finding))
    assert finding.status is FindingStatus.RESOLVED
    assert count(db_session, FindingOccurrence) == 1
    assert {item.assessment_result for item in db_session.scalars(select(ControlAssessment))} == {
        AssessmentResult.FAIL,
        AssessmentResult.PASS,
    }


def test_recurrent_failure_updates_one_finding_with_multiple_occurrences(
    db_session: Session,
) -> None:
    old = scan_bundle()
    new = scan_bundle(observed_at=old["snapshot"].collected_at + timedelta(days=1))
    persist_scan_result(db_session, **old)
    db_session.commit()
    first_id = db_session.scalar(select(Finding.finding_id))
    persist_scan_result(db_session, **new)
    db_session.commit()
    assert count(db_session, Finding) == 1
    assert db_session.scalar(select(Finding.finding_id)) == first_id
    assert count(db_session, FindingOccurrence) == 2
    assert db_session.scalar(select(Finding.status)) is FindingStatus.OPEN


@pytest.mark.parametrize(
    ("options", "expected", "evidence_count"),
    [
        ({"public_ssh": True}, AssessmentResult.FAIL, 1),
        ({"public_ssh": False}, AssessmentResult.PASS, 1),
        ({"malformed": True}, AssessmentResult.INSUFFICIENT_EVIDENCE, 0),
        ({"public_ssh": None}, AssessmentResult.NOT_APPLICABLE, 0),
    ],
)
def test_all_four_results_round_trip(
    db_session: Session, options, expected, evidence_count
) -> None:
    bundle = scan_bundle(**options)
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    assessment = db_session.scalar(select(ControlAssessment))
    assert assessment.assessment_result is expected
    assert assessment.scan_id == scan.scan_id == bundle["snapshot"].scan_id
    assert assessment.resource_snapshot.scan_id == scan.scan_id
    assert count(db_session, EvidenceArtifact) == evidence_count
    assert count(db_session, Finding) == (1 if expected is AssessmentResult.FAIL else 0)
    if expected is AssessmentResult.INSUFFICIENT_EVIDENCE:
        assert assessment.missing_evidence


@pytest.mark.parametrize("status", [CollectionStatus.PARTIAL, CollectionStatus.FAILED])
def test_incomplete_collection_never_resolves_a_finding(db_session: Session, status) -> None:
    old = scan_bundle()
    persist_scan_result(db_session, **old)
    db_session.commit()
    new = scan_bundle(
        public_ssh=False,
        collection_status=status,
        observed_at=old["snapshot"].collected_at + timedelta(days=1),
    )
    result = persist_scan_result(db_session, **new)
    db_session.commit()
    assert result.status is (
        ScanStatus.PARTIAL if status is CollectionStatus.PARTIAL else ScanStatus.FAILED
    )
    assert db_session.scalar(select(Finding.status)) is FindingStatus.OPEN
    assert result.scope_manifest.collector_outcomes == {"security_groups": status.value}


def test_stale_observations_cannot_reopen_or_resolve_newer_state(db_session: Session) -> None:
    moment = datetime(2026, 9, 3, tzinfo=UTC)
    # Newer PASS arrives before an older FAIL. The historical failure is retained, already resolved.
    persist_scan_result(
        db_session, **scan_bundle(public_ssh=False, observed_at=moment + timedelta(days=2))
    )
    db_session.commit()
    persist_scan_result(db_session, **scan_bundle(observed_at=moment))
    db_session.commit()
    assert db_session.scalar(select(Finding.status)) is FindingStatus.RESOLVED
    persist_scan_result(db_session, **scan_bundle(observed_at=moment + timedelta(days=3)))
    db_session.commit()
    assert db_session.scalar(select(Finding.status)) is FindingStatus.OPEN
    persist_scan_result(
        db_session, **scan_bundle(public_ssh=False, observed_at=moment + timedelta(days=1))
    )
    db_session.commit()
    assert db_session.scalar(select(Finding.status)) is FindingStatus.OPEN
    assert count(db_session, FindingOccurrence) == 2


def test_scan_retry_is_idempotent_but_changed_content_is_rejected(db_session: Session) -> None:
    bundle = scan_bundle()
    first = persist_scan_result(db_session, **bundle)
    db_session.commit()
    assert persist_scan_result(db_session, **bundle).scan_id == first.scan_id
    db_session.commit()
    assert count(db_session, Scan) == 1
    assert count(db_session, AuditEvent) == 3
    changed = scan_bundle(public_ssh=False, scan_id=bundle["snapshot"].scan_id)
    with pytest.raises(ScanPersistenceError, match="different content"):
        persist_scan_result(db_session, **changed)
    db_session.rollback()
    assert count(db_session, ResourceSnapshot) == 1


@pytest.mark.parametrize("failure_first", [True, False])
def test_simultaneous_conflicting_observations_conservatively_keep_failure(
    db_session: Session, failure_first: bool
) -> None:
    failure = scan_bundle(public_ssh=True)
    passing = scan_bundle(public_ssh=False)
    bundles = (failure, passing) if failure_first else (passing, failure)
    for bundle in bundles:
        persist_scan_result(db_session, **bundle)
        db_session.commit()
    assert db_session.scalar(select(Finding.status)) is FindingStatus.OPEN


def test_scope_mismatch_is_rejected_before_any_writes(db_session: Session) -> None:
    bundle = scan_bundle()
    bundle["scope"] = bundle["scope"].model_copy(update={"aws_account_id": "999999999999"})
    with pytest.raises(ScanPersistenceError, match="scope account"):
        persist_scan_result(db_session, **bundle)
    assert count(db_session, Scan) == 0
    assert count(db_session, Resource) == 0


def test_inventory_mutation_after_assessment_is_rejected(db_session: Session) -> None:
    bundle = scan_bundle()
    bundle["snapshot"].resources[0].configuration["ingress_rules"] = []
    with pytest.raises(ScanPersistenceError, match="facts changed after assessment"):
        persist_scan_result(db_session, **bundle)
    assert count(db_session, Scan) == 0


def test_tampered_evidence_is_rejected_and_transaction_rolls_back(db_session: Session) -> None:
    bundle = scan_bundle()
    candidate = bundle["assessments"][0]
    artifact = candidate.evidence_artifacts[0].model_copy(update={"payload_sha256": "0" * 64})
    bundle["assessments"] = (candidate.model_copy(update={"evidence_artifacts": (artifact,)}),)
    with pytest.raises(ValueError), db_session.begin():
        persist_scan_result(db_session, **bundle)
    assert count(db_session, Scan) == 0


def test_caller_rollback_removes_the_entire_scan_graph(db_session: Session) -> None:
    with pytest.raises(RuntimeError), db_session.begin():
        persist_scan_result(db_session, **scan_bundle())
        raise RuntimeError("simulated transaction failure")
    for model in (
        Scan,
        Resource,
        ResourceSnapshot,
        ControlAssessment,
        EvidenceArtifact,
        Finding,
        FindingOccurrence,
        AuditEvent,
    ):
        assert count(db_session, model) == 0


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (ResourceSnapshot, {"name": "rewritten"}),
        (ControlAssessment, {"reason": "rewritten"}),
        (EvidenceArtifact, {"payload": {"rewritten": True}}),
        (AuditEvent, {"actor_id": "rewritten"}),
    ],
)
def test_database_rejects_rewriting_historical_records(db_session: Session, model, values) -> None:
    persist_scan_result(db_session, **scan_bundle())
    db_session.commit()
    with pytest.raises(IntegrityError, match="immutable"):
        db_session.execute(update(model).values(**values))
    db_session.rollback()


def test_evidence_cannot_reference_a_different_scan(db_session: Session) -> None:
    persist_scan_result(db_session, **scan_bundle())
    db_session.commit()
    artifact = db_session.scalar(select(EvidenceArtifact))
    values = {
        column.name: getattr(artifact, column.name) for column in EvidenceArtifact.__table__.columns
    }
    values.update(evidence_id=uuid4(), scan_id=uuid4(), evidence_key="mismatched")
    with pytest.raises(IntegrityError):
        db_session.execute(insert(EvidenceArtifact).values(**values))
    db_session.rollback()


def test_exact_scope_and_versions_remain_queryable(db_session: Session) -> None:
    bundle = scan_bundle()
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    scope = scan.scope_manifest
    assert scope.aws_account_id == bundle["snapshot"].account_id
    assert scope.requested_regions == ["us-east-1"]
    assert scope.successful_regions == ["us-east-1"]
    assert scope.requested_services == ["ec2"]
    assert scope.requested_collectors == ["security_groups"]
    assert scope.resource_types == ["security_group"]
    assert scope.enabled_controls == ["NET-001"]
    assessment = db_session.scalar(select(ControlAssessment))
    assert assessment.control_version.catalog.version == scan.control_catalog_version
    assert assessment.assessment_profile.version == scan.assessment_profile_version
    assert assessment.control_version.framework_mappings
    assert scan.inventory_sha256 == inventory_sha256(bundle["snapshot"])


def test_terminal_scan_rejects_late_resource_snapshots(db_session: Session) -> None:
    bundle = scan_bundle()
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    resource = Resource(
        resource_id=uuid4(),
        provider="aws",
        aws_account_id=scan.aws_account_id,
        aws_resource_id="sg-late-write",
        service="ec2",
        resource_type="security_group",
        scope=ResourceScope.REGIONAL,
        region="us-east-1",
    )
    db_session.add(resource)
    db_session.commit()

    db_session.add(
        ResourceSnapshot(
            snapshot_id=uuid4(),
            resource_id=resource.resource_id,
            scan_id=scan.scan_id,
            scope=ResourceScope.REGIONAL,
            region="us-east-1",
            tags={},
            normalized_configuration={},
            state_sha256=canonical_json_sha256({}),
            observed_at=bundle["snapshot"].collected_at,
        )
    )
    with pytest.raises(IntegrityError, match="RUNNING"):
        db_session.flush()
    db_session.rollback()


def test_scan_rows_must_be_inserted_in_running_state(db_session: Session) -> None:
    scan = persist_scan_result(db_session, **scan_bundle())
    db_session.commit()
    values = {column.name: getattr(scan, column.name) for column in Scan.__table__.columns}
    values["scan_id"] = uuid4()
    with pytest.raises(IntegrityError, match="start RUNNING"):
        db_session.execute(insert(Scan).values(**values))
    db_session.rollback()


def test_scope_manifest_provenance_must_match_its_running_scan(
    db_session: Session,
) -> None:
    original = persist_scan_result(db_session, **scan_bundle())
    db_session.commit()
    running_id = uuid4()
    scan_values = {column.name: getattr(original, column.name) for column in Scan.__table__.columns}
    scan_values.update(
        scan_id=running_id,
        status=ScanStatus.RUNNING,
        completed_at=None,
        result_checksum=None,
    )
    db_session.execute(insert(Scan).values(**scan_values))

    original_scope = original.scope_manifest
    scope_values = {
        column.name: getattr(original_scope, column.name)
        for column in ScanScopeManifest.__table__.columns
    }
    scope_values.update(
        manifest_id=uuid4(),
        scan_id=running_id,
        aws_account_id="999999999999",
    )
    with pytest.raises(IntegrityError, match="provenance differs"):
        db_session.execute(insert(ScanScopeManifest).values(**scope_values))
    db_session.rollback()
