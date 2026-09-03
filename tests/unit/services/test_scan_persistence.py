"""Tests for durable scan, resource, and finding lifecycle behavior."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models import Finding, FindingStatus, Resource, Scan, ScanStatus, scan_resources
from app.rules.audit_logging import MissingCloudTrailRule
from app.rules.network import PublicSSHRule
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource
from app.services.scan_persistence import (
    PersistenceInvariantError,
    ScanLifecycleError,
    ScanPersistenceService,
)
from tests.unit.rules.factories import ACCOUNT_ID, REGION, resource

COLLECTED_AT = datetime(2026, 9, 2, 12, tzinfo=UTC)


def _security_group(*, public_ssh: bool) -> NormalizedResource:
    ingress_rules: list[dict[str, object]] = []
    if public_ssh:
        ingress_rules.append(
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": "public SSH"}],
                "ipv6_ranges": [],
                "prefix_lists": [],
                "referenced_security_groups": [],
            }
        )
    return resource(
        service="ec2",
        resource_type="security_group",
        aws_resource_id="sg-persistence-test",
        name="persistence-test",
        configuration={
            "vpc_id": "vpc-test",
            "ingress_rules": ingress_rules,
            "egress_rules": [],
        },
    )


def _snapshot(
    *resources: NormalizedResource,
    collected_at: datetime = COLLECTED_AT,
) -> InventorySnapshot:
    return InventorySnapshot(
        account_id=ACCOUNT_ID,
        requested_region=REGION,
        collected_at=collected_at,
        resources=resources,
    )


def _running_scan(factory: sessionmaker[Session]) -> UUID:
    with factory.begin() as session:
        persistence = ScanPersistenceService(session)
        scan = persistence.queue_scan(account_id=ACCOUNT_ID, region=REGION)
        persistence.start_scan(scan.scan_uuid, started_at=COLLECTED_AT - timedelta(minutes=1))
        return scan.scan_uuid


def _complete_ssh_scan(
    factory: sessionmaker[Session],
    snapshot: InventorySnapshot,
) -> Scan:
    scan_uuid = _running_scan(factory)
    candidates = PublicSSHRule().evaluate(snapshot)
    with factory.begin() as session:
        scan = ScanPersistenceService(session).complete_scan(
            scan_uuid,
            snapshot=snapshot,
            candidates=candidates,
            evaluated_control_ids=("NET-001",),
            completed_at=snapshot.collected_at + timedelta(minutes=1),
        )
        return scan


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def test_two_scans_reuse_resource_and_open_finding(
    session_factory: sessionmaker[Session],
) -> None:
    first_snapshot = _snapshot(_security_group(public_ssh=True))
    first_scan = _complete_ssh_scan(session_factory, first_snapshot)

    with session_factory() as session:
        original_uuid = session.scalar(select(Finding.finding_uuid))

    second_snapshot = _snapshot(
        _security_group(public_ssh=True),
        collected_at=COLLECTED_AT + timedelta(hours=1),
    )
    second_scan = _complete_ssh_scan(session_factory, second_snapshot)

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert session.scalar(select(func.count()).select_from(Scan)) == 2
        assert session.scalar(select(func.count()).select_from(Resource)) == 1
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert session.scalar(select(func.count()).select_from(scan_resources)) == 2
        assert finding.finding_uuid == original_uuid
        assert finding.status is FindingStatus.OPEN
        assert finding.scan_id == first_scan.id
        assert _as_utc(finding.first_detected) == COLLECTED_AT
        assert _as_utc(finding.last_detected) == second_snapshot.collected_at

    assert first_scan.findings_created == 1
    assert second_scan.findings_created == 0
    assert second_scan.findings_resolved == 0


def test_successful_verification_scan_resolves_missing_finding(
    session_factory: sessionmaker[Session],
) -> None:
    discovery_scan = _complete_ssh_scan(
        session_factory,
        _snapshot(_security_group(public_ssh=True)),
    )
    safe_snapshot = _snapshot(
        _security_group(public_ssh=False),
        collected_at=COLLECTED_AT + timedelta(hours=1),
    )

    resolving_scan = _complete_ssh_scan(session_factory, safe_snapshot)

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert finding.status is FindingStatus.RESOLVED
        assert finding.scan_id == discovery_scan.id
        assert _as_utc(finding.last_detected) == COLLECTED_AT
        assert _as_utc(finding.resolved_at) == safe_snapshot.collected_at

    assert resolving_scan.findings_created == 0
    assert resolving_scan.findings_resolved == 1


def test_resolved_finding_reopens_without_creating_a_duplicate(
    session_factory: sessionmaker[Session],
) -> None:
    _complete_ssh_scan(session_factory, _snapshot(_security_group(public_ssh=True)))
    with session_factory() as session:
        original_uuid = session.scalar(select(Finding.finding_uuid))

    _complete_ssh_scan(
        session_factory,
        _snapshot(
            _security_group(public_ssh=False),
            collected_at=COLLECTED_AT + timedelta(hours=1),
        ),
    )
    reopened_scan = _complete_ssh_scan(
        session_factory,
        _snapshot(
            _security_group(public_ssh=True),
            collected_at=COLLECTED_AT + timedelta(hours=2),
        ),
    )

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert finding.finding_uuid == original_uuid
        assert finding.status is FindingStatus.OPEN
        assert finding.resolved_at is None

    assert reopened_scan.findings_created == 0
    assert reopened_scan.findings_resolved == 0


def test_failed_scan_does_not_change_existing_findings(
    session_factory: sessionmaker[Session],
) -> None:
    completed_scan = _complete_ssh_scan(
        session_factory,
        _snapshot(_security_group(public_ssh=True)),
    )
    failed_uuid = _running_scan(session_factory)

    with session_factory.begin() as session:
        failed_scan = ScanPersistenceService(session).fail_scan(
            failed_uuid,
            failed_at=COLLECTED_AT + timedelta(hours=1),
        )

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert finding.status is FindingStatus.OPEN
        assert finding.scan_id == completed_scan.id
        assert session.scalar(select(func.count()).select_from(Resource)) == 1

    assert failed_scan.status is ScanStatus.FAILED
    assert failed_scan.findings_resolved == 0


def test_false_positive_is_not_auto_resolved(
    session_factory: sessionmaker[Session],
) -> None:
    _complete_ssh_scan(session_factory, _snapshot(_security_group(public_ssh=True)))
    with session_factory.begin() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        finding.status = FindingStatus.FALSE_POSITIVE

    verification_scan = _complete_ssh_scan(
        session_factory,
        _snapshot(
            _security_group(public_ssh=False),
            collected_at=COLLECTED_AT + timedelta(hours=1),
        ),
    )

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert finding.status is FindingStatus.FALSE_POSITIVE
        assert finding.resolved_at is None

    assert verification_scan.findings_resolved == 0


def test_account_level_candidate_gets_a_stable_synthetic_resource(
    session_factory: sessionmaker[Session],
) -> None:
    snapshot = _snapshot()
    candidates = MissingCloudTrailRule().evaluate(snapshot)
    scan_uuid = _running_scan(session_factory)

    with session_factory.begin() as session:
        scan = ScanPersistenceService(session).complete_scan(
            scan_uuid,
            snapshot=snapshot,
            candidates=candidates,
            evaluated_control_ids=("LOG-001",),
            completed_at=COLLECTED_AT + timedelta(minutes=1),
        )

    with session_factory() as session:
        resource_record = session.scalar(select(Resource))
        finding = session.scalar(select(Finding))
        assert resource_record is not None
        assert finding is not None
        assert resource_record.resource_type == "aws_account"
        assert resource_record.aws_resource_id == ACCOUNT_ID
        assert resource_record.scope == "global"
        assert finding.resource_id == resource_record.id
        assert session.scalar(select(func.count()).select_from(scan_resources)) == 0

    assert scan.resources_evaluated == 0
    assert scan.findings_created == 1


def test_invalid_candidate_rolls_back_without_partial_persistence(
    session_factory: sessionmaker[Session],
) -> None:
    snapshot = _snapshot(_security_group(public_ssh=True))
    candidates = PublicSSHRule().evaluate(snapshot)
    scan_uuid = _running_scan(session_factory)

    with pytest.raises(PersistenceInvariantError, match="unevaluated control"):
        with session_factory.begin() as session:
            ScanPersistenceService(session).complete_scan(
                scan_uuid,
                snapshot=snapshot,
                candidates=candidates,
                evaluated_control_ids=("S3-002",),
            )

    with session_factory() as session:
        scan = session.scalar(select(Scan).where(Scan.scan_uuid == scan_uuid))
        assert scan is not None
        assert scan.status is ScanStatus.RUNNING
        assert session.scalar(select(func.count()).select_from(Resource)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_completed_scan_cannot_be_completed_again(
    session_factory: sessionmaker[Session],
) -> None:
    snapshot = _snapshot(_security_group(public_ssh=True))
    completed_scan = _complete_ssh_scan(session_factory, snapshot)

    with pytest.raises(ScanLifecycleError, match="must be RUNNING"):
        with session_factory.begin() as session:
            ScanPersistenceService(session).complete_scan(
                completed_scan.scan_uuid,
                snapshot=snapshot,
                candidates=PublicSSHRule().evaluate(snapshot),
                evaluated_control_ids=("NET-001",),
            )


def test_older_scan_cannot_resolve_a_newer_observation(
    session_factory: sessionmaker[Session],
) -> None:
    older_safe_snapshot = _snapshot(
        _security_group(public_ssh=False),
        collected_at=COLLECTED_AT,
    )
    older_scan_uuid = _running_scan(session_factory)
    newer_snapshot = _snapshot(
        _security_group(public_ssh=True),
        collected_at=COLLECTED_AT + timedelta(hours=1),
    )
    discovery_scan = _complete_ssh_scan(session_factory, newer_snapshot)

    with session_factory.begin() as session:
        stale_scan = ScanPersistenceService(session).complete_scan(
            older_scan_uuid,
            snapshot=older_safe_snapshot,
            candidates=(),
            evaluated_control_ids=("NET-001",),
            completed_at=COLLECTED_AT + timedelta(hours=2),
        )

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert finding.status is FindingStatus.OPEN
        assert finding.scan_id == discovery_scan.id
        assert _as_utc(finding.last_detected) == newer_snapshot.collected_at

    assert stale_scan.status is ScanStatus.COMPLETED
    assert stale_scan.findings_resolved == 0


def test_older_scan_cannot_reopen_a_newer_resolution(
    session_factory: sessionmaker[Session],
) -> None:
    _complete_ssh_scan(session_factory, _snapshot(_security_group(public_ssh=True)))
    stale_snapshot = _snapshot(
        _security_group(public_ssh=True),
        collected_at=COLLECTED_AT + timedelta(hours=1),
    )
    stale_candidates = PublicSSHRule().evaluate(stale_snapshot)
    stale_scan_uuid = _running_scan(session_factory)
    safe_snapshot = _snapshot(
        _security_group(public_ssh=False),
        collected_at=COLLECTED_AT + timedelta(hours=2),
    )
    _complete_ssh_scan(session_factory, safe_snapshot)

    with session_factory.begin() as session:
        stale_scan = ScanPersistenceService(session).complete_scan(
            stale_scan_uuid,
            snapshot=stale_snapshot,
            candidates=stale_candidates,
            evaluated_control_ids=("NET-001",),
            completed_at=COLLECTED_AT + timedelta(hours=3),
        )

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert finding.status is FindingStatus.RESOLVED
        assert _as_utc(finding.last_detected) == COLLECTED_AT

    assert stale_scan.findings_created == 0
    assert stale_scan.findings_resolved == 0


def test_unevaluated_control_is_not_resolved(
    session_factory: sessionmaker[Session],
) -> None:
    discovery_scan = _complete_ssh_scan(
        session_factory,
        _snapshot(_security_group(public_ssh=True)),
    )
    unrelated_scan_uuid = _running_scan(session_factory)
    safe_snapshot = _snapshot(
        _security_group(public_ssh=False),
        collected_at=COLLECTED_AT + timedelta(hours=1),
    )

    with session_factory.begin() as session:
        unrelated_scan = ScanPersistenceService(session).complete_scan(
            unrelated_scan_uuid,
            snapshot=safe_snapshot,
            candidates=(),
            evaluated_control_ids=("S3-002",),
            completed_at=COLLECTED_AT + timedelta(hours=1, minutes=1),
        )

    with session_factory() as session:
        finding = session.scalar(select(Finding))
        assert finding is not None
        assert finding.status is FindingStatus.OPEN
        assert finding.scan_id == discovery_scan.id

    assert unrelated_scan.findings_resolved == 0
