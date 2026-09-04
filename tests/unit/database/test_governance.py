"""Focused governance tests use an isolated, foreign-key-enforcing SQLite database."""

from collections.abc import Iterator
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.assessment.models import AssessmentResult
from app.database.base import Base
from app.database.governance import (
    GovernanceError,
    create_finding_exception,
    expire_exceptions,
    revoke_exception,
    set_finding_disposition,
)
from app.database.persistence import persist_scan_result
from app.models import AuditEvent, ControlAssessment, EvidenceArtifact, Finding, FindingException
from app.models.enums import AuditEventType, ExceptionStatus, FindingStatus
from tests.unit.database.factories import scan_bundle

OBSERVED_AT = datetime(2026, 9, 3, 12, tzinfo=UTC)
CREATED_AT = OBSERVED_AT + timedelta(hours=1)
EXPIRES_AT = CREATED_AT + timedelta(days=1)


@pytest.fixture
def governance_session() -> Iterator[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    try:
        with Session(engine, expire_on_commit=False) as session:
            yield session
    finally:
        engine.dispose()


def _seed_finding(session: Session, *, region: str = "us-east-1") -> UUID:
    persist_scan_result(session, **scan_bundle(region=region, observed_at=OBSERVED_AT))
    finding_id = session.scalar(select(Finding.finding_id).where(Finding.region == region))
    assert finding_id is not None
    session.commit()
    return finding_id


def _create_exception(session: Session, finding_id: UUID, **overrides) -> FindingException:
    values = {
        "finding_id": finding_id,
        "reason": "Temporary approved management access during migration.",
        "approved_by": "approver@example.test",
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
    }
    values.update(overrides)
    return create_finding_exception(session, **values)


def _event_count(session: Session, event_type: AuditEventType) -> int:
    count = session.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.event_type == event_type)
    )
    assert count is not None
    return count


def _technical_state(session: Session) -> tuple:
    assessments = tuple(
        (
            row.assessment_id,
            row.assessment_result,
            row.reason,
            deepcopy(row.missing_evidence),
        )
        for row in session.scalars(
            select(ControlAssessment).order_by(ControlAssessment.assessment_id)
        )
    )
    evidence = tuple(
        (row.evidence_id, row.payload_sha256, deepcopy(row.payload))
        for row in session.scalars(select(EvidenceArtifact).order_by(EvidenceArtifact.evidence_id))
    )
    return assessments, evidence


def test_create_exception_preserves_fail_evidence_and_finding_disposition(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    original_technical_state = _technical_state(session)
    exception = _create_exception(session, finding_id)
    session.commit()
    session.expire_all()

    finding = session.get(Finding, finding_id)
    assert finding is not None
    assert exception.resource_id == finding.resource_id
    assert exception.control_id == finding.control_id
    assert exception.status is ExceptionStatus.ACTIVE
    assert finding.status is FindingStatus.OPEN
    assert _technical_state(session) == original_technical_state
    audit = session.scalar(
        select(AuditEvent).where(AuditEvent.event_type == AuditEventType.EXCEPTION_CREATED)
    )
    assert audit is not None
    assert audit.actor_type == "user"
    assert audit.actor_id == exception.approved_by
    assert audit.target_id == exception.exception_id
    assert audit.event_metadata["finding_id"] == str(finding_id)


@pytest.mark.parametrize(
    "overrides",
    [
        {"reason": "  "},
        {"approved_by": " "},
        {"approved_by": "a" * 257},
        {"created_at": CREATED_AT.replace(tzinfo=None)},
        {"expires_at": EXPIRES_AT.replace(tzinfo=None)},
        {"expires_at": CREATED_AT},
        {"created_at": OBSERVED_AT - timedelta(seconds=1)},
    ],
)
def test_invalid_exception_inputs_do_not_write_rows_or_audit(
    governance_session: Session, overrides
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    with pytest.raises(GovernanceError):
        _create_exception(session, finding_id, **overrides)
    assert session.scalar(select(func.count()).select_from(FindingException)) == 0
    assert _event_count(session, AuditEventType.EXCEPTION_CREATED) == 0


def test_expiry_boundary_is_idempotent_and_does_not_change_disposition(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    exception = _create_exception(session, finding_id)
    set_finding_disposition(
        session,
        finding_id=finding_id,
        status=FindingStatus.ACCEPTED_RISK,
        at=CREATED_AT,
        actor_id="analyst",
    )
    assert expire_exceptions(session, at=EXPIRES_AT - timedelta(microseconds=1)) == ()
    expired = expire_exceptions(session, at=EXPIRES_AT)
    assert [item.exception_id for item in expired] == [exception.exception_id]
    assert expire_exceptions(session, at=EXPIRES_AT + timedelta(days=1)) == ()
    assert exception.status is ExceptionStatus.EXPIRED
    assert session.get(Finding, finding_id).status is FindingStatus.ACCEPTED_RISK
    assert session.scalar(select(ControlAssessment.assessment_result)) is AssessmentResult.FAIL
    assert _event_count(session, AuditEventType.EXCEPTION_EXPIRED) == 1


def test_revoke_is_idempotent_and_preserves_technical_history(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    original = _technical_state(session)
    exception = _create_exception(session, finding_id)
    revoked_at = CREATED_AT + timedelta(minutes=5)
    revoke_exception(session, exception_id=exception.exception_id, at=revoked_at, actor_id="owner")
    revoke_exception(
        session,
        exception_id=exception.exception_id,
        at=revoked_at + timedelta(minutes=5),
        actor_id="owner",
    )
    assert exception.status is ExceptionStatus.REVOKED
    assert exception.revoked_at.replace(tzinfo=UTC) == revoked_at
    assert _event_count(session, AuditEventType.EXCEPTION_REVOKED) == 1
    assert expire_exceptions(session, at=EXPIRES_AT) == ()
    assert _technical_state(session) == original


def test_revoking_an_overdue_exception_records_expiry_only(governance_session: Session) -> None:
    session = governance_session
    exception = _create_exception(session, _seed_finding(session))
    revoke_exception(session, exception_id=exception.exception_id, at=EXPIRES_AT, actor_id="owner")
    revoke_exception(session, exception_id=exception.exception_id, at=EXPIRES_AT, actor_id="owner")
    assert exception.status is ExceptionStatus.EXPIRED
    assert exception.revoked_at is None
    assert _event_count(session, AuditEventType.EXCEPTION_EXPIRED) == 1
    assert _event_count(session, AuditEventType.EXCEPTION_REVOKED) == 0


@pytest.mark.parametrize("case", ["missing", "future", "elapsed", "expired", "revoked"])
def test_accepted_risk_requires_an_active_current_exception(
    governance_session: Session, case: str
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    at = CREATED_AT + timedelta(minutes=10)
    if case != "missing":
        exception = _create_exception(session, finding_id)
        if case == "future":
            at = CREATED_AT - timedelta(minutes=1)
        elif case in {"elapsed", "expired"}:
            at = EXPIRES_AT
            if case == "expired":
                expire_exceptions(session, at=at)
        elif case == "revoked":
            revoke_exception(
                session,
                exception_id=exception.exception_id,
                at=CREATED_AT + timedelta(minutes=1),
                actor_id="owner",
            )
    with pytest.raises(GovernanceError, match="active in-scope unexpired exception"):
        set_finding_disposition(
            session,
            finding_id=finding_id,
            status=FindingStatus.ACCEPTED_RISK,
            at=at,
            actor_id="analyst",
        )
    assert session.get(Finding, finding_id).status is FindingStatus.OPEN


def test_another_resource_exception_cannot_authorize_accepted_risk(
    governance_session: Session,
) -> None:
    session = governance_session
    first = _seed_finding(session)
    other = _seed_finding(session, region="us-west-2")
    _create_exception(session, other)
    with pytest.raises(GovernanceError, match="active in-scope"):
        set_finding_disposition(
            session,
            finding_id=first,
            status=FindingStatus.ACCEPTED_RISK,
            at=CREATED_AT,
            actor_id="analyst",
        )


def test_disposition_changes_are_audited_once_and_never_rewrite_fail(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    original = _technical_state(session)
    _create_exception(session, finding_id)
    transitions = (
        (FindingStatus.ACKNOWLEDGED, AuditEventType.FINDING_ACKNOWLEDGED),
        (FindingStatus.FALSE_POSITIVE, AuditEventType.FINDING_FALSE_POSITIVE),
        (FindingStatus.OPEN, AuditEventType.FINDING_UPDATED),
        (FindingStatus.ACCEPTED_RISK, AuditEventType.FINDING_ACCEPTED_RISK),
    )
    for offset, (status, event_type) in enumerate(transitions):
        at = CREATED_AT + timedelta(minutes=offset)
        for _ in range(2):
            finding = set_finding_disposition(
                session,
                finding_id=finding_id,
                status=status,
                at=at,
                actor_id="analyst",
            )
            assert finding.status is status
        assert _event_count(session, event_type) == 1
    assert _technical_state(session) == original


@pytest.mark.parametrize("status", ["RESOLVED", "APPROVED", "REMEDIATION_PROPOSED"])
def test_manual_dispositions_cannot_claim_resolution_or_remediation(
    governance_session: Session, status: str
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    with pytest.raises(GovernanceError):
        set_finding_disposition(
            session,
            finding_id=finding_id,
            status=status,
            at=CREATED_AT,
            actor_id="analyst",
        )
    assert session.get(Finding, finding_id).status is FindingStatus.OPEN


def test_resolved_finding_cannot_be_manually_reopened_or_excepted(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    persist_scan_result(
        session,
        **scan_bundle(public_ssh=False, observed_at=OBSERVED_AT + timedelta(minutes=30)),
    )
    session.commit()
    with pytest.raises(GovernanceError, match="newer FAIL"):
        set_finding_disposition(
            session,
            finding_id=finding_id,
            status=FindingStatus.OPEN,
            at=CREATED_AT,
            actor_id="analyst",
        )
    with pytest.raises(GovernanceError, match="resolved finding"):
        _create_exception(session, finding_id)


def test_backdated_disposition_cannot_overwrite_a_newer_action(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    set_finding_disposition(
        session,
        finding_id=finding_id,
        status=FindingStatus.ACKNOWLEDGED,
        at=CREATED_AT + timedelta(hours=1),
        actor_id="analyst",
    )
    with pytest.raises(GovernanceError, match="must not predate"):
        set_finding_disposition(
            session,
            finding_id=finding_id,
            status=FindingStatus.OPEN,
            at=CREATED_AT,
            actor_id="analyst",
        )


def test_caller_rollback_removes_exception_disposition_and_audit_together(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    with pytest.raises(RuntimeError), session.begin():
        _create_exception(session, finding_id)
        set_finding_disposition(
            session,
            finding_id=finding_id,
            status=FindingStatus.ACCEPTED_RISK,
            at=CREATED_AT,
            actor_id="analyst",
        )
        raise RuntimeError("caller transaction failed")
    assert session.scalar(select(func.count()).select_from(FindingException)) == 0
    assert session.get(Finding, finding_id).status is FindingStatus.OPEN
    assert _event_count(session, AuditEventType.EXCEPTION_CREATED) == 0
    assert _event_count(session, AuditEventType.FINDING_ACCEPTED_RISK) == 0
    assert session.scalar(select(ControlAssessment.assessment_result)) is AssessmentResult.FAIL


def test_governance_rejects_naive_times_blank_actors_and_missing_targets(
    governance_session: Session,
) -> None:
    session = governance_session
    finding_id = _seed_finding(session)
    exception = _create_exception(session, finding_id)
    with pytest.raises(GovernanceError, match="timezone-aware"):
        expire_exceptions(session, at=EXPIRES_AT.replace(tzinfo=None))
    with pytest.raises(GovernanceError, match="actor_id"):
        expire_exceptions(session, at=EXPIRES_AT, actor_id=" ")
    with pytest.raises(GovernanceError, match="timezone-aware"):
        revoke_exception(
            session,
            exception_id=exception.exception_id,
            at=CREATED_AT.replace(tzinfo=None),
            actor_id="owner",
        )
    with pytest.raises(GovernanceError, match="predate exception creation"):
        revoke_exception(
            session,
            exception_id=exception.exception_id,
            at=CREATED_AT - timedelta(seconds=1),
            actor_id="owner",
        )
    with pytest.raises(GovernanceError, match="timezone-aware"):
        set_finding_disposition(
            session,
            finding_id=finding_id,
            status=FindingStatus.OPEN,
            at=CREATED_AT.replace(tzinfo=None),
            actor_id="owner",
        )
    with pytest.raises(GovernanceError, match="does not exist"):
        _create_exception(session, uuid4())
    with pytest.raises(GovernanceError, match="does not exist"):
        revoke_exception(session, exception_id=uuid4(), at=CREATED_AT, actor_id="owner")
