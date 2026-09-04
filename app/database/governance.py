"""Transactional exception and finding-disposition operations without technical reevaluation.

Callers own the SQLAlchemy transaction. These functions never commit, alter an
assessment result, or rewrite evidence; each state change appends an audit event.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.persistence import append_audit_event
from app.models import AuditEvent, Finding, FindingException, Resource
from app.models.enums import AuditEventType, ExceptionStatus, FindingStatus

_DISPOSITION_EVENTS = {
    FindingStatus.OPEN: AuditEventType.FINDING_UPDATED,
    FindingStatus.ACKNOWLEDGED: AuditEventType.FINDING_ACKNOWLEDGED,
    FindingStatus.FALSE_POSITIVE: AuditEventType.FINDING_FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK: AuditEventType.FINDING_ACCEPTED_RISK,
}


class GovernanceError(ValueError):
    """A governance request is invalid for the current finding or exception state."""


def _require_aware(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GovernanceError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _utc(value: datetime) -> datetime:
    """Normalize SQLite's naive UTC database values without accepting naive inputs."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _text(value: str, field: str, *, maximum: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{field} must not be blank")
    normalized = value.strip()
    if maximum is not None and len(normalized) > maximum:
        raise GovernanceError(f"{field} must not exceed {maximum} characters")
    return normalized


def _lock_finding(session: Session, finding_id: UUID) -> Finding:
    """Lock resource before finding, matching scan persistence's scope lock order."""

    resource_id = session.scalar(
        select(Finding.resource_id).where(Finding.finding_id == finding_id)
    )
    if resource_id is None:
        raise GovernanceError(f"finding {finding_id} does not exist")
    resource = session.scalar(
        select(Resource).where(Resource.resource_id == resource_id).with_for_update()
    )
    if resource is None:
        raise GovernanceError("finding resource scope does not exist")
    finding = session.scalar(
        select(Finding)
        .where(Finding.finding_id == finding_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if finding is None or finding.resource_id != resource_id:
        raise GovernanceError("finding scope changed while acquiring its lock")
    return finding


def _lock_exception(session: Session, exception_id: UUID) -> FindingException:
    finding_id = session.scalar(
        select(FindingException.finding_id).where(FindingException.exception_id == exception_id)
    )
    if finding_id is None:
        raise GovernanceError(f"exception {exception_id} does not exist")
    finding = _lock_finding(session, finding_id)
    exception = session.scalar(
        select(FindingException)
        .where(FindingException.exception_id == exception_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if exception is None or (
        exception.finding_id != finding.finding_id
        or exception.resource_id != finding.resource_id
        or exception.control_id != finding.control_id
    ):
        raise GovernanceError("exception scope does not match its finding")
    return exception


def _exception_metadata(exception: FindingException) -> dict[str, str]:
    return {
        "finding_id": str(exception.finding_id),
        "resource_id": str(exception.resource_id),
        "control_id": str(exception.control_id),
        "status": exception.status.value,
        "expires_at": _utc(exception.expires_at).isoformat(),
    }


def create_finding_exception(
    session: Session,
    *,
    finding_id: UUID,
    reason: str,
    approved_by: str,
    created_at: datetime,
    expires_at: datetime,
) -> FindingException:
    """Create an approved, time-bounded exception without changing the finding disposition."""

    created_at = _require_aware(created_at, "created_at")
    expires_at = _require_aware(expires_at, "expires_at")
    reason = _text(reason, "reason")
    approved_by = _text(approved_by, "approved_by", maximum=256)
    if expires_at <= created_at:
        raise GovernanceError("expires_at must be after created_at")
    finding = _lock_finding(session, finding_id)
    if finding.status is FindingStatus.RESOLVED:
        raise GovernanceError("a resolved finding does not require an exception")
    if created_at < _utc(finding.last_detected_at):
        raise GovernanceError("created_at must not predate the latest finding observation")

    exception = FindingException(
        exception_id=uuid4(),
        finding_id=finding.finding_id,
        resource_id=finding.resource_id,
        control_id=finding.control_id,
        reason=reason,
        approved_by=approved_by,
        created_at=created_at,
        expires_at=expires_at,
        status=ExceptionStatus.ACTIVE,
    )
    session.add(exception)
    append_audit_event(
        session,
        AuditEventType.EXCEPTION_CREATED,
        "exception",
        exception.exception_id,
        created_at,
        actor_type="user",
        actor_id=approved_by,
        metadata={**_exception_metadata(exception), "reason": reason},
    )
    session.flush()
    return exception


def _expire_exception(
    session: Session,
    exception: FindingException,
    *,
    at: datetime,
    actor_id: str,
    actor_type: str,
) -> None:
    exception.status = ExceptionStatus.EXPIRED
    append_audit_event(
        session,
        AuditEventType.EXCEPTION_EXPIRED,
        "exception",
        exception.exception_id,
        at,
        actor_type=actor_type,
        actor_id=actor_id,
        metadata=_exception_metadata(exception),
    )


def expire_exceptions(
    session: Session,
    *,
    at: datetime,
    actor_id: str = "system",
) -> tuple[FindingException, ...]:
    """Expire due active exceptions once; finding disposition remains an explicit decision."""

    at = _require_aware(at, "at")
    actor_id = _text(actor_id, "actor_id", maximum=256)
    exception_ids = session.scalars(
        select(FindingException.exception_id)
        .where(
            FindingException.status == ExceptionStatus.ACTIVE,
            FindingException.expires_at <= at,
        )
        .order_by(
            FindingException.resource_id,
            FindingException.finding_id,
            FindingException.exception_id,
        )
    ).all()
    expired: list[FindingException] = []
    for exception_id in exception_ids:
        exception = _lock_exception(session, exception_id)
        if exception.status is not ExceptionStatus.ACTIVE or _utc(exception.expires_at) > at:
            continue
        _expire_exception(session, exception, at=at, actor_id=actor_id, actor_type="system")
        expired.append(exception)
        # Keep later populate_existing reads from discarding this unit of work.
        session.flush()
    return tuple(expired)


def revoke_exception(
    session: Session,
    *,
    exception_id: UUID,
    at: datetime,
    actor_id: str,
) -> FindingException:
    """Revoke an active exception once; already expired or revoked rows are unchanged."""

    at = _require_aware(at, "at")
    actor_id = _text(actor_id, "actor_id", maximum=256)
    exception = _lock_exception(session, exception_id)
    if at < _utc(exception.created_at):
        raise GovernanceError("at must not predate exception creation")
    if exception.status is not ExceptionStatus.ACTIVE:
        return exception
    if at >= _utc(exception.expires_at):
        _expire_exception(session, exception, at=at, actor_id=actor_id, actor_type="user")
    else:
        exception.status = ExceptionStatus.REVOKED
        exception.revoked_at = at
        append_audit_event(
            session,
            AuditEventType.EXCEPTION_REVOKED,
            "exception",
            exception.exception_id,
            at,
            actor_type="user",
            actor_id=actor_id,
            metadata=_exception_metadata(exception),
        )
    session.flush()
    return exception


def set_finding_disposition(
    session: Session,
    *,
    finding_id: UUID,
    status: FindingStatus,
    at: datetime,
    actor_id: str,
) -> Finding:
    """Set an operational disposition; only technical verification may resolve a finding."""

    at = _require_aware(at, "at")
    actor_id = _text(actor_id, "actor_id", maximum=256)
    try:
        status = FindingStatus(status)
    except (TypeError, ValueError) as error:
        raise GovernanceError("unsupported finding disposition") from error
    if status not in _DISPOSITION_EVENTS:
        raise GovernanceError("technical RESOLVED is not a manual finding disposition")
    finding = _lock_finding(session, finding_id)
    if finding.status is FindingStatus.RESOLVED:
        raise GovernanceError("a resolved finding can reopen only after a newer FAIL assessment")
    latest_action = session.scalar(
        select(func.max(AuditEvent.timestamp)).where(
            AuditEvent.target_type == "finding",
            AuditEvent.target_id == finding.finding_id,
        )
    )
    latest_at = _utc(finding.last_detected_at)
    if latest_action is not None:
        latest_at = max(latest_at, _utc(latest_action))
    if at < latest_at:
        raise GovernanceError("at must not predate the latest finding observation or action")
    if status is FindingStatus.ACCEPTED_RISK:
        exception = session.scalar(
            select(FindingException)
            .where(
                FindingException.finding_id == finding.finding_id,
                FindingException.resource_id == finding.resource_id,
                FindingException.control_id == finding.control_id,
                FindingException.status == ExceptionStatus.ACTIVE,
                FindingException.created_at <= at,
                FindingException.expires_at > at,
            )
            .order_by(FindingException.exception_id)
            .limit(1)
            .with_for_update()
        )
        if exception is None:
            raise GovernanceError("ACCEPTED_RISK requires an active in-scope unexpired exception")
    if finding.status is status:
        return finding
    previous_status = finding.status
    finding.status = status
    append_audit_event(
        session,
        _DISPOSITION_EVENTS[status],
        "finding",
        finding.finding_id,
        at,
        actor_type="user",
        actor_id=actor_id,
        metadata={"previous_status": previous_status.value, "status": status.value},
    )
    session.flush()
    return finding
