"""Persistence lifecycle enumerations kept separate from technical assessment results."""

from enum import StrEnum


class ScanStatus(StrEnum):
    """Durable completeness state for one scan."""

    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class FindingStatus(StrEnum):
    """Canonical finding lifecycle; remediation states do not belong here."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class ExceptionStatus(StrEnum):
    """Operational state for an approved security exception."""

    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AuditEventType(StrEnum):
    """Auditable state changes currently emitted by the persistence boundary."""

    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    FINDING_OPENED = "FINDING_OPENED"
    FINDING_UPDATED = "FINDING_UPDATED"
    FINDING_REOPENED = "FINDING_REOPENED"
    FINDING_ACKNOWLEDGED = "FINDING_ACKNOWLEDGED"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    FINDING_FALSE_POSITIVE = "FINDING_FALSE_POSITIVE"
    FINDING_ACCEPTED_RISK = "FINDING_ACCEPTED_RISK"
    EXCEPTION_CREATED = "EXCEPTION_CREATED"
    EXCEPTION_EXPIRED = "EXCEPTION_EXPIRED"
    EXCEPTION_REVOKED = "EXCEPTION_REVOKED"


ACTIVE_FINDING_STATUSES = frozenset(
    {
        FindingStatus.OPEN,
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.ACCEPTED_RISK,
    }
)
