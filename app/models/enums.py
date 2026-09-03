"""Database-backed lifecycle enumerations."""

from enum import StrEnum


class ScanStatus(StrEnum):
    """Supported states for a persisted scan."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingStatus(StrEnum):
    """Supported states for a persisted security finding."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    APPROVED = "APPROVED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


RESOLVABLE_FINDING_STATUSES = frozenset(
    {
        FindingStatus.OPEN,
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.REMEDIATION_PROPOSED,
        FindingStatus.APPROVED,
    }
)
