"""Execution-only lifecycle and grant blockers; never finding or assessment status."""

from enum import StrEnum


class ExecutionPhase(StrEnum):
    QUEUED = "QUEUED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"
    CLAIMED = "CLAIMED"
    WRITE_INTENT = "WRITE_INTENT"
    NO_WRITE = "NO_WRITE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    QUARANTINED = "QUARANTINED"


class ExecutionBlockingReason(StrEnum):
    EXECUTION_EXPIRED = "EXECUTION_EXPIRED"
    APPROVAL_REVOKED = "APPROVAL_REVOKED"
