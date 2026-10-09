"""Versioned service journal contracts, separate from immutable human admission events."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictStr, model_validator

from app.remediation.contracts import BlockingReason, Contract, Sha256
from app.remediation.execution_phases import ExecutionBlockingReason, ExecutionPhase

ROLE_ARN_PATTERN = (
    r"^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:role/"
    r"(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}$"
)


class WorkerEventKind(StrEnum):
    CLAIMED = "CLAIMED"
    WRITE_INTENT = "WRITE_INTENT"
    NO_WRITE = "NO_WRITE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    QUARANTINED = "QUARANTINED"
    OBSERVED = "OBSERVED"
    OBSERVATION_FAILED = "OBSERVATION_FAILED"


class WorkerBlockingReason(StrEnum):
    PRECONDITION_CHANGED = "PRECONDITION_CHANGED"
    READ_UNAVAILABLE = "READ_UNAVAILABLE"
    WRITER_SCOPE_MISMATCH = "WRITER_SCOPE_MISMATCH"
    READ_BUDGET_EXHAUSTED = "READ_BUDGET_EXHAUSTED"
    WRITE_UNCERTAIN = "WRITE_UNCERTAIN"
    LATE_DISPATCH = "LATE_DISPATCH"
    RECOVERY_UNCERTAIN = "RECOVERY_UNCERTAIN"


class WorkerActor(Contract):
    service_id: Literal["remediation-worker"] = "remediation-worker"
    expected_role_arn: str = Field(max_length=2048, pattern=ROLE_ARN_PATTERN)


class RegionalObservation(Contract):
    encryption_by_default: StrictBool
    default_kms_key_id: StrictStr | None
    default_kms_key_expected_absence: StrictBool

    @model_validator(mode="after")
    def complete_key_context(self):
        if self.default_kms_key_expected_absence is not (self.default_kms_key_id is None):
            raise ValueError("default key absence must match the complete observed response")
        if self.default_kms_key_id is not None and not self.default_kms_key_id.strip():
            raise ValueError("a present default key must be nonblank")
        return self


class WriteAcknowledgment(Contract):
    request_id: str = Field(pattern=r"^[A-Za-z0-9-]{1,128}$")


class WorkerEventContent(Contract):
    schema_version: Literal["2.0.0"] = "2.0.0"
    event_id: UUID
    execution_id: UUID
    execution_sha256: Sha256
    sequence: int = Field(ge=2)
    kind: WorkerEventKind
    phase: ExecutionPhase
    previous_event_sha256: Sha256
    actor: WorkerActor
    created_at: datetime
    blocking_reasons: tuple[
        BlockingReason | ExecutionBlockingReason | WorkerBlockingReason, ...
    ] = ()
    observation: RegionalObservation | None = None
    observed_at: datetime | None = None
    request_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,128}$")
    polls: int = Field(default=0, ge=0, le=3)


def worker_phase(kind: WorkerEventKind, previous: ExecutionPhase) -> ExecutionPhase:
    """Closed state machine; quarantine is sticky even after a late acknowledgment."""
    allowed = {
        WorkerEventKind.CLAIMED: {ExecutionPhase.QUEUED, ExecutionPhase.CLAIMED},
        WorkerEventKind.WRITE_INTENT: {ExecutionPhase.CLAIMED},
        WorkerEventKind.NO_WRITE: {ExecutionPhase.QUEUED, ExecutionPhase.CLAIMED},
        WorkerEventKind.ACKNOWLEDGED: {ExecutionPhase.WRITE_INTENT, ExecutionPhase.QUARANTINED},
        WorkerEventKind.QUARANTINED: {ExecutionPhase.WRITE_INTENT, ExecutionPhase.QUARANTINED},
        WorkerEventKind.OBSERVED: {ExecutionPhase.ACKNOWLEDGED, ExecutionPhase.QUARANTINED},
        WorkerEventKind.OBSERVATION_FAILED: {
            ExecutionPhase.ACKNOWLEDGED,
            ExecutionPhase.QUARANTINED,
        },
    }
    if previous not in allowed[kind]:
        raise ValueError("invalid worker transition")
    if kind in {WorkerEventKind.OBSERVED, WorkerEventKind.OBSERVATION_FAILED}:
        return previous
    if kind is WorkerEventKind.ACKNOWLEDGED and previous is ExecutionPhase.QUARANTINED:
        return previous
    return ExecutionPhase(kind.value)


def validate_worker_entry(entry: WorkerEventContent, previous: ExecutionPhase, content) -> None:
    """Validate structured history without credentials, network or changing technical results."""
    if entry.phase is not worker_phase(entry.kind, previous):
        raise ValueError("worker phase mismatch")
    if entry.actor.expected_role_arn.split(":")[4] != content.proposal.account_id:
        raise ValueError("worker actor scope mismatch")
    observation = entry.observation
    if (observation is None) != (entry.observed_at is None):
        raise ValueError("observation time mismatch")
    if entry.observed_at is not None and (
        entry.observed_at.tzinfo is None
        or entry.observed_at.utcoffset() is None
        or entry.observed_at > entry.created_at
    ):
        raise ValueError("invalid observation time")
    if entry.kind in {WorkerEventKind.CLAIMED, WorkerEventKind.WRITE_INTENT}:
        if entry.created_at >= content.expires_at or entry.blocking_reasons:
            raise ValueError("invalid pre-intent authority time")
    if entry.kind is WorkerEventKind.WRITE_INTENT:
        baseline = content.proposal.baseline
        if (
            observation is None
            or observation.encryption_by_default is not False
            or observation.default_kms_key_id != baseline.default_kms_key_id
            or observation.default_kms_key_expected_absence
            != baseline.default_kms_key_expected_absence
        ):
            raise ValueError("intent precondition mismatch")
    elif entry.kind is WorkerEventKind.OBSERVED:
        if observation is None or entry.blocking_reasons:
            raise ValueError("invalid readback observation")
    elif entry.kind is not WorkerEventKind.NO_WRITE and observation is not None:
        raise ValueError("unexpected observation")
    if (entry.request_id is not None) != (entry.kind is WorkerEventKind.ACKNOWLEDGED):
        raise ValueError("acknowledgment receipt mismatch")
    if entry.kind in {
        WorkerEventKind.NO_WRITE,
        WorkerEventKind.QUARANTINED,
        WorkerEventKind.OBSERVATION_FAILED,
    }:
        if not entry.blocking_reasons:
            raise ValueError("missing outcome classification")
    elif entry.blocking_reasons:
        raise ValueError("unexpected blockers")
    if entry.kind in {WorkerEventKind.OBSERVED, WorkerEventKind.OBSERVATION_FAILED}:
        if not 1 <= entry.polls <= 3:
            raise ValueError("invalid readback budget")
    elif entry.polls:
        raise ValueError("unexpected readback budget")
