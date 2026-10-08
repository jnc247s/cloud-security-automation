"""Immutable human admission and versioned execution READ views; no AWS dependency."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool, model_validator

from app.remediation.contracts import (
    ActorContext,
    BlockingReason,
    Contract,
    DecisionView,
    ProposalContent,
    ReasonedContract,
    Sha256,
)
from app.remediation.execution_phases import ExecutionBlockingReason, ExecutionPhase
from app.remediation.worker_contracts import WorkerBlockingReason, WorkerEventContent

REGION_PATTERN = r"^[a-z]{2,8}(?:-[a-z0-9]+){1,6}-[0-9]+$"
ADMISSION_CAPACITY = 32


class AdmissionScope(Contract):
    enabled: StrictBool = False
    account_id: str | None = Field(default=None, pattern=r"^[0-9]{12}$")
    region: str | None = Field(default=None, max_length=64, pattern=REGION_PATTERN)

    @model_validator(mode="after")
    def require_explicit_scope(self):
        if self.enabled and (self.account_id is None or self.region is None):
            raise ValueError("enabled execution admission requires explicit account and Region")
        return self


class ExecutionRequest(ReasonedContract):
    proposal_sha256: Sha256
    approval_decision_id: UUID


class ExecutionEventKind(StrEnum):
    REQUESTED = "REQUESTED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


class ExecutionContent(ReasonedContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    execution_id: UUID
    proposal: ProposalContent
    proposal_sha256: Sha256
    approval: DecisionView
    approval_sha256: Sha256
    requested_by: ActorContext
    idempotency_key: UUID
    created_at: datetime
    expires_at: datetime


class ExecutionEventContent(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID
    execution_id: UUID
    execution_sha256: Sha256
    sequence: int = Field(ge=1, le=2)
    kind: ExecutionEventKind
    phase: Literal[ExecutionPhase.QUEUED, ExecutionPhase.EXPIRED, ExecutionPhase.BLOCKED]
    previous_event_sha256: Sha256 | None
    actor: ActorContext
    created_at: datetime
    blocking_reasons: tuple[BlockingReason | ExecutionBlockingReason, ...] = ()


class ExecutionEventView(Contract):
    content: Annotated[
        ExecutionEventContent | WorkerEventContent, Field(discriminator="schema_version")
    ]
    event_sha256: Sha256
    audit_event_id: UUID


class ExecutionView(Contract):
    content: ExecutionContent
    execution_sha256: Sha256
    phase: ExecutionPhase
    blocking_reasons: tuple[BlockingReason | ExecutionBlockingReason | WorkerBlockingReason, ...]
    validity_checked_at: datetime
    reservation_held: StrictBool
    events: tuple[ExecutionEventView, ...]
