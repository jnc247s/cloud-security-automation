"""Frozen browser coordination, never an authorization grant or domain ledger."""

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, TypeAdapter, ValidationError

from app.remediation.contracts import (
    ACTION_ID,
    ACTION_VERSION,
    Contract,
    DecisionRequest,
    ProposalRequest,
    ReasonedContract,
    RevocationRequest,
)
from app.remediation.execution_contracts import ExecutionRequest
from app.remediation.verification_contracts import VerificationRequest
from app.security.authorization import Capability

MAX_PREPARATION_BYTES = 12 * 1024


class InvalidPreparation(ValueError):
    """Closed, safe failure: do not expose parser input or validation errors."""


class OperationUnavailable(Exception):
    """No operation exists in the caller's current session/identity context."""


class OperationExpired(Exception):
    """Preparation cannot be renewed; this says nothing about prior effects."""


class OperationKind(StrEnum):
    PROPOSE = "PROPOSE"
    DECIDE = "DECIDE"
    REVOKE = "REVOKE"
    REQUEST_EXECUTION = "REQUEST_EXECUTION"
    REQUEST_VERIFICATION = "REQUEST_VERIFICATION"


class OperationState(StrEnum):
    PREPARED = "PREPARED"
    IN_FLIGHT = "IN_FLIGHT"
    UNCONFIRMED = "UNCONFIRMED"
    CONFIRMED = "CONFIRMED"
    EXPIRED = "EXPIRED"


class ProposalSelection(ReasonedContract):
    finding_id: UUID
    occurrence_id: UUID


class PrepareProposal(Contract):
    schema_version: Literal["1.0.0"]
    operation: Literal["PROPOSE"]
    input: ProposalSelection


class PrepareDecision(Contract):
    schema_version: Literal["1.0.0"]
    operation: Literal["DECIDE"]
    target_id: UUID
    input: DecisionRequest


class PrepareRevocation(Contract):
    schema_version: Literal["1.0.0"]
    operation: Literal["REVOKE"]
    target_id: UUID
    input: RevocationRequest


class PrepareExecution(Contract):
    schema_version: Literal["1.0.0"]
    operation: Literal["REQUEST_EXECUTION"]
    target_id: UUID
    input: ExecutionRequest


class PrepareVerification(Contract):
    schema_version: Literal["1.0.0"]
    operation: Literal["REQUEST_VERIFICATION"]
    target_id: UUID
    input: VerificationRequest


Preparation = Annotated[
    PrepareProposal | PrepareDecision | PrepareRevocation | PrepareExecution | PrepareVerification,
    Field(discriminator="operation"),
]
_PREPARATION = TypeAdapter(Preparation)


@dataclass(frozen=True)
class OperationInput:
    kind: OperationKind
    target_id: UUID | None
    body_json: str = field(repr=False)

    @property
    def capability(self) -> Capability:
        return {
            OperationKind.PROPOSE: Capability.PROPOSE,
            OperationKind.DECIDE: Capability.APPROVE,
            OperationKind.REVOKE: Capability.APPROVE,
            OperationKind.REQUEST_EXECUTION: Capability.EXECUTE,
            OperationKind.REQUEST_VERIFICATION: Capability.EXECUTE,
        }[self.kind]

    @property
    def path(self) -> str:
        if self.kind == OperationKind.PROPOSE:
            return "/api/v1/remediations"
        if self.kind == OperationKind.REQUEST_VERIFICATION:
            return f"/api/v1/remediation-executions/{self.target_id}/verifications"
        suffix = {
            OperationKind.DECIDE: "decisions",
            OperationKind.REVOKE: "revocations",
            OperationKind.REQUEST_EXECUTION: "executions",
        }[self.kind]
        return f"/api/v1/remediations/{self.target_id}/{suffix}"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidPreparation
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise InvalidPreparation


def validate_json_document(raw: bytes) -> None:
    """Reject duplicate keys, non-finite numbers and non-UTF-8/invalid Unicode JSON."""
    decoded = raw.decode("utf-8", errors="strict")
    document = json.loads(
        decoded, object_pairs_hook=_unique_object, parse_constant=_reject_constant
    )
    json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")


def parse_preparation(raw: bytes) -> OperationInput:
    """Strict JSON scalars, closed keys, no duplicate keys, bounded Unicode input."""
    if len(raw) > MAX_PREPARATION_BYTES:
        raise InvalidPreparation
    try:
        validate_json_document(raw)
        request = _PREPARATION.validate_json(raw, strict=True)
        if isinstance(request, PrepareProposal):
            body = ProposalRequest(
                **request.input.model_dump(), action_id=ACTION_ID, action_version=ACTION_VERSION
            )
            target_id = None
        else:
            body = request.input
            target_id = request.target_id
        return OperationInput(OperationKind(request.operation), target_id, body.model_dump_json())
    except (ValueError, UnicodeError, ValidationError, RecursionError):
        raise InvalidPreparation("Invalid remediation preparation") from None


@dataclass(frozen=True)
class ResultReference:
    result_id: UUID
    scan_id: UUID | None = None


@dataclass(frozen=True)
class PreparedOperation:
    operation_id: UUID
    session_id: str = field(repr=False)
    actor: tuple[str, str] = field(repr=False)
    input: OperationInput = field(repr=False)
    prepared_at: float
    expires_at: float
    state: OperationState = OperationState.PREPARED
    attempts: int = 0
    result: ResultReference | None = None
