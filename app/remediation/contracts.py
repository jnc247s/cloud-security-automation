"""Closed proposal-only contracts. No credential source or execution handler."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from app.security.authorization import Capability

ACTION_ID = "aws.ec2.enable-ebs-encryption-by-default"
ACTION_VERSION = "1.0.0"
ACTION_RISK = (
    "Enables encryption for future EBS volumes and snapshot copies in this account/Region. "
    "Existing volumes are unchanged. Review workload and KMS compatibility; "
    "this action does not change the default KMS key or support automatic rollback."
)
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Reason = Annotated[str, Field(min_length=1, max_length=2000)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReasonedContract(Contract):
    reason: Reason

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason must not be blank")
        return value


class DecisionKind(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REVOKE = "REVOKE"


class ApprovalStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"


class BlockingReason(StrEnum):
    EXPIRED = "EXPIRED"
    STALE_TARGET = "STALE_TARGET"
    STALE_GOVERNANCE = "STALE_GOVERNANCE"
    INELIGIBLE_FINDING = "INELIGIBLE_FINDING"
    ACTIVE_EXCEPTION = "ACTIVE_EXCEPTION"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"


class ActorContext(Contract):
    issuer: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    roles: tuple[str, ...]
    capability: Capability


class ProposalRequest(ReasonedContract):
    finding_id: UUID
    occurrence_id: UUID
    action_id: Literal["aws.ec2.enable-ebs-encryption-by-default"]
    action_version: Literal["1.0.0"]


class DecisionRequest(ReasonedContract):
    proposal_sha256: Sha256
    decision: Literal[DecisionKind.APPROVE, DecisionKind.REJECT]


class RevocationRequest(ReasonedContract):
    proposal_sha256: Sha256
    approval_decision_id: UUID


class SourceBinding(Contract):
    source_outcome_id: UUID
    artifact_id: UUID
    evidence_reference: str
    evidence_sha256: Sha256


class AssessmentEvidenceBinding(Contract):
    evidence_id: UUID
    payload_sha256: Sha256


class Baseline(Contract):
    occurrence_id: UUID
    assessment_id: UUID
    scan_id: UUID
    snapshot_id: UUID
    state_sha256: Sha256
    observed_at: datetime
    profile_id: str
    profile_version: str
    profile_sha256: Sha256
    catalog_id: str
    catalog_version: str
    catalog_sha256: Sha256
    control_version_id: UUID
    control_definition_sha256: Sha256
    inventory_sha256: Sha256
    assessment_evidence: tuple[AssessmentEvidenceBinding, ...]
    encryption_source: SourceBinding
    kms_source: SourceBinding
    default_kms_key_id: str | None
    default_kms_key_expected_absence: StrictBool


class ProposalContent(ReasonedContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    proposal_id: UUID
    finding_id: UUID
    resource_id: UUID
    control_id: UUID
    control_key: Literal["EC2-004"] = "EC2-004"
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(min_length=1, max_length=64)
    action_id: Literal["aws.ec2.enable-ebs-encryption-by-default"] = ACTION_ID
    action_version: Literal["1.0.0"] = ACTION_VERSION
    risk_summary: Literal[ACTION_RISK] = ACTION_RISK
    expected_encryption_by_default: StrictBool = False
    desired_encryption_by_default: StrictBool = True
    baseline: Baseline
    governance_sha256: Sha256
    proposer: ActorContext
    created_at: datetime
    expires_at: datetime


class DecisionView(ReasonedContract):
    decision_id: UUID
    proposal_id: UUID
    kind: DecisionKind
    proposal_sha256: Sha256
    approval_decision_id: UUID | None
    actor: ActorContext
    created_at: datetime


class ProposalView(Contract):
    content: ProposalContent
    proposal_sha256: Sha256
    approval_status: ApprovalStatus
    blocking_reasons: tuple[BlockingReason, ...]
    validity_checked_at: datetime
    decisions: tuple[DecisionView, ...]
