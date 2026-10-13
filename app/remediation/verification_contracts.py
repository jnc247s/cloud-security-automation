"""Closed, versioned read-only verification contracts; never execution authority."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.assessment.models import AssessmentResult
from app.models.enums import ScanStatus
from app.remediation.contracts import (
    ActorContext,
    AssessmentEvidenceBinding,
    Contract,
    ReasonedContract,
    Sha256,
    SourceBinding,
)
from app.remediation.execution_contracts import AdmissionScope

VERIFICATION_VERSION = "1.0.0"
MAX_VERIFICATION_ATTEMPTS = 3


class VerificationScope(AdmissionScope):
    """Independent default-off configuration, never a scanner or writer fallback."""


class VerificationRequest(ReasonedContract):
    pass


class VerificationOutcome(StrEnum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationReason(StrEnum):
    POSTCONDITION_PASS = "POSTCONDITION_PASS"
    POSTCONDITION_FAIL = "POSTCONDITION_FAIL"
    SCAN_INCOMPLETE = "SCAN_INCOMPLETE"
    PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"
    OBSERVATION_NOT_LATER = "OBSERVATION_NOT_LATER"
    KMS_CONTEXT_CHANGED = "KMS_CONTEXT_CHANGED"


class VerificationContent(ReasonedContract):
    schema_version: Literal["1.0.0"] = VERIFICATION_VERSION
    verification_id: UUID
    execution_id: UUID
    execution_sha256: Sha256
    acknowledgment_event_id: UUID
    acknowledgment_sha256: Sha256
    acknowledged_at: datetime
    baseline_scan_id: UUID
    scan_id: UUID
    attempt: int = Field(ge=1, le=MAX_VERIFICATION_ATTEMPTS)
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(min_length=1, max_length=64)
    requested_services: tuple[str, ...]
    requested_collectors: tuple[str, ...]
    resource_types: tuple[str, ...]
    profile_id: str
    profile_version: str
    profile_sha256: Sha256
    catalog_id: str
    catalog_version: str
    catalog_sha256: Sha256
    requested_by: ActorContext
    idempotency_key: UUID
    created_at: datetime


class VerificationEvidence(Contract):
    resource_id: UUID
    snapshot_id: UUID
    state_sha256: Sha256
    assessment_id: UUID
    control_version_id: UUID
    control_definition_sha256: Sha256
    observed_at: datetime
    technical_result: Literal[AssessmentResult.PASS, AssessmentResult.FAIL]
    assessment_evidence: tuple[AssessmentEvidenceBinding, ...]
    encryption_source: SourceBinding
    kms_source: SourceBinding


class VerificationReceipt(Contract):
    schema_version: Literal["1.0.0"] = VERIFICATION_VERSION
    verification_id: UUID
    verification_sha256: Sha256
    scan_id: UUID
    scan_status: Literal[ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED]
    result_sha256: Sha256
    inventory_sha256: Sha256 | None
    outcome: VerificationOutcome
    reason: VerificationReason
    evidence: VerificationEvidence | None
    created_at: datetime


class VerificationView(Contract):
    content: VerificationContent
    verification_sha256: Sha256
    request_audit_event_id: UUID
    receipt: VerificationReceipt | None
    receipt_sha256: Sha256 | None
    receipt_audit_event_id: UUID | None
