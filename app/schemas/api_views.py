"""Stable, machine-readable representations returned by the read API."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.assessment.controls import AssessmentType
from app.assessment.frameworks import FrameworkReferenceLevel
from app.assessment.models import AssessmentResult
from app.models.enums import AuditEventType, ExceptionStatus, FindingStatus
from app.schemas.finding import ControlCategory, Severity
from app.schemas.resource import ResourceScope


class ApiView(BaseModel):
    """Shared validation behavior for immutable API projections."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Page[ViewT](ApiView):
    """Offset page with a total count for deterministic client traversal."""

    items: tuple[ViewT, ...]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class ResourceSnapshotView(ApiView):
    snapshot_id: UUID
    resource_id: UUID
    scan_id: UUID
    scope: ResourceScope
    region: str | None
    arn: str | None
    name: str | None
    tags: dict[str, Any]
    normalized_configuration: dict[str, Any]
    state_sha256: str
    observed_at: datetime


class ResourceView(ApiView):
    resource_id: UUID
    provider: str
    aws_account_id: str
    aws_resource_id: str
    arn: str | None
    service: str
    resource_type: str
    scope: ResourceScope
    region: str
    latest_snapshot: ResourceSnapshotView | None = None


class EvidenceArtifactView(ApiView):
    evidence_id: UUID
    assessment_id: UUID
    scan_id: UUID
    resource_snapshot_id: UUID
    control_version_id: UUID
    control_id: UUID
    collector: str
    source: str
    source_api: str
    collected_at: datetime
    schema_name: str
    schema_version: str
    evidence_key: str
    payload: dict[str, Any]
    payload_sha256: str


class FrameworkMappingView(ApiView):
    mapping_id: UUID
    control_version_id: UUID
    framework_id: UUID
    framework_key: str
    framework_version: str
    framework_reference_id: UUID
    reference_key: str
    reference_level: FrameworkReferenceLevel
    reference_title: str
    mapping_rationale: str
    mapping_source: str
    mapping_source_version: str
    verified_at: datetime
    mapping_checksum: str


class AssessmentView(ApiView):
    assessment_id: UUID
    scan_id: UUID
    resource_snapshot_id: UUID
    resource_id: UUID
    control_version_id: UUID
    control_id: UUID
    assessment_profile_version_id: UUID
    assessment_result: AssessmentResult
    reason: str
    missing_evidence: tuple[Any, ...]
    evaluated_at: datetime
    evidence_count: int


class AssessmentDetailView(AssessmentView):
    evidence: tuple[EvidenceArtifactView, ...]
    framework_mappings: tuple[FrameworkMappingView, ...]
    finding_id: UUID | None
    finding_occurrence_id: UUID | None


class FindingOccurrenceView(ApiView):
    occurrence_id: UUID
    finding_id: UUID
    assessment_id: UUID
    scan_id: UUID
    resource_snapshot_id: UUID
    resource_id: UUID
    control_version_id: UUID
    control_id: UUID
    assessment_result: AssessmentResult
    detected_at: datetime


class FindingExceptionView(ApiView):
    exception_id: UUID
    finding_id: UUID
    resource_id: UUID
    control_id: UUID
    reason: str
    approved_by: str
    created_at: datetime
    expires_at: datetime
    status: ExceptionStatus
    revoked_at: datetime | None


class FindingView(ApiView):
    finding_id: UUID
    fingerprint: str
    aws_account_id: str
    resource_id: UUID
    control_id: UUID
    region: str | None
    status: FindingStatus
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None
    occurrence_count: int
    active_exception_ids: tuple[UUID, ...]


class FindingDetailView(FindingView):
    occurrences: tuple[FindingOccurrenceView, ...]
    exceptions: tuple[FindingExceptionView, ...]


class ControlVersionView(ApiView):
    control_version_id: UUID
    catalog_id: UUID
    catalog_key: str
    catalog_version: str
    title: str
    category: ControlCategory
    resource_type: str
    assessment_type: AssessmentType
    measure: str
    required_evidence: tuple[Any, ...]
    pass_logic: str
    fail_logic: str
    insufficient_evidence_behavior: str
    not_applicable_logic: str
    severity: Severity
    impact: str
    remediation_guidance: str
    profile_parameters: tuple[Any, ...]
    limitations: tuple[Any, ...]
    definition_checksum: str
    created_at: datetime
    framework_mappings: tuple[FrameworkMappingView, ...]


class ControlView(ApiView):
    control_id: UUID
    control_key: str
    created_at: datetime
    versions: tuple[ControlVersionView, ...]


class FrameworkControlMappingView(ApiView):
    mapping_id: UUID
    control_id: UUID
    control_key: str
    control_version_id: UUID
    mapping_rationale: str
    mapping_source: str
    mapping_source_version: str
    verified_at: datetime
    mapping_checksum: str


class FrameworkReferenceView(ApiView):
    framework_reference_id: UUID
    framework_id: UUID
    reference_key: str
    level: FrameworkReferenceLevel
    title: str
    description: str
    parent_reference_id: UUID | None
    control_mappings: tuple[FrameworkControlMappingView, ...]


class FrameworkView(ApiView):
    framework_id: UUID
    framework_key: str
    name: str
    version: str
    source: str
    source_retrieved_at: datetime
    source_checksum: str
    created_at: datetime
    references: tuple[FrameworkReferenceView, ...]


class AuditEventView(ApiView):
    event_id: UUID
    event_type: AuditEventType
    actor_type: str
    actor_id: str
    target_type: str
    target_id: UUID
    timestamp: datetime
    metadata: dict[str, Any]
