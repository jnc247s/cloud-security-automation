"""Additive exact-scan reporting models, not new technical result states."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.assessment.controls import AssessmentType
from app.assessment.frameworks import FrameworkReferenceLevel
from app.schemas.api_views import ApiView, FrameworkMappingView
from app.schemas.finding import ControlCategory, Severity
from app.schemas.resource import ResourceScope
from app.schemas.scan import ScanDetail


class AssessmentCounts(ApiView):
    """Counts of unique assessments; never a control or compliance score."""

    pass_count: int = Field(default=0, ge=0)
    fail_count: int = Field(default=0, ge=0)
    insufficient_evidence_count: int = Field(default=0, ge=0)
    not_applicable_count: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        return sum(
            (
                self.pass_count,
                self.fail_count,
                self.insufficient_evidence_count,
                self.not_applicable_count,
            )
        )


class ControlCoverage(ApiView):
    """Definition/enablement counts kept separate from target-assessment counts."""

    registered_count: int = Field(ge=0)
    enabled_count: int = Field(ge=0)
    disabled_count: int = Field(ge=0)
    assessed_count: int | None = Field(ge=0)
    unassessed_count: int | None = Field(ge=0)


class CatalogProvenance(ApiView):
    catalog_id: UUID
    catalog_key: str
    version: str
    content_checksum: str


class ControlPosture(ApiView):
    control_id: UUID
    control_version_id: UUID
    control_key: str
    title: str
    category: ControlCategory
    resource_type: str
    assessment_type: AssessmentType
    severity: Severity
    definition_checksum: str
    enabled: bool
    assessment_coverage: Literal["ASSESSED", "UNASSESSED", "DISABLED", "UNAVAILABLE"]
    assessment_counts: AssessmentCounts | None
    framework_mappings: tuple[FrameworkMappingView, ...]


class TargetPosture(ApiView):
    """Assessed snapshot groups; owner and observed scope are not scan scope."""

    target_kind: Literal["ACCOUNT", "RESOURCE"]
    aws_account_id: str
    service: str
    resource_type: str
    scope: ResourceScope
    region: str | None
    assessed_snapshot_count: int = Field(ge=1)
    assessment_counts: AssessmentCounts


class FrameworkReferencePosture(ApiView):
    """Version-bound mapped context, including unmapped/unassessed subset rows."""

    framework_reference_id: UUID
    reference_key: str
    level: FrameworkReferenceLevel
    title: str
    parent_reference_id: UUID | None
    mapped_control_version_ids: tuple[UUID, ...]
    control_coverage: ControlCoverage
    assessment_counts: AssessmentCounts | None


class FrameworkPosture(ApiView):
    framework_id: UUID
    framework_key: str
    name: str
    version: str
    source: str
    source_retrieved_at: datetime
    source_checksum: str
    interpretation: Literal["MAPPED_TECHNICAL_SUBSET"] = "MAPPED_TECHNICAL_SUBSET"
    references: tuple[FrameworkReferencePosture, ...]


class TechnicalPosture(ApiView):
    """Immutable technical facts for one scan; live finding handling is excluded."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    interpretation: Literal["TECHNICAL_CONTEXT_ONLY"] = "TECHNICAL_CONTEXT_ONLY"
    scan: ScanDetail
    availability: Literal["IN_PROGRESS", "AVAILABLE", "UNAVAILABLE"]
    catalog: CatalogProvenance
    assessment_profile_version_id: UUID
    enabled_controls: tuple[str, ...]
    control_coverage: ControlCoverage
    assessment_counts: AssessmentCounts | None
    targets: tuple[TargetPosture, ...] | None
    controls: tuple[ControlPosture, ...]
    frameworks: tuple[FrameworkPosture, ...]
