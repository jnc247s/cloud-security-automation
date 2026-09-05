"""Validated API contracts for asynchronous security scans."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ScanStatus


class ScanCreateRequest(BaseModel):
    """Requested technical scope for the current single-region executor."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    region: str | None = Field(
        default=None,
        min_length=1,
        max_length=32,
        pattern=r"^[a-z0-9-]+$",
        description="AWS region; defaults to AWS_REGION when omitted.",
    )


class ScanFailure(BaseModel):
    """Bounded failure details safe to return across the API boundary."""

    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=256)


class ScanSummary(BaseModel):
    """Lifecycle and declared coverage for one scan."""

    scan_id: UUID
    status: ScanStatus
    aws_account_id: str | None
    requested_regions: tuple[str, ...]
    successful_regions: tuple[str, ...]
    requested_services: tuple[str, ...]
    successful_collectors: tuple[str, ...]
    started_at: datetime
    completed_at: datetime | None
    failure: ScanFailure | None = None


class ScanScope(BaseModel):
    """Exact immutable technical scope recorded when collection finishes."""

    requested_collectors: tuple[str, ...]
    collector_outcomes: dict[str, str]
    resource_types: tuple[str, ...]
    enabled_controls: tuple[str, ...]


class ScanDetail(ScanSummary):
    """Full scan provenance and terminal result identity."""

    scanner_version: str
    control_catalog_id: str
    control_catalog_version: str
    assessment_profile_id: str
    assessment_profile_version: str
    assessment_profile_checksum: str
    inventory_sha256: str | None
    result_checksum: str | None
    scope: ScanScope | None


class ScanListResponse(BaseModel):
    """Stable pagination envelope for scan collection responses."""

    items: tuple[ScanSummary, ...]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)
