"""Durable scan identity, lifecycle, and exact scope records."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.enums import ScanStatus
from app.models.types import (
    JsonArray,
    JsonObject,
    enum_check_constraint,
    json_document_type,
    string_enum_type,
)

if TYPE_CHECKING:
    from app.models.assessment import ControlAssessment
    from app.models.resource import ResourceSnapshot


class Scan(Base):
    """One durable scan with declared inputs and observed completion coverage."""

    __tablename__ = "scans"
    __table_args__ = (
        enum_check_constraint("status", ScanStatus, name="scan_status"),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name="completion_after_start",
        ),
        CheckConstraint(
            "(status = 'RUNNING' AND completed_at IS NULL) OR "
            "(status IN ('COMPLETED', 'PARTIAL', 'FAILED') AND completed_at IS NOT NULL)",
            name="lifecycle_timestamps_consistent",
        ),
        CheckConstraint(
            "result_checksum IS NULL OR length(result_checksum) = 64",
            name="result_checksum_length",
        ),
        CheckConstraint(
            "length(inventory_sha256) = 64",
            name="inventory_sha256_length",
        ),
        CheckConstraint(
            "length(assessment_profile_checksum) = 64",
            name="assessment_profile_checksum_length",
        ),
        CheckConstraint(
            "(status = 'RUNNING' AND result_checksum IS NULL) OR "
            "(status IN ('COMPLETED', 'PARTIAL', 'FAILED') AND result_checksum IS NOT NULL)",
            name="lifecycle_checksum_consistent",
        ),
        ForeignKeyConstraint(
            ["assessment_profile_id", "assessment_profile_version"],
            ["assessment_profiles.profile_id", "assessment_profiles.version"],
            name="fk_scans_profile_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["control_catalog_id", "control_catalog_version"],
            ["control_catalogs.catalog_key", "control_catalogs.version"],
            name="fk_scans_catalog_version",
            ondelete="RESTRICT",
        ),
        Index("ix_scans_account_started", "aws_account_id", "started_at"),
        Index("ix_scans_status_started", "status", "started_at"),
    )

    scan_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    aws_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_regions: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    successful_regions: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    requested_services: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    successful_collectors: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ScanStatus] = mapped_column(
        string_enum_type(ScanStatus, name="scan_status", length=16),
        nullable=False,
    )
    scanner_version: Mapped[str] = mapped_column(String(64), nullable=False)
    control_catalog_id: Mapped[str] = mapped_column(String(128), nullable=False)
    control_catalog_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    assessment_profile_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_profile_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    inventory_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    result_checksum: Mapped[str | None] = mapped_column(String(64))

    scope_manifest: Mapped[ScanScopeManifest] = relationship(
        back_populates="scan",
        uselist=False,
    )
    resource_snapshots: Mapped[list[ResourceSnapshot]] = relationship(back_populates="scan")
    assessments: Mapped[list[ControlAssessment]] = relationship(
        back_populates="scan", overlaps="assessments,resource_snapshot"
    )


class ScanScopeManifest(Base):
    """Exact intended and actual technical coverage for one scan."""

    __tablename__ = "scan_scope_manifests"
    __table_args__ = (
        CheckConstraint(
            "length(assessment_profile_checksum) = 64",
            name="assessment_profile_checksum_length",
        ),
        Index("ix_scan_scope_manifests_account", "aws_account_id"),
    )

    manifest_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("scans.scan_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    aws_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_regions: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    successful_regions: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    requested_services: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    requested_collectors: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    collector_outcomes: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    resource_types: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    enabled_controls: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    assessment_profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    assessment_profile_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_profile_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    control_catalog_id: Mapped[str] = mapped_column(String(128), nullable=False)
    control_catalog_version: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="scope_manifest")
