"""Stable cloud resource identities and immutable per-scan observations."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.types import JsonObject, enum_check_constraint, json_document_type, string_enum_type
from app.schemas.resource import ResourceScope

if TYPE_CHECKING:
    from app.models.assessment import ControlAssessment
    from app.models.finding import Finding
    from app.models.scan import Scan


GLOBAL_REGION_SENTINEL = "global"


class Resource(Base):
    """Stable provider identity that is never overwritten with observed configuration."""

    __tablename__ = "resources"
    __table_args__ = (
        enum_check_constraint("scope", ResourceScope, name="resource_scope"),
        CheckConstraint("length(trim(provider)) > 0", name="provider_not_blank"),
        CheckConstraint("length(trim(aws_account_id)) > 0", name="account_not_blank"),
        CheckConstraint("length(trim(service)) > 0", name="service_not_blank"),
        CheckConstraint("length(trim(resource_type)) > 0", name="resource_type_not_blank"),
        CheckConstraint("length(trim(aws_resource_id)) > 0", name="aws_resource_id_not_blank"),
        CheckConstraint("length(trim(region)) > 0", name="region_not_blank"),
        CheckConstraint(
            f"(scope = 'regional' AND region <> '{GLOBAL_REGION_SENTINEL}') OR "
            f"(scope = 'global' AND region = '{GLOBAL_REGION_SENTINEL}')",
            name="scope_region_consistent",
        ),
        UniqueConstraint(
            "provider",
            "aws_account_id",
            "service",
            "resource_type",
            "scope",
            "region",
            "aws_resource_id",
            name="uq_resources_stable_identity",
        ),
        Index(
            "ix_resources_account_service_type",
            "aws_account_id",
            "service",
            "resource_type",
            "scope",
            "region",
        ),
    )

    resource_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    aws_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    aws_resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    arn: Mapped[str | None] = mapped_column(Text)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    scope: Mapped[ResourceScope] = mapped_column(
        string_enum_type(ResourceScope, name="resource_scope", length=16),
        nullable=False,
    )
    region: Mapped[str] = mapped_column(String(64), nullable=False)

    snapshots: Mapped[list[ResourceSnapshot]] = relationship(back_populates="resource")
    findings: Mapped[list[Finding]] = relationship(back_populates="resource")


class ResourceSnapshot(Base):
    """Resource state observed during one scan; prior rows remain historical truth."""

    __tablename__ = "resource_snapshots"
    __table_args__ = (
        enum_check_constraint("scope", ResourceScope, name="resource_snapshot_scope"),
        CheckConstraint(
            "(scope = 'regional' AND region IS NOT NULL) OR (scope = 'global' AND region IS NULL)",
            name="scope_region_consistent",
        ),
        CheckConstraint(
            "region IS NULL OR length(trim(region)) > 0",
            name="region_not_blank",
        ),
        CheckConstraint("length(state_sha256) = 64", name="state_checksum_length"),
        UniqueConstraint("scan_id", "resource_id", name="uq_resource_snapshots_scan_resource"),
        UniqueConstraint(
            "snapshot_id",
            "scan_id",
            name="uq_resource_snapshots_snapshot_scan",
        ),
        UniqueConstraint(
            "snapshot_id",
            "scan_id",
            "resource_id",
            name="uq_resource_snapshots_snapshot_scan_resource",
        ),
        Index("ix_resource_snapshots_resource_observed", "resource_id", "observed_at"),
        Index("ix_resource_snapshots_scan", "scan_id"),
    )

    snapshot_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    resource_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("resources.resource_id", ondelete="RESTRICT"),
        nullable=False,
    )
    scan_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("scans.scan_id", ondelete="RESTRICT"),
        nullable=False,
    )
    scope: Mapped[ResourceScope] = mapped_column(
        string_enum_type(ResourceScope, name="resource_snapshot_scope", length=16),
        nullable=False,
    )
    region: Mapped[str | None] = mapped_column(String(64))
    arn: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    normalized_configuration: Mapped[JsonObject] = mapped_column(
        json_document_type(), nullable=False
    )
    state_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    resource: Mapped[Resource] = relationship(back_populates="snapshots")
    scan: Mapped[Scan] = relationship(back_populates="resource_snapshots")
    assessments: Mapped[list[ControlAssessment]] = relationship(back_populates="resource_snapshot")

    __mapper_args__ = {"confirm_deleted_rows": True}
