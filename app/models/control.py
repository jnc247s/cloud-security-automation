"""Persistent control catalogs and independently versioned framework metadata."""

from __future__ import annotations

from datetime import UTC, datetime
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
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.assessment.controls import AssessmentType
from app.assessment.frameworks import FrameworkReferenceLevel
from app.database.base import Base
from app.models.types import JsonArray, enum_check_constraint, json_document_type, string_enum_type
from app.schemas.finding import ControlCategory, Severity

if TYPE_CHECKING:
    from app.models.assessment import ControlAssessment


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Control(Base):
    """Stable internal control identity shared by all catalog versions."""

    __tablename__ = "controls"
    __table_args__ = (
        CheckConstraint("length(trim(control_key)) > 0", name="control_key_not_blank"),
    )

    control_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    control_key: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )

    versions: Mapped[list[ControlVersion]] = relationship(back_populates="control")


class ControlCatalog(Base):
    """Immutable identity and integrity metadata for one catalog release."""

    __tablename__ = "control_catalogs"
    __table_args__ = (
        CheckConstraint("length(trim(catalog_key)) > 0", name="catalog_key_not_blank"),
        CheckConstraint("length(trim(version)) > 0", name="version_not_blank"),
        CheckConstraint("length(content_checksum) = 64", name="checksum_length"),
        UniqueConstraint(
            "catalog_key",
            "version",
            name="uq_control_catalogs_key_version",
        ),
    )

    catalog_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    catalog_key: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    content_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )

    control_versions: Mapped[list[ControlVersion]] = relationship(back_populates="catalog")


class ControlVersion(Base):
    """Exact framework-independent technical contract used by a scan."""

    __tablename__ = "control_versions"
    __table_args__ = (
        enum_check_constraint("category", ControlCategory, name="control_category"),
        enum_check_constraint("assessment_type", AssessmentType, name="assessment_type"),
        enum_check_constraint("severity", Severity, name="control_severity"),
        CheckConstraint("length(trim(title)) > 0", name="title_not_blank"),
        CheckConstraint("length(trim(resource_type)) > 0", name="resource_type_not_blank"),
        CheckConstraint("length(definition_checksum) = 64", name="checksum_length"),
        UniqueConstraint(
            "catalog_id",
            "control_id",
            name="uq_control_versions_catalog_control",
        ),
        UniqueConstraint(
            "control_version_id",
            "control_id",
            name="uq_control_versions_version_control",
        ),
        Index("ix_control_versions_control", "control_id"),
    )

    control_version_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    catalog_id: Mapped[UUID] = mapped_column(
        ForeignKey("control_catalogs.catalog_id", ondelete="RESTRICT"),
        nullable=False,
    )
    control_id: Mapped[UUID] = mapped_column(
        ForeignKey("controls.control_id", ondelete="RESTRICT"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[ControlCategory] = mapped_column(
        string_enum_type(ControlCategory, name="control_category", length=16),
        nullable=False,
    )
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    assessment_type: Mapped[AssessmentType] = mapped_column(
        string_enum_type(AssessmentType, name="assessment_type", length=32),
        nullable=False,
    )
    measure: Mapped[str] = mapped_column(Text, nullable=False)
    required_evidence: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    pass_logic: Mapped[str] = mapped_column(Text, nullable=False)
    fail_logic: Mapped[str] = mapped_column(Text, nullable=False)
    insufficient_evidence_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    not_applicable_logic: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        string_enum_type(Severity, name="control_severity", length=16),
        nullable=False,
    )
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    profile_parameters: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    limitations: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    definition_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )

    catalog: Mapped[ControlCatalog] = relationship(back_populates="control_versions")
    control: Mapped[Control] = relationship(back_populates="versions")
    framework_mappings: Mapped[list[ControlFrameworkMapping]] = relationship(
        back_populates="control_version"
    )
    assessments: Mapped[list[ControlAssessment]] = relationship(back_populates="control_version")


class Framework(Base):
    """One immutable version of an external security framework."""

    __tablename__ = "frameworks"
    __table_args__ = (
        CheckConstraint("length(trim(framework_key)) > 0", name="framework_key_not_blank"),
        CheckConstraint("length(trim(version)) > 0", name="version_not_blank"),
        CheckConstraint("length(source_checksum) = 64", name="checksum_length"),
        UniqueConstraint(
            "framework_key",
            "version",
            name="uq_frameworks_key_version",
        ),
    )

    framework_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    framework_key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    source_retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )

    references: Mapped[list[FrameworkReference]] = relationship(back_populates="framework")


class FrameworkReference(Base):
    """Version-bound Function, Category, or Subcategory in a framework hierarchy."""

    __tablename__ = "framework_references"
    __table_args__ = (
        enum_check_constraint("level", FrameworkReferenceLevel, name="framework_reference_level"),
        CheckConstraint("length(trim(reference_key)) > 0", name="reference_key_not_blank"),
        CheckConstraint(
            "(level = 'function' AND parent_reference_id IS NULL) OR "
            "(level IN ('category', 'subcategory') AND parent_reference_id IS NOT NULL)",
            name="level_parent_consistent",
        ),
        CheckConstraint(
            "parent_reference_id IS NULL OR parent_reference_id <> framework_reference_id",
            name="parent_not_self",
        ),
        UniqueConstraint(
            "framework_id",
            "reference_key",
            name="uq_framework_references_framework_key",
        ),
        UniqueConstraint(
            "framework_id",
            "framework_reference_id",
            name="uq_framework_references_framework_id",
        ),
        ForeignKeyConstraint(
            ["framework_id", "parent_reference_id"],
            ["framework_references.framework_id", "framework_references.framework_reference_id"],
            name="fk_framework_references_parent_same_framework",
            ondelete="RESTRICT",
        ),
        Index("ix_framework_references_framework_level", "framework_id", "level"),
    )

    framework_reference_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    framework_id: Mapped[UUID] = mapped_column(
        ForeignKey("frameworks.framework_id", ondelete="RESTRICT"),
        nullable=False,
    )
    reference_key: Mapped[str] = mapped_column(String(64), nullable=False)
    level: Mapped[FrameworkReferenceLevel] = mapped_column(
        string_enum_type(
            FrameworkReferenceLevel,
            name="framework_reference_level",
            length=16,
        ),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    parent_reference_id: Mapped[UUID | None] = mapped_column(Uuid)

    framework: Mapped[Framework] = relationship(back_populates="references")
    control_mappings: Mapped[list[ControlFrameworkMapping]] = relationship(
        back_populates="framework_reference"
    )


class ControlFrameworkMapping(Base):
    """Auditable mapping from one control definition to one framework reference."""

    __tablename__ = "control_framework_mappings"
    __table_args__ = (
        CheckConstraint("length(trim(mapping_rationale)) > 0", name="rationale_not_blank"),
        CheckConstraint("length(trim(mapping_source)) > 0", name="source_not_blank"),
        CheckConstraint(
            "length(trim(mapping_source_version)) > 0",
            name="source_version_not_blank",
        ),
        CheckConstraint("length(mapping_checksum) = 64", name="checksum_length"),
        UniqueConstraint(
            "control_version_id",
            "framework_reference_id",
            name="uq_control_framework_mappings_control_reference",
        ),
        Index("ix_control_framework_mappings_reference", "framework_reference_id"),
    )

    mapping_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    control_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("control_versions.control_version_id", ondelete="RESTRICT"),
        nullable=False,
    )
    framework_reference_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "framework_references.framework_reference_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    mapping_source: Mapped[str] = mapped_column(Text, nullable=False)
    mapping_source_version: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mapping_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )

    control_version: Mapped[ControlVersion] = relationship(back_populates="framework_mappings")
    framework_reference: Mapped[FrameworkReference] = relationship(
        back_populates="control_mappings"
    )
