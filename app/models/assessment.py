"""Immutable technical assessments and their structured evidence artifacts."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.assessment.models import AssessmentResult
from app.database.base import Base
from app.models.types import (
    JsonArray,
    JsonObject,
    enum_check_constraint,
    json_document_type,
    string_enum_type,
)

if TYPE_CHECKING:
    from app.models.control import ControlVersion
    from app.models.finding import FindingOccurrence
    from app.models.profile import PersistedAssessmentProfile
    from app.models.resource import ResourceSnapshot
    from app.models.scan import Scan


class ControlAssessment(Base):
    """One immutable four-state technical result for a scan target and control version."""

    __tablename__ = "control_assessments"
    __table_args__ = (
        enum_check_constraint("assessment_result", AssessmentResult, name="assessment_result"),
        CheckConstraint("length(trim(reason)) > 0", name="reason_not_blank"),
        UniqueConstraint(
            "scan_id",
            "resource_snapshot_id",
            "control_version_id",
            name="uq_control_assessments_scan_snapshot_control",
        ),
        UniqueConstraint(
            "assessment_id",
            "scan_id",
            "resource_snapshot_id",
            "control_version_id",
            "control_id",
            name="uq_control_assessments_evidence_identity",
        ),
        UniqueConstraint(
            "assessment_id",
            "scan_id",
            "resource_snapshot_id",
            "resource_id",
            "control_version_id",
            "control_id",
            "assessment_result",
            name="uq_control_assessments_occurrence_identity",
        ),
        ForeignKeyConstraint(
            ["resource_snapshot_id", "scan_id", "resource_id"],
            [
                "resource_snapshots.snapshot_id",
                "resource_snapshots.scan_id",
                "resource_snapshots.resource_id",
            ],
            name="fk_control_assessments_snapshot_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["control_version_id", "control_id"],
            ["control_versions.control_version_id", "control_versions.control_id"],
            name="fk_control_assessments_version_control",
            ondelete="RESTRICT",
        ),
        Index("ix_control_assessments_scan_result", "scan_id", "assessment_result"),
        Index(
            "ix_control_assessments_control_result",
            "control_id",
            "assessment_result",
        ),
        Index("ix_control_assessments_snapshot", "resource_snapshot_id"),
    )

    assessment_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="RESTRICT"),
        nullable=False,
    )
    resource_snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    resource_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    assessment_profile_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("assessment_profiles.profile_version_id", ondelete="RESTRICT"),
        nullable=False,
    )
    assessment_result: Mapped[AssessmentResult] = mapped_column(
        string_enum_type(
            AssessmentResult,
            name="assessment_result",
            length=32,
        ),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    missing_evidence: Mapped[JsonArray] = mapped_column(
        json_document_type(),
        nullable=False,
        default=list,
    )
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[Scan] = relationship(
        back_populates="assessments",
        foreign_keys=[scan_id],
        overlaps="assessments,resource_snapshot",
    )
    resource_snapshot: Mapped[ResourceSnapshot] = relationship(
        back_populates="assessments",
        foreign_keys=[resource_snapshot_id, scan_id, resource_id],
        overlaps="assessments,scan",
    )
    control_version: Mapped[ControlVersion] = relationship(back_populates="assessments")
    assessment_profile: Mapped[PersistedAssessmentProfile] = relationship()
    evidence_artifacts: Mapped[list[EvidenceArtifact]] = relationship(back_populates="assessment")
    finding_occurrence: Mapped[FindingOccurrence | None] = relationship(
        back_populates="assessment",
        uselist=False,
        overlaps="finding,occurrences",
    )


class EvidenceArtifact(Base):
    """Structured evidence bound to exactly one assessment, scan, and resource snapshot."""

    __tablename__ = "evidence_artifacts"
    __table_args__ = (
        CheckConstraint("length(trim(collector)) > 0", name="collector_not_blank"),
        CheckConstraint("length(trim(source)) > 0", name="source_not_blank"),
        CheckConstraint("length(trim(source_api)) > 0", name="source_api_not_blank"),
        CheckConstraint("length(trim(schema_name)) > 0", name="schema_name_not_blank"),
        CheckConstraint("length(trim(schema_version)) > 0", name="schema_version_not_blank"),
        CheckConstraint("length(trim(evidence_key)) > 0", name="evidence_key_not_blank"),
        CheckConstraint("length(payload_sha256) = 64", name="payload_sha256_length"),
        UniqueConstraint(
            "assessment_id",
            "evidence_key",
            name="uq_evidence_artifacts_assessment_key",
        ),
        ForeignKeyConstraint(
            [
                "assessment_id",
                "scan_id",
                "resource_snapshot_id",
                "control_version_id",
                "control_id",
            ],
            [
                "control_assessments.assessment_id",
                "control_assessments.scan_id",
                "control_assessments.resource_snapshot_id",
                "control_assessments.control_version_id",
                "control_assessments.control_id",
            ],
            name="fk_evidence_artifacts_assessment_provenance",
            ondelete="RESTRICT",
        ),
        Index("ix_evidence_artifacts_snapshot", "resource_snapshot_id"),
        Index("ix_evidence_artifacts_scan", "scan_id"),
        Index("ix_evidence_artifacts_payload_sha256", "payload_sha256"),
    )

    evidence_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    assessment_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scan_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    resource_snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    collector: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    source_api: Mapped[str] = mapped_column(Text, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    schema_name: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_key: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    assessment: Mapped[ControlAssessment] = relationship(
        back_populates="evidence_artifacts",
        foreign_keys=[
            assessment_id,
            scan_id,
            resource_snapshot_id,
            control_version_id,
            control_id,
        ],
    )
