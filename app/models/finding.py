"""Actionable FAIL findings and immutable per-assessment occurrence history."""

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
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.assessment.models import AssessmentResult
from app.database.base import Base
from app.models.enums import FindingStatus
from app.models.types import enum_check_constraint, string_enum_type

if TYPE_CHECKING:
    from app.models.assessment import ControlAssessment
    from app.models.exception import FindingException
    from app.models.resource import Resource


class Finding(Base):
    """Current operational lifecycle for one deduplicated technical failure."""

    __tablename__ = "findings"
    __table_args__ = (
        enum_check_constraint("status", FindingStatus, name="finding_status"),
        CheckConstraint("length(fingerprint) = 64", name="fingerprint_length"),
        CheckConstraint("last_detected_at >= first_detected_at", name="detected_ordered"),
        CheckConstraint(
            "(status = 'RESOLVED' AND resolved_at IS NOT NULL) OR "
            "(status <> 'RESOLVED' AND resolved_at IS NULL)",
            name="resolution_status_consistent",
        ),
        CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= last_detected_at",
            name="resolution_after_detection",
        ),
        UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),
        UniqueConstraint(
            "finding_id",
            "resource_id",
            "control_id",
            name="uq_findings_scope_identity",
        ),
        Index("ix_findings_account_status", "aws_account_id", "status"),
        Index("ix_findings_resource_status", "resource_id", "status"),
        Index("ix_findings_control_status", "control_id", "status"),
    )

    finding_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    aws_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[UUID] = mapped_column(
        ForeignKey("resources.resource_id", ondelete="RESTRICT"),
        nullable=False,
    )
    control_id: Mapped[UUID] = mapped_column(
        ForeignKey("controls.control_id", ondelete="RESTRICT"),
        nullable=False,
    )
    region: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[FindingStatus] = mapped_column(
        string_enum_type(FindingStatus, name="finding_status", length=32),
        nullable=False,
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
    )
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    resource: Mapped[Resource] = relationship(back_populates="findings")
    occurrences: Mapped[list[FindingOccurrence]] = relationship(
        back_populates="finding",
        overlaps="assessment,finding_occurrence",
    )
    exceptions: Mapped[list[FindingException]] = relationship(back_populates="finding")


class FindingOccurrence(Base):
    """Append-only link proving that one persisted FAIL assessment produced a finding."""

    __tablename__ = "finding_occurrences"
    __table_args__ = (
        enum_check_constraint(
            "assessment_result", AssessmentResult, name="finding_occurrence_assessment_result"
        ),
        CheckConstraint("assessment_result = 'FAIL'", name="assessment_must_fail"),
        UniqueConstraint(
            "assessment_id",
            name="uq_finding_occurrences_assessment",
        ),
        ForeignKeyConstraint(
            ["finding_id", "resource_id", "control_id"],
            ["findings.finding_id", "findings.resource_id", "findings.control_id"],
            name="fk_finding_occurrences_finding_scope",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "assessment_id",
                "scan_id",
                "resource_snapshot_id",
                "resource_id",
                "control_version_id",
                "control_id",
                "assessment_result",
            ],
            [
                "control_assessments.assessment_id",
                "control_assessments.scan_id",
                "control_assessments.resource_snapshot_id",
                "control_assessments.resource_id",
                "control_assessments.control_version_id",
                "control_assessments.control_id",
                "control_assessments.assessment_result",
            ],
            name="fk_finding_occurrences_failed_assessment",
            ondelete="RESTRICT",
        ),
        Index("ix_finding_occurrences_finding_detected", "finding_id", "detected_at"),
        Index("ix_finding_occurrences_scan", "scan_id"),
    )

    occurrence_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    assessment_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scan_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    resource_snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    resource_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    assessment_result: Mapped[AssessmentResult] = mapped_column(
        string_enum_type(
            AssessmentResult,
            name="finding_occurrence_assessment_result",
            length=32,
        ),
        nullable=False,
        default=AssessmentResult.FAIL,
        server_default=AssessmentResult.FAIL.value,
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    finding: Mapped[Finding] = relationship(
        back_populates="occurrences",
        overlaps="assessment,finding_occurrence",
    )
    assessment: Mapped[ControlAssessment] = relationship(
        back_populates="finding_occurrence",
        foreign_keys=[
            assessment_id,
            scan_id,
            resource_snapshot_id,
            resource_id,
            control_version_id,
            control_id,
            assessment_result,
        ],
        overlaps="finding,occurrences",
    )
