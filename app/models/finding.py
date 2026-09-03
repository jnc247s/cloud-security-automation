"""Persisted security finding model."""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.enums import FindingStatus
from app.schemas.finding import ControlCategory, Severity

if TYPE_CHECKING:
    from app.models.resource import Resource
    from app.models.scan import Scan


JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


class Finding(Base):
    """Current lifecycle state for one control and resource pair."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "category IN ('network', 'storage', 'identity', 'logging')",
            name="control_category",
        ),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="finding_severity",
        ),
        CheckConstraint(
            "status IN ('OPEN', 'ACKNOWLEDGED', 'REMEDIATION_PROPOSED', "
            "'APPROVED', 'RESOLVED', 'FALSE_POSITIVE')",
            name="finding_status",
        ),
        CheckConstraint("last_detected >= first_detected", name="detected_ordered"),
        CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= last_detected",
            name="resolution_after_detection",
        ),
        UniqueConstraint("control_id", "resource_id", name="uq_findings_control_resource"),
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_resource_id", "resource_id"),
        Index("ix_findings_scan_id", "scan_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_uuid: Mapped[UUID] = mapped_column(Uuid, default=uuid4, unique=True, nullable=False)
    control_id: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    category: Mapped[ControlCategory] = mapped_column(
        Enum(
            ControlCategory,
            name="control_category",
            native_enum=False,
            create_constraint=False,
            validate_strings=True,
            values_callable=lambda enum_type: [member.value for member in enum_type],
        ),
        nullable=False,
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(
            Severity,
            name="finding_severity",
            native_enum=False,
            create_constraint=False,
            validate_strings=True,
        ),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, default=dict, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(
            FindingStatus,
            name="finding_status",
            native_enum=False,
            create_constraint=False,
            validate_strings=True,
        ),
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
        nullable=False,
    )
    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    resource: Mapped["Resource"] = relationship(back_populates="findings")
    scan: Mapped["Scan"] = relationship(back_populates="findings")
