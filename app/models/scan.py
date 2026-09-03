"""Persisted security scan model."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.associations import scan_resources
from app.models.enums import ScanStatus

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.resource import Resource


class Scan(Base):
    """One queued, running, completed, or failed control evaluation."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')",
            name="scan_status",
        ),
        CheckConstraint(
            "(status = 'QUEUED' AND started_at IS NULL AND completed_at IS NULL) OR "
            "(status = 'RUNNING' AND started_at IS NOT NULL AND completed_at IS NULL) OR "
            "(status IN ('COMPLETED', 'FAILED') AND started_at IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name="lifecycle_timestamps_consistent",
        ),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name="completion_after_start",
        ),
        CheckConstraint("resources_evaluated >= 0", name="resources_evaluated_nonnegative"),
        CheckConstraint("controls_evaluated >= 0", name="controls_evaluated_nonnegative"),
        CheckConstraint("findings_created >= 0", name="findings_created_nonnegative"),
        CheckConstraint("findings_resolved >= 0", name="findings_resolved_nonnegative"),
        Index("ix_scans_account_region_started", "account_id", "region", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_uuid: Mapped[UUID] = mapped_column(Uuid, default=uuid4, unique=True, nullable=False)
    account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(
            ScanStatus,
            name="scan_status",
            native_enum=False,
            create_constraint=False,
            validate_strings=True,
        ),
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
        nullable=False,
    )
    resources_evaluated: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )
    controls_evaluated: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )
    findings_created: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )
    findings_resolved: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )

    resources: Mapped[list["Resource"]] = relationship(
        secondary=scan_resources,
        back_populates="scans",
    )
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")
