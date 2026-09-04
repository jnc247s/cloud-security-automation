"""Explicit operational exceptions that never rewrite technical assessment results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.enums import ExceptionStatus
from app.models.types import enum_check_constraint, string_enum_type

if TYPE_CHECKING:
    from app.models.finding import Finding


def _utc_now() -> datetime:
    return datetime.now(UTC)


class FindingException(Base):
    """Time-bounded handling decision scoped to one finding's resource and control."""

    __tablename__ = "finding_exceptions"
    __table_args__ = (
        enum_check_constraint("status", ExceptionStatus, name="exception_status"),
        CheckConstraint("length(trim(reason)) > 0", name="reason_not_blank"),
        CheckConstraint("length(trim(approved_by)) > 0", name="approved_by_not_blank"),
        CheckConstraint("expires_at > created_at", name="expires_after_creation"),
        CheckConstraint(
            "(status = 'REVOKED' AND revoked_at IS NOT NULL) OR "
            "(status <> 'REVOKED' AND revoked_at IS NULL)",
            name="revocation_status_consistent",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="revocation_after_creation",
        ),
        ForeignKeyConstraint(
            ["finding_id", "resource_id", "control_id"],
            ["findings.finding_id", "findings.resource_id", "findings.control_id"],
            name="fk_finding_exceptions_finding_scope",
            ondelete="RESTRICT",
        ),
        Index(
            "ix_finding_exceptions_scope_status",
            "resource_id",
            "control_id",
            "status",
        ),
        Index("ix_finding_exceptions_status_expires", "status", "expires_at"),
    )

    exception_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    resource_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    control_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[ExceptionStatus] = mapped_column(
        string_enum_type(ExceptionStatus, name="exception_status", length=16),
        nullable=False,
        default=ExceptionStatus.ACTIVE,
        server_default=ExceptionStatus.ACTIVE.value,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship(back_populates="exceptions")
