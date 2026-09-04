"""Append-only-style audit records for lifecycle and governance actions."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import AuditEventType
from app.models.types import JsonObject, enum_check_constraint, json_document_type, string_enum_type


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditEvent(Base):
    """Immutable polymorphic event; later state changes append rows instead of editing one."""

    __tablename__ = "audit_events"
    __table_args__ = (
        enum_check_constraint("event_type", AuditEventType, name="audit_event_type"),
        CheckConstraint("length(trim(actor_type)) > 0", name="actor_type_not_blank"),
        CheckConstraint("length(trim(actor_id)) > 0", name="actor_id_not_blank"),
        CheckConstraint("length(trim(target_type)) > 0", name="target_type_not_blank"),
        Index("ix_audit_events_target_time", "target_type", "target_id", "timestamp"),
        Index("ix_audit_events_type_time", "event_type", "timestamp"),
        Index("ix_audit_events_actor_time", "actor_type", "actor_id", "timestamp"),
    )

    event_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    event_type: Mapped[AuditEventType] = mapped_column(
        string_enum_type(AuditEventType, name="audit_event_type", length=64),
        nullable=False,
    )
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )
    event_metadata: Mapped[JsonObject] = mapped_column(
        "metadata",
        json_document_type(),
        nullable=False,
        default=dict,
    )
