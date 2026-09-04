"""Immutable, versioned assessment-profile persistence."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.types import JsonArray, json_document_type


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PersistedAssessmentProfile(Base):
    """One immutable version of the policy inputs used by the rule engine.

    Each JSON array preserves the complete validated Pydantic profile rather than
    reconstructing historical policy from current environment settings.
    """

    __tablename__ = "assessment_profiles"
    __table_args__ = (
        CheckConstraint("length(trim(profile_id)) > 0", name="profile_id_not_blank"),
        CheckConstraint("length(trim(version)) > 0", name="version_not_blank"),
        CheckConstraint("stale_key_days >= 1", name="stale_key_days_positive"),
        CheckConstraint("length(content_checksum) = 64", name="checksum_length"),
        UniqueConstraint(
            "profile_id",
            "version",
            name="uq_assessment_profiles_profile_version",
        ),
        Index("ix_assessment_profiles_checksum", "content_checksum"),
    )

    profile_version_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled_controls: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    required_tags: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    stale_key_days: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_management_cidrs: Mapped[JsonArray] = mapped_column(
        json_document_type(),
        nullable=False,
    )
    public_ec2_exceptions: Mapped[JsonArray] = mapped_column(
        json_document_type(),
        nullable=False,
    )
    restricted_data_requires_kms: Mapped[bool] = mapped_column(Boolean, nullable=False)
    content_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )
