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
        CheckConstraint(
            "(schema_version IS NULL AND policy_extensions IS NULL) OR "
            "(schema_version IS NOT NULL AND schema_version = '2.0.0' "
            "AND policy_extensions IS NOT NULL)",
            name="profile_schema_pair",
        ),
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
    schema_version: Mapped[str | None] = mapped_column(String(32))
    policy_extensions: Mapped[dict | None] = mapped_column(json_document_type(none_as_null=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        server_default=func.now(),
    )


class AssessmentPolicyArtifact(Base):
    """Closed-kind immutable policy versions shared by exact profile definitions."""

    __tablename__ = "assessment_policy_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "artifact_kind", "artifact_id", "version", name="uq_policy_artifact_version"
        ),
        CheckConstraint("artifact_kind IN ('s3-exposure', 'sensitive-bucket')", name="policy_kind"),
        CheckConstraint("length(content_checksum) = 64", name="policy_checksum"),
    )

    policy_artifact_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    artifact_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    content_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict] = mapped_column(json_document_type(), nullable=False)
