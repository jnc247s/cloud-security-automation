"""Persisted normalized AWS resource model."""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, CheckConstraint, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.associations import scan_resources

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.scan import Scan


JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


class Resource(Base):
    """Latest known facts for one stable AWS resource identity."""

    __tablename__ = "resources"
    __table_args__ = (
        CheckConstraint(
            "(scope = 'regional' AND region IS NOT NULL) OR (scope = 'global' AND region IS NULL)",
            name="scope_region_consistent",
        ),
        CheckConstraint("last_seen >= first_seen", name="seen_ordered"),
        Index("ix_resources_account_service_type", "account_id", "service", "resource_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    aws_resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    arn: Mapped[str | None] = mapped_column(Text)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    region: Mapped[str | None] = mapped_column(String(64))
    account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[dict[str, str]] = mapped_column(JSON_DOCUMENT, default=dict, nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT,
        default=dict,
        nullable=False,
    )
    raw_configuration: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT,
        default=dict,
        nullable=False,
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scans: Mapped[list["Scan"]] = relationship(
        secondary=scan_resources,
        back_populates="resources",
    )
    findings: Mapped[list["Finding"]] = relationship(back_populates="resource")
