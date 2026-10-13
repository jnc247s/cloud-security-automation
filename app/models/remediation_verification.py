"""Immutable linked requests and terminal receipts with independent coordination."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.types import JsonObject, json_document_type


class RemediationVerificationGuard(Base):
    __tablename__ = "remediation_verification_guard"
    __table_args__ = (CheckConstraint("guard_id = 1", name="verification_singleton"),)
    guard_id: Mapped[int] = mapped_column(Integer, primary_key=True)


class RemediationVerification(Base):
    __tablename__ = "remediation_verifications"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_remediation_verification_scan"),
        UniqueConstraint("execution_id", "attempt", name="uq_remediation_verification_attempt"),
        UniqueConstraint("actor_identity_sha256", "idempotency_key", name="uq_verification_key"),
        UniqueConstraint("audit_event_id", name="uq_verification_request_audit"),
        CheckConstraint("attempt BETWEEN 1 AND 3", name="verification_attempt_bound"),
        CheckConstraint("length(content_sha256) = 64", name="verification_content_digest"),
        CheckConstraint("length(request_sha256) = 64", name="verification_request_digest"),
        CheckConstraint("length(actor_identity_sha256) = 64", name="verification_actor_digest"),
        CheckConstraint("length(trim(actor_issuer)) > 0", name="verification_actor_issuer"),
        CheckConstraint("length(trim(actor_subject)) > 0", name="verification_actor_subject"),
        Index("ix_remediation_verifications_acknowledgment", "acknowledgment_event_id"),
        Index("ix_remediation_verifications_created", "created_at", "verification_id"),
    )
    verification_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_executions.execution_id", ondelete="RESTRICT"), nullable=False
    )
    acknowledgment_event_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_execution_events.event_id", ondelete="RESTRICT"), nullable=False
    )
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="RESTRICT"), nullable=False
    )
    audit_event_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_events.event_id", ondelete="RESTRICT"), nullable=False
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_issuer: Mapped[str] = mapped_column(Text, nullable=False)
    actor_subject: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RemediationVerificationReceipt(Base):
    __tablename__ = "remediation_verification_receipts"
    __table_args__ = (
        UniqueConstraint("audit_event_id", name="uq_verification_receipt_audit"),
        CheckConstraint("length(content_sha256) = 64", name="verification_receipt_digest"),
        CheckConstraint(
            "outcome IN ('VERIFIED', 'NOT_VERIFIED', 'INCONCLUSIVE')", name="verification_outcome"
        ),
        Index("ix_verification_receipts_created", "created_at", "verification_id"),
    )
    verification_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_verifications.verification_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    audit_event_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_events.event_id", ondelete="RESTRICT"), nullable=False
    )
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
