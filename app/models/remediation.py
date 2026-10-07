"""Append-only remediation authority, distinct from findings and assessments."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.types import JsonArray, JsonObject, json_document_type


class RemediationProposal(Base):
    __tablename__ = "remediation_proposals"
    __table_args__ = (
        CheckConstraint("length(proposal_sha256) = 64", name="proposal_digest_length"),
        CheckConstraint("expires_at > created_at", name="proposal_expiry_order"),
        CheckConstraint("length(account_id) = 12", name="proposal_account_length"),
        CheckConstraint("length(trim(actor_issuer)) > 0", name="proposal_actor_issuer"),
        CheckConstraint("length(trim(actor_subject)) > 0", name="proposal_actor_subject"),
        Index("ix_remediation_proposals_finding_created", "finding_id", "created_at"),
        Index("ix_remediation_proposals_account_created", "account_id", "created_at"),
        Index("ix_remediation_proposals_occurrence", "occurrence_id"),
    )
    proposal_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.finding_id", ondelete="RESTRICT"), nullable=False
    )
    occurrence_id: Mapped[UUID] = mapped_column(
        ForeignKey("finding_occurrences.occurrence_id", ondelete="RESTRICT"), nullable=False
    )
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    actor_issuer: Mapped[str] = mapped_column(Text, nullable=False)
    actor_subject: Mapped[str] = mapped_column(Text, nullable=False)
    actor_roles: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    content: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    proposal_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RemediationDecision(Base):
    __tablename__ = "remediation_decisions"
    __table_args__ = (
        CheckConstraint("kind IN ('APPROVE', 'REJECT', 'REVOKE')", name="decision_kind"),
        CheckConstraint(
            "(kind = 'REVOKE' AND approval_decision_id IS NOT NULL) OR "
            "(kind <> 'REVOKE' AND approval_decision_id IS NULL)",
            name="decision_approval_reference",
        ),
        CheckConstraint("length(trim(reason)) BETWEEN 1 AND 2000", name="decision_reason"),
        CheckConstraint("length(proposal_sha256) = 64", name="decision_digest_length"),
        CheckConstraint("length(trim(actor_issuer)) > 0", name="decision_actor_issuer"),
        CheckConstraint("length(trim(actor_subject)) > 0", name="decision_actor_subject"),
        Index(
            "uq_remediation_decisions_initial",
            "proposal_id",
            unique=True,
            postgresql_where=text("kind IN ('APPROVE', 'REJECT')"),
            sqlite_where=text("kind IN ('APPROVE', 'REJECT')"),
        ),
        Index(
            "uq_remediation_decisions_revocation",
            "proposal_id",
            unique=True,
            postgresql_where=text("kind = 'REVOKE'"),
            sqlite_where=text("kind = 'REVOKE'"),
        ),
        Index("ix_remediation_decisions_proposal", "proposal_id"),
        Index("ix_remediation_decisions_approval", "approval_decision_id"),
    )
    decision_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_proposals.proposal_id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    proposal_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_decision_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("remediation_decisions.decision_id", ondelete="RESTRICT")
    )
    actor_issuer: Mapped[str] = mapped_column(Text, nullable=False)
    actor_subject: Mapped[str] = mapped_column(Text, nullable=False)
    actor_roles: Mapped[JsonArray] = mapped_column(json_document_type(), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RemediationRequest(Base):
    __tablename__ = "remediation_requests"
    __table_args__ = (
        UniqueConstraint(
            "actor_identity_sha256",
            "operation",
            "idempotency_key",
            name="uq_remediation_request_key",
        ),
        CheckConstraint("operation IN ('CREATE', 'DECIDE', 'REVOKE')", name="request_operation"),
        CheckConstraint(
            "(operation = 'CREATE' AND decision_id IS NULL) OR "
            "(operation <> 'CREATE' AND decision_id IS NOT NULL)",
            name="request_result_kind",
        ),
        CheckConstraint("length(request_sha256) = 64", name="request_digest_length"),
        CheckConstraint("length(actor_identity_sha256) = 64", name="request_actor_digest"),
        CheckConstraint("length(trim(actor_issuer)) > 0", name="request_actor_issuer"),
        CheckConstraint("length(trim(actor_subject)) > 0", name="request_actor_subject"),
        Index("ix_remediation_requests_proposal", "proposal_id"),
        Index("ix_remediation_requests_decision", "decision_id"),
    )
    request_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    actor_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_issuer: Mapped[str] = mapped_column(Text, nullable=False)
    actor_subject: Mapped[str] = mapped_column(Text, nullable=False)
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    idempotency_key: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_proposals.proposal_id", ondelete="RESTRICT"), nullable=False
    )
    decision_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("remediation_decisions.decision_id", ondelete="RESTRICT")
    )
