"""Immutable admission/journal and mutable coordination; deliberately no dispatch state."""

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
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.types import JsonObject, json_document_type


class RemediationExecution(Base):
    __tablename__ = "remediation_executions"
    __table_args__ = (
        UniqueConstraint("proposal_id", name="uq_remediation_execution_proposal"),
        UniqueConstraint(
            "actor_identity_sha256", "idempotency_key", name="uq_remediation_execution_key"
        ),
        CheckConstraint("length(execution_sha256) = 64", name="execution_digest_length"),
        CheckConstraint("length(request_sha256) = 64", name="execution_request_digest"),
        CheckConstraint("length(actor_identity_sha256) = 64", name="execution_actor_digest"),
        CheckConstraint("length(trim(actor_issuer)) > 0", name="execution_actor_issuer"),
        CheckConstraint("length(trim(actor_subject)) > 0", name="execution_actor_subject"),
        CheckConstraint("expires_at > created_at", name="execution_expiry_order"),
        Index("ix_remediation_executions_approval", "approval_decision_id"),
        Index("ix_remediation_executions_created", "created_at", "execution_id"),
        Index("ix_remediation_executions_expiry", "expires_at"),
    )
    execution_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_proposals.proposal_id", ondelete="RESTRICT"), nullable=False
    )
    approval_decision_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_decisions.decision_id", ondelete="RESTRICT"), nullable=False
    )
    actor_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_issuer: Mapped[str] = mapped_column(Text, nullable=False)
    actor_subject: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    execution_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RemediationExecutionEvent(Base):
    __tablename__ = "remediation_execution_events"
    __table_args__ = (
        UniqueConstraint("execution_id", "sequence", name="uq_remediation_execution_sequence"),
        UniqueConstraint("audit_event_id", name="uq_remediation_execution_audit"),
        CheckConstraint("sequence >= 1", name="execution_event_sequence"),
        CheckConstraint(
            "kind IN ('REQUESTED', 'EXPIRED', 'BLOCKED', 'CLAIMED', 'WRITE_INTENT', "
            "'NO_WRITE', 'ACKNOWLEDGED', 'QUARANTINED', 'OBSERVED', 'OBSERVATION_FAILED')",
            name="execution_event_kind",
        ),
        CheckConstraint("length(event_sha256) = 64", name="execution_event_digest"),
        Index(
            "uq_remediation_execution_single_intent_receipt",
            "execution_id",
            "kind",
            unique=True,
            sqlite_where=text("kind IN ('WRITE_INTENT', 'ACKNOWLEDGED')"),
            postgresql_where=text("kind IN ('WRITE_INTENT', 'ACKNOWLEDGED')"),
        ),
        CheckConstraint(
            "(sequence = 1 AND kind = 'REQUESTED' AND previous_event_sha256 IS NULL) OR "
            "(sequence >= 2 AND kind <> 'REQUESTED' AND length(previous_event_sha256) = 64 "
            "AND (kind NOT IN ('EXPIRED', 'BLOCKED') OR sequence = 2))",
            name="execution_event_transition",
        ),
    )
    event_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_executions.execution_id", ondelete="RESTRICT"), nullable=False
    )
    audit_event_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_events.event_id", ondelete="RESTRICT"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    event_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_event_sha256: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RemediationAdmissionGuard(Base):
    __tablename__ = "remediation_admission_guard"
    __table_args__ = (CheckConstraint("guard_id = 1", name="admission_singleton"),)
    guard_id: Mapped[int] = mapped_column(Integer, primary_key=True)


class RemediationTargetReservation(Base):
    __tablename__ = "remediation_target_reservations"
    __table_args__ = (
        UniqueConstraint("account_id", "region", "action_id", name="uq_remediation_target_scope"),
        UniqueConstraint("execution_id", name="uq_remediation_target_execution"),
        CheckConstraint("length(account_id) = 12", name="reservation_account_length"),
        CheckConstraint("length(trim(region)) BETWEEN 1 AND 64", name="reservation_region"),
        CheckConstraint(
            "action_id = 'aws.ec2.enable-ebs-encryption-by-default'", name="reservation_action"
        ),
        Index("ix_remediation_target_reservations_resource", "resource_id"),
    )
    reservation_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    resource_id: Mapped[UUID] = mapped_column(
        ForeignKey("resources.resource_id", ondelete="RESTRICT"), nullable=False
    )
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("remediation_executions.execution_id", ondelete="RESTRICT")
    )


class RemediationWorkerClaim(Base):
    """Private mutable fencing coordinate. Never returned by execution READ APIs."""

    __tablename__ = "remediation_worker_claims"
    __table_args__ = (
        CheckConstraint("length(token_sha256) = 64", name="worker_token_digest"),
        CheckConstraint("generation >= 1", name="worker_claim_generation"),
        CheckConstraint("read_attempts BETWEEN 0 AND 3", name="worker_read_budget"),
        CheckConstraint("readback_attempts BETWEEN 0 AND 3", name="worker_readback_budget"),
        CheckConstraint(
            "(readback_attempts = 0 AND readback_started_at IS NULL) OR "
            "(readback_attempts > 0 AND readback_started_at IS NOT NULL)",
            name="worker_readback_window",
        ),
        CheckConstraint("length(trim(expected_role_arn)) > 0", name="worker_role"),
        Index("ix_remediation_worker_claims_lease", "lease_until", "execution_id"),
        Index("ix_remediation_worker_claims_intent", "write_intent_event_id"),
    )
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_executions.execution_id", ondelete="RESTRICT"), primary_key=True
    )
    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_role_arn: Mapped[str] = mapped_column(String(2048), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    read_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    readback_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    readback_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    write_intent_event_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("remediation_execution_events.event_id", ondelete="RESTRICT")
    )
