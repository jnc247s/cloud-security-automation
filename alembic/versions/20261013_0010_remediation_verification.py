"""Add immutable read-only verification attempts/receipts; preserve worker history."""

import sqlalchemy as sa
from alembic import context, op
from alembic.script import ScriptDirectory

revision = "20261013_0010"
down_revision = "20261008_0009"
branch_labels = None
depends_on = None

_HISTORY = ("remediation_verifications", "remediation_verification_receipts")
_EVENTS = ("REMEDIATION_VERIFICATION_REQUESTED", "REMEDIATION_VERIFICATION_COMPLETED")


def _predecessors():
    worker = ScriptDirectory.from_config(context.config).get_revision(down_revision).module
    admission = worker._admission()
    return worker, admission, admission._authority()


def _prior_events():
    worker, admission, authority = _predecessors()
    return (
        *authority._OLD_EVENTS,
        *authority._NEW_EVENTS,
        *admission._EVENTS,
        *("REMEDIATION_EXECUTION_" + kind for kind in worker._WORKER_EVENTS),
    )


def _guards():
    worker, _, _ = _predecessors()
    dialect = op.get_bind().dialect.name
    for table in (*_HISTORY, "remediation_verification_guard"):
        if dialect == "postgresql":
            op.execute(
                f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE OR TRUNCATE "
                f"ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_history_mutation()"
            )
        else:
            for action in ("update", "delete"):
                op.execute(
                    f"CREATE TRIGGER immutable_{table}_{action} BEFORE {action} ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'verification history is immutable'); END"
                )
    phase = (
        "v.content->>'phase'" if dialect == "postgresql" else "json_extract(v.content, '$.phase')"
    )
    marker = (
        "a.metadata->>'verification_id'"
        if dialect == "postgresql"
        else "json_extract(a.metadata, '$.verification_id')"
    )
    worker._install_guard(
        "verification_request",
        "remediation_verifications",
        "NOT EXISTS (SELECT 1 FROM remediation_executions e "
        "JOIN remediation_execution_events v ON v.execution_id = e.execution_id "
        "JOIN remediation_proposals p ON p.proposal_id = e.proposal_id "
        "JOIN finding_occurrences o ON o.occurrence_id = p.occurrence_id "
        "JOIN scans b ON b.scan_id = o.scan_id JOIN scans s ON s.scan_id = NEW.scan_id "
        "WHERE e.execution_id = NEW.execution_id AND v.event_id = NEW.acknowledgment_event_id "
        f"AND v.kind = 'ACKNOWLEDGED' AND {phase} = 'ACKNOWLEDGED' "
        "AND NEW.created_at >= v.created_at AND s.started_at = NEW.created_at "
        "AND s.status = 'RUNNING' AND s.requested_regions = b.requested_regions "
        "AND s.requested_services = b.requested_services "
        "AND s.assessment_profile_id = b.assessment_profile_id "
        "AND s.assessment_profile_version = b.assessment_profile_version "
        "AND s.assessment_profile_checksum = b.assessment_profile_checksum "
        "AND s.control_catalog_id = b.control_catalog_id "
        "AND s.control_catalog_version = b.control_catalog_version) OR "
        "NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.target_type = 'scan' "
        "AND a.target_id = NEW.scan_id AND a.event_type = 'SCAN_STARTED' "
        f"AND replace({marker}, '-', '') = replace(CAST(NEW.verification_id AS TEXT), '-', '') "
        "AND a.timestamp = NEW.created_at) OR "
        "NEW.attempt <> (SELECT count(*) + 1 FROM remediation_verifications v "
        "WHERE v.execution_id = NEW.execution_id) OR EXISTS "
        "(SELECT 1 FROM remediation_verifications v LEFT JOIN remediation_verification_receipts r "
        "ON r.verification_id = v.verification_id WHERE v.execution_id = NEW.execution_id "
        "AND r.verification_id IS NULL) OR NOT EXISTS (SELECT 1 FROM audit_events a "
        "WHERE a.event_id = NEW.audit_event_id AND a.target_type = 'remediation_verification' "
        "AND a.target_id = NEW.verification_id AND a.timestamp = NEW.created_at "
        "AND a.actor_type = 'human' AND a.actor_id = NEW.actor_identity_sha256 "
        "AND a.event_type = 'REMEDIATION_VERIFICATION_REQUESTED')",
        ("insert",),
    )
    worker._install_guard(
        "verification_receipt",
        "remediation_verification_receipts",
        "NOT EXISTS (SELECT 1 FROM remediation_verifications v JOIN scans s "
        "ON s.scan_id = v.scan_id WHERE v.verification_id = NEW.verification_id "
        "AND s.status IN ('COMPLETED', 'PARTIAL', 'FAILED') AND s.result_checksum IS NOT NULL "
        "AND s.completed_at = NEW.created_at AND NEW.created_at >= v.created_at) "
        "OR NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.event_id = NEW.audit_event_id "
        "AND a.target_type = 'remediation_verification' AND a.target_id = NEW.verification_id "
        "AND a.timestamp = NEW.created_at AND a.actor_type = 'system' "
        "AND a.actor_id = 'scan-executor' AND a.event_type = 'REMEDIATION_VERIFICATION_COMPLETED')",
        ("insert",),
    )


def upgrade():
    _, _, old = _predecessors()
    old._reserve_sqlite_writer(op.get_bind())
    # Maintenance DDL: exclude the existing writers before rebuilding their audit constraint.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "LOCK TABLE remediation_admission_guard, scans, audit_events IN ACCESS EXCLUSIVE MODE"
        )
    old._audit_constraint((*_prior_events(), *_EVENTS))
    op.create_table(
        "remediation_verification_guard",
        sa.Column("guard_id", sa.Integer(), primary_key=True),
        sa.CheckConstraint("guard_id = 1", name="verification_singleton"),
    )
    op.execute("INSERT INTO remediation_verification_guard (guard_id) VALUES (1)")
    op.create_table(
        "remediation_verifications",
        sa.Column("verification_id", sa.Uuid(), primary_key=True),
        old._foreign("execution_id", "remediation_executions.execution_id"),
        old._foreign("acknowledgment_event_id", "remediation_execution_events.event_id"),
        old._foreign("scan_id", "scans.scan_id"),
        old._foreign("audit_event_id", "audit_events.event_id"),
        old._column("attempt", sa.Integer()),
        old._column("actor_identity_sha256", sa.String(64)),
        old._column("actor_issuer", sa.Text()),
        old._column("actor_subject", sa.Text()),
        old._column("idempotency_key", sa.Uuid()),
        old._column("request_sha256", sa.String(64)),
        old._column("content", old._json()),
        old._column("content_sha256", sa.String(64)),
        old._column("created_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("scan_id", name="uq_remediation_verification_scan"),
        sa.UniqueConstraint("execution_id", "attempt", name="uq_remediation_verification_attempt"),
        sa.UniqueConstraint("actor_identity_sha256", "idempotency_key", name="uq_verification_key"),
        sa.UniqueConstraint("audit_event_id", name="uq_verification_request_audit"),
        sa.CheckConstraint("attempt BETWEEN 1 AND 3", name="verification_attempt_bound"),
        sa.CheckConstraint("length(content_sha256) = 64", name="verification_content_digest"),
        sa.CheckConstraint("length(request_sha256) = 64", name="verification_request_digest"),
        sa.CheckConstraint("length(actor_identity_sha256) = 64", name="verification_actor_digest"),
        sa.CheckConstraint("length(trim(actor_issuer)) > 0", name="verification_actor_issuer"),
        sa.CheckConstraint("length(trim(actor_subject)) > 0", name="verification_actor_subject"),
    )
    op.create_index(
        "ix_remediation_verifications_acknowledgment",
        "remediation_verifications",
        ["acknowledgment_event_id"],
    )
    op.create_index(
        "ix_remediation_verifications_created",
        "remediation_verifications",
        ["created_at", "verification_id"],
    )
    op.create_table(
        "remediation_verification_receipts",
        sa.Column(
            "verification_id",
            sa.Uuid(),
            sa.ForeignKey("remediation_verifications.verification_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        old._foreign("audit_event_id", "audit_events.event_id"),
        old._column("outcome", sa.String(16)),
        old._column("content", old._json()),
        old._column("content_sha256", sa.String(64)),
        old._column("created_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("audit_event_id", name="uq_verification_receipt_audit"),
        sa.CheckConstraint("length(content_sha256) = 64", name="verification_receipt_digest"),
        sa.CheckConstraint(
            "outcome IN ('VERIFIED', 'NOT_VERIFIED', 'INCONCLUSIVE')", name="verification_outcome"
        ),
    )
    op.create_index(
        "ix_verification_receipts_created",
        "remediation_verification_receipts",
        ["created_at", "verification_id"],
    )
    _guards()


def downgrade():
    # env.py performs whole-path compatibility checks before ANY downgrade DDL.
    worker, _, old = _predecessors()
    worker._drop_guard("verification_receipt", "remediation_verification_receipts", ("insert",))
    worker._drop_guard("verification_request", "remediation_verifications", ("insert",))
    for table in (
        "remediation_verification_receipts",
        "remediation_verifications",
        "remediation_verification_guard",
    ):
        op.drop_table(table)
    old._audit_constraint(_prior_events())
