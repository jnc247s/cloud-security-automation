"""Immutable execution admission/journal only; no AWS dispatch state."""

import sqlalchemy as sa
from alembic import context, op
from alembic.script import ScriptDirectory

revision = "20261007_0008"
down_revision = "20261006_0007"
branch_labels = None
depends_on = None

_HISTORY = ("remediation_executions", "remediation_execution_events")
_EVENTS = (
    "REMEDIATION_EXECUTION_REQUESTED",
    "REMEDIATION_EXECUTION_EXPIRED",
    "REMEDIATION_EXECUTION_BLOCKED",
)


def _authority():
    # Reuse the frozen predecessor's safe audit rebuild; never import evolving ORM schema.
    return ScriptDirectory.from_config(context.config).get_revision(down_revision).module


def _column(name, kind, nullable=False):
    return sa.Column(name, kind, nullable=nullable)


def _foreign(name, target, nullable=False):
    return sa.Column(name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=nullable)


def _install_guards():
    dialect = op.get_bind().dialect.name
    for table in (*_HISTORY, "remediation_admission_guard", "remediation_target_reservations"):
        actions = (
            "DELETE OR TRUNCATE"
            if table == "remediation_target_reservations"
            else "UPDATE OR DELETE OR TRUNCATE"
        )
        if dialect == "postgresql":
            op.execute(
                f"CREATE TRIGGER immutable_{table} BEFORE {actions} "
                f"ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_history_mutation()"
            )
        else:
            for action in actions.split(" OR "):
                if action == "TRUNCATE":
                    continue
                op.execute(
                    f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} "
                    f"ON {table} BEGIN SELECT RAISE(ABORT, 'historical records are immutable'); END"
                )
    lifetime = (
        "NEW.expires_at > NEW.created_at + INTERVAL '5 minutes'"
        if dialect == "postgresql"
        else "julianday(NEW.expires_at) > julianday(NEW.created_at, '+5 minutes')"
    )
    predicates = {
        "execution_admission": (
            "remediation_executions",
            "NOT EXISTS (SELECT 1 FROM remediation_proposals p JOIN remediation_decisions d "
            "ON d.proposal_id = p.proposal_id WHERE p.proposal_id = NEW.proposal_id "
            "AND d.decision_id = NEW.approval_decision_id AND d.kind = 'APPROVE' "
            "AND (p.actor_issuer <> NEW.actor_issuer OR p.actor_subject <> NEW.actor_subject) "
            "AND (d.actor_issuer <> NEW.actor_issuer OR d.actor_subject <> NEW.actor_subject) "
            "AND NEW.created_at >= d.created_at AND NEW.created_at < p.expires_at "
            "AND NEW.expires_at <= p.expires_at) OR " + lifetime + " OR EXISTS "
            "(SELECT 1 FROM remediation_decisions d WHERE d.proposal_id = NEW.proposal_id "
            "AND d.kind = 'REVOKE')",
            "INSERT",
        ),
        "execution_event": (
            "remediation_execution_events",
            "NOT EXISTS (SELECT 1 FROM remediation_executions e WHERE "
            "e.execution_id = NEW.execution_id AND NEW.created_at >= e.created_at "
            "AND (NEW.kind <> 'EXPIRED' OR NEW.created_at >= e.expires_at)) OR "
            "(NEW.sequence = 2 AND NOT EXISTS (SELECT 1 FROM remediation_execution_events v "
            "WHERE v.execution_id = NEW.execution_id AND v.sequence = 1 "
            "AND v.event_sha256 = NEW.previous_event_sha256 "
            "AND NEW.created_at >= v.created_at)) OR "
            "NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.event_id = NEW.audit_event_id "
            "AND a.target_type = 'remediation_execution' AND a.target_id = NEW.execution_id "
            "AND a.timestamp = NEW.created_at "
            "AND a.event_type = 'REMEDIATION_EXECUTION_' || NEW.kind)",
            "INSERT",
        ),
        "execution_reservation": (
            "remediation_target_reservations",
            "NOT EXISTS (SELECT 1 FROM resources r WHERE r.resource_id = NEW.resource_id "
            "AND r.aws_account_id = NEW.account_id AND r.region = NEW.region) OR "
            "(NEW.execution_id IS NOT NULL AND (NOT EXISTS (SELECT 1 FROM remediation_executions e "
            "JOIN remediation_proposals p ON p.proposal_id = e.proposal_id JOIN findings f "
            "ON f.finding_id = p.finding_id WHERE e.execution_id = NEW.execution_id "
            "AND f.resource_id = NEW.resource_id AND p.account_id = NEW.account_id "
            "AND f.region = NEW.region) OR EXISTS (SELECT 1 FROM remediation_execution_events v "
            "WHERE v.execution_id = NEW.execution_id AND v.sequence = 2)))",
            "INSERT OR UPDATE",
        ),
        "execution_reservation_clear": (
            "remediation_target_reservations",
            "OLD.execution_id IS NOT NULL AND (NEW.execution_id IS NULL OR "
            "NEW.execution_id <> OLD.execution_id) AND NOT EXISTS "
            "(SELECT 1 FROM remediation_execution_events v "
            "WHERE v.execution_id = OLD.execution_id AND v.sequence = 2)",
            "UPDATE",
        ),
    }
    for name, (table, predicate, actions) in predicates.items():
        if dialect == "postgresql":
            op.execute(
                f"CREATE FUNCTION guard_{name}() RETURNS trigger LANGUAGE plpgsql AS $$ "
                f"BEGIN IF {predicate} THEN RAISE EXCEPTION "
                "'execution admission provenance is invalid' USING ERRCODE = '23514'; "
                "END IF; RETURN NEW; END; $$"
            )
            op.execute(
                f"CREATE TRIGGER guard_{name} BEFORE {actions} ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION guard_{name}()"
            )
        else:
            for action in actions.split(" OR "):
                op.execute(
                    f"CREATE TRIGGER guard_{name}_{action.lower()} BEFORE {action} ON {table} "
                    f"WHEN {predicate} BEGIN SELECT RAISE(ABORT, "
                    "'execution admission provenance is invalid'); END"
                )


def upgrade():
    old = _authority()
    old._reserve_sqlite_writer(op.get_bind())
    op.create_table(
        "remediation_executions",
        sa.Column("execution_id", sa.Uuid(), primary_key=True),
        _foreign("proposal_id", "remediation_proposals.proposal_id"),
        _foreign("approval_decision_id", "remediation_decisions.decision_id"),
        _column("actor_identity_sha256", sa.String(64)),
        _column("actor_issuer", sa.Text()),
        _column("actor_subject", sa.Text()),
        _column("idempotency_key", sa.Uuid()),
        _column("request_sha256", sa.String(64)),
        _column("content", old._json()),
        _column("execution_sha256", sa.String(64)),
        _column("created_at", sa.DateTime(timezone=True)),
        _column("expires_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("proposal_id", name="uq_remediation_execution_proposal"),
        sa.UniqueConstraint(
            "actor_identity_sha256", "idempotency_key", name="uq_remediation_execution_key"
        ),
        sa.CheckConstraint("length(execution_sha256) = 64", name="execution_digest_length"),
        sa.CheckConstraint("length(request_sha256) = 64", name="execution_request_digest"),
        sa.CheckConstraint("length(actor_identity_sha256) = 64", name="execution_actor_digest"),
        sa.CheckConstraint("length(trim(actor_issuer)) > 0", name="execution_actor_issuer"),
        sa.CheckConstraint("length(trim(actor_subject)) > 0", name="execution_actor_subject"),
        sa.CheckConstraint("expires_at > created_at", name="execution_expiry_order"),
    )
    old._indexes(
        "remediation_executions",
        (
            ("approval", ["approval_decision_id"]),
            ("created", ["created_at", "execution_id"]),
            ("expiry", ["expires_at"]),
        ),
    )
    op.create_table(
        "remediation_execution_events",
        sa.Column("event_id", sa.Uuid(), primary_key=True),
        _foreign("execution_id", "remediation_executions.execution_id"),
        _foreign("audit_event_id", "audit_events.event_id"),
        _column("sequence", sa.Integer()),
        _column("kind", sa.String(16)),
        _column("content", old._json()),
        _column("event_sha256", sa.String(64)),
        _column("previous_event_sha256", sa.String(64), nullable=True),
        _column("created_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("execution_id", "sequence", name="uq_remediation_execution_sequence"),
        sa.UniqueConstraint("audit_event_id", name="uq_remediation_execution_audit"),
        sa.CheckConstraint("sequence BETWEEN 1 AND 2", name="execution_event_sequence"),
        sa.CheckConstraint(
            "kind IN ('REQUESTED', 'EXPIRED', 'BLOCKED')", name="execution_event_kind"
        ),
        sa.CheckConstraint("length(event_sha256) = 64", name="execution_event_digest"),
        sa.CheckConstraint(
            "(sequence = 1 AND kind = 'REQUESTED' AND previous_event_sha256 IS NULL) OR "
            "(sequence = 2 AND kind IN ('EXPIRED', 'BLOCKED') "
            "AND length(previous_event_sha256) = 64)",
            name="execution_event_transition",
        ),
    )
    op.create_table(
        "remediation_admission_guard",
        sa.Column("guard_id", sa.Integer(), primary_key=True),
        sa.CheckConstraint("guard_id = 1", name="admission_singleton"),
    )
    op.execute("INSERT INTO remediation_admission_guard (guard_id) VALUES (1)")
    op.create_table(
        "remediation_target_reservations",
        sa.Column("reservation_id", sa.Uuid(), primary_key=True),
        _foreign("resource_id", "resources.resource_id"),
        _column("account_id", sa.String(12)),
        _column("region", sa.String(64)),
        _column("action_id", sa.String(64)),
        _foreign("execution_id", "remediation_executions.execution_id", nullable=True),
        sa.UniqueConstraint(
            "account_id", "region", "action_id", name="uq_remediation_target_scope"
        ),
        sa.UniqueConstraint("execution_id", name="uq_remediation_target_execution"),
        sa.CheckConstraint("length(account_id) = 12", name="reservation_account_length"),
        sa.CheckConstraint("length(trim(region)) BETWEEN 1 AND 64", name="reservation_region"),
        sa.CheckConstraint(
            "action_id = 'aws.ec2.enable-ebs-encryption-by-default'", name="reservation_action"
        ),
    )
    op.create_index(
        "ix_remediation_target_reservations_resource",
        "remediation_target_reservations",
        ["resource_id"],
    )
    old._audit_constraint((*old._OLD_EVENTS, *old._NEW_EVENTS, *_EVENTS))
    _install_guards()


def downgrade():
    # env.py checks the complete path with writers excluded before any downgrade DDL.
    dialect = op.get_bind().dialect.name
    for name, table, actions in (
        ("execution_admission", "remediation_executions", ("insert",)),
        ("execution_event", "remediation_execution_events", ("insert",)),
        ("execution_reservation", "remediation_target_reservations", ("insert", "update")),
        ("execution_reservation_clear", "remediation_target_reservations", ("update",)),
    ):
        if dialect == "postgresql":
            op.execute(f"DROP TRIGGER guard_{name} ON {table}")
            op.execute(f"DROP FUNCTION guard_{name}()")
        else:
            for action in actions:
                op.execute(f"DROP TRIGGER guard_{name}_{action}")
    for table in (
        "remediation_target_reservations",
        "remediation_execution_events",
        "remediation_executions",
        "remediation_admission_guard",
    ):
        op.drop_table(table)
    old = _authority()
    old._audit_constraint((*old._OLD_EVENTS, *old._NEW_EVENTS))
