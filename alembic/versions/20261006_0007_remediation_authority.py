"""Durable proposal/approval authority only; no remediation execution."""

import sqlalchemy as sa
from alembic import op, util
from sqlalchemy.dialects import postgresql

revision = "20261006_0007"
down_revision = "20261001_0006"
branch_labels = None
depends_on = None

_TABLES = ("remediation_proposals", "remediation_decisions", "remediation_requests")
_OLD_EVENTS = (
    "SCAN_STARTED",
    "SCAN_COMPLETED",
    "SCAN_FAILED",
    "FINDING_OPENED",
    "FINDING_UPDATED",
    "FINDING_REOPENED",
    "FINDING_ACKNOWLEDGED",
    "FINDING_RESOLVED",
    "FINDING_FALSE_POSITIVE",
    "FINDING_ACCEPTED_RISK",
    "EXCEPTION_CREATED",
    "EXCEPTION_EXPIRED",
    "EXCEPTION_REVOKED",
)
_NEW_EVENTS = (
    "REMEDIATION_PROPOSED",
    "REMEDIATION_APPROVED",
    "REMEDIATION_REJECTED",
    "REMEDIATION_REVOKED",
)


def _reserve_sqlite_writer(bind):
    if bind.dialect.name == "sqlite":
        if not bind.connection.driver_connection.in_transaction:
            op.execute("BEGIN IMMEDIATE")
        else:
            op.execute("UPDATE alembic_version SET version_num = version_num WHERE 0")


def _audit_constraint(events):
    expression = "event_type IN (" + ", ".join("'" + event + "'" for event in events) + ")"
    name = op.f("ck_audit_events_audit_event_type")
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        op.drop_constraint(name, "audit_events", type_="check")
        op.create_check_constraint(name, "audit_events", expression)
        return
    if op.get_context().as_sql:
        raise NotImplementedError("SQLite audit migration requires online execution")
    _reserve_sqlite_writer(bind)
    if bind.execute(sa.text("PRAGMA foreign_key_check")).first() is not None:
        raise util.CommandError("Audit migration requires valid retained foreign keys.")
    triggers = tuple(
        bind.execute(
            sa.text(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND (tbl_name = 'audit_events' OR lower(sql) LIKE '%audit_events%') ORDER BY name"
            )
        )
    )
    deferred = bind.scalar(sa.text("PRAGMA defer_foreign_keys"))
    quote = bind.dialect.identifier_preparer.quote
    op.execute("PRAGMA defer_foreign_keys=ON")
    try:
        with bind.begin_nested():
            for trigger_name, _ in triggers:
                op.execute(sa.text(f"DROP TRIGGER {quote(trigger_name)}"))
            with op.batch_alter_table("audit_events", recreate="always") as batch:
                batch.drop_constraint(name, type_="check")
                batch.create_check_constraint(name, expression)
            for _, sql in triggers:
                op.execute(sa.text(sql))
            if bind.execute(sa.text("PRAGMA foreign_key_check")).first() is not None:
                raise util.CommandError("Audit migration did not preserve retained foreign keys.")
        op.execute("PRAGMA defer_foreign_keys=OFF")
    finally:
        op.execute(f"PRAGMA defer_foreign_keys={'ON' if deferred else 'OFF'}")


def _column(name, kind, nullable=False):
    return sa.Column(name, kind, nullable=nullable)


def _foreign(name, target, nullable=False):
    return sa.Column(name, sa.Uuid(), sa.ForeignKey(target, ondelete="RESTRICT"), nullable=nullable)


def _actors(prefix, roles=True):
    columns = [
        _column("actor_issuer", sa.Text()),
        _column("actor_subject", sa.Text()),
        sa.CheckConstraint("length(trim(actor_issuer)) > 0", name=f"{prefix}_actor_issuer"),
        sa.CheckConstraint("length(trim(actor_subject)) > 0", name=f"{prefix}_actor_subject"),
    ]
    if roles:
        columns.append(_column("actor_roles", _json()))
    return columns


def _json():
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _indexes(table, columns_by_suffix):
    for suffix, columns in columns_by_suffix:
        op.create_index("ix_" + table + "_" + suffix, table, columns)


_INSERT_GUARDS = {
    "remediation_proposal": (
        "remediation_proposals",
        "NOT EXISTS (SELECT 1 FROM finding_occurrences o JOIN findings f "
        "ON f.finding_id = o.finding_id WHERE o.occurrence_id = NEW.occurrence_id "
        "AND o.finding_id = NEW.finding_id AND f.aws_account_id = NEW.account_id)",
    ),
    "remediation_decision": (
        "remediation_decisions",
        "NOT EXISTS (SELECT 1 FROM remediation_proposals p "
        "WHERE p.proposal_id = NEW.proposal_id AND p.proposal_sha256 = NEW.proposal_sha256 "
        "AND NEW.created_at >= p.created_at "
        "AND (NEW.kind = 'REVOKE' OR p.actor_issuer <> NEW.actor_issuer "
        "OR p.actor_subject <> NEW.actor_subject) "
        "AND (NEW.kind <> 'APPROVE' OR NEW.created_at < p.expires_at)) "
        "OR (NEW.kind = 'REVOKE' AND NOT EXISTS (SELECT 1 FROM remediation_decisions d "
        "WHERE d.decision_id = NEW.approval_decision_id AND d.proposal_id = NEW.proposal_id "
        "AND d.kind = 'APPROVE' AND NEW.created_at >= d.created_at))",
    ),
    "remediation_request": (
        "remediation_requests",
        "(NEW.operation = 'CREATE' AND NOT EXISTS (SELECT 1 FROM remediation_proposals p "
        "WHERE p.proposal_id = NEW.proposal_id AND p.actor_issuer = NEW.actor_issuer "
        "AND p.actor_subject = NEW.actor_subject)) "
        "OR (NEW.operation <> 'CREATE' AND NOT EXISTS (SELECT 1 FROM remediation_decisions d "
        "WHERE d.decision_id = NEW.decision_id AND d.proposal_id = NEW.proposal_id "
        "AND d.actor_issuer = NEW.actor_issuer AND d.actor_subject = NEW.actor_subject "
        "AND ((NEW.operation = 'REVOKE' AND d.kind = 'REVOKE') OR "
        "(NEW.operation = 'DECIDE' AND d.kind IN ('APPROVE', 'REJECT')))))",
    ),
}


def _install_guards():
    dialect = op.get_bind().dialect.name
    for table in _TABLES:
        if dialect == "postgresql":
            op.execute(
                f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE OR TRUNCATE "
                f"ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_history_mutation()"
            )
        elif dialect == "sqlite":
            for action in ("UPDATE", "DELETE"):
                op.execute(
                    f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} "
                    f"ON {table} BEGIN SELECT RAISE(ABORT, 'historical records are immutable'); END"
                )
    for name, (table, predicate) in _INSERT_GUARDS.items():
        if dialect == "postgresql":
            op.execute(
                f"CREATE FUNCTION guard_{name}() RETURNS trigger LANGUAGE plpgsql AS $$ "
                f"BEGIN IF {predicate} THEN RAISE EXCEPTION "
                "'remediation authority provenance is invalid' USING ERRCODE = '23514'; "
                "END IF; RETURN NEW; END; $$"
            )
            op.execute(
                f"CREATE TRIGGER guard_{name} BEFORE INSERT ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION guard_{name}()"
            )
        elif dialect == "sqlite":
            op.execute(
                f"CREATE TRIGGER guard_{name} BEFORE INSERT ON {table} WHEN {predicate} "
                "BEGIN SELECT RAISE(ABORT, 'remediation authority provenance is invalid'); END"
            )


def upgrade():
    _reserve_sqlite_writer(op.get_bind())
    op.create_table(
        "remediation_proposals",
        sa.Column("proposal_id", sa.Uuid(), primary_key=True),
        _foreign("finding_id", "findings.finding_id"),
        _foreign("occurrence_id", "finding_occurrences.occurrence_id"),
        _column("account_id", sa.String(12)),
        *_actors("proposal"),
        _column("content", _json()),
        _column("proposal_sha256", sa.String(64)),
        _column("created_at", sa.DateTime(timezone=True)),
        _column("expires_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("length(proposal_sha256) = 64", name="proposal_digest_length"),
        sa.CheckConstraint("expires_at > created_at", name="proposal_expiry_order"),
        sa.CheckConstraint("length(account_id) = 12", name="proposal_account_length"),
    )
    _indexes(
        "remediation_proposals",
        (
            ("finding_created", ["finding_id", "created_at"]),
            ("account_created", ["account_id", "created_at"]),
            ("occurrence", ["occurrence_id"]),
        ),
    )
    op.create_table(
        "remediation_decisions",
        sa.Column("decision_id", sa.Uuid(), primary_key=True),
        _foreign("proposal_id", "remediation_proposals.proposal_id"),
        _column("kind", sa.String(16)),
        _column("proposal_sha256", sa.String(64)),
        _foreign("approval_decision_id", "remediation_decisions.decision_id", nullable=True),
        *_actors("decision"),
        _column("reason", sa.Text()),
        _column("created_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("kind IN ('APPROVE', 'REJECT', 'REVOKE')", name="decision_kind"),
        sa.CheckConstraint(
            "(kind = 'REVOKE' AND approval_decision_id IS NOT NULL) OR "
            "(kind <> 'REVOKE' AND approval_decision_id IS NULL)",
            name="decision_approval_reference",
        ),
        sa.CheckConstraint("length(trim(reason)) BETWEEN 1 AND 2000", name="decision_reason"),
        sa.CheckConstraint("length(proposal_sha256) = 64", name="decision_digest_length"),
    )
    for suffix, predicate in (
        ("initial", "kind IN ('APPROVE', 'REJECT')"),
        ("revocation", "kind = 'REVOKE'"),
    ):
        op.create_index(
            "uq_remediation_decisions_" + suffix,
            "remediation_decisions",
            ["proposal_id"],
            unique=True,
            postgresql_where=sa.text(predicate),
            sqlite_where=sa.text(predicate),
        )
    _indexes(
        "remediation_decisions",
        (
            ("proposal", ["proposal_id"]),
            ("approval", ["approval_decision_id"]),
        ),
    )
    op.create_table(
        "remediation_requests",
        sa.Column("request_id", sa.Uuid(), primary_key=True),
        _column("actor_identity_sha256", sa.String(64)),
        *_actors("request", roles=False),
        _column("operation", sa.String(16)),
        _column("idempotency_key", sa.Uuid()),
        _column("request_sha256", sa.String(64)),
        _foreign("proposal_id", "remediation_proposals.proposal_id"),
        _foreign("decision_id", "remediation_decisions.decision_id", nullable=True),
        sa.UniqueConstraint(
            "actor_identity_sha256",
            "operation",
            "idempotency_key",
            name="uq_remediation_request_key",
        ),
        sa.CheckConstraint("operation IN ('CREATE', 'DECIDE', 'REVOKE')", name="request_operation"),
        sa.CheckConstraint(
            "(operation = 'CREATE' AND decision_id IS NULL) OR "
            "(operation <> 'CREATE' AND decision_id IS NOT NULL)",
            name="request_result_kind",
        ),
        sa.CheckConstraint("length(request_sha256) = 64", name="request_digest_length"),
        sa.CheckConstraint("length(actor_identity_sha256) = 64", name="request_actor_digest"),
    )
    _indexes(
        "remediation_requests",
        (
            ("proposal", ["proposal_id"]),
            ("decision", ["decision_id"]),
        ),
    )
    _audit_constraint((*_OLD_EVENTS, *_NEW_EVENTS))
    op.create_index(
        "ix_control_assessments_target_control",
        "control_assessments",
        ["resource_id", "control_id"],
    )
    _install_guards()


def downgrade():
    # env.py holds writer-excluding locks and checks the full path before any DDL.
    dialect = op.get_bind().dialect.name
    for name, (table, _) in _INSERT_GUARDS.items():
        if dialect == "postgresql":
            op.execute(f"DROP TRIGGER guard_{name} ON {table}")
            op.execute(f"DROP FUNCTION guard_{name}()")
        elif dialect == "sqlite":
            op.execute(f"DROP TRIGGER guard_{name}")
    for table in reversed(_TABLES):
        op.drop_table(table)
    op.drop_index("ix_control_assessments_target_control", table_name="control_assessments")
    _audit_constraint(_OLD_EVENTS)
