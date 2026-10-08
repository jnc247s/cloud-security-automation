"""Add private fenced claims and versioned worker journal states; preserve 0008 history."""

import sqlalchemy as sa
from alembic import context, op, util
from alembic.script import ScriptDirectory

revision = "20261008_0009"
down_revision = "20261007_0008"
branch_labels = None
depends_on = None

_WORKER_EVENTS = (
    "CLAIMED",
    "WRITE_INTENT",
    "NO_WRITE",
    "ACKNOWLEDGED",
    "QUARANTINED",
    "OBSERVED",
    "OBSERVATION_FAILED",
)
_EVENT_TABLE = "remediation_execution_events"
_OLD_CHECKS = {
    "execution_event_sequence": "sequence BETWEEN 1 AND 2",
    "execution_event_kind": "kind IN ('REQUESTED', 'EXPIRED', 'BLOCKED')",
    "execution_event_transition": (
        "(sequence = 1 AND kind = 'REQUESTED' AND previous_event_sha256 IS NULL) OR "
        "(sequence = 2 AND kind IN ('EXPIRED', 'BLOCKED') "
        "AND length(previous_event_sha256) = 64)"
    ),
}
_NEW_CHECKS = {
    "execution_event_sequence": "sequence >= 1",
    "execution_event_kind": (
        "kind IN ('REQUESTED', 'EXPIRED', 'BLOCKED', 'CLAIMED', 'WRITE_INTENT', "
        "'NO_WRITE', 'ACKNOWLEDGED', 'QUARANTINED', 'OBSERVED', 'OBSERVATION_FAILED')"
    ),
    "execution_event_transition": (
        "(sequence = 1 AND kind = 'REQUESTED' AND previous_event_sha256 IS NULL) OR "
        "(sequence >= 2 AND kind <> 'REQUESTED' AND length(previous_event_sha256) = 64 "
        "AND (kind NOT IN ('EXPIRED', 'BLOCKED') OR sequence = 2))"
    ),
}


def _admission():
    return ScriptDirectory.from_config(context.config).get_revision(down_revision).module


def _drop_guard(name, table, actions):
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP TRIGGER guard_{name} ON {table}")
        op.execute(f"DROP FUNCTION guard_{name}()")
    else:
        for action in actions:
            op.execute(f"DROP TRIGGER guard_{name}_{action}")


def _install_guard(name, table, predicate, actions):
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            f"CREATE FUNCTION guard_{name}() RETURNS trigger LANGUAGE plpgsql AS $$ "
            f"BEGIN IF {predicate} THEN RAISE EXCEPTION "
            "'execution worker provenance is invalid' USING ERRCODE = '23514'; "
            "END IF; RETURN NEW; END; $$"
        )
        op.execute(
            f"CREATE TRIGGER guard_{name} BEFORE {' OR '.join(a.upper() for a in actions)} "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION guard_{name}()"
        )
    else:
        for action in actions:
            op.execute(
                f"CREATE TRIGGER guard_{name}_{action} BEFORE {action.upper()} ON {table} "
                f"WHEN {predicate} BEGIN SELECT RAISE(ABORT, "
                "'execution worker provenance is invalid'); END"
            )


def _event_constraints(checks, *, length):
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        for name, expression in checks.items():
            full_name = op.f(f"ck_{_EVENT_TABLE}_{name}")
            op.drop_constraint(full_name, _EVENT_TABLE, type_="check")
            op.create_check_constraint(full_name, _EVENT_TABLE, expression)
        op.alter_column(_EVENT_TABLE, "kind", type_=sa.String(length), existing_nullable=False)
        return
    if op.get_context().as_sql:
        raise util.CommandError("SQLite worker migration requires online execution")
    if bind.execute(sa.text("PRAGMA foreign_key_check")).first() is not None:
        raise util.CommandError("Worker migration requires valid retained foreign keys")
    triggers = tuple(
        bind.execute(
            sa.text(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND (tbl_name = 'remediation_execution_events' "
                "OR lower(sql) LIKE '%remediation_execution_events%') ORDER BY name"
            )
        )
    )
    deferred = bind.scalar(sa.text("PRAGMA defer_foreign_keys"))
    quote = bind.dialect.identifier_preparer.quote
    op.execute("PRAGMA defer_foreign_keys=ON")
    try:
        with bind.begin_nested():
            for name, _ in triggers:
                op.execute(sa.text(f"DROP TRIGGER {quote(name)}"))
            with op.batch_alter_table(_EVENT_TABLE, recreate="always") as batch:
                for name, expression in checks.items():
                    full_name = op.f(f"ck_{_EVENT_TABLE}_{name}")
                    batch.drop_constraint(full_name, type_="check")
                    batch.create_check_constraint(full_name, expression)
                batch.alter_column("kind", type_=sa.String(length), existing_nullable=False)
            for _, sql in triggers:
                op.execute(sa.text(sql))
            if bind.execute(sa.text("PRAGMA foreign_key_check")).first() is not None:
                raise util.CommandError("Worker migration did not preserve retained foreign keys")
        op.execute("PRAGMA defer_foreign_keys=OFF")
    finally:
        op.execute(f"PRAGMA defer_foreign_keys={'ON' if deferred else 'OFF'}")


def _terminal(execution):
    return (
        f"EXISTS (SELECT 1 FROM remediation_execution_events v WHERE v.execution_id = {execution} "
        "AND v.kind IN ('EXPIRED', 'BLOCKED', 'NO_WRITE')) OR "
        f"(EXISTS (SELECT 1 FROM remediation_execution_events v WHERE v.execution_id = {execution} "
        "AND v.kind = 'ACKNOWLEDGED') AND NOT EXISTS (SELECT 1 FROM remediation_execution_events q "
        f"WHERE q.execution_id = {execution} AND q.kind = 'QUARANTINED'))"
    )


def _install_worker_guards():
    _install_guard(
        "execution_event",
        _EVENT_TABLE,
        (
            "NOT EXISTS (SELECT 1 FROM remediation_executions e "
            "WHERE e.execution_id = NEW.execution_id AND NEW.created_at >= e.created_at "
            "AND (NEW.kind <> 'EXPIRED' OR NEW.created_at >= e.expires_at) "
            "AND (NEW.kind NOT IN ('CLAIMED', 'WRITE_INTENT') "
            "OR NEW.created_at < e.expires_at)) OR "
            "EXISTS (SELECT 1 FROM remediation_execution_events x "
            "WHERE x.execution_id = NEW.execution_id "
            "AND x.sequence >= NEW.sequence) OR "
            "(NEW.sequence > 1 AND NOT EXISTS (SELECT 1 FROM remediation_execution_events v "
            "WHERE v.execution_id = NEW.execution_id AND v.sequence = NEW.sequence - 1 "
            "AND v.event_sha256 = NEW.previous_event_sha256 AND NEW.created_at >= v.created_at "
            "AND ((NEW.kind IN ('EXPIRED', 'BLOCKED') AND v.kind = 'REQUESTED') "
            "OR (NEW.kind = 'CLAIMED' AND v.kind IN ('REQUESTED', 'CLAIMED')) "
            "OR (NEW.kind = 'WRITE_INTENT' AND v.kind = 'CLAIMED') "
            "OR (NEW.kind = 'NO_WRITE' AND v.kind IN ('REQUESTED', 'CLAIMED')) "
            "OR (NEW.kind IN ('ACKNOWLEDGED', 'QUARANTINED') "
            "AND v.kind IN ('WRITE_INTENT', 'QUARANTINED', 'OBSERVED', 'OBSERVATION_FAILED')) "
            "OR (NEW.kind IN ('OBSERVED', 'OBSERVATION_FAILED') "
            "AND v.kind IN ('ACKNOWLEDGED', 'QUARANTINED', 'OBSERVED', "
            "'OBSERVATION_FAILED'))))) OR "
            "(NEW.kind = 'CLAIMED' AND EXISTS (SELECT 1 FROM remediation_worker_claims c "
            "WHERE c.execution_id = NEW.execution_id AND "
            "(c.write_intent_event_id IS NOT NULL OR NEW.created_at < c.lease_until))) OR "
            "(NEW.kind = 'WRITE_INTENT' AND NOT EXISTS (SELECT 1 FROM remediation_worker_claims c "
            "WHERE c.execution_id = NEW.execution_id AND c.write_intent_event_id IS NULL "
            "AND NEW.created_at < c.lease_until)) OR "
            "NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.event_id = NEW.audit_event_id "
            "AND a.target_type = 'remediation_execution' AND a.target_id = NEW.execution_id "
            "AND a.timestamp = NEW.created_at "
            "AND a.event_type = 'REMEDIATION_EXECUTION_' || NEW.kind)"
        ),
        ("insert",),
    )
    _install_guard(
        "execution_reservation",
        "remediation_target_reservations",
        (
            "NOT EXISTS (SELECT 1 FROM resources r WHERE r.resource_id = NEW.resource_id "
            "AND r.aws_account_id = NEW.account_id AND r.region = NEW.region) OR "
            "(NEW.execution_id IS NOT NULL AND (NOT EXISTS (SELECT 1 FROM remediation_executions e "
            "JOIN remediation_proposals p ON p.proposal_id = e.proposal_id JOIN findings f "
            "ON f.finding_id = p.finding_id WHERE e.execution_id = NEW.execution_id "
            "AND f.resource_id = NEW.resource_id AND p.account_id = NEW.account_id "
            "AND f.region = NEW.region) OR (" + _terminal("NEW.execution_id") + ")))"
        ),
        ("insert", "update"),
    )
    _install_guard(
        "execution_reservation_clear",
        "remediation_target_reservations",
        (
            "OLD.execution_id IS NOT NULL AND (NEW.execution_id IS NULL OR "
            "NEW.execution_id <> OLD.execution_id) AND NOT (" + _terminal("OLD.execution_id") + ")"
        ),
        ("update",),
    )
    _install_guard(
        "worker_claim_scope",
        "remediation_worker_claims",
        (
            "NOT EXISTS (SELECT 1 FROM remediation_executions e "
            "WHERE e.execution_id = NEW.execution_id "
            "AND NEW.lease_until <= e.expires_at AND NEW.lease_until > e.created_at) OR "
            "(NEW.write_intent_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM "
            "remediation_execution_events v WHERE v.event_id = NEW.write_intent_event_id "
            "AND v.execution_id = NEW.execution_id AND v.kind = 'WRITE_INTENT'))"
        ),
        ("insert", "update"),
    )
    _install_guard(
        "worker_claim_fence",
        "remediation_worker_claims",
        (
            "NEW.expected_role_arn <> OLD.expected_role_arn "
            "OR NEW.read_attempts < OLD.read_attempts OR "
            "NEW.read_attempts > OLD.read_attempts + 1 OR "
            "NEW.readback_attempts < OLD.readback_attempts OR "
            "NEW.readback_attempts > OLD.readback_attempts + 1 OR "
            "(OLD.readback_started_at IS NOT NULL AND (NEW.readback_started_at IS NULL OR "
            "NEW.readback_started_at <> OLD.readback_started_at)) OR "
            "(OLD.write_intent_event_id IS NOT NULL AND (NEW.write_intent_event_id IS NULL OR "
            "NEW.write_intent_event_id <> OLD.write_intent_event_id OR "
            "NEW.token_sha256 <> OLD.token_sha256 OR NEW.generation <> OLD.generation OR "
            "NEW.lease_until <> OLD.lease_until)) OR "
            "(OLD.write_intent_event_id IS NULL AND "
            "((NEW.token_sha256 = OLD.token_sha256 AND (NEW.generation <> OLD.generation "
            "OR NEW.lease_until <> OLD.lease_until)) OR "
            "(NEW.token_sha256 <> OLD.token_sha256 AND (NEW.generation <> OLD.generation + 1 OR "
            "NOT EXISTS (SELECT 1 FROM remediation_execution_events v WHERE v.execution_id = "
            "OLD.execution_id AND v.kind = 'CLAIMED' AND v.created_at >= OLD.lease_until "
            "AND v.sequence = (SELECT max(x.sequence) FROM remediation_execution_events x "
            "WHERE x.execution_id = OLD.execution_id))))))"
        ),
        ("update",),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE TRIGGER immutable_remediation_worker_claims BEFORE DELETE OR TRUNCATE "
            "ON remediation_worker_claims FOR EACH STATEMENT "
            "EXECUTE FUNCTION reject_history_mutation()"
        )
    else:
        op.execute(
            "CREATE TRIGGER immutable_remediation_worker_claims_delete BEFORE DELETE "
            "ON remediation_worker_claims BEGIN SELECT RAISE(ABORT, "
            "'worker claims cannot be erased'); END"
        )


def upgrade():
    admission = _admission()
    authority = admission._authority()
    authority._reserve_sqlite_writer(op.get_bind())
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "LOCK TABLE remediation_admission_guard, remediation_executions, "
            "remediation_execution_events, remediation_target_reservations, audit_events "
            "IN ACCESS EXCLUSIVE MODE"
        )
    authority._audit_constraint(
        (
            *authority._OLD_EVENTS,
            *authority._NEW_EVENTS,
            *admission._EVENTS,
            *("REMEDIATION_EXECUTION_" + kind for kind in _WORKER_EVENTS),
        )
    )
    for name, table, actions in (
        ("execution_event", _EVENT_TABLE, ("insert",)),
        ("execution_reservation", "remediation_target_reservations", ("insert", "update")),
        ("execution_reservation_clear", "remediation_target_reservations", ("update",)),
    ):
        _drop_guard(name, table, actions)
    _event_constraints(_NEW_CHECKS, length=32)
    op.create_index(
        "uq_remediation_execution_single_intent_receipt",
        _EVENT_TABLE,
        ["execution_id", "kind"],
        unique=True,
        sqlite_where=sa.text("kind IN ('WRITE_INTENT', 'ACKNOWLEDGED')"),
        postgresql_where=sa.text("kind IN ('WRITE_INTENT', 'ACKNOWLEDGED')"),
    )
    op.create_table(
        "remediation_worker_claims",
        sa.Column(
            "execution_id",
            sa.Uuid(),
            sa.ForeignKey("remediation_executions.execution_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("token_sha256", sa.String(64), nullable=False),
        sa.Column("expected_role_arn", sa.String(2048), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("read_attempts", sa.Integer(), nullable=False),
        sa.Column("readback_attempts", sa.Integer(), nullable=False),
        sa.Column("readback_started_at", sa.DateTime(timezone=True)),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "write_intent_event_id",
            sa.Uuid(),
            sa.ForeignKey("remediation_execution_events.event_id", ondelete="RESTRICT"),
        ),
        sa.CheckConstraint("length(token_sha256) = 64", name="worker_token_digest"),
        sa.CheckConstraint("generation >= 1", name="worker_claim_generation"),
        sa.CheckConstraint("read_attempts BETWEEN 0 AND 3", name="worker_read_budget"),
        sa.CheckConstraint("readback_attempts BETWEEN 0 AND 3", name="worker_readback_budget"),
        sa.CheckConstraint(
            "(readback_attempts = 0 AND readback_started_at IS NULL) OR "
            "(readback_attempts > 0 AND readback_started_at IS NOT NULL)",
            name="worker_readback_window",
        ),
        sa.CheckConstraint("length(trim(expected_role_arn)) > 0", name="worker_role"),
    )
    op.create_index(
        "ix_remediation_worker_claims_lease",
        "remediation_worker_claims",
        ["lease_until", "execution_id"],
    )
    op.create_index(
        "ix_remediation_worker_claims_intent",
        "remediation_worker_claims",
        ["write_intent_event_id"],
    )
    _install_worker_guards()


def downgrade():
    # env.py verifies the complete path before any DDL with the coordination guard held.
    for name, table, actions in (
        ("worker_claim_fence", "remediation_worker_claims", ("update",)),
        ("worker_claim_scope", "remediation_worker_claims", ("insert", "update")),
        ("execution_event", _EVENT_TABLE, ("insert",)),
        ("execution_reservation", "remediation_target_reservations", ("insert", "update")),
        ("execution_reservation_clear", "remediation_target_reservations", ("update",)),
    ):
        _drop_guard(name, table, actions)
    op.drop_table("remediation_worker_claims")
    op.drop_index("uq_remediation_execution_single_intent_receipt", table_name=_EVENT_TABLE)
    _event_constraints(_OLD_CHECKS, length=16)
    admission = _admission()
    authority = admission._authority()
    authority._audit_constraint(
        (*authority._OLD_EVENTS, *authority._NEW_EVENTS, *admission._EVENTS)
    )
    # Restore the exact frozen predecessor guards, not a hand-maintained approximation.
    dialect = op.get_bind().dialect.name
    for table in (
        "remediation_executions",
        _EVENT_TABLE,
        "remediation_admission_guard",
        "remediation_target_reservations",
    ):
        if dialect == "postgresql":
            op.execute(f"DROP TRIGGER immutable_{table} ON {table}")
        else:
            actions = (
                ("delete",) if table == "remediation_target_reservations" else ("update", "delete")
            )
            for action in actions:
                op.execute(f"DROP TRIGGER immutable_{table}_{action}")
    _drop_guard("execution_admission", "remediation_executions", ("insert",))
    admission._install_guards()
