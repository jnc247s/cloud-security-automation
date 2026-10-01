"""Preserve unresolved regional references without inventing a target Region."""

import sqlalchemy as sa
from alembic import op

revision = "20261001_0005"
down_revision = "20260924_0004"
branch_labels = None
depends_on = None

_TABLE = "resource_relationship_observations"
_CONSTRAINT = "ck_resource_relationship_observations_target_scope_region_consistent"
_PREVIOUS = (
    "target_scope IS NULL OR "
    "(target_scope = 'regional' AND target_region IS NOT NULL) OR "
    "(target_scope = 'global' AND target_region IS NULL)"
)
_CURRENT = (
    "target_scope IS NULL OR "
    "(target_scope = 'regional' AND "
    "(target_region IS NOT NULL OR target_identity_state = 'unresolved')) OR "
    "(target_scope = 'global' AND target_region IS NULL)"
)


def _replace_constraint(expression):
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        op.drop_constraint(op.f(_CONSTRAINT), _TABLE, type_="check")
        op.create_check_constraint(op.f(_CONSTRAINT), _TABLE, expression)
        return
    # This is an unreferenced child table. Keep FK enforcement enabled and reserve the
    # writer before the trigger/table swap; never commit the caller's transaction.
    if op.get_context().as_sql:
        raise NotImplementedError("SQLite constraint repair requires an online migration")
    if not bind.connection.driver_connection.in_transaction:
        op.execute("BEGIN IMMEDIATE")
    triggers = tuple(
        bind.execute(
            sa.text(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND (tbl_name = :table OR lower(sql) LIKE :reference) ORDER BY name"
            ),
            {"table": _TABLE, "reference": f"%{_TABLE}%"},
        )
    )
    quote = bind.dialect.identifier_preparer.quote
    for name, _ in triggers:
        op.execute(sa.text(f"DROP TRIGGER {quote(name)}"))
    with op.batch_alter_table(_TABLE, recreate="always") as batch:
        batch.drop_constraint(op.f(_CONSTRAINT), type_="check")
        batch.create_check_constraint(op.f(_CONSTRAINT), expression)
    for _, sql in triggers:
        op.execute(sa.text(sql))


def upgrade():
    _replace_constraint(_CURRENT)


def downgrade():
    # env.py checks the entire path and serializes writers before any DDL.
    _replace_constraint(_PREVIOUS)
