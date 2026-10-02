"""Add the approved governance category without rewriting retained control history."""

import sqlalchemy as sa
from alembic import op, util

revision = "20261001_0006"
down_revision = "20261001_0005"
branch_labels = None
depends_on = None

_TABLE = "control_versions"
_CONSTRAINT = "ck_control_versions_control_category"
_PREVIOUS = "category IN ('network', 'storage', 'identity', 'logging')"
_CURRENT = "category IN ('network', 'storage', 'identity', 'logging', 'governance')"


def _replace_constraint(expression):
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        op.drop_constraint(op.f(_CONSTRAINT), _TABLE, type_="check")
        op.create_check_constraint(op.f(_CONSTRAINT), _TABLE, expression)
        return
    if op.get_context().as_sql:
        raise NotImplementedError("SQLite category migration requires an online migration")
    # Reserve the writer, preserving an existing caller-owned transaction and FK enforcement.
    if not bind.connection.driver_connection.in_transaction:
        op.execute("BEGIN IMMEDIATE")
    else:
        op.execute("UPDATE alembic_version SET version_num = version_num WHERE 0")
    if bind.execute(sa.text("PRAGMA foreign_key_check")).first() is not None:
        raise util.CommandError("Category migration requires valid retained foreign keys.")
    inspector = sa.inspect(bind)
    for table in inspector.get_table_names():
        for foreign_key in inspector.get_foreign_keys(table):
            if foreign_key["referred_table"] == _TABLE and foreign_key.get("options", {}).get(
                "ondelete", "NO ACTION"
            ).upper() not in {"RESTRICT", "NO ACTION"}:
                raise util.CommandError(
                    "Category migration cannot preserve this foreign key action."
                )
    triggers = tuple(
        bind.execute(
            sa.text(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND (tbl_name = :table OR lower(sql) LIKE :reference) ORDER BY name"
            ),
            {"table": _TABLE, "reference": f"%{_TABLE}%"},
        )
    )
    deferred = bind.scalar(sa.text("PRAGMA defer_foreign_keys"))
    quote = bind.dialect.identifier_preparer.quote
    op.execute("PRAGMA defer_foreign_keys=ON")
    try:
        # A failed swap rolls itself back even if the outer caller catches the error.
        with bind.begin_nested():
            for name, _ in triggers:
                op.execute(sa.text(f"DROP TRIGGER {quote(name)}"))
            with op.batch_alter_table(_TABLE, recreate="always") as batch:
                batch.drop_constraint(op.f(_CONSTRAINT), type_="check")
                batch.create_check_constraint(op.f(_CONSTRAINT), expression)
            for _, sql in triggers:
                op.execute(sa.text(sql))
            if bind.execute(sa.text("PRAGMA foreign_key_check")).first() is not None:
                raise util.CommandError(
                    "Category migration did not preserve retained foreign keys."
                )
        # SQLite retains a deferred violation counter for the replaced parent, even after
        # all references resolve again. Clear it ONLY after the complete integrity check.
        # Never disable foreign_keys or commit the caller's transaction.
        op.execute("PRAGMA defer_foreign_keys=OFF")
    finally:
        op.execute(f"PRAGMA defer_foreign_keys={'ON' if deferred else 'OFF'}")


def upgrade():
    _replace_constraint(_CURRENT)


def downgrade():
    # env.py preflights the entire downgrade path before any DDL and excludes writers.
    _replace_constraint(_PREVIOUS)
