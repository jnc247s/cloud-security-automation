"""allow a pending scan before AWS collection

Revision ID: 20260904_0002
Revises: 20260903_0001
Create Date: 2026-09-04 16:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260904_0002"
down_revision: str | None = "20260903_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alter_pending_identity_nullability(*, nullable: bool, add_constraint: bool) -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        # SQLite cannot rebuild a populated referenced parent while FK enforcement
        # is enabled, and changing that PRAGMA inside a DBAPI transaction is a
        # no-op. SQLite DDL is already non-transactional under Alembic, so end the
        # DBAPI transaction without closing SQLAlchemy's migration context, disable
        # enforcement only for the table swap, then always restore it.
        dbapi_connection = op.get_bind().connection.driver_connection
        dbapi_connection.commit()
        dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        # SQLite recreates the table for a nullability change. Temporarily remove
        # every trigger whose SQL references ``scans`` so schema validation does
        # not see a dangling parent name during that operation, then restore the
        # exact trigger definitions installed by the prior migration.
        trigger_rows = tuple(
            op.get_bind()
            .execute(
                sa.text(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type = 'trigger' AND lower(sql) LIKE '%scans%'"
                )
            )
            .all()
        )
        try:
            for trigger_name, _ in trigger_rows:
                op.execute(f'DROP TRIGGER "{trigger_name}"')
            with op.batch_alter_table("scans") as batch_op:
                if not add_constraint:
                    batch_op.drop_constraint(
                        op.f("ck_scans_completed_evidence_identity_present"),
                        type_="check",
                    )
                batch_op.alter_column(
                    "aws_account_id",
                    existing_type=sa.String(length=32),
                    nullable=nullable,
                )
                batch_op.alter_column(
                    "inventory_sha256",
                    existing_type=sa.String(length=64),
                    nullable=nullable,
                )
                if add_constraint:
                    batch_op.create_check_constraint(
                        op.f("ck_scans_completed_evidence_identity_present"),
                        "status NOT IN ('COMPLETED', 'PARTIAL') OR "
                        "(aws_account_id IS NOT NULL AND inventory_sha256 IS NOT NULL)",
                    )
            for _, trigger_sql in trigger_rows:
                if trigger_sql is not None:
                    op.execute(trigger_sql)
        finally:
            dbapi_connection.commit()
            dbapi_connection.execute("PRAGMA foreign_keys=ON")
        return
    if not add_constraint:
        op.drop_constraint(
            op.f("ck_scans_completed_evidence_identity_present"),
            "scans",
            type_="check",
        )
    op.alter_column(
        "scans",
        "aws_account_id",
        existing_type=sa.String(length=32),
        nullable=nullable,
    )
    op.alter_column(
        "scans",
        "inventory_sha256",
        existing_type=sa.String(length=64),
        nullable=nullable,
    )
    if add_constraint:
        op.create_check_constraint(
            op.f("ck_scans_completed_evidence_identity_present"),
            "scans",
            "status NOT IN ('COMPLETED', 'PARTIAL') OR "
            "(aws_account_id IS NOT NULL AND inventory_sha256 IS NOT NULL)",
        )


def upgrade() -> None:
    """Allow a durable RUNNING scan before its inventory digest exists."""

    _alter_pending_identity_nullability(nullable=True, add_constraint=True)


def downgrade() -> None:
    """Restore the Sprint 3 requirement after all pending scans are complete."""

    _alter_pending_identity_nullability(nullable=False, add_constraint=False)
