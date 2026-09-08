"""Alembic environment for the cloud security persistence schema."""

from __future__ import annotations

from logging.config import fileConfig
from typing import Final

from alembic import context, util
from alembic.script import ScriptDirectory
from alembic.script.revision import RangeNotAncestorError
from sqlalchemy import Connection, engine_from_config, pool, text

import app.models  # noqa: F401
from app.config import get_settings
from app.database.base import Base

config = context.config
if config.config_file_name is not None and "connection" not in config.attributes:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

database_url = config.attributes.get("database_url", get_settings().database_url)
config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
target_metadata = Base.metadata
script_directory = ScriptDirectory.from_config(config)

_PENDING_SCAN_INVENTORY_REVISION: Final = "20260904_0002"
_RECOVERY_DOCUMENT: Final = "docs/operations/known-limitations.md"
_UNSAFE_DOWNGRADE_MESSAGE: Final = (
    "Downgrade blocked before revision 20260904_0002: retained scan history contains "
    "NULL aws_account_id or inventory_sha256 values that the older NOT NULL schema cannot "
    "represent. No schema or data changes were applied. Keep the current revision, take a "
    f"verified backup, and follow the safe recovery guidance in {_RECOVERY_DOCUMENT}."
)
_OFFLINE_DOWNGRADE_MESSAGE: Final = (
    "Offline downgrade blocked before revision 20260904_0002: retained scan compatibility "
    "must be verified against the live database before the older NOT NULL schema can be "
    "restored. Run the downgrade online during a maintenance window and follow "
    f"{_RECOVERY_DOCUMENT}."
)


def _downgrades_pending_scan_inventory(
    current_revisions: str | tuple[str, ...] | None,
) -> bool:
    """Return whether the requested path would execute revision 0002's downgrade."""

    if not current_revisions:
        return False
    try:
        destination_revision = context.get_revision_argument()
    except KeyError:
        # Commands such as ``alembic check`` run this environment without a
        # destination revision and cannot be a downgrade.
        return False

    try:
        revisions = script_directory.iterate_revisions(
            current_revisions,
            destination_revision,
            select_for_downgrade=True,
        )
        return any(revision.revision == _PENDING_SCAN_INVENTORY_REVISION for revision in revisions)
    except RangeNotAncestorError:
        # The requested path is an upgrade rather than a downgrade.
        return False


def _assert_pending_scan_downgrade_safe(connection: Connection) -> None:
    """Reject a rollback that the older non-null scan schema cannot represent."""

    if connection.dialect.name == "postgresql":
        # The following ALTER COLUMN operations require ACCESS EXCLUSIVE anyway.
        # Taking that lock before the predicate check prevents a concurrent
        # RUNNING scan insert from invalidating the decision before DDL executes.
        connection.execute(text("LOCK TABLE scans IN ACCESS EXCLUSIVE MODE"))

    incompatible_row_exists = connection.execute(
        text(
            "SELECT EXISTS ("
            "SELECT 1 FROM scans "
            "WHERE aws_account_id IS NULL OR inventory_sha256 IS NULL"
            ")"
        )
    ).scalar_one()
    if incompatible_row_exists:
        raise util.CommandError(_UNSAFE_DOWNGRADE_MESSAGE)


def run_migrations_offline() -> None:
    """Run migrations without creating a database connection."""

    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    if _downgrades_pending_scan_inventory(context.get_starting_revision_argument()):
        raise util.CommandError(_OFFLINE_DOWNGRADE_MESSAGE)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the configured database."""

    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        context.configure(
            connection=supplied_connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            if _downgrades_pending_scan_inventory(context.get_context().get_current_heads()):
                _assert_pending_scan_downgrade_safe(supplied_connection)
            context.run_migrations()
        return

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            if _downgrades_pending_scan_inventory(context.get_context().get_current_heads()):
                _assert_pending_scan_downgrade_safe(connection)
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
