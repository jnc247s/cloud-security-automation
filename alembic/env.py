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
_EVIDENCE_GRAPH_REVISION: Final = "20260915_0003"
_ASSESSMENT_EXECUTION_REVISION: Final = "20260924_0004"
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
_UNSAFE_EVIDENCE_GRAPH_DOWNGRADE_MESSAGE: Final = (
    "Downgrade blocked before revision 20260915_0003: retained source-evidence, relationship, "
    "source-manifest, exceptional-owner, or supplemental-Region history cannot be represented "
    "by the older schema. No schema or data changes were applied. Keep the current revision, "
    "take a verified backup, and follow the safe recovery guidance in "
    f"{_RECOVERY_DOCUMENT}."
)
_OFFLINE_EVIDENCE_GRAPH_DOWNGRADE_MESSAGE: Final = (
    "Offline downgrade blocked before revision 20260915_0003: retained evidence-graph and "
    "snapshot compatibility must be verified against the live database before the older "
    f"schema can be restored. Follow {_RECOVERY_DOCUMENT}."
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


def _downgrades_assessment_execution(current_revisions) -> bool:
    if not current_revisions:
        return False
    try:
        destination = context.get_revision_argument()
        return any(
            revision.revision == _ASSESSMENT_EXECUTION_REVISION
            for revision in script_directory.iterate_revisions(
                current_revisions, destination, select_for_downgrade=True
            )
        )
    except (KeyError, RangeNotAncestorError):
        return False


def _assert_assessment_execution_downgrade_safe(connection: Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.execute(
            text(
                "LOCK TABLE scans, assessment_profiles, control_catalogs, control_versions, "
                "assessment_policy_artifacts, resources, resource_snapshots, control_assessments "
                "IN ACCESS EXCLUSIVE MODE"
            )
        )
    elif connection.dialect.name == "sqlite":
        # sqlite3 legacy transaction mode does not BEGIN for SELECT/DDL. Reserve the writer
        # lock before checking history, and keep DDL inside this caller-owned transaction.
        if not connection.connection.driver_connection.in_transaction:
            connection.execute(text("BEGIN IMMEDIATE"))
        else:
            connection.execute(text("UPDATE alembic_version SET version_num = version_num WHERE 0"))
    incompatible = connection.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM assessment_profiles WHERE schema_version IS NOT NULL "
            "OR policy_extensions IS NOT NULL UNION ALL SELECT 1 FROM control_versions "
            "WHERE execution_contract IS NOT NULL "
            "UNION ALL SELECT 1 FROM assessment_policy_artifacts "
            "UNION ALL SELECT 1 FROM resources "
            "WHERE resource_type = 'aws_account' AND scope = 'regional')"
        )
    ).scalar_one()
    if incompatible:
        raise util.CommandError(
            "Downgrade blocked before revision 20260924_0004: retained assessment policy or "
            "execution history cannot be represented by the older schema. No schema or data "
            "changes were applied. Keep this revision, verify backups, and follow "
            "docs/operations/known-limitations.md."
        )


def _downgrades_evidence_graph(
    current_revisions: str | tuple[str, ...] | None,
) -> bool:
    """Return whether the requested path would execute revision 0003's downgrade."""

    if not current_revisions:
        return False
    try:
        destination_revision = context.get_revision_argument()
    except KeyError:
        return False

    try:
        revisions = script_directory.iterate_revisions(
            current_revisions,
            destination_revision,
            select_for_downgrade=True,
        )
        return any(revision.revision == _EVIDENCE_GRAPH_REVISION for revision in revisions)
    except RangeNotAncestorError:
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


def _assert_evidence_graph_downgrade_safe(connection: Connection) -> None:
    """Reject rollback before any evidence graph or incompatible snapshot can be lost."""

    if connection.dialect.name == "postgresql":
        # Serialize writers with the same fixed parent-to-child order used by
        # the migration. The following downgrade drops these tables and needs
        # ACCESS EXCLUSIVE locks in any case.
        connection.execute(
            text(
                "LOCK TABLE scans, scan_scope_manifests, resources, resource_snapshots, "
                "scan_source_contracts, source_evidence_artifacts, source_evidence_outcomes, "
                "resource_relationship_observations IN ACCESS EXCLUSIVE MODE"
            )
        )

    graph_history_exists = connection.execute(
        text(
            "SELECT EXISTS ("
            "SELECT 1 FROM scan_scope_manifests "
            "WHERE source_manifest_schema_version IS NOT NULL "
            "OR source_manifest_checksum IS NOT NULL "
            "UNION ALL SELECT 1 FROM scan_source_contracts "
            "UNION ALL SELECT 1 FROM source_evidence_artifacts "
            "UNION ALL SELECT 1 FROM source_evidence_outcomes "
            "UNION ALL SELECT 1 FROM resource_relationship_observations"
            ")"
        )
    ).scalar_one()

    region_membership = (
        "EXISTS (SELECT 1 FROM jsonb_array_elements_text(s.requested_regions) region(value) "
        "WHERE region.value = rs.region)"
        if connection.dialect.name == "postgresql"
        else "EXISTS (SELECT 1 FROM json_each(s.requested_regions) "
        "WHERE json_each.value = rs.region)"
    )
    incompatible_snapshot_exists = connection.execute(
        text(
            "SELECT EXISTS ("
            "SELECT 1 FROM resource_snapshots rs "
            "JOIN resources r ON r.resource_id = rs.resource_id "
            "JOIN scans s ON s.scan_id = rs.scan_id "
            "WHERE r.aws_account_id <> s.aws_account_id "
            "OR r.scope <> rs.scope "
            "OR (r.scope = 'global' AND (r.region <> 'global' OR rs.region IS NOT NULL)) "
            "OR (r.scope = 'regional' AND (r.region <> rs.region OR ("
            f"r.service NOT IN ('s3', 'cloudtrail') AND NOT ({region_membership})"
            "))))"
        )
    ).scalar_one()
    if graph_history_exists or incompatible_snapshot_exists:
        raise util.CommandError(_UNSAFE_EVIDENCE_GRAPH_DOWNGRADE_MESSAGE)


def run_migrations_offline() -> None:
    """Run migrations without creating a database connection."""

    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    starting_revision = context.get_starting_revision_argument()
    if _downgrades_assessment_execution(starting_revision):
        raise util.CommandError(
            "Offline downgrade across 20260924_0004 requires an online history compatibility check."
        )
    if _downgrades_evidence_graph(starting_revision):
        raise util.CommandError(_OFFLINE_EVIDENCE_GRAPH_DOWNGRADE_MESSAGE)
    if _downgrades_pending_scan_inventory(starting_revision):
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
            current_heads = context.get_context().get_current_heads()
            if _downgrades_assessment_execution(current_heads):
                _assert_assessment_execution_downgrade_safe(supplied_connection)
            if _downgrades_evidence_graph(current_heads):
                _assert_evidence_graph_downgrade_safe(supplied_connection)
            if _downgrades_pending_scan_inventory(current_heads):
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
            current_heads = context.get_context().get_current_heads()
            if _downgrades_assessment_execution(current_heads):
                _assert_assessment_execution_downgrade_safe(connection)
            if _downgrades_evidence_graph(current_heads):
                _assert_evidence_graph_downgrade_safe(connection)
            if _downgrades_pending_scan_inventory(current_heads):
                _assert_pending_scan_downgrade_safe(connection)
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
