"""0009 preserves B1 bytes and refuses unrepresentable worker history before DDL."""

import json
from uuid import uuid4

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.database.persistence import append_audit_event
from app.models.enums import AuditEventType
from tests.execution_fixtures import admit, approved
from tests.remediation_fixtures import NOW
from tests.unit.database.test_migrations import _migration_config
from tests.unit.services.test_remediation_worker import Harness
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine


def snapshot(engine):
    with engine.connect() as connection:
        ddl = tuple(
            tuple(row)
            for row in connection.execute(
                text(
                    "SELECT type, name, sql FROM sqlite_master "
                    "WHERE sql IS NOT NULL ORDER BY type, name"
                )
            )
        )
        names = connection.scalars(
            text("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        ).all()
        rows = {
            name: tuple(
                sorted(
                    (tuple(row) for row in connection.execute(text(f'SELECT * FROM "{name}"'))),
                    key=str,
                )
            )
            for name in names
        }
        return ddl, rows


def structural_snapshot(engine):
    """Compare every schema contract, not nondeterministic reflected CHECK clause ordering."""
    with engine.connect() as connection:
        inspector = inspect(connection)
        tables = {}
        for name in inspector.get_table_names():
            tables[name] = {
                "columns": [
                    {key: str(value) if key == "type" else value for key, value in column.items()}
                    for column in inspector.get_columns(name)
                ],
                "primary_key": inspector.get_pk_constraint(name),
                "foreign_keys": sorted(inspector.get_foreign_keys(name), key=str),
                "unique": sorted(inspector.get_unique_constraints(name), key=str),
                "checks": sorted(inspector.get_check_constraints(name), key=str),
                "indexes": sorted(inspector.get_indexes(name), key=str),
            }
        triggers = tuple(
            tuple(row)
            for row in connection.execute(
                text("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
            )
        )
        return json.dumps(tables, sort_keys=True, default=str), triggers


def test_0009_preserves_populated_b1_upgrade_and_can_restore_b1_without_worker_history(
    migrated_engine,
):
    proposal, request, _ = approved(migrated_engine)
    original = admit(migrated_engine, proposal, request).value
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261007_0008")
    before = snapshot(migrated_engine)
    before_structure = structural_snapshot(migrated_engine)
    with migrated_engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        command.check(_migration_config(connection))
        assert connection.execute(text("PRAGMA foreign_key_check")).first() is None
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261007_0008")
    after = snapshot(migrated_engine)
    assert after[1] == before[1]
    assert structural_snapshot(migrated_engine) == before_structure
    with migrated_engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
    from app.services.remediation_execution_service import RemediationExecutionService
    from tests.remediation_fixtures import VIEWER

    with Session(migrated_engine) as session:
        assert (
            RemediationExecutionService(session, clock=lambda: NOW).get_execution(
                original.content.execution_id,
                VIEWER,
            )
            == original
        )


@pytest.mark.parametrize("phase", ["claim", "intent", "quarantine", "acknowledgment"])
def test_worker_history_blocks_0009_downgrade_with_exact_schema_and_rows_unchanged(
    migrated_engine, phase
):
    harness = Harness(migrated_engine)
    if phase == "claim":
        harness.service("claim", harness.execution_id)
    else:
        claim = harness.intent()
        if phase == "quarantine":
            harness.service("quarantine", harness.execution_id)
        if phase == "acknowledgment":
            harness.service("acknowledge", claim, "synthetic-complete-request")
    before = snapshot(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261008_0009"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), "20261007_0008")
    assert snapshot(migrated_engine) == before


@pytest.mark.parametrize(
    "kind",
    [
        "CLAIMED",
        "WRITE_INTENT",
        "NO_WRITE",
        "ACKNOWLEDGED",
        "QUARANTINED",
        "OBSERVED",
        "OBSERVATION_FAILED",
    ],
)
@pytest.mark.parametrize("destination", ["20261007_0008", "base"])
def test_worker_audit_alone_blocks_whole_path_before_any_ddl(migrated_engine, kind, destination):
    with Session(migrated_engine) as session, session.begin():
        append_audit_event(
            session,
            AuditEventType("REMEDIATION_EXECUTION_" + kind),
            "remediation_execution",
            uuid4(),
            NOW,
            actor_type="service",
            actor_id="synthetic-worker",
        )
    before = snapshot(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261008_0009"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), destination)
    assert snapshot(migrated_engine) == before


@pytest.mark.parametrize("destination", ["20261007_0008", "20261006_0007", "base"])
def test_offline_worker_downgrade_has_no_destructive_sql(migrated_engine, capsys, destination):
    with (
        migrated_engine.connect() as connection,
        pytest.raises(CommandError, match="Offline downgrade"),
    ):
        command.downgrade(_migration_config(connection), "20261008_0009:" + destination, sql=True)
    assert "DROP" not in capsys.readouterr().out
