"""Upgrade/history fidelity and fail-before-DDL remediation downgrade checks."""

from uuid import uuid4

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from app.database.persistence import append_audit_event, persist_scan_result
from app.models import AuditEvent
from app.models.enums import AuditEventType
from tests.remediation_fixtures import NOW, propose
from tests.unit.database.factories import scan_bundle
from tests.unit.database.test_migrations import _migration_config, _sqlite_migration_state


def test_empty_remediation_revision_round_trip_matches_metadata(migrated_engine):
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261001_0006")
        assert "remediation_proposals" not in inspect(connection).get_table_names()
        command.upgrade(_migration_config(connection), "head")
        command.check(_migration_config(connection))
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1


def test_populated_predecessor_upgrade_preserves_legacy_rows_and_audit_guards(migrated_engine):
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261001_0006")
    with Session(migrated_engine) as session, session.begin():
        persist_scan_result(session, **scan_bundle())
    with migrated_engine.connect() as connection:
        before = {
            table: tuple(tuple(row) for row in connection.execute(text(f"SELECT * FROM {table}")))
            for table in (
                "audit_events",
                "resource_snapshots",
                "control_assessments",
                "evidence_artifacts",
            )
        }
        triggers = tuple(
            tuple(row)
            for row in connection.execute(
                text(
                    "SELECT name, sql FROM sqlite_master WHERE type='trigger' "
                    "AND tbl_name='audit_events' ORDER BY name"
                )
            )
        )
    with migrated_engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        command.check(_migration_config(connection))
        for table, rows in before.items():
            assert (
                tuple(tuple(row) for row in connection.execute(text(f"SELECT * FROM {table}")))
                == rows
            )
        assert (
            tuple(
                tuple(row)
                for row in connection.execute(
                    text(
                        "SELECT name, sql FROM sqlite_master WHERE type='trigger' "
                        "AND tbl_name='audit_events' ORDER BY name"
                    )
                )
            )
            == triggers
        )
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        assert connection.execute(text("PRAGMA foreign_key_check")).first() is None


@pytest.mark.parametrize("destination", ["20261001_0006", "20260915_0003", "base"])
def test_populated_remediation_blocks_entire_downgrade_path_before_any_ddl(
    migrated_engine, destination
):
    propose(migrated_engine)
    before = _sqlite_migration_state(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261006_0007"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), destination)
    assert _sqlite_migration_state(migrated_engine) == before


def test_new_audit_event_alone_blocks_lossy_downgrade(migrated_engine):
    with Session(migrated_engine) as session, session.begin():
        append_audit_event(
            session,
            AuditEventType.REMEDIATION_PROPOSED,
            "remediation",
            uuid4(),
            NOW,
            actor_type="human",
            actor_id="offline-operator",
            metadata={"fixture": "privileged direct insert still requires retention"},
        )
    before = _sqlite_migration_state(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261006_0007"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), "20261001_0006")
    assert _sqlite_migration_state(migrated_engine) == before
    with Session(migrated_engine) as session:
        assert session.scalar(select(AuditEvent.event_id)) is not None


def test_offline_remediation_downgrade_emits_no_destructive_sql(migrated_engine, capsys):
    with migrated_engine.connect() as connection:
        with pytest.raises(
            CommandError, match="Offline downgrade blocked before revision 20261006_0007"
        ):
            command.downgrade(_migration_config(connection), "20261006_0007:base", sql=True)
    assert "DROP" not in capsys.readouterr().out
