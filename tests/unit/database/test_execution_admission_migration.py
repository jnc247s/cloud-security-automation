"""Additive history-preserving upgrade and fail-before-DDL execution downgrade."""

from uuid import uuid4

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from app.database.persistence import append_audit_event
from app.models import AuditEvent
from app.models.enums import AuditEventType
from tests.execution_fixtures import admit, approved
from tests.remediation_fixtures import NOW
from tests.unit.database.test_migrations import _migration_config, _sqlite_migration_state
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine


def test_empty_execution_revision_round_trip_matches_metadata(migrated_engine):
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261006_0007")
        assert "remediation_executions" not in inspect(connection).get_table_names()
        command.upgrade(_migration_config(connection), "head")
        command.check(_migration_config(connection))
        assert connection.scalar(text("SELECT guard_id FROM remediation_admission_guard")) == 1
        assert connection.execute(text("PRAGMA foreign_key_check")).first() is None


def test_upgrade_keeps_populated_8a_authority_and_audit(migrated_engine):
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261006_0007")
    proposal, request, _ = approved(migrated_engine)
    with migrated_engine.connect() as connection:
        before = {
            name: tuple(tuple(row) for row in connection.execute(text(f"SELECT * FROM {name}")))
            for name in (
                "remediation_proposals",
                "remediation_decisions",
                "remediation_requests",
                "audit_events",
            )
        }
    with migrated_engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        command.check(_migration_config(connection))
        for name, rows in before.items():
            assert (
                tuple(tuple(row) for row in connection.execute(text(f"SELECT * FROM {name}")))
                == rows
            )
    assert admit(migrated_engine, proposal, request).value.phase == "QUEUED"


@pytest.mark.parametrize("destination", ["20261006_0007", "20261001_0006", "base"])
def test_populated_execution_blocks_entire_downgrade_before_ddl(migrated_engine, destination):
    proposal, request, _ = approved(migrated_engine)
    admit(migrated_engine, proposal, request)
    before = _sqlite_migration_state(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261007_0008"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), destination)
    assert _sqlite_migration_state(migrated_engine) == before


def test_execution_audit_alone_blocks_downgrade(migrated_engine):
    with Session(migrated_engine) as session, session.begin():
        append_audit_event(
            session,
            AuditEventType.REMEDIATION_EXECUTION_REQUESTED,
            "remediation_execution",
            uuid4(),
            NOW,
            actor_type="human",
            actor_id="fixture",
        )
    before = _sqlite_migration_state(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261007_0008"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), "20261006_0007")
    assert _sqlite_migration_state(migrated_engine) == before
    with Session(migrated_engine) as session:
        assert session.scalar(select(AuditEvent.event_id)) is not None


def test_offline_execution_downgrade_emits_no_destructive_sql(migrated_engine, capsys):
    with (
        migrated_engine.connect() as connection,
        pytest.raises(
            CommandError, match="Offline downgrade blocked before revision 20261007_0008"
        ),
    ):
        command.downgrade(_migration_config(connection), "20261007_0008:base", sql=True)
    assert "DROP" not in capsys.readouterr().out
