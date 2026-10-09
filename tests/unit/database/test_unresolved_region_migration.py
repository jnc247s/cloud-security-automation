"""Populated transitions preserve exact graph history and safely guard rollback."""

import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import CheckConstraint, Column, MetaData, String, Table, event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import conv

from app.database.evidence_graph import load_evidence_graph
from app.database.persistence import persist_scan_result
from tests.cloudtrail_fixtures import logging_bundle
from tests.unit.database.conftest import migrated_engine as _migrated_engine
from tests.unit.database.factories import graph_scan_bundle
from tests.unit.database.test_migrations import _migration_config

migrated_engine = _migrated_engine
CURRENT = "20261001_0005"
PREVIOUS = "20260924_0004"
TABLE = "resource_relationship_observations"
SUFFIX = "target_scope_region_consistent"


def constraint_name(dialect):
    return dialect.identifier_preparer.truncate_and_render_constraint_name(
        conv(f"ck_{TABLE}_{SUFFIX}"), _alembic_quote=False
    )


def state(engine):
    with engine.connect() as connection:
        return state_on_connection(connection)


def state_on_connection(connection):
    """Read the same snapshot without acquiring or completing a caller's transaction."""
    inspector = inspect(connection)
    quote = connection.dialect.identifier_preparer.quote
    tables = inspector.get_table_names()
    result = {
        "region_constraint": constraint_name(connection.dialect),
        "revision": connection.scalar(text("SELECT version_num FROM alembic_version")),
        "rows": {
            table: sorted(
                json.dumps(dict(row), sort_keys=True, default=str)
                for row in connection.execute(text(f"SELECT * FROM {quote(table)}")).mappings()
            )
            for table in tables
            if table != "alembic_version"
        },
        "checks": {
            table: sorted((c["name"], c["sqltext"]) for c in inspector.get_check_constraints(table))
            for table in tables
        },
    }
    if connection.dialect.name == "sqlite":
        result["triggers"] = list(
            connection.execute(
                text("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
            )
        )
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
    return result


def exercise_state_on_connection_preserves_caller_transaction(engine, monkeypatch):
    before = state(engine)
    with engine.connect() as connection:
        transaction = connection.begin()
        assert state_on_connection(connection) == before
        connection.execute(text("CREATE TABLE snapshot_state_probe (value INTEGER NOT NULL)"))
        connection.execute(text("INSERT INTO snapshot_state_probe (value) VALUES (7)"))
        completions = []

        @event.listens_for(connection, "commit")
        def committed(_connection):
            completions.append("commit")

        @event.listens_for(connection, "rollback")
        def rolled_back(_connection):
            completions.append("rollback")

        def unexpected_connection(*_args, **_kwargs):
            raise AssertionError("snapshot must reuse the caller's connection")

        with monkeypatch.context() as patch:
            patch.setattr(engine, "connect", unexpected_connection)
            snapshot = state_on_connection(connection)
        assert snapshot["rows"]["snapshot_state_probe"] == [
            json.dumps({"value": 7}, sort_keys=True)
        ]
        assert connection.get_transaction() is transaction
        assert transaction.is_active and not connection.closed
        assert completions == []
        assert connection.scalar(text("SELECT value FROM snapshot_state_probe")) == 7
        transaction.rollback()
        assert completions == ["rollback"]
        assert not connection.closed


def persist(engine, bundle):
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)


def exercise_upgrade(engine, config_factory):
    with engine.begin() as connection:
        command.downgrade(config_factory(connection), PREVIOUS)
    bundle = graph_scan_bundle()
    persist(engine, bundle)
    before = state(engine)
    with engine.begin() as connection:
        command.upgrade(config_factory(connection), CURRENT)
    after = state(engine)
    assert before["revision"] == PREVIOUS and after["revision"] == CURRENT
    assert before["rows"] == after["rows"]
    assert before.get("triggers") == after.get("triggers")
    for table in before["checks"]:
        if table == TABLE:
            assert len(before["checks"][table]) == len(after["checks"][table])
            assert [c for c in before["checks"][table] if c[0] != before["region_constraint"]] == [
                c for c in after["checks"][table] if c[0] != after["region_constraint"]
            ]
        else:
            assert before["checks"][table] == after["checks"][table]
    with Session(engine) as session:
        assert load_evidence_graph(session, bundle["snapshot"].scan_id) == (
            bundle["snapshot"].evidence_graph
        )
    # Keep the exact historical 0004 -> 0005 assertions above. Drift validation belongs
    # at the current head, after subsequent independently tested additive migrations.
    with engine.begin() as connection:
        command.upgrade(config_factory(connection), "head")
        command.check(config_factory(connection))


def exercise_safe_round_trip(engine, config_factory):
    bundle = graph_scan_bundle()
    persist(engine, bundle)
    before = state(engine)
    with engine.begin() as connection:
        command.downgrade(config_factory(connection), PREVIOUS)
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == PREVIOUS
        command.upgrade(config_factory(connection), "head")
        command.check(config_factory(connection))
    assert state(engine) == before


def exercise_blocked_downgrade(engine, config_factory):
    bundle = logging_bundle()
    persist(engine, bundle)
    before = state(engine)
    with pytest.raises(CommandError, match="blocked before revision 20261001_0005") as error:
        with engine.begin() as connection:
            command.downgrade(config_factory(connection), PREVIOUS)
    assert state(engine) == before
    for sensitive in (
        str(bundle["snapshot"].scan_id),
        bundle["snapshot"].account_id,
        "CoverageTrail",
        "postgresql://",
        "sqlite://",
    ):
        assert sensitive not in str(error.value)
    with Session(engine) as session:
        assert load_evidence_graph(session, bundle["snapshot"].scan_id) == (
            bundle["snapshot"].evidence_graph
        )


def exercise_failed_transition(engine, config_factory, direction):
    bundle = graph_scan_bundle()
    if direction == "upgrade":
        with engine.begin() as connection:
            command.downgrade(config_factory(connection), PREVIOUS)
    persist(engine, bundle)
    before = state(engine)

    def fail_after_first_ddl(_conn, _cursor, statement, *_args):
        if statement.lstrip().startswith(
            f"CREATE TABLE _alembic_tmp_{TABLE}"
        ) or statement.lstrip().startswith(f"ALTER TABLE {TABLE} ADD CONSTRAINT"):
            raise RuntimeError("injected relationship transition failure")

    event.listen(engine, "before_cursor_execute", fail_after_first_ddl)
    try:
        with pytest.raises(RuntimeError, match="injected relationship transition failure"):
            with engine.begin() as connection:
                if direction == "upgrade":
                    command.upgrade(config_factory(connection), "head")
                else:
                    command.downgrade(config_factory(connection), PREVIOUS)
    finally:
        event.remove(engine, "before_cursor_execute", fail_after_first_ddl)
    assert state(engine) == before
    # The entire original history and trigger set survived; retry the exact transition.
    with engine.begin() as connection:
        if direction == "downgrade":
            command.downgrade(config_factory(connection), PREVIOUS)
        command.upgrade(config_factory(connection), "head")
        command.check(config_factory(connection))
    after_rows = state(engine)["rows"]
    assert {table: after_rows[table] for table in before["rows"]} == before["rows"]
    added_tables = set(after_rows) - set(before["rows"])
    assert added_tables == (
        {
            "remediation_proposals",
            "remediation_decisions",
            "remediation_requests",
            "remediation_executions",
            "remediation_execution_events",
            "remediation_admission_guard",
            "remediation_target_reservations",
            "remediation_worker_claims",
        }
        if direction == "upgrade"
        else set()
    )
    assert all(after_rows[table] == [] for table in added_tables - {"remediation_admission_guard"})
    if "remediation_admission_guard" in added_tables:
        assert after_rows["remediation_admission_guard"] == [
            json.dumps({"guard_id": 1}, sort_keys=True)
        ]


def exercise_constraint(engine):
    # Probe the actual migrated CHECK expression independently of provenance triggers.
    # Full application persistence/HTTP tests exercise the other constraints and triggers.
    with engine.begin() as connection:
        constraints = inspect(connection).get_check_constraints(TABLE)
        expression = next(
            c["sqltext"] for c in constraints if c["name"] == constraint_name(connection.dialect)
        )
        probe = Table(
            "relationship_region_probe",
            MetaData(),
            Column("target_identity_state", String),
            Column("target_scope", String),
            Column("target_region", String),
            CheckConstraint(expression),
            prefixes=["TEMPORARY"],
        )
        probe.create(connection)
        try:
            for identity, scope, region, allowed in (
                ("unresolved", "regional", None, True),
                ("stable", "regional", "us-east-1", True),
                ("unresolved", "regional", "us-east-1", True),
                ("stable", "global", None, True),
                ("stable", "regional", None, False),
                ("stable", "global", "us-east-1", False),
                ("unresolved", "global", "us-east-1", False),
            ):
                if allowed:
                    connection.execute(
                        probe.insert().values(
                            target_identity_state=identity, target_scope=scope, target_region=region
                        )
                    )
                else:
                    with pytest.raises(IntegrityError), connection.begin_nested():
                        connection.execute(
                            probe.insert().values(
                                target_identity_state=identity,
                                target_scope=scope,
                                target_region=region,
                            )
                        )
        finally:
            probe.drop(connection)


def test_populated_upgrade(migrated_engine):
    exercise_upgrade(migrated_engine, _migration_config)


def test_state_on_connection_preserves_caller_transaction(migrated_engine, monkeypatch):
    exercise_state_on_connection_preserves_caller_transaction(migrated_engine, monkeypatch)


def test_compatible_populated_round_trip(migrated_engine):
    exercise_safe_round_trip(migrated_engine, _migration_config)


def test_incompatible_downgrade_is_atomic_and_sanitized(migrated_engine):
    exercise_blocked_downgrade(migrated_engine, _migration_config)


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_failed_transition_is_atomic_and_retryable(migrated_engine, direction):
    exercise_failed_transition(migrated_engine, _migration_config, direction)


def test_stable_identity_and_global_scope_stay_strict(migrated_engine):
    exercise_constraint(migrated_engine)


def test_offline_downgrade_is_blocked():
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    with pytest.raises(CommandError, match="Offline downgrade blocked before revision 20261001"):
        command.downgrade(config, f"{CURRENT}:{PREVIOUS}", sql=True)
