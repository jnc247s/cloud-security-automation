"""Authoritative PostgreSQL transition, strict constraint and concurrent-writer gates."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic, sleep

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.database.persistence import persist_scan_result
from tests.cloudtrail_fixtures import logging_bundle
from tests.integration.test_persistence_postgres import migration_config
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_unresolved_region_migration import (
    exercise_blocked_downgrade,
    exercise_constraint,
    exercise_failed_transition,
    exercise_safe_round_trip,
    exercise_state_on_connection_preserves_caller_transaction,
    exercise_upgrade,
    state,
    state_on_connection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_populated_upgrade(postgres_engine):
    exercise_upgrade(postgres_engine, migration_config)


def test_state_on_connection_preserves_caller_transaction(postgres_engine, monkeypatch):
    exercise_state_on_connection_preserves_caller_transaction(postgres_engine, monkeypatch)


def test_compatible_populated_round_trip(postgres_engine):
    exercise_safe_round_trip(postgres_engine, migration_config)


def test_incompatible_downgrade_is_atomic_and_sanitized(postgres_engine):
    exercise_blocked_downgrade(postgres_engine, migration_config)


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_failed_transition_is_atomic_and_retryable(postgres_engine, direction):
    exercise_failed_transition(postgres_engine, migration_config, direction)


def test_stable_identity_and_global_scope_stay_strict(postgres_engine):
    exercise_constraint(postgres_engine)


@pytest.mark.parametrize("_attempt", range(5))
def test_writer_is_serialized_before_downgrade_preflight(postgres_engine, _attempt):
    bundle = logging_bundle()
    inserted, release, lock_attempted = Event(), Event(), Event()
    backend_pids, baselines, ddl = {}, [], []

    def writer():
        with postgres_engine.connect() as connection:
            backend_pids["writer"] = connection.scalar(text("SELECT pg_backend_pid()"))
            connection.rollback()

            @event.listens_for(connection, "after_cursor_execute")
            def hold(_connection, _cursor, statement, *_args):
                if "INSERT INTO resource_relationship_observations" in statement:
                    inserted.set()
                    if not release.wait(timeout=15):
                        raise AssertionError("relationship writer was not released")

            with Session(connection) as session, session.begin():
                persist_scan_result(session, **bundle)

    def downgrade():
        with postgres_engine.begin() as connection:
            backend_pids["downgrade"] = connection.scalar(text("SELECT pg_backend_pid()"))

            @event.listens_for(connection, "before_cursor_execute")
            def observe(_connection, _cursor, statement, *_args):
                if (
                    statement.lstrip()
                    .upper()
                    .startswith(("CREATE ", "ALTER ", "DROP ", "TRUNCATE "))
                ):
                    ddl.append(statement)
                # The new 0008 guard is first on the complete downgrade path.
                if statement.startswith("LOCK TABLE remediation_admission_guard, scans, resources"):
                    lock_attempted.set()
                if statement.startswith("LOCK TABLE scans, scan_scope_manifests, resources"):
                    # Earlier guards have serialized the writer and hold parent locks.
                    # Reuse that transaction: a separate snapshot reader can deadlock
                    # with the guard by acquiring graph/parent locks in reverse order.
                    assert ddl == [] and baselines == []
                    baselines.append(state_on_connection(connection))
                    assert baselines[0]["revision"] == "20261007_0008"
                    assert any(
                        json.loads(row)["scan_id"] == str(bundle["snapshot"].scan_id)
                        for row in baselines[0]["rows"]["scans"]
                    )

            command.downgrade(migration_config(connection), "20260924_0004")

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(writer)
        try:
            assert inserted.wait(timeout=10)
            downgrading = pool.submit(downgrade)
            assert lock_attempted.wait(timeout=10)
            assert not downgrading.done()
            # Catalog-only observation cannot acquire competing application-table locks.
            with postgres_engine.connect() as monitor:
                deadline = monotonic() + 3
                while backend_pids["writer"] not in monitor.scalar(
                    text("SELECT pg_blocking_pids(:pid)"), {"pid": backend_pids["downgrade"]}
                ):
                    assert not downgrading.done()
                    assert monotonic() < deadline, "downgrade did not wait for the writer"
                    sleep(0.01)
            assert not downgrading.done()
        finally:
            release.set()
        writing.result(timeout=15)
        with pytest.raises(CommandError, match="blocked before revision 20261001_0005"):
            downgrading.result(timeout=15)
    assert len(baselines) == 1 and ddl == []
    assert state(postgres_engine) == baselines[0]
