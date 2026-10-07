"""Authoritative PostgreSQL transition, strict constraint and concurrent-writer gates."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event
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
    exercise_upgrade,
    state,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_populated_upgrade(postgres_engine):
    exercise_upgrade(postgres_engine, migration_config)


def test_compatible_populated_round_trip(postgres_engine):
    exercise_safe_round_trip(postgres_engine, migration_config)


def test_incompatible_downgrade_is_atomic_and_sanitized(postgres_engine):
    exercise_blocked_downgrade(postgres_engine, migration_config)


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_failed_transition_is_atomic_and_retryable(postgres_engine, direction):
    exercise_failed_transition(postgres_engine, migration_config, direction)


def test_stable_identity_and_global_scope_stay_strict(postgres_engine):
    exercise_constraint(postgres_engine)


def test_writer_is_serialized_before_downgrade_preflight(postgres_engine):
    bundle = logging_bundle()
    inserted, release, lock_attempted = Event(), Event(), Event()

    def writer():
        with postgres_engine.connect() as connection:

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

            @event.listens_for(connection, "before_cursor_execute")
            def observe(_connection, _cursor, statement, *_args):
                # The new 0007 guard is first on the complete downgrade path.
                if statement.startswith("LOCK TABLE scans, resources, findings, remediation_"):
                    lock_attempted.set()

            command.downgrade(migration_config(connection), "20260924_0004")

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(writer)
        try:
            assert inserted.wait(timeout=10)
            downgrading = pool.submit(downgrade)
            assert lock_attempted.wait(timeout=10)
            assert not downgrading.done()
        finally:
            release.set()
        writing.result(timeout=15)
        before = state(postgres_engine)
        with pytest.raises(CommandError, match="blocked before revision 20261001_0005"):
            downgrading.result(timeout=15)
    assert state(postgres_engine) == before
