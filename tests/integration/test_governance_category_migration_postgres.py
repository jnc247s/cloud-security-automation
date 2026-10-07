"""Disposable PostgreSQL category history, transaction and writer-exclusion acceptance."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.schemas.finding import ControlCategory
from tests.integration.test_persistence_postgres import migration_config
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_governance_category_migration import (
    CURRENT,
    PREVIOUS,
    category_probe,
    exercise_blocked_downgrade,
    exercise_caller_rollback,
    exercise_round_trip,
    persist_history,
    state,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_populated_round_trip(postgres_engine):
    exercise_round_trip(postgres_engine, migration_config)


def test_incompatible_downgrade_before_ddl(postgres_engine):
    exercise_blocked_downgrade(postgres_engine, migration_config)


def test_caller_owns_rollback(postgres_engine):
    exercise_caller_rollback(postgres_engine, migration_config)


def test_writer_is_excluded_before_category_preflight(postgres_engine):
    # This exercises the frozen 0006 guard, not the newer whole-path authority guard.
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), CURRENT)
    persist_history(postgres_engine)
    inserted, release, attempted = Event(), Event(), Event()

    def writer():
        with Session(postgres_engine) as session, session.begin():
            category_probe(session, ControlCategory.GOVERNANCE)
            inserted.set()
            assert release.wait(15), "category writer was not released"

    def downgrade():
        with postgres_engine.begin() as connection:

            @event.listens_for(connection, "before_cursor_execute")
            def record(_connection, _cursor, statement, *_args):
                if statement.startswith("LOCK TABLE control_versions IN ACCESS EXCLUSIVE MODE"):
                    attempted.set()

            command.downgrade(migration_config(connection), PREVIOUS)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(writer)
        try:
            assert inserted.wait(15)
            downgrading = pool.submit(downgrade)
            assert attempted.wait(15)
            assert not downgrading.done()
        finally:
            release.set()
        writing.result(timeout=15)
        with pytest.raises(CommandError, match="blocked before revision 20261001_0006"):
            downgrading.result(timeout=15)
    assert state(postgres_engine)["revision"] == CURRENT
