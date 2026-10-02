"""Narrow category transitions preserve populated history, integrity and transaction ownership."""

from io import StringIO
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import String, event, insert, literal, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.persistence import persist_scan_result
from app.models.control import ControlCatalog, ControlVersion
from app.schemas.finding import ControlCategory
from tests.cloudtrail_destination_fixtures import destination_bundle
from tests.unit.database.conftest import migrated_engine as _migrated_engine
from tests.unit.database.test_migrations import _migration_config
from tests.unit.database.test_unresolved_region_migration import state

migrated_engine = _migrated_engine
CURRENT = "20261001_0006"
PREVIOUS = "20261001_0005"
CHECK = "ck_control_versions_control_category"


def persist_history(engine):
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **destination_bundle())


def category_probe(session, category):
    """Isolated database CHECK probe, not an executable or validated catalog."""
    original = session.scalars(select(ControlVersion)).first()
    catalog = ControlCatalog(
        catalog_key="migration-category-probe",
        version=str(uuid4()),
        content_checksum="f" * 64,
    )
    session.add(catalog)
    session.flush()
    values = {
        column.name: getattr(original, column.name) for column in ControlVersion.__table__.columns
    }
    values.update(
        control_version_id=uuid4(),
        catalog_id=catalog.catalog_id,
        # Exercise the database CHECK rather than stopping at the ORM enum validator.
        category=literal(str(category), String()),
    )
    session.execute(insert(ControlVersion).values(**values))


def assert_checks_preserved(before, after):
    for table in before["checks"]:
        if table == "control_versions":
            assert len(before["checks"][table]) == len(after["checks"][table])
            assert [c for c in before["checks"][table] if c[0] != CHECK] == [
                c for c in after["checks"][table] if c[0] != CHECK
            ]
        else:
            assert before["checks"][table] == after["checks"][table]


def exercise_round_trip(engine, config_factory):
    with engine.begin() as connection:
        command.downgrade(config_factory(connection), PREVIOUS)
    persist_history(engine)
    before = state(engine)
    with Session(engine) as session, pytest.raises(IntegrityError), session.begin():
        category_probe(session, ControlCategory.GOVERNANCE)
    assert state(engine) == before
    with engine.begin() as connection:
        command.upgrade(config_factory(connection), CURRENT)
        command.check(config_factory(connection))
    after = state(engine)
    assert before["revision"] == PREVIOUS and after["revision"] == CURRENT
    assert before["rows"] == after["rows"]
    assert before.get("triggers") == after.get("triggers")
    assert_checks_preserved(before, after)
    with engine.begin() as connection:
        command.downgrade(config_factory(connection), PREVIOUS)
    assert state(engine) == before
    with engine.begin() as connection:
        command.upgrade(config_factory(connection), CURRENT)
    assert state(engine) == after
    with Session(engine) as session, pytest.raises(IntegrityError), session.begin():
        category_probe(session, "unknown")
    assert state(engine) == after


def exercise_blocked_downgrade(engine, config_factory):
    persist_history(engine)
    with Session(engine) as session, session.begin():
        category_probe(session, ControlCategory.GOVERNANCE)
    before = state(engine)
    ddl = []

    def record(_connection, _cursor, statement, *_args):
        if statement.lstrip().upper().startswith(("ALTER", "CREATE", "DROP")):
            ddl.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        with pytest.raises(CommandError, match="blocked before revision 20261001_0006") as error:
            with engine.begin() as connection:
                command.downgrade(config_factory(connection), PREVIOUS)
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert ddl == []
    assert state(engine) == before
    assert "migration-category-probe" not in str(error.value)


def exercise_caller_rollback(engine, config_factory):
    with engine.begin() as connection:
        command.downgrade(config_factory(connection), PREVIOUS)
    persist_history(engine)
    before = state(engine)
    with engine.connect() as connection:
        transaction = connection.begin()
        command.upgrade(config_factory(connection), CURRENT)
        assert transaction.is_active
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == CURRENT
        transaction.rollback()
    assert state(engine) == before


def test_populated_round_trip(migrated_engine):
    exercise_round_trip(migrated_engine, _migration_config)


def test_incompatible_downgrade_before_ddl(migrated_engine):
    exercise_blocked_downgrade(migrated_engine, _migration_config)


def test_caller_owns_rollback(migrated_engine):
    exercise_caller_rollback(migrated_engine, _migration_config)


def test_failed_swap_is_atomic_even_when_caller_catches_error(migrated_engine):
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), PREVIOUS)
    persist_history(migrated_engine)
    before = state(migrated_engine)

    def fail(_connection, _cursor, statement, *_args):
        if statement.lstrip().startswith("CREATE TABLE _alembic_tmp_control_versions"):
            raise RuntimeError("injected category swap failure")

    event.listen(migrated_engine, "before_cursor_execute", fail)
    try:
        with migrated_engine.begin() as connection:
            with pytest.raises(RuntimeError, match="injected category"):
                command.upgrade(_migration_config(connection), CURRENT)
            assert connection.in_transaction()
    finally:
        event.remove(migrated_engine, "before_cursor_execute", fail)
    assert state(migrated_engine) == before
    with migrated_engine.connect() as connection:
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(text("PRAGMA defer_foreign_keys")) == 0
        assert connection.execute(text("PRAGMA foreign_key_check")).all() == []


def test_offline_downgrade_fails_before_sql():
    output = StringIO()
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"), output_buffer=output)
    config.attributes["database_url"] = "sqlite://"
    with pytest.raises(
        CommandError, match="Offline downgrade blocked before revision 20261001_0006"
    ):
        command.downgrade(config, f"{CURRENT}:{PREVIOUS}", sql=True)
    assert "DROP" not in output.getvalue() and "ALTER" not in output.getvalue()


@pytest.mark.parametrize("deferred", [False, True])
def test_caller_defer_flag_and_foreign_keys_are_preserved(migrated_engine, deferred):
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), PREVIOUS)
    persist_history(migrated_engine)
    with migrated_engine.begin() as connection:
        # sqlite3 legacy mode does not physically BEGIN for connection.begin().
        # Establish the caller's transaction before setting its defer flag; outside
        # a physical transaction SQLite resets that flag during metadata reads.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        connection.exec_driver_sql(f"PRAGMA defer_foreign_keys={'ON' if deferred else 'OFF'}")
        command.upgrade(_migration_config(connection), CURRENT)
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(text("PRAGMA defer_foreign_keys")) == int(deferred)
        assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
    assert state(migrated_engine)["revision"] == CURRENT
