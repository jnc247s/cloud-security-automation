"""Portable Alembic upgrade, drift, and downgrade verification."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.persistence import persist_scan_result
from app.models import ControlAssessment, ResourceSnapshot, Scan
from tests.unit.database.factories import scan_bundle


def test_sqlite_migration_round_trip_has_no_metadata_drift(migrated_engine: Engine) -> None:
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    with migrated_engine.begin() as connection:
        config.attributes["connection"] = connection
        command.check(config)
        command.downgrade(config, "base")
        assert inspect(connection).get_table_names() == ["alembic_version"]
        command.upgrade(config, "head")
        command.check(config)


def test_pending_scan_migration_preserves_existing_sprint3_history() -> None:
    """The table rebuild must retain populated immutable history and its guards."""

    engine = create_engine("sqlite://", poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "20260903_0001")

    bundle = scan_bundle()
    with Session(engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        command.check(config)

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.inventory_sha256 is not None
        assert session.scalar(select(func.count()).select_from(ResourceSnapshot)) == 1
        assert session.scalar(select(func.count()).select_from(ControlAssessment)) == 1
    engine.dispose()
