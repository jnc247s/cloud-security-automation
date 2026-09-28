"""Supplemental SQLite HTTP acceptance; PostgreSQL is authoritative."""

from alembic import command
from sqlalchemy import create_engine, event

from tests.integration.test_persistence_postgres import migration_config
from tests.network_http_acceptance import exercise_network_http


def test_local_network_http(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'network-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_network_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
