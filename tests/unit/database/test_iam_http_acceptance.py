"""Supplemental local HTTP smoke; PostgreSQL remains the authoritative CI execution."""

from alembic import command
from sqlalchemy import create_engine, event

from tests.iam_http_acceptance import exercise_iam_http
from tests.integration.test_persistence_postgres import migration_config


def test_local_iam_http_acceptance(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'iam-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_iam_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
