"""Supplemental local HTTP acceptance; PostgreSQL is authoritative in CI."""

from alembic import command
from sqlalchemy import create_engine, event

from tests.ec2_http_acceptance import exercise_ec2_http
from tests.integration.test_persistence_postgres import migration_config


def test_local_ec2_http(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'ec2-http.sqlite').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        exercise_ec2_http(engine, monkeypatch, tmp_path)
    finally:
        engine.dispose()
