"""PostgreSQL migration, integrity, and concurrency checks in isolated test schemas."""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, inspect, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.persistence import persist_scan_result
from app.models import AuditEvent, Finding, FindingOccurrence, ResourceSnapshot, Scan
from tests.unit.database.factories import scan_bundle

pytestmark = pytest.mark.integration


def migration_config(connection) -> Config:
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.attributes["database_url"] = str(connection.engine.url)
    config.attributes["connection"] = connection
    return config


@pytest.fixture
def postgres_engine() -> Iterator[Engine]:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail("TEST_DATABASE_URL must use PostgreSQL")
    # Only this generated schema is created/dropped. Existing schemas and data are untouched.
    schema = "sprint3_test_" + uuid4().hex
    admin_engine = create_engine(database_url, connect_args={"connect_timeout": 5})
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        database_url,
        connect_args={"connect_timeout": 5, "options": f"-csearch_path={schema}"},
        pool_pre_ping=True,
    )
    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        yield engine
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()


def test_postgres_migration_round_trip_and_jsonb(postgres_engine: Engine) -> None:
    with postgres_engine.begin() as connection:
        config = migration_config(connection)
        command.check(config)
        columns = {
            column["name"]: column
            for column in inspect(connection).get_columns("resource_snapshots")
        }
        assert isinstance(columns["normalized_configuration"]["type"], JSONB)
        assert isinstance(columns["tags"]["type"], JSONB)
        command.downgrade(config, "base")
        assert inspect(connection).get_table_names() == ["alembic_version"]
        command.upgrade(config, "head")
        command.check(config)


def test_postgres_history_and_append_only_audit(postgres_engine: Engine) -> None:
    bundle = scan_bundle()
    with Session(postgres_engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(postgres_engine) as session:
        observed = session.scalar(select(ResourceSnapshot.observed_at))
        assert observed.tzinfo is not None
        assert observed == bundle["snapshot"].collected_at
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 3
        with pytest.raises(IntegrityError, match="immutable"):
            session.execute(update(AuditEvent).values(actor_id="rewritten"))
        session.rollback()
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 3


def test_postgres_concurrent_failures_deduplicate_without_losing_occurrences(
    postgres_engine: Engine,
) -> None:
    first = scan_bundle()
    second = scan_bundle(observed_at=first["snapshot"].collected_at + timedelta(minutes=1))
    barrier = Barrier(2)

    def write(bundle) -> None:
        with Session(postgres_engine) as session, session.begin():
            barrier.wait(timeout=10)
            persist_scan_result(session, **bundle)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write, bundle) for bundle in (first, second)]
        for future in futures:
            future.result(timeout=30)
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 2
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert session.scalar(select(func.count()).select_from(FindingOccurrence)) == 2


def test_postgres_concurrent_identical_scan_retry_is_idempotent(postgres_engine: Engine) -> None:
    bundle = scan_bundle()
    barrier = Barrier(2)

    def write() -> None:
        with Session(postgres_engine) as session, session.begin():
            barrier.wait(timeout=10)
            persist_scan_result(session, **bundle)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write) for _ in range(2)]
        for future in futures:
            future.result(timeout=30)
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert session.scalar(select(func.count()).select_from(FindingOccurrence)) == 1
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 3
