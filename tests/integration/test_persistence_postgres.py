"""PostgreSQL migration, integrity, and concurrency checks in isolated test schemas."""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, inspect, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import __version__
from app.assessment.controls import build_default_control_catalog
from app.assessment.profiles import create_default_assessment_profile
from app.config import Settings
from app.database.persistence import fail_pending_scan, persist_scan_result
from app.models import AuditEvent, Finding, FindingOccurrence, ResourceSnapshot, Scan
from app.models.enums import AuditEventType, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import _scope_for
from app.services.scan_service import ScanService
from tests.unit.database.factories import scan_bundle

pytestmark = pytest.mark.integration


class _RecordingExecutor:
    def __init__(self) -> None:
        self.scan_ids: list[UUID] = []

    def submit(self, scan_id: UUID) -> None:
        self.scan_ids.append(scan_id)

    def resume_pending(self) -> int:
        return 0

    def shutdown(self, *, wait: bool = True) -> None:
        del wait


def _scan_settings(postgres_engine: Engine) -> Settings:
    return Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        database_url=str(postgres_engine.url),
        aws_region="us-east-1",
    )


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
    schema = "sprint4_test_" + uuid4().hex
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


def test_postgres_finalizes_a_committed_pending_scan(postgres_engine: Engine) -> None:
    """Exercise the Sprint 4 pre-created RUNNING row against PostgreSQL guards."""

    settings = _scan_settings(postgres_engine)
    executor = _RecordingExecutor()
    with Session(postgres_engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            executor,
            actor_id="integration-admin",
        )
    assert executor.scan_ids == [pending.scan_id]

    collected_at = datetime.now(UTC)
    snapshot = InventorySnapshot(
        scan_id=pending.scan_id,
        account_id="123456789012",
        requested_region="us-east-1",
        collected_at=collected_at,
        collector_outcomes=tuple(
            CollectorOutcome(collector_name=name, status=CollectionStatus.SUCCEEDED)
            for name in (
                "cloudtrail_trails",
                "iam_users",
                "s3_buckets",
                "security_groups",
            )
        ),
        resources=(),
    )
    profile = create_default_assessment_profile(
        required_tags=settings.required_tag_names,
        stale_key_days=settings.stale_access_key_days,
    )
    catalog = build_default_control_catalog()
    assessments = RuleEngine(build_default_registry()).assess(snapshot, profile)
    scope = _scope_for(snapshot, profile, catalog)

    with Session(postgres_engine) as session, session.begin():
        scan = session.get(Scan, pending.scan_id)
        assert scan is not None
        persist_scan_result(
            session,
            snapshot=snapshot,
            scope=scope,
            profile=profile,
            catalog=catalog,
            assessments=assessments,
            started_at=scan.started_at,
            completed_at=collected_at + timedelta(seconds=1),
            scanner_version=__version__,
            actor_type="system",
            actor_id="scan-executor",
        )

    with Session(postgres_engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan is not None
        assert scan.status is ScanStatus.COMPLETED
        assert scan.aws_account_id == "123456789012"
        assert scan.inventory_sha256 is not None
        assert scan.result_checksum is not None
        assert scan.scope_manifest is not None
        event_types = tuple(
            session.scalars(
                select(AuditEvent.event_type)
                .where(AuditEvent.target_type == "scan", AuditEvent.target_id == pending.scan_id)
                .order_by(AuditEvent.timestamp)
            )
        )
        assert event_types == (AuditEventType.SCAN_STARTED, AuditEventType.SCAN_COMPLETED)


def test_postgres_allows_bounded_failure_before_aws_identity(postgres_engine: Engine) -> None:
    settings = _scan_settings(postgres_engine)
    with Session(postgres_engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            _RecordingExecutor(),
            actor_id="integration-admin",
        )
        fail_pending_scan(
            session,
            scan_id=pending.scan_id,
            completed_at=datetime.now(UTC),
            failure_code="AWS_IDENTITY_UNAVAILABLE",
            failure_message="AWS identity could not be verified.",
        )
        session.commit()

    with Session(postgres_engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan is not None
        assert scan.status is ScanStatus.FAILED
        assert scan.aws_account_id is None
        assert scan.inventory_sha256 is None
        assert scan.result_checksum is not None
        failure_event = session.scalar(
            select(AuditEvent).where(
                AuditEvent.target_id == pending.scan_id,
                AuditEvent.event_type == AuditEventType.SCAN_FAILED,
            )
        )
        assert failure_event is not None
        assert failure_event.event_metadata["failure_code"] == "AWS_IDENTITY_UNAVAILABLE"


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
