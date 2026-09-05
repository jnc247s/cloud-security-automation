"""Durable asynchronous scan creation and execution tests."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Lock
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.database.persistence import fail_pending_scan
from app.models import AuditEvent, Scan
from app.models.enums import AuditEventType, ScanStatus
from app.schemas.scan import ScanCreateRequest
from app.services.scan_executor import InProcessScanExecutor, ScanExecutorCapacityError
from app.services.scan_service import ScanService, ScanSubmissionError
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator


@pytest.fixture
def migrated_engine() -> Iterator[Engine]:
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(migrated_engine: Engine) -> Iterator[Session]:
    with Session(migrated_engine, expire_on_commit=False) as session:
        yield session


class RecordingExecutor:
    def __init__(self, error: Exception | None = None) -> None:
        self.submissions: list[Any] = []
        self.error = error

    def submit(self, scan_id) -> None:
        self.submissions.append(scan_id)
        if self.error is not None:
            raise self.error

    def shutdown(self, *, wait: bool = True) -> None:
        pass


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        database_url="sqlite://",
        aws_region="us-west-2",
        auth_mode="development",
    )


def _empty_provider() -> FakeClientProvider:
    region = "us-west-2"
    return FakeClientProvider(
        {
            ("ec2", region): FakeAWSClient(
                paginators={"describe_security_groups": FakePaginator([{"SecurityGroups": []}])}
            ),
            ("s3", region): FakeAWSClient(
                paginators={"list_buckets": FakePaginator([{"Buckets": []}])}
            ),
            ("iam", region): FakeAWSClient(
                paginators={"list_users": FakePaginator([{"Users": []}])}
            ),
            ("cloudtrail", region): FakeAWSClient(
                paginators={"list_trails": FakePaginator([{"Trails": []}])}
            ),
        },
        region_name=region,
    )


def test_start_scan_commits_pending_identity_before_submission(db_session: Session) -> None:
    executor = RecordingExecutor()

    result = ScanService(db_session, _settings()).start_scan(
        ScanCreateRequest(),
        executor,
        actor_id="analyst@example.test",
    )

    assert executor.submissions == [result.scan_id]
    assert result.status is ScanStatus.RUNNING
    assert result.aws_account_id is None
    assert result.inventory_sha256 is None
    persisted = db_session.get(Scan, result.scan_id)
    assert persisted is not None
    event = db_session.scalar(
        select(AuditEvent).where(AuditEvent.event_type == AuditEventType.SCAN_STARTED)
    )
    assert event is not None
    assert event.actor_type == "authenticated_user"
    assert event.actor_id == "analyst@example.test"


def test_submission_failure_terminalizes_scan_with_sanitized_details(
    db_session: Session,
) -> None:
    executor = RecordingExecutor(RuntimeError("internal queue detail must not escape"))
    service = ScanService(db_session, _settings())

    with pytest.raises(ScanSubmissionError):
        service.start_scan(ScanCreateRequest(), executor, actor_id="operator")

    scan_id = executor.submissions[0]
    result = service.get_scan(scan_id)
    assert result.status is ScanStatus.FAILED
    assert result.failure is not None
    assert result.failure.code == "EXECUTOR_SUBMISSION_FAILED"
    assert "internal queue detail" not in result.failure.message
    assert result.aws_account_id is None
    assert result.inventory_sha256 is None


def test_executor_resolves_account_and_finalizes_precreated_scan(
    db_session: Session,
    migrated_engine,
) -> None:
    pending = ScanService(db_session, _settings()).start_scan(
        ScanCreateRequest(),
        RecordingExecutor(),
        actor_id="operator",
    )
    factory = sessionmaker(bind=migrated_engine, expire_on_commit=False)
    executor = InProcessScanExecutor(
        session_factory=factory,
        settings=_settings(),
        provider_factory=lambda _region: _empty_provider(),
    )
    try:
        executor._execute(pending.scan_id)
    finally:
        executor.shutdown()
    db_session.expire_all()

    scan = db_session.get(Scan, pending.scan_id)
    assert scan is not None
    assert scan.status is ScanStatus.COMPLETED
    assert scan.aws_account_id == "123456789012"
    assert scan.inventory_sha256 is not None
    assert scan.result_checksum is not None
    assert scan.scope_manifest is not None
    assert scan.completed_at.replace(tzinfo=UTC).tzinfo is not None
    scan_events = tuple(
        db_session.scalars(
            select(AuditEvent)
            .where(AuditEvent.target_type == "scan", AuditEvent.target_id == pending.scan_id)
            .order_by(AuditEvent.timestamp)
        )
    )
    assert [event.event_type for event in scan_events] == [
        AuditEventType.SCAN_STARTED,
        AuditEventType.SCAN_COMPLETED,
    ]


def test_executor_records_bounded_failure_without_verified_identity(
    db_session: Session,
    migrated_engine,
) -> None:
    pending = ScanService(db_session, _settings()).start_scan(
        ScanCreateRequest(),
        RecordingExecutor(),
        actor_id="operator",
    )
    factory = sessionmaker(bind=migrated_engine, expire_on_commit=False)

    def fail_provider(_region: str):
        raise RuntimeError("credential-shaped internal failure")

    executor = InProcessScanExecutor(
        session_factory=factory,
        settings=_settings(),
        provider_factory=fail_provider,
    )
    try:
        executor._run(pending.scan_id)
    finally:
        executor.shutdown()
    db_session.expire_all()

    result = ScanService(db_session, _settings()).get_scan(pending.scan_id)
    assert result.status is ScanStatus.FAILED
    assert result.failure is not None
    assert result.failure.code == "SCAN_EXECUTION_FAILED"
    assert "credential-shaped" not in result.model_dump_json()
    assert result.aws_account_id is None


def test_immediately_completed_future_does_not_deadlock_submit(db_session: Session) -> None:
    executor = InProcessScanExecutor(
        session_factory=lambda: db_session,
        settings=_settings(),
        max_workers=1,
        max_outstanding=1,
    )
    executor._run = lambda _scan_id: None
    try:
        with ThreadPoolExecutor(max_workers=1) as caller:
            caller.submit(executor.submit, uuid4()).result(timeout=2)
    finally:
        executor.shutdown()


def test_executor_rejects_work_beyond_bounded_capacity(db_session: Session) -> None:
    started = Event()
    release = Event()

    def block(_scan_id) -> None:
        started.set()
        release.wait(timeout=2)

    executor = InProcessScanExecutor(
        session_factory=lambda: db_session,
        settings=_settings(),
        max_workers=1,
        max_outstanding=1,
    )
    executor._run = block
    try:
        executor.submit(uuid4())
        assert started.wait(timeout=2)
        with pytest.raises(ScanExecutorCapacityError):
            executor.submit(uuid4())
    finally:
        release.set()
        executor.shutdown()


def test_resume_pending_drains_more_rows_than_executor_capacity(
    db_session: Session,
    migrated_engine: Engine,
) -> None:
    pending_ids = [
        ScanService(db_session, _settings())
        .start_scan(ScanCreateRequest(), RecordingExecutor(), actor_id="operator")
        .scan_id
        for _ in range(3)
    ]
    factory = sessionmaker(bind=migrated_engine, expire_on_commit=False)
    processed: list = []
    processed_lock = Lock()
    all_processed = Event()

    def terminalize(scan_id) -> None:
        with factory() as session, session.begin():
            fail_pending_scan(
                session,
                scan_id=scan_id,
                completed_at=datetime.now(UTC),
                failure_code="TEST_RECOVERY",
                failure_message="Recovery test intentionally terminalized this scan.",
            )
        with processed_lock:
            processed.append(scan_id)
            if len(processed) == len(pending_ids):
                all_processed.set()

    executor = InProcessScanExecutor(
        session_factory=factory,
        settings=_settings(),
        max_workers=1,
        max_outstanding=1,
    )
    executor._run = terminalize
    try:
        assert executor.resume_pending() == 1
        assert all_processed.wait(timeout=5)
    finally:
        executor.shutdown()

    assert set(processed) == set(pending_ids)
