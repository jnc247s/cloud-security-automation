"""PostgreSQL migration, integrity, and concurrency checks in isolated test schemas."""

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from time import monotonic
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, inspect, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.assessment.controls import build_default_control_catalog
from app.assessment.models import AssessmentResult
from app.assessment.profiles import create_default_assessment_profile
from app.config import Settings, get_settings
from app.database import session as database_session
from app.database.persistence import fail_pending_scan, persist_scan_result
from app.main import create_app
from app.models import (
    AuditEvent,
    Control,
    ControlAssessment,
    EvidenceArtifact,
    Finding,
    FindingOccurrence,
    PersistedAssessmentProfile,
    Resource,
    ResourceSnapshot,
    Scan,
)
from app.models.enums import AuditEventType, FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.scan import ScanCreateRequest
from app.security.authentication import DEVELOPMENT_BEARER_MARKER
from app.services.errors import AssessmentProfileConflictError
from app.services.scan_executor import InProcessScanExecutor, _scope_for
from app.services.scan_service import ScanService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator
from tests.unit.database.factories import scan_bundle

pytestmark = pytest.mark.integration

_CURRENT_REVISION = "20260904_0002"
_PREVIOUS_REVISION = "20260903_0001"
_COMPLETED_IDENTITY_CONSTRAINT = "ck_scans_completed_evidence_identity_present"


class _RecordingExecutor:
    def __init__(self) -> None:
        self.scan_ids: list[UUID] = []

    def submit(self, scan_id: UUID) -> None:
        self.scan_ids.append(scan_id)

    def resume_pending(self) -> int:
        return 0

    def shutdown(self, *, wait: bool = True) -> None:
        del wait


class _CollectionGatePaginator(FakePaginator):
    """Hold one fake AWS call until the HTTP request has returned."""

    def __init__(self, pages, *, entered: Event, release: Event) -> None:
        super().__init__(pages)
        self._entered = entered
        self._release = release

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        self._entered.set()
        if not self._release.wait(timeout=30):
            raise AssertionError("acceptance-test AWS gate was not released")
        yield from self.pages


def _scan_settings(postgres_engine: Engine, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "test",
        "auth_mode": "development",
        "database_url": str(postgres_engine.url),
        "aws_region": "us-east-1",
    }
    values.update(overrides)
    return Settings(
        _env_file=None,
        **values,
    )


def _empty_provider(region: str = "us-east-1") -> FakeClientProvider:
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


def migration_config(connection) -> Config:
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.attributes["database_url"] = str(connection.engine.url)
    config.attributes["connection"] = connection
    return config


def _postgres_migration_state(engine: Engine) -> dict:
    with engine.connect() as connection:
        inspector = inspect(connection)
        table_names = inspector.get_table_names()
        return {
            "revision": connection.scalar(text("SELECT version_num FROM alembic_version")),
            "scan_columns": {
                column["name"]: column["nullable"] for column in inspector.get_columns("scans")
            },
            "scan_constraints": tuple(
                sorted(
                    (constraint["name"], constraint["sqltext"])
                    for constraint in inspector.get_check_constraints("scans")
                )
            ),
            "scan_rows": tuple(
                dict(row)
                for row in connection.execute(
                    text("SELECT * FROM scans ORDER BY scan_id")
                ).mappings()
            ),
            "table_counts": {
                table_name: connection.scalar(text(f'SELECT COUNT(*) FROM "{table_name}"'))
                for table_name in table_names
                if table_name != "alembic_version"
            },
            "scan_triggers": tuple(
                tuple(row)
                for row in connection.execute(
                    text(
                        "SELECT tgname, pg_get_triggerdef(oid) "
                        "FROM pg_trigger "
                        "WHERE tgrelid = CAST('scans' AS regclass) AND NOT tgisinternal "
                        "ORDER BY tgname"
                    )
                )
            ),
        }


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


def test_postgres_pending_scan_downgrade_preserves_compatible_populated_history(
    postgres_engine: Engine,
) -> None:
    bundle = scan_bundle()
    with Session(postgres_engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    before = _postgres_migration_state(postgres_engine)
    assert before["scan_rows"][0]["aws_account_id"] is not None
    assert before["scan_rows"][0]["inventory_sha256"] is not None
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), _PREVIOUS_REVISION)
    after = _postgres_migration_state(postgres_engine)

    assert before["revision"] == _CURRENT_REVISION
    assert after["revision"] == _PREVIOUS_REVISION
    assert after["scan_columns"]["aws_account_id"] is False
    assert after["scan_columns"]["inventory_sha256"] is False
    assert _COMPLETED_IDENTITY_CONSTRAINT not in {name for name, _ in after["scan_constraints"]}
    assert after["scan_rows"] == before["scan_rows"]
    assert after["table_counts"] == before["table_counts"]
    assert after["scan_triggers"] == before["scan_triggers"]
    assert len(after["scan_rows"]) == 1
    assert after["scan_rows"][0]["scan_id"] == scan_id


@pytest.mark.parametrize(
    ("status", "aws_account_id", "inventory_sha256", "target_revision"),
    (
        (ScanStatus.RUNNING, None, None, "base"),
        (ScanStatus.FAILED, None, None, _PREVIOUS_REVISION),
        (ScanStatus.RUNNING, "123456789012", None, _PREVIOUS_REVISION),
        (ScanStatus.RUNNING, None, "f" * 64, _PREVIOUS_REVISION),
    ),
    ids=(
        "running-both-missing",
        "failed-both-missing",
        "running-digest-missing",
        "running-account-missing",
    ),
)
def test_postgres_pending_scan_downgrade_blocks_incompatible_history_without_changes(
    postgres_engine: Engine,
    status: ScanStatus,
    aws_account_id: str | None,
    inventory_sha256: str | None,
    target_revision: str,
) -> None:
    settings = _scan_settings(postgres_engine)
    with Session(postgres_engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            _RecordingExecutor(),
            actor_id="migration-test-admin",
        )
        if aws_account_id is not None or inventory_sha256 is not None:
            scan = session.get(Scan, pending.scan_id)
            assert scan is not None
            scan.aws_account_id = aws_account_id
            scan.inventory_sha256 = inventory_sha256
            session.commit()
        if status is ScanStatus.FAILED:
            fail_pending_scan(
                session,
                scan_id=pending.scan_id,
                completed_at=datetime.now(UTC),
                failure_code="AWS_IDENTITY_UNAVAILABLE",
                failure_message="AWS identity could not be verified.",
            )
            session.commit()

    before = _postgres_migration_state(postgres_engine)
    assert before["scan_rows"][0]["aws_account_id"] == aws_account_id
    assert before["scan_rows"][0]["inventory_sha256"] == inventory_sha256
    with pytest.raises(CommandError, match="Downgrade blocked before revision") as error:
        with postgres_engine.begin() as connection:
            command.downgrade(migration_config(connection), target_revision)

    after = _postgres_migration_state(postgres_engine)
    assert after == before
    assert after["revision"] == _CURRENT_REVISION
    assert after["scan_columns"]["aws_account_id"] is True
    assert after["scan_columns"]["inventory_sha256"] is True
    assert _COMPLETED_IDENTITY_CONSTRAINT in {name for name, _ in after["scan_constraints"]}
    assert after["scan_rows"][0]["status"] == status.value
    error_message = str(error.value)
    assert "No schema or data changes were applied" in error_message
    assert "docs/operations/known-limitations.md" in error_message
    assert str(pending.scan_id) not in error_message
    assert pending.scan_id.hex not in error_message

    with postgres_engine.begin() as connection:
        command.check(migration_config(connection))


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
        version=settings.assessment_profile_version,
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


def test_postgres_profile_roll_forward_and_restart_preserve_exact_provenance(
    postgres_engine: Engine,
) -> None:
    original_settings = _scan_settings(
        postgres_engine,
        assessment_profile_version="1.0.0",
        required_tags="Owner",
        stale_access_key_days=45,
    )
    recorder = _RecordingExecutor()
    with Session(postgres_engine, expire_on_commit=False) as session:
        original = ScanService(session, original_settings).start_scan(
            ScanCreateRequest(), recorder, actor_id="integration-admin"
        )
        repeated = ScanService(session, original_settings).start_scan(
            ScanCreateRequest(), recorder, actor_id="integration-admin"
        )
    assert recorder.scan_ids == [original.scan_id, repeated.scan_id]
    assert original.assessment_profile_checksum == repeated.assessment_profile_checksum

    restarted_settings = _scan_settings(
        postgres_engine,
        assessment_profile_version="1.1.0",
        required_tags="DataClassification",
        stale_access_key_days=120,
    )
    session_factory = sessionmaker(bind=postgres_engine, expire_on_commit=False)
    restarted_executor = InProcessScanExecutor(
        session_factory=session_factory,
        settings=restarted_settings,
        provider_factory=lambda region: _empty_provider(region),
        max_workers=1,
        max_outstanding=2,
    )
    try:
        assert restarted_executor.resume_pending() == 2
    finally:
        restarted_executor.shutdown(wait=True)

    with Session(postgres_engine) as session:
        stored_profiles = tuple(session.scalars(select(PersistedAssessmentProfile)))
        assert len(stored_profiles) == 1
        original_profile = stored_profiles[0]
        assert original_profile.version == "1.0.0"
        assert original_profile.required_tags == ["Owner"]
        assert original_profile.stale_key_days == 45
        for scan_id in (original.scan_id, repeated.scan_id):
            scan = session.get(Scan, scan_id)
            assert scan is not None
            assert scan.status is ScanStatus.COMPLETED
            assert scan.assessment_profile_version == "1.0.0"
            assert scan.assessment_profile_checksum == original_profile.content_checksum
            assert scan.scope_manifest is not None
            assert scan.scope_manifest.assessment_profile_version == "1.0.0"
            profile_ids = set(
                session.scalars(
                    select(ControlAssessment.assessment_profile_version_id).where(
                        ControlAssessment.scan_id == scan_id
                    )
                )
            )
            assert profile_ids == {original_profile.profile_version_id}

    conflicting_settings = _scan_settings(
        postgres_engine,
        assessment_profile_version="1.0.0",
        required_tags="DataClassification",
        stale_access_key_days=120,
    )
    with Session(postgres_engine) as session:
        with pytest.raises(AssessmentProfileConflictError):
            ScanService(session, conflicting_settings).start_scan(
                ScanCreateRequest(), _RecordingExecutor(), actor_id="integration-admin"
            )
        assert session.scalar(select(func.count()).select_from(Scan)) == 2
        assert session.scalar(select(func.count()).select_from(PersistedAssessmentProfile)) == 1

    with Session(postgres_engine, expire_on_commit=False) as session:
        replacement = ScanService(session, restarted_settings).start_scan(
            ScanCreateRequest(), _RecordingExecutor(), actor_id="integration-admin"
        )
    replacement_executor = InProcessScanExecutor(
        session_factory=session_factory,
        settings=restarted_settings,
        provider_factory=lambda region: _empty_provider(region),
        max_workers=1,
        max_outstanding=1,
    )
    try:
        replacement_executor._execute(replacement.scan_id)
    finally:
        replacement_executor.shutdown(wait=True)

    with Session(postgres_engine) as session:
        profiles = {
            profile.version: profile
            for profile in session.scalars(
                select(PersistedAssessmentProfile).order_by(PersistedAssessmentProfile.version)
            )
        }
        assert set(profiles) == {"1.0.0", "1.1.0"}
        assert profiles["1.0.0"].required_tags == ["Owner"]
        assert profiles["1.1.0"].required_tags == ["DataClassification"]
        assert profiles["1.0.0"].content_checksum != profiles["1.1.0"].content_checksum
        for original_scan_id in (original.scan_id, repeated.scan_id):
            historical_scan = session.get(Scan, original_scan_id)
            assert historical_scan is not None
            assert historical_scan.assessment_profile_version == "1.0.0"
            historical_profile_ids = set(
                session.scalars(
                    select(ControlAssessment.assessment_profile_version_id).where(
                        ControlAssessment.scan_id == original_scan_id
                    )
                )
            )
            assert historical_profile_ids == {profiles["1.0.0"].profile_version_id}
        new_scan = session.get(Scan, replacement.scan_id)
        assert new_scan is not None
        assert new_scan.status is ScanStatus.COMPLETED
        assert new_scan.assessment_profile_version == "1.1.0"
        assert new_scan.assessment_profile_checksum == profiles["1.1.0"].content_checksum
        new_assessment_profile_ids = set(
            session.scalars(
                select(ControlAssessment.assessment_profile_version_id).where(
                    ControlAssessment.scan_id == replacement.scan_id
                )
            )
        )
        assert new_assessment_profile_ids == {profiles["1.1.0"].profile_version_id}


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


def _development_settings(
    monkeypatch: pytest.MonkeyPatch,
    postgres_engine: Engine,
    *,
    subject: str,
    role: str,
) -> Settings:
    """Configure the supported development bearer backend for one real identity."""

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("AUTH_MODE", "development")
    monkeypatch.setenv("DEV_IDENTITY_SUBJECT", subject)
    monkeypatch.setenv("DEV_IDENTITY_ROLES", role)
    monkeypatch.setenv(
        "DATABASE_URL",
        postgres_engine.url.render_as_string(hide_password=False),
    )
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("REQUIRED_TAGS", "Owner,Environment")
    monkeypatch.setenv("STALE_ACCESS_KEY_DAYS", "90")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    get_settings.cache_clear()
    return get_settings()


def _poll_terminal_scan(
    client: TestClient,
    scan_id: UUID,
    headers: dict[str, str],
    *,
    timeout_seconds: float = 20,
) -> dict:
    """Poll the public API to a terminal scan state under a monotonic deadline."""

    deadline = monotonic() + timeout_seconds
    poll_interval = Event()
    attempts = 0
    last_document: dict | None = None
    terminal_states = {"COMPLETED", "FAILED", "PARTIAL"}
    while monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert response.status_code == 200, response.text
        last_document = response.json()
        attempts += 1
        if last_document["status"] in terminal_states:
            return last_document
        poll_interval.wait(timeout=0.01)

    pytest.fail(
        f"scan {scan_id} did not reach a terminal state within {timeout_seconds}s "
        f"after {attempts} API polls; last response was {last_document}"
    )


def test_authenticated_http_scan_persists_and_exposes_sprint_0_to_4_graph(
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove the accepted HTTP-to-PostgreSQL scan workflow with only AWS replaced."""

    session_factory = sessionmaker(
        bind=postgres_engine,
        autoflush=False,
        expire_on_commit=False,
    )
    monkeypatch.setattr(database_session, "SessionLocal", session_factory)
    headers = {"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"}

    try:
        analyst_settings = _development_settings(
            monkeypatch,
            postgres_engine,
            subject="acceptance-analyst",
            role="ANALYST",
        )
        analyst_application = create_app(
            executor_factory=lambda: InProcessScanExecutor(
                session_factory=session_factory,
                settings=analyst_settings,
                provider_factory=lambda region: FakeClientProvider({}, region_name=region),
                max_workers=1,
                max_outstanding=1,
            )
        )
        assert analyst_application.dependency_overrides == {}
        with TestClient(analyst_application) as analyst_client:
            denied = analyst_client.post(
                "/api/v1/scans",
                headers=headers,
                json={"region": "us-east-1"},
            )
        assert denied.status_code == 403
        assert denied.json()["detail"] == {
            "code": "insufficient_capability",
            "message": "The EXECUTE capability is required.",
        }
        with Session(postgres_engine) as session:
            assert session.scalar(select(func.count()).select_from(Scan)) == 0

        admin_settings = _development_settings(
            monkeypatch,
            postgres_engine,
            subject="acceptance-admin",
            role="ADMIN",
        )
        collection_entered = Event()
        collection_release = Event()
        security_group_pages = _CollectionGatePaginator(
            [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-acceptance-public-ssh",
                            "GroupName": "acceptance-public-ssh",
                            "Description": "Deterministic offline acceptance fixture",
                            "VpcId": "vpc-acceptance",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    "Ipv6Ranges": [],
                                    "PrefixListIds": [],
                                    "UserIdGroupPairs": [],
                                }
                            ],
                            "IpPermissionsEgress": [],
                            "Tags": [
                                {"Key": "Owner", "Value": "security"},
                                {"Key": "Environment", "Value": "acceptance"},
                            ],
                        }
                    ]
                }
            ],
            entered=collection_entered,
            release=collection_release,
        )
        s3_pages = FakePaginator([{"Buckets": []}])
        iam_pages = FakePaginator([{"Users": []}])
        cloudtrail_pages = FakePaginator([{"Trails": []}])
        provider = FakeClientProvider(
            {
                ("ec2", "us-east-1"): FakeAWSClient(
                    paginators={"describe_security_groups": security_group_pages}
                ),
                ("s3", "us-east-1"): FakeAWSClient(paginators={"list_buckets": s3_pages}),
                ("iam", "us-east-1"): FakeAWSClient(paginators={"list_users": iam_pages}),
                ("cloudtrail", "us-east-1"): FakeAWSClient(
                    paginators={"list_trails": cloudtrail_pages}
                ),
            },
            region_name="us-east-1",
            account_id="123456789012",
        )
        application = create_app(
            executor_factory=lambda: InProcessScanExecutor(
                session_factory=session_factory,
                settings=admin_settings,
                provider_factory=lambda _region: provider,
                max_workers=1,
                max_outstanding=1,
            )
        )
        assert application.dependency_overrides == {}

        with TestClient(application) as client:
            with ThreadPoolExecutor(max_workers=1) as request_pool:
                request = request_pool.submit(
                    client.post,
                    "/api/v1/scans",
                    headers=headers,
                    json={"region": "us-east-1"},
                )
                try:
                    assert collection_entered.wait(timeout=15), (
                        "the real executor did not reach the fake AWS boundary"
                    )
                    response = request.result(timeout=10)
                    assert not collection_release.is_set()
                except TimeoutError:
                    pytest.fail("POST /api/v1/scans waited for AWS collection")
                finally:
                    collection_release.set()

            assert response.status_code == 202, response.text
            submitted = response.json()
            assert submitted["status"] == "RUNNING"
            scan_id = UUID(submitted["scan_id"])

            terminal = _poll_terminal_scan(client, scan_id, headers)
            assert terminal["status"] == "COMPLETED", terminal
            assert terminal["aws_account_id"] == "123456789012"
            assert terminal["requested_regions"] == ["us-east-1"]
            assert terminal["successful_regions"] == ["us-east-1"]
            assert set(terminal["successful_collectors"]) == {
                "cloudtrail_trails",
                "iam_users",
                "s3_buckets",
                "security_groups",
            }
            assert terminal["scope"]["enabled_controls"] == [
                "IAM-001",
                "LOG-001",
                "NET-001",
                "NET-002",
                "S3-900",
            ]
            assert set(terminal["scope"]["collector_outcomes"].values()) == {"SUCCEEDED"}

            assert provider.client_requests == [
                ("ec2", "us-east-1"),
                ("s3", "us-east-1"),
                ("iam", "us-east-1"),
                ("cloudtrail", "us-east-1"),
            ]
            assert security_group_pages.calls == [{}]
            assert s3_pages.calls == [{"PaginationConfig": {"PageSize": 1000}}]
            assert iam_pages.calls == [{}]
            assert cloudtrail_pages.calls == [{}]

            with Session(postgres_engine) as session:
                persisted_scan = session.get(Scan, scan_id)
                assert persisted_scan is not None
                assert persisted_scan.status is ScanStatus.COMPLETED
                assert persisted_scan.aws_account_id == "123456789012"
                assert persisted_scan.inventory_sha256 == terminal["inventory_sha256"]
                assert persisted_scan.result_checksum == terminal["result_checksum"]

                resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "security_group",
                        Resource.aws_resource_id == "sg-acceptance-public-ssh",
                    )
                ).one()
                snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == resource.resource_id,
                    )
                ).one()
                assert snapshot.normalized_configuration["ingress_rules"][0]["ipv4_ranges"] == [
                    {"cidr": "0.0.0.0/0", "description": None}
                ]

                assessed_control_keys = set(
                    session.scalars(
                        select(Control.control_key)
                        .join(
                            ControlAssessment,
                            ControlAssessment.control_id == Control.control_id,
                        )
                        .where(ControlAssessment.scan_id == scan_id)
                    )
                )
                assert assessed_control_keys == {
                    "IAM-001",
                    "LOG-001",
                    "NET-001",
                    "NET-002",
                    "S3-900",
                }
                control = session.scalars(
                    select(Control).where(Control.control_key == "NET-001")
                ).one()
                assessment = session.scalars(
                    select(ControlAssessment).where(
                        ControlAssessment.scan_id == scan_id,
                        ControlAssessment.resource_id == resource.resource_id,
                        ControlAssessment.control_id == control.control_id,
                    )
                ).one()
                assert assessment.assessment_result is AssessmentResult.FAIL
                assert assessment.resource_snapshot_id == snapshot.snapshot_id

                evidence = session.scalars(
                    select(EvidenceArtifact).where(
                        EvidenceArtifact.assessment_id == assessment.assessment_id
                    )
                ).one()
                assert evidence.resource_snapshot_id == snapshot.snapshot_id
                assert evidence.control_id == control.control_id
                assert evidence.collector == "security_groups"
                assert evidence.source_api == "ec2:DescribeSecurityGroups"
                assert evidence.payload["target_port"] == 22
                assert evidence.payload["matched_ingress"][0]["cidr"] == "0.0.0.0/0"

                finding = session.scalars(
                    select(Finding).where(
                        Finding.resource_id == resource.resource_id,
                        Finding.control_id == control.control_id,
                    )
                ).one()
                assert finding.status is FindingStatus.OPEN
                occurrence = session.scalars(
                    select(FindingOccurrence).where(
                        FindingOccurrence.finding_id == finding.finding_id,
                        FindingOccurrence.assessment_id == assessment.assessment_id,
                    )
                ).one()
                assert occurrence.scan_id == scan_id
                assert occurrence.resource_snapshot_id == snapshot.snapshot_id

                scan_events = tuple(
                    session.scalars(
                        select(AuditEvent)
                        .where(
                            AuditEvent.target_type == "scan",
                            AuditEvent.target_id == scan_id,
                        )
                        .order_by(AuditEvent.timestamp, AuditEvent.event_id)
                    )
                )
                assert [
                    (event.event_type, event.actor_type, event.actor_id) for event in scan_events
                ] == [
                    (AuditEventType.SCAN_STARTED, "authenticated_user", "acceptance-admin"),
                    (AuditEventType.SCAN_COMPLETED, "system", "scan-executor"),
                ]
                finding_event = session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.target_type == "finding",
                        AuditEvent.target_id == finding.finding_id,
                        AuditEvent.event_type == AuditEventType.FINDING_OPENED,
                    )
                ).one()
                assert finding_event.actor_type == "system"
                assert finding_event.actor_id == "scan-executor"
                assert finding_event.event_metadata["assessment_id"] == str(
                    assessment.assessment_id
                )

                resource_id = resource.resource_id
                snapshot_id = snapshot.snapshot_id
                control_id = control.control_id
                assessment_id = assessment.assessment_id
                control_version_id = assessment.control_version_id
                evidence_id = evidence.evidence_id
                finding_id = finding.finding_id
                occurrence_id = occurrence.occurrence_id

            scan_detail = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
            assert scan_detail.status_code == 200
            assert scan_detail.json() == terminal

            resource_page = client.get(
                "/api/v1/resources",
                headers=headers,
                params={
                    "account_id": "123456789012",
                    "service": "ec2",
                    "resource_type": "security_group",
                    "region": "us-east-1",
                },
            )
            assert resource_page.status_code == 200
            assert resource_page.json()["total"] == 1
            resource_document = resource_page.json()["items"][0]
            assert resource_document["resource_id"] == str(resource_id)
            assert resource_document["aws_resource_id"] == "sg-acceptance-public-ssh"
            assert resource_document["latest_snapshot"]["snapshot_id"] == str(snapshot_id)
            assert resource_document["latest_snapshot"]["scan_id"] == str(scan_id)

            resource_detail = client.get(f"/api/v1/resources/{resource_id}", headers=headers)
            assert resource_detail.status_code == 200
            assert resource_detail.json() == resource_document
            history = client.get(
                f"/api/v1/resources/{resource_id}/history",
                headers=headers,
            )
            assert history.status_code == 200
            assert history.json()["total"] == 1
            assert history.json()["items"][0]["snapshot_id"] == str(snapshot_id)
            assert history.json()["items"][0]["scan_id"] == str(scan_id)

            assessment_page = client.get(
                "/api/v1/assessments",
                headers=headers,
                params={
                    "scan_id": str(scan_id),
                    "resource_id": str(resource_id),
                    "control_id": str(control_id),
                    "result": "FAIL",
                },
            )
            assert assessment_page.status_code == 200
            assert assessment_page.json()["total"] == 1
            assert assessment_page.json()["items"][0]["assessment_id"] == str(assessment_id)
            assert assessment_page.json()["items"][0]["evidence_count"] == 1

            assessment_detail = client.get(
                f"/api/v1/assessments/{assessment_id}",
                headers=headers,
            )
            assert assessment_detail.status_code == 200
            assessment_document = assessment_detail.json()
            assert assessment_document["resource_snapshot_id"] == str(snapshot_id)
            assert assessment_document["resource_id"] == str(resource_id)
            assert assessment_document["control_id"] == str(control_id)
            assert assessment_document["control_version_id"] == str(control_version_id)
            assert assessment_document["assessment_result"] == "FAIL"
            assert assessment_document["finding_id"] == str(finding_id)
            assert assessment_document["finding_occurrence_id"] == str(occurrence_id)
            assert [item["evidence_id"] for item in assessment_document["evidence"]] == [
                str(evidence_id)
            ]
            assert assessment_document["evidence"][0]["payload"]["target_port"] == 22
            mapping = assessment_document["framework_mappings"][0]
            assert mapping["control_version_id"] == str(control_version_id)
            assert mapping["framework_key"] == "nist-csf"
            assert mapping["framework_version"] == "2.0"
            assert mapping["reference_key"] == "PR.IR-01"

            finding_page = client.get(
                "/api/v1/findings",
                headers=headers,
                params={
                    "resource_id": str(resource_id),
                    "control_id": str(control_id),
                    "status": "OPEN",
                },
            )
            assert finding_page.status_code == 200
            assert finding_page.json()["total"] == 1
            assert finding_page.json()["items"][0]["finding_id"] == str(finding_id)
            finding_detail = client.get(f"/api/v1/findings/{finding_id}", headers=headers)
            assert finding_detail.status_code == 200
            finding_document = finding_detail.json()
            assert finding_document["resource_id"] == str(resource_id)
            assert finding_document["control_id"] == str(control_id)
            assert finding_document["occurrences"] == [
                {
                    "occurrence_id": str(occurrence_id),
                    "finding_id": str(finding_id),
                    "assessment_id": str(assessment_id),
                    "scan_id": str(scan_id),
                    "resource_snapshot_id": str(snapshot_id),
                    "resource_id": str(resource_id),
                    "control_version_id": str(control_version_id),
                    "control_id": str(control_id),
                    "assessment_result": "FAIL",
                    "detected_at": finding_document["occurrences"][0]["detected_at"],
                }
            ]

            control_detail = client.get(f"/api/v1/controls/{control_id}", headers=headers)
            assert control_detail.status_code == 200
            assert control_detail.json()["control_key"] == "NET-001"
            control_version = next(
                item
                for item in control_detail.json()["versions"]
                if item["control_version_id"] == str(control_version_id)
            )
            assert [item["mapping_id"] for item in control_version["framework_mappings"]] == [
                mapping["mapping_id"]
            ]

            framework_detail = client.get(
                f"/api/v1/frameworks/{mapping['framework_id']}",
                headers=headers,
            )
            assert framework_detail.status_code == 200
            framework_document = framework_detail.json()
            assert framework_document["framework_key"] == "nist-csf"
            assert framework_document["version"] == "2.0"
            reference = next(
                item
                for item in framework_document["references"]
                if item["framework_reference_id"] == mapping["framework_reference_id"]
            )
            assert reference["reference_key"] == "PR.IR-01"
            framework_mapping = next(
                item
                for item in reference["control_mappings"]
                if item["mapping_id"] == mapping["mapping_id"]
            )
            assert framework_mapping["control_id"] == str(control_id)
            assert framework_mapping["control_key"] == "NET-001"
            assert framework_mapping["control_version_id"] == str(control_version_id)
    finally:
        get_settings.cache_clear()
