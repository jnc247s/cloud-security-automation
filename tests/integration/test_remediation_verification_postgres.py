"""Disposable PostgreSQL verification acceptance and concurrency; no live providers."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier
from uuid import uuid4

import pytest

from app.services.errors import RemediationError
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.unit.services import test_remediation_verification as checks
from tests.verification_fixtures import VerificationHarness
from tests.verification_http import exercise_verification_http

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("enabled,outcome", [(True, "VERIFIED"), (False, "NOT_VERIFIED")])
@pytest.mark.parametrize("key", [None, "reviewed-key"])
def test_postgres_verification_postcondition(postgres_engine, enabled, outcome, key):
    checks.test_normal_completed_postcondition(postgres_engine, enabled, outcome, key)


@pytest.mark.parametrize("denial", ["disabled", "scope", "queued", "capability", "active"])
def test_postgres_verification_denial(postgres_engine, denial):
    checks.test_denial_has_no_admission_effects(postgres_engine, denial)


def test_postgres_replay_and_attempt_bounds(postgres_engine):
    checks.test_replay_namespace_conflict_current_capability_and_three_attempt_bound(
        postgres_engine
    )


def test_postgres_wrong_identity(postgres_engine):
    checks.test_wrong_scanner_identity_fails_before_any_collection(postgres_engine)


def test_postgres_submission_failure(postgres_engine):
    checks.test_submission_failure_seals_receipt_and_replay_never_requeues(postgres_engine)


def test_postgres_receipt_and_result_rollback(postgres_engine, monkeypatch):
    checks.test_receipt_failure_rolls_back_complete_result_and_findings(
        postgres_engine, monkeypatch
    )


def test_postgres_signed_verification_http(postgres_engine, monkeypatch, tmp_path):
    exercise_verification_http(postgres_engine, monkeypatch, tmp_path)


@pytest.mark.parametrize("same_key", [False, True])
def test_concurrent_verification_admission_is_one_active(postgres_engine, same_key):
    harness = VerificationHarness(postgres_engine)
    barrier, shared_key = Barrier(2), uuid4()

    def request():
        barrier.wait(timeout=15)
        try:
            return harness.request(key=shared_key if same_key else uuid4())
        except RemediationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: request(), range(2)))
    if same_key:
        assert {result.replayed for result in results} == {False, True}
        assert results[0].value.content.scan_id == results[1].value.content.scan_id
    else:
        assert sum(result == "remediation_verification_active" for result in results) == 1
        assert len([result for result in results if not isinstance(result, str)]) == 1


@pytest.mark.parametrize(
    "exercise",
    [
        checks.test_equal_acknowledgment_observation_is_not_verified,
        checks.test_wrong_provider_region_fails_before_collection,
        checks.test_acknowledged_write_remains_verifiable_after_revocation,
        checks.test_recovery_resubmits_the_same_durable_scan_identity,
    ],
)
def test_postgres_verification_recovery_and_authority(postgres_engine, exercise):
    exercise(postgres_engine)


def test_postgres_populated_upgrade_and_downgrade_history_guard(postgres_engine):
    from alembic import command
    from alembic.util import CommandError
    from sqlalchemy import inspect, select, text

    from app.database.base import Base
    from tests.integration.test_persistence_postgres import migration_config

    harness = VerificationHarness(postgres_engine)
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), "20261008_0009")
        names = inspect(connection).get_table_names()
        before = {
            name: tuple(
                connection.execute(
                    select(Base.metadata.tables[name]).order_by(
                        *Base.metadata.tables[name].primary_key
                    )
                ).all()
            )
            for name in names
            if name != "alembic_version"
        }
        command.upgrade(migration_config(connection), "head")
        command.check(migration_config(connection))
        assert {
            name: tuple(
                connection.execute(
                    select(Base.metadata.tables[name]).order_by(
                        *Base.metadata.tables[name].primary_key
                    )
                ).all()
            )
            for name in before
        } == before
    value = harness.request().value
    harness.run(value.content.scan_id)
    with postgres_engine.begin() as connection:
        names = inspect(connection).get_table_names()
        with pytest.raises(CommandError, match="blocked before revision 20261013_0010"):
            command.downgrade(migration_config(connection), "base")
        assert inspect(connection).get_table_names() == names
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20261013_0010"
    assert harness.view(value.content.verification_id).receipt.outcome.value == "VERIFIED"


@pytest.mark.parametrize(
    "table", ["remediation_verifications", "remediation_verification_receipts"]
)
@pytest.mark.parametrize("mutation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_postgres_verification_history_guards(postgres_engine, table, mutation):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    harness = VerificationHarness(postgres_engine)
    value = harness.request().value
    harness.run(value.content.scan_id)
    original = harness.view(value.content.verification_id)
    statements = {
        "UPDATE": f"UPDATE {table} SET created_at = created_at",
        "DELETE": f"DELETE FROM {table}",
        "TRUNCATE": f"TRUNCATE {table} CASCADE",
    }
    with pytest.raises(DBAPIError, match="immutable"):
        with postgres_engine.begin() as connection:
            connection.execute(text(statements[mutation]))
    assert harness.view(value.content.verification_id) == original


def test_postgres_verification_read_preserves_pending_work(postgres_engine):
    checks.test_read_rejects_pending_caller_writes_before_sql_and_preserves_them(postgres_engine)


def test_postgres_independent_result_identity_guard(postgres_engine, monkeypatch):
    checks.test_collected_account_is_independently_checked_before_result_writes(
        postgres_engine, monkeypatch
    )


@pytest.mark.parametrize("linked", [False, True])
def test_scan_terminal_reader_fences_downgrade_before_audit_read(postgres_engine, linked):
    from threading import Event

    from alembic import command
    from alembic.util import CommandError
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    from app.config import Settings
    from app.database.persistence import fail_pending_scan
    from app.schemas.scan import ScanCreateRequest
    from app.services.scan_service import ScanService
    from tests.integration.test_persistence_postgres import migration_config
    from tests.unit.services.test_scan_service import RecordingExecutor

    harness = VerificationHarness(postgres_engine) if linked else None
    if linked:
        scan_id = harness.request().value.content.scan_id
    else:
        with Session(postgres_engine) as session:
            scan_id = (
                ScanService(
                    session,
                    Settings(
                        _env_file=None,
                        app_env="test",
                        auth_mode="development",
                        database_url="sqlite://",
                    ),
                )
                .start_scan(
                    ScanCreateRequest(region="us-west-2"),
                    RecordingExecutor(),
                    actor_id="offline-operator",
                )
                .scan_id
            )
    entered, release, ddl_waiting = Event(), Event(), Event()

    def read_barrier(connection, _cursor, statement, *_args):
        if (
            connection.info.get("verification_fence_reader")
            and statement.startswith("SELECT remediation_verification_guard.guard_id")
            and not entered.is_set()
        ):
            entered.set()
            assert release.wait(15)

    def ddl_attempt(_connection, _cursor, statement, *_args):
        if statement.startswith("LOCK TABLE remediation_verification_guard"):
            ddl_waiting.set()

    def terminalize():
        with postgres_engine.connect() as connection:
            connection.info["verification_fence_reader"] = True
            try:
                with Session(bind=connection) as session, session.begin():
                    fail_pending_scan(
                        session,
                        scan_id=scan_id,
                        completed_at=harness.clock() if linked else datetime.now(UTC),
                        failure_code="OFFLINE_FAILURE",
                        failure_message="Synthetic failure.",
                    )
            finally:
                connection.info.pop("verification_fence_reader", None)

    def downgrade():
        with postgres_engine.begin() as connection:
            if linked:
                with pytest.raises(CommandError, match="blocked before revision 20261013_0010"):
                    command.downgrade(migration_config(connection), "20261008_0009")
            else:
                command.downgrade(migration_config(connection), "20261008_0009")

    event.listen(postgres_engine, "after_cursor_execute", read_barrier)
    event.listen(postgres_engine, "before_cursor_execute", ddl_attempt)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            reader = pool.submit(terminalize)
            assert entered.wait(15)
            ddl = pool.submit(downgrade)
            try:
                assert ddl_waiting.wait(15)
                assert not ddl.done()
            finally:
                release.set()
            reader.result(timeout=15)
            ddl.result(timeout=15)
    finally:
        release.set()
        event.remove(postgres_engine, "after_cursor_execute", read_barrier)
        event.remove(postgres_engine, "before_cursor_execute", ddl_attempt)
