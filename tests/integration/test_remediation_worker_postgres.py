"""Worker rules and lock races on explicitly disposable PostgreSQL; no AWS network."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event, inspect, select, text
from sqlalchemy.orm import Session

from app.database.governance import set_finding_disposition
from app.database.persistence import append_audit_event
from app.models import Resource
from app.models.enums import AuditEventType, FindingStatus
from app.services.remediation_service import RemediationService
from tests.integration.test_persistence_postgres import migration_config
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.unit.services import test_remediation_worker as checks

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "exercise",
    [
        checks.test_success_is_unverified_separate_service_audit_and_no_finding_or_scan_change,
        checks.test_transient_precondition_read_budget_is_durable_three_total,
        checks.test_pre_intent_claim_fencing_and_retry_budget_survive_reclaim,
        checks.test_crash_during_sdk_call_leaves_intent_and_recovery_never_resends,
        checks.test_crash_before_sdk_still_never_reclaims_post_intent_and_late_ack_is_sticky,
        checks.test_readback_budget_and_window_do_not_reset_on_restart,
        checks.test_readback_response_after_deadline_is_not_a_desired_observation,
        checks.test_acknowledgment_commit_failure_retains_intent_for_read_only_recovery,
        checks.test_caller_transaction_is_never_rolled_back_or_flushed,
    ],
)
def test_postgres_worker_rules(postgres_engine, exercise):
    exercise(checks.Harness(postgres_engine))


@pytest.mark.parametrize("when", ["before-claim", "during-read", "after-intent"])
def test_postgres_revocation_cutoff(postgres_engine, when):
    checks.test_revocation_cutoff_is_intent_commit_not_acknowledgment(
        checks.Harness(postgres_engine), when
    )


@pytest.mark.parametrize("mutation", ["token", "generation", "lease", "intent", "delete"])
def test_postgres_post_intent_owner_never_reclaimed(postgres_engine, mutation):
    checks.test_database_rejects_post_intent_owner_reclaim_or_erase(
        checks.Harness(postgres_engine), mutation
    )


def test_two_workers_can_claim_only_one_owner(postgres_engine):
    harness = checks.Harness(postgres_engine)
    start = Barrier(2)

    def claim():
        start.wait(timeout=10)
        return harness.service("claim", harness.execution_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert sum(value is not None for value in results) == 1
    assert harness.view().phase == "CLAIMED"


@pytest.mark.parametrize("change", ["expiry", "governance"])
def test_intent_revalidates_after_resource_lock_wait(postgres_engine, change):
    harness = checks.Harness(postgres_engine)
    claim = harness.service("claim", harness.execution_id)
    assert harness.service("begin_read", claim)
    blocked = Event()

    def capture(_connection, _cursor, sql, *_args):
        if "FROM resources" in sql and "FOR UPDATE" in sql:
            blocked.set()

    with Session(postgres_engine) as writer:
        writer.scalar(
            select(Resource)
            .where(
                Resource.resource_id == harness.proposal.content.resource_id,
            )
            .with_for_update()
        )
        if change == "governance":
            for status in (FindingStatus.ACKNOWLEDGED, FindingStatus.OPEN):
                set_finding_disposition(
                    writer,
                    finding_id=harness.proposal.content.finding_id,
                    status=status,
                    actor_id="risk-owner",
                    at=harness.clock(),
                )
        event.listen(postgres_engine, "before_cursor_execute", capture)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiting = pool.submit(
                    harness.service, "write_intent", claim, harness.observation(), harness.clock()
                )
                try:
                    assert blocked.wait(10) and not waiting.done()
                    if change == "expiry":
                        harness.clock.advance(300)
                finally:
                    writer.commit()
                assert waiting.result(timeout=15) is False
        finally:
            event.remove(postgres_engine, "before_cursor_execute", capture)
    assert harness.view().phase == "NO_WRITE" and not harness.view().reservation_held


def test_revocation_commits_before_waiting_intent_and_blocks_it(postgres_engine, monkeypatch):
    harness = checks.Harness(postgres_engine)
    claim = harness.service("claim", harness.execution_id)
    assert harness.service("begin_read", claim)
    inserted, release, waiting_for_resource = Event(), Event(), Event()
    original = RemediationService._audit

    def pause(self, *args, **kwargs):
        original(self, *args, **kwargs)
        inserted.set()
        assert release.wait(15)

    def capture(_connection, _cursor, sql, *_args):
        if "FROM resources" in sql and "FOR UPDATE" in sql and inserted.is_set():
            waiting_for_resource.set()

    monkeypatch.setattr(RemediationService, "_audit", pause)
    event.listen(postgres_engine, "before_cursor_execute", capture)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            revocation = pool.submit(harness.revoke)
            try:
                assert inserted.wait(10)
                intent = pool.submit(
                    harness.service, "write_intent", claim, harness.observation(), harness.clock()
                )
                assert waiting_for_resource.wait(10) and not intent.done()
            finally:
                release.set()
            revocation.result(timeout=15)
            assert intent.result(timeout=15) is False
    finally:
        event.remove(postgres_engine, "before_cursor_execute", capture)
    assert harness.view().phase == "NO_WRITE"


def test_populated_worker_downgrade_refuses_before_schema_change(postgres_engine):
    harness = checks.Harness(postgres_engine)
    harness.intent()
    with postgres_engine.begin() as connection:
        before = connection.scalar(text("SELECT version_num FROM alembic_version"))
        with pytest.raises(CommandError, match="blocked before revision 20261008_0009"):
            command.downgrade(migration_config(connection), "20261007_0008")
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == before
        assert connection.scalar(text("SELECT COUNT(*) FROM remediation_worker_claims")) == 1
    assert harness.view().phase == "WRITE_INTENT"


def test_postgres_populated_b1_round_trip_preserves_exact_history(postgres_engine):
    harness = checks.Harness(postgres_engine)
    tables = (
        "remediation_proposals",
        "remediation_decisions",
        "remediation_requests",
        "remediation_executions",
        "remediation_execution_events",
        "audit_events",
    )
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), "20261007_0008")
        original = {
            name: tuple(tuple(row) for row in connection.execute(text(f'SELECT * FROM "{name}"')))
            for name in tables
        }
        command.upgrade(migration_config(connection), "head")
        command.check(migration_config(connection))
        command.downgrade(migration_config(connection), "20261007_0008")
        for name, rows in original.items():
            assert (
                tuple(tuple(row) for row in connection.execute(text(f'SELECT * FROM "{name}"')))
                == rows
            )
        assert "remediation_worker_claims" not in inspect(connection).get_table_names()
        command.upgrade(migration_config(connection), "head")
        command.check(migration_config(connection))
    assert harness.view() == harness.initial


@pytest.mark.parametrize(
    "kind",
    [
        "CLAIMED",
        "WRITE_INTENT",
        "NO_WRITE",
        "ACKNOWLEDGED",
        "QUARANTINED",
        "OBSERVED",
        "OBSERVATION_FAILED",
    ],
)
@pytest.mark.parametrize("destination", ["20261007_0008", "base"])
def test_postgres_worker_audit_alone_refuses_whole_path(postgres_engine, kind, destination):
    with Session(postgres_engine) as session, session.begin():
        append_audit_event(
            session,
            AuditEventType("REMEDIATION_EXECUTION_" + kind),
            "remediation_execution",
            checks.uuid4(),
            checks.NOW,
            actor_type="service",
            actor_id="synthetic-worker",
        )
    with postgres_engine.begin() as connection:
        before = inspect(connection).get_table_names()
        with pytest.raises(CommandError, match="blocked before revision 20261008_0009"):
            command.downgrade(migration_config(connection), destination)
        assert inspect(connection).get_table_names() == before
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20261008_0009"
        assert connection.scalar(text("SELECT COUNT(*) FROM audit_events")) == 1


def test_worker_writer_finishes_before_downgrade_preflight_checks_history(
    postgres_engine, monkeypatch
):
    from app.services.remediation_worker_service import RemediationWorkerService

    harness = checks.Harness(postgres_engine)
    inserted, release, downgrade_waiting = Event(), Event(), Event()
    original = RemediationWorkerService._append

    def pause(self, *args, **kwargs):
        value = original(self, *args, **kwargs)
        inserted.set()
        assert release.wait(15)
        return value

    def capture(_connection, _cursor, sql, *_args):
        if sql.startswith("LOCK TABLE remediation_admission_guard"):
            downgrade_waiting.set()

    def downgrade():
        # Snapshot on this same connection, never a third reader behind queued DDL.
        with postgres_engine.begin() as connection:

            def columns():
                return [
                    (c["name"], str(c["type"]), c["nullable"], c["default"])
                    for c in inspect(connection).get_columns("remediation_worker_claims")
                ]

            before_columns = columns()
            with pytest.raises(CommandError, match="blocked before revision 20261008_0009"):
                command.downgrade(migration_config(connection), "20261007_0008")
            assert columns() == before_columns
            assert (
                connection.scalar(text("SELECT version_num FROM alembic_version"))
                == "20261008_0009"
            )
            assert connection.scalar(text("SELECT COUNT(*) FROM remediation_worker_claims")) == 1

    monkeypatch.setattr(RemediationWorkerService, "_append", pause)
    event.listen(postgres_engine, "before_cursor_execute", capture)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(harness.service, "claim", harness.execution_id)
            try:
                assert inserted.wait(10)
                rollback = pool.submit(downgrade)
                assert downgrade_waiting.wait(10) and not rollback.done()
            finally:
                release.set()
            assert writer.result(timeout=15) is not None
            rollback.result(timeout=15)
    finally:
        event.remove(postgres_engine, "before_cursor_execute", capture)
    assert harness.view().phase == "CLAIMED"


def test_postgres_worker_claims_cannot_be_truncated(postgres_engine):
    from sqlalchemy.exc import IntegrityError

    harness = checks.Harness(postgres_engine)
    harness.intent()
    with postgres_engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(text("TRUNCATE remediation_worker_claims"))
    assert harness.view().phase == "WRITE_INTENT"
