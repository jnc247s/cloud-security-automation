"""Disposable PostgreSQL execution admission, signed requests and writer exclusion."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest.mock import patch
from uuid import uuid4

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.governance import create_finding_exception, set_finding_disposition
from app.database.persistence import persist_scan_result
from app.models import Resource
from app.models.enums import FindingStatus
from app.models.remediation_execution import RemediationAdmissionGuard
from app.remediation.contracts import RevocationRequest
from app.remediation.execution_contracts import AdmissionScope
from app.services.errors import RemediationError
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import RemediationService
from tests.ec2_fixtures import OBSERVED, ec2_bundle
from tests.execution_fixtures import SCOPE, admit, approved
from tests.execution_http import exercise_execution_http
from tests.integration.test_persistence_postgres import _postgres_migration_state, migration_config
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.remediation_fixtures import ADMIN, APPROVER, NOW
from tests.unit.database import test_remediation_execution as admission_checks

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "exercise",
    [
        admission_checks.test_admission_is_separate_from_approval_findings_and_technical_results,
        admission_checks.test_same_subject_different_issuer_is_a_distinct_identity,
        admission_checks.test_idempotency_replay_never_extends_or_requeues_expired_authority,
        admission_checks.test_one_execution_per_proposal_and_one_outstanding_per_target,
        admission_checks.test_read_derives_revocation_without_mutating_execution_history,
        admission_checks.test_governance_round_trip_blocks_new_admission,
        admission_checks.test_grant_is_capped_by_proposal_expiry_and_exact_expiry_blocks_admission,
        admission_checks.test_mutation_preserves_caller_transaction_and_pending_work,
        admission_checks.test_failed_admission_rolls_back_expiry_cleanup,
        admission_checks.test_removed_authority_is_journaled_before_target_can_be_reserved_again,
        admission_checks.test_active_reservation_cannot_be_cleared_without_terminal_journal,
        admission_checks.test_capacity_is_a_durable_global_bound,
    ],
)
def test_postgres_admission_rules(postgres_engine, exercise):
    exercise(postgres_engine)


def test_signed_execution_admission_http_postgres(postgres_engine, monkeypatch, tmp_path):
    exercise_execution_http(postgres_engine, monkeypatch, tmp_path)


def test_postgres_journal_and_audit_rollback_together(postgres_engine, monkeypatch):
    admission_checks.test_journal_audit_and_reservation_rollback_together(
        postgres_engine, monkeypatch
    )


@pytest.mark.parametrize("kind", ["FAIL", "PASS", "INSUFFICIENT_EVIDENCE"])
@pytest.mark.parametrize("same_time", [False, True])
def test_postgres_any_new_or_equal_assessment_blocks_execution(postgres_engine, kind, same_time):
    admission_checks.test_new_or_equal_assessment_blocks_execution(postgres_engine, kind, same_time)


@pytest.mark.parametrize("change", ["approval_id", "digest", "revoke", "exception"])
def test_postgres_removed_authority_never_partially_admits(postgres_engine, change):
    admission_checks.test_bad_or_removed_authority_never_partially_admits(postgres_engine, change)


@pytest.mark.parametrize("method", ["get", "list"])
def test_postgres_read_preserves_caller_work(postgres_engine, method):
    admission_checks.test_read_rejects_pending_work_before_sql_and_preserves_clean_transaction(
        postgres_engine, method
    )


@pytest.mark.parametrize("same_key", [True, False])
def test_concurrent_requests_have_one_winner_and_no_partial_effects(postgres_engine, same_key):
    proposal, request, _ = approved(postgres_engine)
    start = Barrier(2)
    key = uuid4()

    def create():
        start.wait(timeout=10)
        try:
            return admit(postgres_engine, proposal, request, key=key if same_key else uuid4())
        except RemediationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: create(), range(2)))
    if same_key:
        assert len({r.value.content.execution_id for r in results}) == 1
        assert sum(r.replayed for r in results) == 1
    else:
        assert sum(r == "remediation_state_conflict" for r in results) == 1
    assert admission_checks.counts(postgres_engine)[:3] == (1, 1, 1)


def test_concurrent_proposals_cannot_both_reserve_one_target(postgres_engine):
    first, request, source = approved(postgres_engine)
    second, other_request, _ = approved(postgres_engine, request=source)
    start = Barrier(2)

    def create(pair):
        start.wait(timeout=10)
        try:
            return admit(postgres_engine, *pair)
        except RemediationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, ((first, request), (second, other_request))))
    assert sum(r == "remediation_execution_target_reserved" for r in results) == 1
    assert admission_checks.counts(postgres_engine)[:3] == (1, 1, 1)


def test_concurrent_targets_cannot_reuse_one_actor_key(postgres_engine):
    first, request, _ = approved(postgres_engine)
    second, other_request, _ = approved(postgres_engine, region="us-west-2")
    start, key = Barrier(2), uuid4()

    def create(pair):
        proposal, body = pair
        start.wait(timeout=10)
        try:
            return admit(
                postgres_engine,
                proposal,
                body,
                key=key,
                scope=AdmissionScope(
                    enabled=True, account_id=SCOPE.account_id, region=proposal.content.region
                ),
            )
        except RemediationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, ((first, request), (second, other_request))))
    assert sum(r == "remediation_idempotency_conflict" for r in results) == 1
    assert admission_checks.counts(postgres_engine)[:3] == (1, 1, 1)


@pytest.mark.parametrize("change", ["assessment", "exception", "governance", "expiry"])
def test_resource_lock_wait_rechecks_committed_state_and_current_clock(postgres_engine, change):
    proposal, request, _ = approved(postgres_engine)
    blocked = Event()
    clock = [NOW]

    def capture(_conn, _cursor, sql, *_args):
        if "FROM resources" in sql and "FOR UPDATE" in sql:
            blocked.set()

    def create():
        with Session(postgres_engine) as session:
            with pytest.raises(RemediationError) as error:
                RemediationExecutionService(session, scope=SCOPE, clock=lambda: clock[0]).admit(
                    proposal.content.proposal_id, request, ADMIN, uuid4()
                )
            assert error.value.code == "remediation_ineligible"

    with Session(postgres_engine) as writer:
        writer.scalar(
            select(Resource)
            .where(Resource.resource_id == proposal.content.resource_id)
            .with_for_update()
        )
        if change == "assessment":
            with patch("tests.ec2_fixtures.OBSERVED", OBSERVED + timedelta(seconds=1)):
                bundle = ec2_bundle()
            persist_scan_result(writer, **bundle)
        elif change == "exception":
            create_finding_exception(
                writer,
                finding_id=proposal.content.finding_id,
                reason="Concurrent exception",
                approved_by="risk-owner",
                created_at=NOW,
                expires_at=NOW + timedelta(hours=1),
            )
        elif change == "governance":
            for status in (FindingStatus.ACKNOWLEDGED, FindingStatus.OPEN):
                set_finding_disposition(
                    writer,
                    finding_id=proposal.content.finding_id,
                    status=status,
                    actor_id="risk-owner",
                    at=NOW,
                )
        event.listen(postgres_engine, "before_cursor_execute", capture)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiting = pool.submit(create)
                try:
                    assert blocked.wait(10)
                    assert not waiting.done()
                    if change == "expiry":
                        clock[0] = proposal.content.expires_at
                finally:
                    writer.commit()
                waiting.result(timeout=15)
        finally:
            event.remove(postgres_engine, "before_cursor_execute", capture)
    assert admission_checks.counts(postgres_engine)[:3] == (0, 0, 0)


def test_admission_guard_wait_does_not_freeze_expiry(postgres_engine):
    proposal, request, _ = approved(postgres_engine)
    blocked = Event()
    clock = [NOW]

    def capture(_conn, _cursor, sql, *_args):
        if "FROM remediation_admission_guard" in sql and "FOR UPDATE" in sql:
            blocked.set()

    def create():
        with Session(postgres_engine) as session:
            with pytest.raises(RemediationError) as error:
                RemediationExecutionService(session, scope=SCOPE, clock=lambda: clock[0]).admit(
                    proposal.content.proposal_id, request, ADMIN, uuid4()
                )
            assert error.value.code == "remediation_ineligible"

    with Session(postgres_engine) as writer:
        writer.scalar(select(RemediationAdmissionGuard).with_for_update())
        event.listen(postgres_engine, "before_cursor_execute", capture)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiting = pool.submit(create)
                try:
                    assert blocked.wait(10) and not waiting.done()
                    clock[0] = proposal.content.expires_at
                finally:
                    writer.commit()
                waiting.result(timeout=15)
        finally:
            event.remove(postgres_engine, "before_cursor_execute", capture)
    assert admission_checks.counts(postgres_engine)[:3] == (0, 0, 0)


def test_revocation_committing_while_admission_waits_removes_authority(
    postgres_engine, monkeypatch
):
    proposal, request, _ = approved(postgres_engine)
    inserted, release, blocked = Event(), Event(), Event()
    original = RemediationService._audit

    def pause(self, *args, **kwargs):
        original(self, *args, **kwargs)
        inserted.set()
        assert release.wait(15)

    monkeypatch.setattr(RemediationService, "_audit", pause)

    def revoke():
        with Session(postgres_engine) as session:
            return RemediationService(session, clock=lambda: NOW).revoke(
                proposal.content.proposal_id,
                RevocationRequest(
                    proposal_sha256=proposal.proposal_sha256,
                    approval_decision_id=request.approval_decision_id,
                    reason="Cancel concurrent admission",
                ),
                APPROVER,
                uuid4(),
            )

    def capture(_conn, _cursor, sql, *_args):
        if "FROM resources" in sql and "FOR UPDATE" in sql:
            blocked.set()

    event.listen(postgres_engine, "before_cursor_execute", capture)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            removing = pool.submit(revoke)
            try:
                assert inserted.wait(10)
                blocked.clear()
                admitting = pool.submit(admit, postgres_engine, proposal, request)
                assert blocked.wait(10) and not admitting.done()
            finally:
                release.set()
            removing.result(timeout=15)
            with pytest.raises(RemediationError, match="ineligible"):
                admitting.result(timeout=15)
    finally:
        event.remove(postgres_engine, "before_cursor_execute", capture)
    assert admission_checks.counts(postgres_engine)[:3] == (0, 0, 0)


@pytest.mark.parametrize(
    "table",
    [
        "remediation_executions",
        "remediation_execution_events",
        "remediation_admission_guard",
        "remediation_target_reservations",
    ],
)
def test_postgres_history_and_coordination_cannot_be_truncated(postgres_engine, table):
    proposal, request, _ = approved(postgres_engine)
    admit(postgres_engine, proposal, request)
    before = admission_checks.counts(postgres_engine)
    with postgres_engine.connect() as connection:
        with pytest.raises(IntegrityError, match="immutable"):
            connection.execute(text(f"TRUNCATE {table} CASCADE"))
        connection.rollback()
    assert admission_checks.counts(postgres_engine) == before


@pytest.mark.parametrize("destination", ["20261006_0007", "20261001_0006", "base"])
def test_populated_execution_downgrade_changes_nothing(postgres_engine, destination):
    proposal, request, _ = approved(postgres_engine)
    admit(postgres_engine, proposal, request)
    before = _postgres_migration_state(postgres_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261007_0008"):
        with postgres_engine.begin() as connection:
            command.downgrade(migration_config(connection), destination)
    assert _postgres_migration_state(postgres_engine) == before


def test_populated_predecessor_upgrade_keeps_authority_and_schema(postgres_engine):
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), "20261006_0007")
    proposal, request, _ = approved(postgres_engine)
    with postgres_engine.connect() as connection:
        before = {
            table: tuple(
                tuple(row) for row in connection.execute(text(f"SELECT * FROM {table} ORDER BY 1"))
            )
            for table in (
                "remediation_proposals",
                "remediation_decisions",
                "remediation_requests",
                "audit_events",
            )
        }
    with postgres_engine.begin() as connection:
        command.upgrade(migration_config(connection), "head")
        command.check(migration_config(connection))
        for table, rows in before.items():
            assert (
                tuple(
                    tuple(row)
                    for row in connection.execute(text(f"SELECT * FROM {table} ORDER BY 1"))
                )
                == rows
            )
    assert admit(postgres_engine, proposal, request).value.phase == "QUEUED"


def test_execution_writer_is_excluded_before_any_downgrade_ddl(postgres_engine, monkeypatch):
    proposal, request, _ = approved(postgres_engine)
    inserted, release, attempted = Event(), Event(), Event()
    ddl = []
    original = RemediationExecutionService._view

    def pause(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        inserted.set()
        assert release.wait(15)
        return result

    monkeypatch.setattr(RemediationExecutionService, "_view", pause)

    def downgrade():
        with postgres_engine.begin() as connection:

            @event.listens_for(connection, "before_cursor_execute")
            def observe(_conn, _cursor, sql, *_args):
                if sql.startswith("LOCK TABLE remediation_admission_guard, scans, resources"):
                    attempted.set()
                if sql.lstrip().upper().startswith(("ALTER", "CREATE", "DROP")):
                    ddl.append(sql)

            command.downgrade(migration_config(connection), "base")

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(admit, postgres_engine, proposal, request)
        try:
            assert inserted.wait(10)
            downgrading = pool.submit(downgrade)
            assert attempted.wait(10) and not downgrading.done()
        finally:
            release.set()
        writing.result(timeout=15)
        with pytest.raises(CommandError, match="blocked before revision 20261007_0008"):
            downgrading.result(timeout=15)
    assert ddl == []
    assert admission_checks.counts(postgres_engine)[:3] == (1, 1, 1)
