"""Signed fault/recovery journeys and deterministic real PostgreSQL lock races."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, get_ident

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.database.governance import set_finding_disposition
from app.models import Resource
from app.models.enums import AuditEventType, FindingStatus
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.worker_driver import WorkerResult
from app.services.remediation_service import RemediationService
from app.services.remediation_worker_service import RemediationWorkerService
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.worker_fault_http import (
    PREINTENT_CASES,
    READ_FALSE,
    RECOVERY_CASES,
    UNCERTAIN_CASES,
    exercise_after_intent_revoke,
    exercise_capacity,
    exercise_preintent,
    exercise_readback,
    exercise_reclaim,
    exercise_recovery,
    exercise_uncertain,
    signed_fault_journey,
)
from tests.worker_http import database_state, protected_state

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("case", PREINTENT_CASES)
def test_signed_postgres_preintent_no_write(postgres_engine, monkeypatch, tmp_path, case):
    exercise_preintent(postgres_engine, monkeypatch, tmp_path, case)


@pytest.mark.parametrize("case", UNCERTAIN_CASES)
def test_signed_postgres_one_attempt_uncertainty(postgres_engine, monkeypatch, tmp_path, case):
    exercise_uncertain(postgres_engine, monkeypatch, tmp_path, case)


@pytest.mark.parametrize("case", RECOVERY_CASES)
def test_signed_postgres_read_only_recovery(postgres_engine, monkeypatch, tmp_path, case):
    exercise_recovery(postgres_engine, monkeypatch, tmp_path, case)


def test_signed_postgres_reclaim_retains_global_budget(postgres_engine, monkeypatch, tmp_path):
    exercise_reclaim(postgres_engine, monkeypatch, tmp_path)


@pytest.mark.parametrize("late", [False, True])
def test_signed_postgres_global_readback_limits(postgres_engine, monkeypatch, tmp_path, late):
    exercise_readback(postgres_engine, monkeypatch, tmp_path, late=late)


def test_signed_postgres_revocation_after_intent_is_not_cancellation(
    postgres_engine, monkeypatch, tmp_path
):
    exercise_after_intent_revoke(postgres_engine, monkeypatch, tmp_path)


def test_signed_postgres_quarantine_retains_target_and_capacity(
    postgres_engine, monkeypatch, tmp_path
):
    exercise_capacity(postgres_engine, monkeypatch, tmp_path)


def test_signed_postgres_competing_claims_have_one_owner(postgres_engine, monkeypatch, tmp_path):
    with signed_fault_journey(postgres_engine, monkeypatch, tmp_path) as journey:
        start = Barrier(2)

        def claim():
            start.wait(timeout=15)
            return journey.service("claim", journey.execution_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(claim), pool.submit(claim)
            claims = (first.result(timeout=20), second.result(timeout=20))
        assert sum(value is not None for value in claims) == 1
        journey.check(ExecutionPhase.CLAIMED, True)
        assert journey.transport.calls == []
        journey.check_reads_and_replay()


@pytest.mark.parametrize("change", ["expiry", "governance"])
def test_signed_postgres_driver_revalidates_after_resource_wait(
    postgres_engine, monkeypatch, tmp_path, change
):
    with signed_fault_journey(postgres_engine, monkeypatch, tmp_path) as journey:
        read_ready, holder_ready, blocked = Event(), Event(), Event()
        worker_thread = []
        original = RemediationWorkerService.write_intent

        def intent(service, *args, **kwargs):
            # The real adapter's read has returned; no network spans the held test lock.
            worker_thread.append(get_ident())
            read_ready.set()
            assert holder_ready.wait(15)
            return original(service, *args, **kwargs)

        def capture(_connection, _cursor, sql, *_args):
            if (
                worker_thread
                and get_ident() == worker_thread[0]
                and "FROM resources" in sql
                and "FOR UPDATE" in sql
            ):
                blocked.set()

        monkeypatch.setattr(RemediationWorkerService, "write_intent", intent)
        event.listen(postgres_engine, "before_cursor_execute", capture)
        before = database_state(postgres_engine)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                running = pool.submit(journey.run, READ_FALSE)
                try:
                    assert read_ready.wait(15)
                    with Session(postgres_engine) as writer:
                        writer.scalar(
                            select(Resource)
                            .where(
                                Resource.resource_id == journey.initial.content.proposal.resource_id
                            )
                            .with_for_update()
                        )
                        try:
                            holder_ready.set()
                            assert blocked.wait(15) and not running.done()
                            if change == "expiry":
                                journey.clock.advance(300)
                            else:
                                for status in (FindingStatus.ACKNOWLEDGED, FindingStatus.OPEN):
                                    set_finding_disposition(
                                        writer,
                                        finding_id=journey.source.finding_id,
                                        status=status,
                                        actor_id="offline-risk-owner",
                                        at=journey.clock(),
                                    )
                        finally:
                            writer.commit()
                    assert running.result(timeout=20) is WorkerResult.NO_WRITE
                finally:
                    holder_ready.set()
        finally:
            event.remove(postgres_engine, "before_cursor_execute", capture)
        if change == "governance":
            after = database_state(postgres_engine)
            assert protected_state(after) == protected_state(before)
            original_ids = {row.event_id for row in before["audit_events"]}
            added = [
                row
                for row in after["audit_events"]
                if row.event_id not in original_ids and row.target_type == "finding"
            ]
            assert len(added) == 2
            assert {row.metadata["status"] for row in added} == {"ACKNOWLEDGED", "OPEN"}
            assert all(row.target_id == journey.source.finding_id for row in added)
            journey.other_audits = journey._other_audits()
        journey.check(ExecutionPhase.NO_WRITE, False)
        assert not any("EnableEbsEncryptionByDefault" in value for value in journey.transport.calls)
        journey.check_reads_and_replay()


def test_signed_postgres_revocation_commits_before_waiting_driver_intent(
    postgres_engine, monkeypatch, tmp_path
):
    with signed_fault_journey(postgres_engine, monkeypatch, tmp_path) as journey:
        read_ready, revoking, permit_intent, blocked, release = (Event() for _ in range(5))
        original_intent, original_audit = (
            RemediationWorkerService.write_intent,
            RemediationService._audit,
        )
        worker_thread = []

        def intent(service, *args, **kwargs):
            worker_thread.append(get_ident())
            read_ready.set()
            assert permit_intent.wait(15)
            return original_intent(service, *args, **kwargs)

        def audit(service, kind, *args, **kwargs):
            result = original_audit(service, kind, *args, **kwargs)
            if kind is AuditEventType.REMEDIATION_REVOKED:
                revoking.set()
                assert release.wait(20)
            return result

        def capture(_connection, _cursor, sql, *_args):
            if (
                worker_thread
                and get_ident() == worker_thread[0]
                and "FROM resources" in sql
                and "FOR UPDATE" in sql
            ):
                blocked.set()

        monkeypatch.setattr(RemediationWorkerService, "write_intent", intent)
        monkeypatch.setattr(RemediationService, "_audit", audit)
        event.listen(postgres_engine, "before_cursor_execute", capture)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                running = pool.submit(journey.run, READ_FALSE)
                try:
                    assert read_ready.wait(15)
                    revocation = pool.submit(journey.revoke)
                    assert revoking.wait(15)
                    permit_intent.set()
                    assert blocked.wait(15) and not running.done()
                finally:
                    permit_intent.set()
                    release.set()
                revocation.result(timeout=20)
                assert running.result(timeout=20) is WorkerResult.NO_WRITE
        finally:
            event.remove(postgres_engine, "before_cursor_execute", capture)
        journey.check(ExecutionPhase.NO_WRITE, False)
        assert not any("EnableEbsEncryptionByDefault" in value for value in journey.transport.calls)
        journey.check_reads_and_replay()
