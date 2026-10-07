"""Disposable PostgreSQL authority, real signed HTTP, races and migration gates."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest.mock import patch
from uuid import uuid4

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.governance import create_finding_exception, set_finding_disposition
from app.database.persistence import persist_scan_result
from app.models import AuditEvent, Finding
from app.models.enums import FindingStatus
from app.models.remediation import RemediationDecision, RemediationProposal, RemediationRequest
from app.remediation.contracts import DecisionRequest
from app.services.errors import RemediationError
from app.services.remediation_service import RemediationService
from tests.ec2_fixtures import OBSERVED, ec2_bundle
from tests.integration.test_persistence_postgres import (
    _postgres_migration_state,
    migration_config,
)
from tests.integration.test_persistence_postgres import (
    postgres_engine as postgres_engine,
)
from tests.remediation_fixtures import ADMIN, APPROVER, NOW, propose, seed
from tests.remediation_http import exercise_remediation_http
from tests.unit.database import test_remediation as authority_checks
from tests.unit.database.factories import scan_bundle

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "exercise",
    [
        authority_checks.test_propose_approve_revoke_retains_findings_and_full_audit,
        authority_checks.test_idempotency_replay_and_conflicting_content,
        authority_checks.test_optional_kms_failure_does_not_change_fail_but_blocks_proposal,
        authority_checks.test_active_exception_blocks_creation_and_later_approval,
        authority_checks.test_cross_region_occurrence_and_wrong_digest_are_rejected,
        authority_checks.test_direct_sql_rejects_self_approval_and_foreign_revocation,
        authority_checks.test_revocation_can_remove_expired_authority_and_is_idempotent,
        authority_checks.test_present_default_key_is_bound_without_changing_the_technical_rule,
        authority_checks.test_new_assessment_preserves_approval_history_but_allows_revocation,
        authority_checks.test_rejection_can_close_expired_proposal,
        authority_checks.test_proposer_with_approve_capability_may_remove_but_not_grant_authority,
        authority_checks.test_direct_sql_rejects_another_proposals_real_approval_reference,
        authority_checks.test_retry_still_requires_current_capability_for_the_same_identity,
        authority_checks.test_rehashed_forged_baseline_is_read_as_blocked_and_cannot_be_approved,
        authority_checks.test_unrelated_finding_history_does_not_stale_proposal,
    ],
)
def test_postgres_authority_rules(postgres_engine, exercise):
    exercise(postgres_engine)


@pytest.mark.parametrize("caller_state", ["explicit", "read", "flushed"])
def test_postgres_mutations_preserve_caller_transaction_ownership(postgres_engine, caller_state):
    authority_checks.test_mutations_reject_and_preserve_an_existing_caller_transaction(
        postgres_engine, caller_state
    )


@pytest.mark.parametrize("approved", [False, True])
@pytest.mark.parametrize("same_timestamp", [False, True])
@pytest.mark.parametrize("intermediate", ["ACKNOWLEDGED", "FALSE_POSITIVE"])
def test_postgres_governance_round_trip_never_revives_old_authority(
    postgres_engine, approved, same_timestamp, intermediate
):
    authority_checks.test_governance_round_trip_never_revives_old_authority(
        postgres_engine, approved, same_timestamp, intermediate
    )


@pytest.mark.parametrize("read_method", ["detail", "list"])
@pytest.mark.parametrize("autoflush", [False, True])
@pytest.mark.parametrize("pending", ["insert", "update", "delete"])
def test_postgres_reads_preserve_pending_caller_changes(
    postgres_engine, read_method, autoflush, pending
):
    authority_checks.test_reads_reject_pending_changes_without_sql_or_caller_state_loss(
        postgres_engine, read_method, autoflush, pending
    )


@pytest.mark.parametrize("read_method", ["detail", "list"])
@pytest.mark.parametrize("autoflush", [False, True])
@pytest.mark.parametrize("caller_state", ["explicit", "read", "flushed"])
def test_postgres_reads_preserve_a_clean_caller_transaction(
    postgres_engine, read_method, autoflush, caller_state
):
    authority_checks.test_reads_preserve_a_clean_caller_transaction(
        postgres_engine, read_method, autoflush, caller_state
    )


def test_signed_remediation_http_postgres(postgres_engine, monkeypatch, tmp_path):
    exercise_remediation_http(postgres_engine, monkeypatch, tmp_path)


@pytest.mark.parametrize("same_key", [True, False])
def test_concurrent_proposals_preserve_idempotency_and_atomicity(postgres_engine, same_key):
    request, _ = seed(postgres_engine)
    gate = Barrier(2)
    shared_key = uuid4()

    def create():
        gate.wait(timeout=10)
        return propose(postgres_engine, request, key=shared_key if same_key else uuid4())

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: create(), range(2)))
    assert len({row.value.content.proposal_id for row in results}) == (1 if same_key else 2)
    assert sum(row.replayed for row in results) == (1 if same_key else 0)
    with Session(postgres_engine) as session:
        expected = 1 if same_key else 2
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == expected
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == expected


def test_concurrent_distinct_targets_cannot_reuse_one_actor_operation_key(postgres_engine):
    first, _ = seed(postgres_engine)
    second, _ = seed(postgres_engine, region="us-west-2")
    gate = Barrier(2)
    key = uuid4()

    def create(request):
        gate.wait(timeout=10)
        try:
            return propose(postgres_engine, request, key=key)
        except RemediationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, (first, second)))
    assert sum(result == "remediation_idempotency_conflict" for result in results) == 1
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.target_type == "remediation")
            )
            == 1
        )


@pytest.mark.parametrize(
    "table", ["remediation_proposals", "remediation_decisions", "remediation_requests"]
)
def test_postgres_authority_history_cannot_be_truncated(postgres_engine, table):
    propose(postgres_engine)
    with postgres_engine.connect() as connection:
        with pytest.raises(IntegrityError, match="immutable"):
            connection.execute(text(f"TRUNCATE {table} CASCADE"))
        connection.rollback()
        assert connection.scalar(text("SELECT count(*) FROM remediation_proposals")) == 1


def test_committing_authority_writer_is_excluded_before_any_downgrade_ddl(
    postgres_engine, monkeypatch
):
    request, _ = seed(postgres_engine)
    inserted, release, attempted = Event(), Event(), Event()
    ddl = []
    original_audit = RemediationService._audit

    def pause_after_audit(self, *args, **kwargs):
        original_audit(self, *args, **kwargs)
        inserted.set()
        assert release.wait(15), "authority writer was not released"

    monkeypatch.setattr(RemediationService, "_audit", pause_after_audit)

    def downgrade():
        with postgres_engine.begin() as connection:

            @event.listens_for(connection, "before_cursor_execute")
            def observe(_connection, _cursor, sql, *_args):
                if sql.startswith("LOCK TABLE scans, resources, findings, remediation_"):
                    attempted.set()
                if sql.lstrip().upper().startswith(("ALTER", "CREATE", "DROP")):
                    ddl.append(sql)

            command.downgrade(migration_config(connection), "base")

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(propose, postgres_engine, request)
        try:
            assert inserted.wait(10)
            downgrading = pool.submit(downgrade)
            assert attempted.wait(10)
            assert not downgrading.done()
        finally:
            release.set()
        writing.result(timeout=15)
        with pytest.raises(CommandError, match="blocked before revision 20261006_0007"):
            downgrading.result(timeout=15)
    assert ddl == []
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 1


def test_concurrent_approvers_cannot_create_conflicting_decisions(postgres_engine):
    proposal = propose(postgres_engine).value
    gate = Barrier(2)

    def decide(principal):
        gate.wait(timeout=10)
        with Session(postgres_engine) as session:
            try:
                return RemediationService(session, clock=lambda: NOW).decide(
                    proposal.content.proposal_id,
                    DecisionRequest(
                        proposal_sha256=proposal.proposal_sha256,
                        decision="APPROVE",
                        reason="Concurrent independent review.",
                    ),
                    principal,
                    uuid4(),
                )
            except RemediationError as error:
                return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, (APPROVER, ADMIN)))
    assert sum(result == "remediation_state_conflict" for result in results) == 1
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 2


@pytest.mark.parametrize("change", ["assessment", "exception", "disposition_round_trip"])
def test_approval_waits_for_resource_lock_then_rechecks_committed_state(postgres_engine, change):
    proposal = propose(postgres_engine).value
    blocked = Event()

    def capture(_conn, _cursor, sql, _parameters, _context, _many):
        if "FROM resources" in sql and "FOR UPDATE" in sql:
            blocked.set()

    def approve():
        with Session(postgres_engine) as session:
            with pytest.raises(RemediationError) as raised:
                authority_checks.approve(session, proposal)
            assert raised.value.code == "remediation_ineligible"

    with Session(postgres_engine) as writer:
        if change == "assessment":
            with patch("tests.ec2_fixtures.OBSERVED", OBSERVED + timedelta(seconds=1)):
                bundle = ec2_bundle()
            persist_scan_result(writer, **bundle)
        elif change == "exception":
            create_finding_exception(
                writer,
                finding_id=proposal.content.finding_id,
                reason="Concurrent exception.",
                approved_by="risk-owner",
                created_at=NOW,
                expires_at=NOW + timedelta(hours=1),
            )
        else:
            for status in (FindingStatus.ACKNOWLEDGED, FindingStatus.OPEN):
                set_finding_disposition(
                    writer,
                    finding_id=proposal.content.finding_id,
                    status=status,
                    actor_id="concurrent-risk-owner",
                    at=NOW,
                )
        event.listen(postgres_engine, "before_cursor_execute", capture)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(approve)
                try:
                    assert blocked.wait(10)
                    assert not future.done()
                finally:
                    writer.commit()
                future.result(timeout=10)
        finally:
            event.remove(postgres_engine, "before_cursor_execute", capture)
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0


@pytest.mark.parametrize("destination", ["20261001_0006", "base"])
def test_postgres_populated_remediation_downgrade_changes_nothing(postgres_engine, destination):
    propose(postgres_engine)
    before = _postgres_migration_state(postgres_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261006_0007"):
        with postgres_engine.begin() as connection:
            command.downgrade(migration_config(connection), destination)
    assert _postgres_migration_state(postgres_engine) == before


def test_postgres_predecessor_upgrade_keeps_legacy_history_and_matches_metadata(postgres_engine):
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), "20261001_0006")
    with Session(postgres_engine) as session, session.begin():
        persist_scan_result(session, **scan_bundle())
    with Session(postgres_engine) as session:
        before = session.scalars(select(AuditEvent.event_id).order_by(AuditEvent.event_id)).all()
        finding_ids = session.scalars(select(Finding.finding_id)).all()
    with postgres_engine.begin() as connection:
        command.upgrade(migration_config(connection), "head")
        command.check(migration_config(connection))
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20261006_0007"
    with Session(postgres_engine) as session:
        assert (
            session.scalars(select(AuditEvent.event_id).order_by(AuditEvent.event_id)).all()
            == before
        )
        assert session.scalars(select(Finding.finding_id)).all() == finding_ids
