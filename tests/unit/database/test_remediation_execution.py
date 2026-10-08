"""Offline third-human admission, separate history, reservation and transaction integrity."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.governance import create_finding_exception, set_finding_disposition
from app.database.persistence import persist_scan_result
from app.models import AuditEvent, Finding, Scan
from app.models.enums import FindingStatus
from app.models.remediation_execution import (
    RemediationAdmissionGuard,
    RemediationExecution,
    RemediationExecutionEvent,
    RemediationTargetReservation,
)
from app.remediation.contracts import RevocationRequest
from app.remediation.execution_contracts import (
    AdmissionScope,
    ExecutionBlockingReason,
    ExecutionPhase,
    ExecutionRequest,
)
from app.security.authentication import Principal
from app.services.errors import RemediationError
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import RemediationService
from tests.ec2_fixtures import OBSERVED, ec2_bundle
from tests.execution_fixtures import SCOPE, admit, approved
from tests.remediation_fixtures import ADMIN, APPROVER, NOW, PROPOSER, VIEWER
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine


def counts(engine):
    with Session(engine) as session:
        return tuple(
            session.scalar(select(func.count()).select_from(model))
            for model in (
                RemediationExecution,
                RemediationExecutionEvent,
                RemediationTargetReservation,
                AuditEvent,
            )
        )


def test_admission_is_separate_from_approval_findings_and_technical_results(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    with Session(migrated_engine) as session:
        scans = tuple(session.scalars(select(Scan.scan_id)))
    with patch("app.aws.client.Boto3ClientProvider", side_effect=AssertionError("No AWS provider")):
        result = admit(migrated_engine, proposal, request).value
    assert result.phase is ExecutionPhase.QUEUED
    assert result.reservation_held is True
    assert result.blocking_reasons == ()
    assert result.content.expires_at == NOW + timedelta(minutes=5)
    assert result.content.approval.actor.subject == APPROVER.subject
    assert result.content.requested_by.subject == ADMIN.subject
    assert len(result.events) == 1
    with Session(migrated_engine) as session:
        assert session.get(Finding, proposal.content.finding_id).status is FindingStatus.OPEN
        assert tuple(session.scalars(select(Scan.scan_id))) == scans
        assert (
            RemediationService(session, clock=lambda: NOW)
            .get_proposal(
                proposal.content.proposal_id,
                VIEWER,
            )
            .approval_status
            == "APPROVED"
        )
        audit = session.get(AuditEvent, result.events[0].audit_event_id)
        assert audit.event_metadata["actor"] == result.content.requested_by.model_dump(mode="json")


@pytest.mark.parametrize("principal", [VIEWER, PROPOSER, APPROVER])
def test_admission_requires_execute_without_writes(migrated_engine, principal):
    proposal, request, _ = approved(migrated_engine)
    before = counts(migrated_engine)
    with pytest.raises(RemediationError, match="capability"):
        admit(migrated_engine, proposal, request, principal=principal)
    assert counts(migrated_engine) == before


@pytest.mark.parametrize("actor", [PROPOSER, APPROVER])
def test_admin_cannot_bypass_three_identity_separation(migrated_engine, actor):
    proposal, request, _ = approved(migrated_engine)
    principal = Principal(actor.subject, frozenset({"ADMIN"}), actor.issuer)
    with pytest.raises(RemediationError, match="different verified principal"):
        admit(migrated_engine, proposal, request, principal=principal)
    assert counts(migrated_engine)[:3] == (0, 0, 0)


def test_same_subject_different_issuer_is_a_distinct_identity(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    principal = Principal(APPROVER.subject, frozenset({"ADMIN"}), "https://another.example.test")
    assert (
        admit(
            migrated_engine, proposal, request, principal=principal
        ).value.content.requested_by.issuer
        == principal.issuer
    )


@pytest.mark.parametrize(
    "scope, code",
    [
        (AdmissionScope(), "remediation_execution_disabled"),
        (
            AdmissionScope(enabled=True, account_id="111111111111", region="us-east-1"),
            "remediation_execution_scope_conflict",
        ),
        (
            AdmissionScope(enabled=True, account_id=SCOPE.account_id, region="us-west-2"),
            "remediation_execution_scope_conflict",
        ),
    ],
)
def test_default_off_and_scope_gate_are_fail_closed(migrated_engine, scope, code):
    proposal, request, _ = approved(migrated_engine)
    before = counts(migrated_engine)
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request, scope=scope)
    assert error.value.code == code
    assert counts(migrated_engine) == before


@pytest.mark.parametrize(
    "extra",
    [
        "account_id",
        "region",
        "role_arn",
        "credentials",
        "endpoint_url",
        "action_id",
        "desired_encryption_by_default",
    ],
)
def test_execution_body_has_no_caller_controlled_aws_input(extra):
    with pytest.raises(ValidationError):
        ExecutionRequest(
            proposal_sha256="0" * 64,
            approval_decision_id=uuid4(),
            reason="Reviewed",
            **{extra: "injected"},
        )


def test_idempotency_replay_never_extends_or_requeues_expired_authority(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    key = uuid4()
    first = admit(migrated_engine, proposal, request, key=key).value
    before = counts(migrated_engine)
    replay = admit(
        migrated_engine,
        proposal,
        request,
        key=key,
        scope=AdmissionScope(),
        at=NOW + timedelta(minutes=6),
    )
    assert replay.replayed
    assert replay.value.content == first.content
    assert replay.value.phase is ExecutionPhase.QUEUED
    assert ExecutionBlockingReason.EXECUTION_EXPIRED in replay.value.blocking_reasons
    assert counts(migrated_engine) == before
    with pytest.raises(RemediationError) as error:
        admit(
            migrated_engine,
            proposal,
            request.model_copy(update={"reason": "Changed intent"}),
            key=key,
        )
    assert error.value.code == "remediation_idempotency_conflict"
    lost_role = Principal(ADMIN.subject, frozenset({"VIEWER"}), ADMIN.issuer)
    with pytest.raises(RemediationError, match="capability"):
        admit(migrated_engine, proposal, request, key=key, principal=lost_role)
    assert counts(migrated_engine) == before


def test_one_execution_per_proposal_and_one_outstanding_per_target(migrated_engine):
    proposal, request, source = approved(migrated_engine)
    first = admit(migrated_engine, proposal, request).value
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request)
    assert error.value.code == "remediation_state_conflict"
    second, second_request, _ = approved(migrated_engine, request=source)
    before = counts(migrated_engine)
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, second, second_request)
    assert error.value.code == "remediation_execution_target_reserved"
    assert counts(migrated_engine) == before
    renewed = admit(migrated_engine, second, second_request, at=first.content.expires_at).value
    with Session(migrated_engine) as session:
        old = RemediationExecutionService(
            session, clock=lambda: first.content.expires_at
        ).get_execution(first.content.execution_id, VIEWER)
        assert old.phase is ExecutionPhase.EXPIRED
        assert not old.reservation_held
        assert old.events[1].content.previous_event_sha256 == old.events[0].event_sha256
        assert renewed.reservation_held


def test_read_derives_revocation_without_mutating_execution_history(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    execution = admit(migrated_engine, proposal, request).value
    with Session(migrated_engine) as session:
        RemediationService(session, clock=lambda: NOW).revoke(
            proposal.content.proposal_id,
            RevocationRequest(
                proposal_sha256=proposal.proposal_sha256,
                approval_decision_id=request.approval_decision_id,
                reason="Cancel window",
            ),
            APPROVER,
            uuid4(),
        )
    before = counts(migrated_engine)
    with Session(migrated_engine) as session:
        view = RemediationExecutionService(session, clock=lambda: NOW).get_execution(
            execution.content.execution_id, VIEWER
        )
        assert view.phase is ExecutionPhase.QUEUED
        assert ExecutionBlockingReason.APPROVAL_REVOKED in view.blocking_reasons
    assert counts(migrated_engine) == before


def test_governance_round_trip_blocks_new_admission(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    with Session(migrated_engine) as session, session.begin():
        set_finding_disposition(
            session,
            finding_id=proposal.content.finding_id,
            status=FindingStatus.ACKNOWLEDGED,
            at=NOW,
            actor_id="governance",
        )
    with Session(migrated_engine) as session, session.begin():
        set_finding_disposition(
            session,
            finding_id=proposal.content.finding_id,
            status=FindingStatus.OPEN,
            at=NOW,
            actor_id="governance",
        )
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request)
    assert error.value.code == "remediation_ineligible"
    assert counts(migrated_engine)[:3] == (0, 0, 0)


def test_grant_is_capped_by_proposal_expiry_and_exact_expiry_blocks_admission(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    at = proposal.content.expires_at - timedelta(seconds=30)
    assert (
        admit(migrated_engine, proposal, request, at=at).value.content.expires_at
        == proposal.content.expires_at
    )
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request, at=proposal.content.expires_at)
    assert error.value.code == "remediation_ineligible"


@pytest.mark.parametrize("table", [RemediationExecution, RemediationExecutionEvent])
@pytest.mark.parametrize("operation", ["update", "delete"])
def test_execution_authority_and_journal_are_immutable(migrated_engine, table, operation):
    proposal, request, _ = approved(migrated_engine)
    admit(migrated_engine, proposal, request)
    with migrated_engine.begin() as connection, pytest.raises(IntegrityError, match="immutable"):
        statement = update(table).values(created_at=NOW) if operation == "update" else delete(table)
        connection.execute(statement)


def test_journal_audit_and_reservation_rollback_together(migrated_engine, monkeypatch):
    proposal, request, _ = approved(migrated_engine)
    before = counts(migrated_engine)
    monkeypatch.setattr(
        RemediationExecutionService,
        "_view",
        lambda *_: (_ for _ in ()).throw(RuntimeError("injected commit-boundary failure")),
    )
    with pytest.raises(RuntimeError, match="injected"):
        admit(migrated_engine, proposal, request)
    assert counts(migrated_engine) == before


def test_mutation_preserves_caller_transaction_and_pending_work(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    with Session(migrated_engine) as session, session.begin():
        finding = session.get(Finding, proposal.content.finding_id)
        finding.status = FindingStatus.ACKNOWLEDGED
        with pytest.raises(RemediationError) as error:
            RemediationExecutionService(session, scope=SCOPE, clock=lambda: NOW).admit(
                proposal.content.proposal_id, request, ADMIN, uuid4()
            )
        assert error.value.code == "remediation_state_conflict"
        assert session.in_transaction()
        assert finding.status is FindingStatus.ACKNOWLEDGED
        assert finding in session.dirty
        session.rollback()


@pytest.mark.parametrize("method", ["get", "list"])
def test_read_rejects_pending_work_before_sql_and_preserves_clean_transaction(
    migrated_engine, method
):
    proposal, request, _ = approved(migrated_engine)
    execution = admit(migrated_engine, proposal, request).value
    with Session(migrated_engine) as session:
        finding = session.get(Finding, proposal.content.finding_id)
        calls = []

        def listener(*_):
            calls.append(1)

        event.listen(migrated_engine, "before_cursor_execute", listener)
        try:
            finding.status = FindingStatus.ACKNOWLEDGED
            service = RemediationExecutionService(session, clock=lambda: NOW)

            def read():
                if method == "get":
                    return service.get_execution(execution.content.execution_id, VIEWER)
                return service.list_executions(VIEWER)

            with pytest.raises(RemediationError, match="conflicts"):
                read()
            assert calls == []
            assert finding in session.dirty
            session.rollback()
            with session.begin():
                assert read()
                assert session.in_transaction()
        finally:
            event.remove(migrated_engine, "before_cursor_execute", listener)


def test_missing_admission_guard_fails_closed(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    with migrated_engine.begin() as connection:
        # Privileged fixture corruption simulates a missing migration seed. Normal DML
        # cannot remove it; admission must not reconstruct coordination on demand.
        from sqlalchemy import text

        connection.execute(text("DROP TRIGGER immutable_remediation_admission_guard_delete"))
        connection.execute(delete(RemediationAdmissionGuard))
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request)
    assert error.value.code == "remediation_database_unavailable"


@pytest.mark.parametrize("kind", ["FAIL", "PASS", "INSUFFICIENT_EVIDENCE"])
@pytest.mark.parametrize("same_time", [False, True])
def test_new_or_equal_assessment_blocks_execution(migrated_engine, kind, same_time):
    from botocore.exceptions import ClientError

    proposal, request, _ = approved(migrated_engine)
    options = {"default": kind == "PASS"}
    if kind == "INSUFFICIENT_EVIDENCE":
        options["setting_error"] = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "GetEbsEncryptionByDefault"
        )
    with patch(
        "tests.ec2_fixtures.OBSERVED", OBSERVED if same_time else OBSERVED + timedelta(seconds=1)
    ):
        bundle = ec2_bundle(**options)
    with Session(migrated_engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    before = counts(migrated_engine)
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request)
    assert error.value.code == "remediation_ineligible"
    assert counts(migrated_engine) == before


@pytest.mark.parametrize("change", ["approval_id", "digest", "revoke", "exception"])
def test_bad_or_removed_authority_never_partially_admits(migrated_engine, change):
    proposal, request, _ = approved(migrated_engine)
    if change == "approval_id":
        request = request.model_copy(update={"approval_decision_id": uuid4()})
    elif change == "digest":
        request = request.model_copy(update={"proposal_sha256": "0" * 64})
    elif change == "revoke":
        with Session(migrated_engine) as session:
            RemediationService(session, clock=lambda: NOW).revoke(
                proposal.content.proposal_id,
                RevocationRequest(
                    proposal_sha256=proposal.proposal_sha256,
                    approval_decision_id=request.approval_decision_id,
                    reason="Remove execution authority",
                ),
                APPROVER,
                uuid4(),
            )
    else:
        with Session(migrated_engine) as session, session.begin():
            create_finding_exception(
                session,
                finding_id=proposal.content.finding_id,
                reason="Accepted risk",
                approved_by="risk-owner",
                created_at=NOW,
                expires_at=NOW + timedelta(hours=1),
            )
    before = counts(migrated_engine)
    with pytest.raises(RemediationError) as error:
        admit(migrated_engine, proposal, request)
    assert error.value.code == (
        "remediation_provenance_conflict" if change == "digest" else "remediation_ineligible"
    )
    assert counts(migrated_engine) == before


def test_failed_admission_rolls_back_expiry_cleanup(migrated_engine):
    proposal, request, source = approved(migrated_engine)
    old = admit(migrated_engine, proposal, request).value
    second, second_request, _ = approved(migrated_engine, request=source)
    before = counts(migrated_engine)
    with pytest.raises(RemediationError, match="scope"):
        admit(
            migrated_engine,
            second,
            second_request,
            at=old.content.expires_at,
            scope=AdmissionScope(enabled=True, account_id="111111111111", region=SCOPE.region),
        )
    assert counts(migrated_engine) == before
    with Session(migrated_engine) as session:
        view = RemediationExecutionService(
            session, clock=lambda: old.content.expires_at
        ).get_execution(old.content.execution_id, VIEWER)
        assert view.phase is ExecutionPhase.QUEUED and view.reservation_held
        assert len(view.events) == 1


def test_removed_authority_is_journaled_before_target_can_be_reserved_again(migrated_engine):
    proposal, request, source = approved(migrated_engine)
    old = admit(migrated_engine, proposal, request).value
    with Session(migrated_engine) as session:
        RemediationService(session, clock=lambda: NOW).revoke(
            proposal.content.proposal_id,
            RevocationRequest(
                proposal_sha256=proposal.proposal_sha256,
                approval_decision_id=request.approval_decision_id,
                reason="Cancel window",
            ),
            APPROVER,
            uuid4(),
        )
    second, second_request, _ = approved(migrated_engine, request=source)
    assert admit(migrated_engine, second, second_request).value.reservation_held
    with Session(migrated_engine) as session:
        view = RemediationExecutionService(session, clock=lambda: NOW).get_execution(
            old.content.execution_id, VIEWER
        )
        assert view.phase is ExecutionPhase.BLOCKED and not view.reservation_held
        assert ExecutionBlockingReason.APPROVAL_REVOKED in view.events[-1].content.blocking_reasons


def test_capacity_is_a_durable_global_bound(migrated_engine):
    for number in range(33):
        account = f"{100000000000 + number:012d}"
        proposal, request, _ = approved(migrated_engine, account=account)
        scope = AdmissionScope(enabled=True, account_id=account, region=SCOPE.region)
        if number < 32:
            assert admit(migrated_engine, proposal, request, scope=scope).value.reservation_held
        else:
            before = counts(migrated_engine)
            with pytest.raises(RemediationError) as error:
                admit(migrated_engine, proposal, request, scope=scope)
            assert error.value.code == "remediation_execution_capacity"
            assert counts(migrated_engine) == before
    assert counts(migrated_engine)[:3] == (32, 32, 32)


@pytest.mark.parametrize("table", [RemediationAdmissionGuard, RemediationTargetReservation])
def test_coordination_rows_cannot_be_deleted(migrated_engine, table):
    proposal, request, _ = approved(migrated_engine)
    admit(migrated_engine, proposal, request)
    with migrated_engine.begin() as connection, pytest.raises(IntegrityError, match="immutable"):
        connection.execute(delete(table))


def test_active_reservation_cannot_be_cleared_without_terminal_journal(migrated_engine):
    proposal, request, _ = approved(migrated_engine)
    admit(migrated_engine, proposal, request)
    with migrated_engine.begin() as connection, pytest.raises(IntegrityError, match="provenance"):
        connection.execute(update(RemediationTargetReservation).values(execution_id=None))
