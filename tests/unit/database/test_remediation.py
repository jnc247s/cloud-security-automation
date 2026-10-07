"""Authority, lifecycle and provenance checks against migration-installed SQLite guards."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import delete, event, func, insert, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.database.governance import create_finding_exception, set_finding_disposition
from app.database.integrity import canonical_json_sha256
from app.database.persistence import persist_scan_result
from app.models import AuditEvent, ControlAssessment, Finding, FindingOccurrence
from app.models.enums import AuditEventType, FindingStatus
from app.models.remediation import RemediationDecision, RemediationProposal, RemediationRequest
from app.remediation.contracts import (
    ApprovalStatus,
    BlockingReason,
    DecisionRequest,
    RevocationRequest,
)
from app.remediation.provenance import baseline_for
from app.security.authentication import Principal
from app.services.errors import RemediationError
from app.services.remediation_service import RemediationService
from tests.ec2_fixtures import OBSERVED, ec2_bundle, ec2_profile
from tests.remediation_fixtures import ADMIN, APPROVER, NOW, PROPOSER, VIEWER, propose, seed
from tests.unit.collectors.test_ec2 import _client


def approve(session, proposal, *, principal=APPROVER, at=NOW, key=None, decision="APPROVE"):
    return RemediationService(session, clock=lambda: at).decide(
        proposal.content.proposal_id,
        DecisionRequest(
            proposal_sha256=proposal.proposal_sha256,
            decision=decision,
            reason="Reviewed exact immutable intent.",
        ),
        principal,
        key or uuid4(),
    )


def test_retained_ec2_fail_has_valid_remediation_provenance(migrated_engine):
    request, _ = seed(migrated_engine)
    with Session(migrated_engine) as session:
        baseline = baseline_for(
            session,
            session.get(Finding, request.finding_id),
            session.get(FindingOccurrence, request.occurrence_id),
        )
        assert baseline.default_kms_key_expected_absence is True


def test_present_default_key_is_bound_without_changing_the_technical_rule(migrated_engine):
    key = "arn:aws:kms:us-east-1:123456789012:key/reviewed-example"
    client = _client(
        encryption_response={"EbsEncryptionByDefault": False}, kms_response={"KmsKeyId": key}
    )
    with patch("tests.ec2_fixtures.ec2_client", return_value=client):
        request, _ = seed(migrated_engine)
    proposal = propose(migrated_engine, request).value
    assert proposal.content.baseline.default_kms_key_id == key
    assert proposal.content.baseline.default_kms_key_expected_absence is False
    with Session(migrated_engine) as session:
        approve(session, proposal)
        assert session.get(Finding, request.finding_id).status is FindingStatus.OPEN


def test_propose_approve_revoke_retains_findings_and_full_audit(migrated_engine):
    request, _ = seed(migrated_engine)
    proposal = propose(migrated_engine, request).value
    assert proposal.approval_status is ApprovalStatus.PROPOSED
    assert proposal.blocking_reasons == ()
    assert proposal.content.expires_at == NOW + timedelta(hours=24)
    assert proposal.content.baseline.default_kms_key_expected_absence is True
    assert proposal.content.baseline.default_kms_key_id is None
    with Session(migrated_engine) as session:
        service = RemediationService(session, clock=lambda: NOW)
        approved = service.decide(
            proposal.content.proposal_id,
            DecisionRequest(
                proposal_sha256=proposal.proposal_sha256,
                decision="APPROVE",
                reason="Reviewed exact proposal.",
            ),
            APPROVER,
            uuid4(),
        )
        assert approved.value.actor.subject == APPROVER.subject
        assert (
            service.get_proposal(proposal.content.proposal_id, VIEWER).approval_status
            is ApprovalStatus.APPROVED
        )
        session.rollback()  # End the read transaction; the next mutation owns a fresh one.
        service.revoke(
            proposal.content.proposal_id,
            RevocationRequest(
                proposal_sha256=proposal.proposal_sha256,
                approval_decision_id=approved.value.decision_id,
                reason="Change window cancelled.",
            ),
            ADMIN,
            uuid4(),
        )
        assert (
            service.get_proposal(proposal.content.proposal_id, VIEWER).approval_status
            is ApprovalStatus.REVOKED
        )
        finding = session.get(Finding, request.finding_id)
        assert finding.status is FindingStatus.OPEN
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.target_id == proposal.content.proposal_id)
            .order_by(AuditEvent.event_type)
        ).all()
        assert {event.event_type for event in events} == {
            AuditEventType.REMEDIATION_PROPOSED,
            AuditEventType.REMEDIATION_APPROVED,
            AuditEventType.REMEDIATION_REVOKED,
        }
        for event in events:
            actor = event.event_metadata["actor"]
            assert actor["issuer"] == PROPOSER.issuer
            assert actor["subject"] in {PROPOSER.subject, APPROVER.subject, ADMIN.subject}
            assert len(event.actor_id) == 64
            assert actor["roles"]
            assert actor["capability"] in {"PROPOSE", "APPROVE"}
        assert session.scalar(select(func.count()).select_from(ControlAssessment)) == 4


def test_idempotency_replay_and_conflicting_content(migrated_engine):
    request, _ = seed(migrated_engine)
    key = uuid4()
    first = propose(migrated_engine, request, key=key)
    replay = propose(migrated_engine, request, key=key)
    assert replay.replayed and not first.replayed
    assert replay.value.content.proposal_id == first.value.content.proposal_id
    changed = request.model_copy(update={"reason": "Different intent."})
    with pytest.raises(RemediationError, match="different request content"):
        propose(migrated_engine, changed, key=key)
    with Session(migrated_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0


def test_retry_still_requires_current_capability_for_the_same_identity(migrated_engine):
    request, _ = seed(migrated_engine)
    key = uuid4()
    propose(migrated_engine, request, key=key)
    demoted = Principal(PROPOSER.subject, VIEWER.role_names, PROPOSER.issuer)
    with pytest.raises(RemediationError) as raised:
        propose(migrated_engine, request, principal=demoted, key=key)
    assert raised.value.code == "insufficient_capability"


@pytest.mark.parametrize("caller_state", ["explicit", "read", "flushed"])
def test_mutations_reject_and_preserve_an_existing_caller_transaction(
    migrated_engine, caller_state
):
    request, _ = seed(migrated_engine)
    with Session(migrated_engine) as session:
        if caller_state == "explicit":
            session.begin()
        elif caller_state == "read":
            session.get(Finding, request.finding_id)
        else:
            set_finding_disposition(
                session,
                finding_id=request.finding_id,
                status=FindingStatus.ACKNOWLEDGED,
                actor_id="caller-owned-governance",
                at=NOW,
            )
            session.flush()
            assert not session.new and not session.dirty
        transaction = session.get_transaction()
        with pytest.raises(RemediationError) as raised:
            RemediationService(session, clock=lambda: NOW).propose(request, PROPOSER, uuid4())
        assert raised.value.code == "remediation_state_conflict"
        assert transaction is session.get_transaction() and transaction.is_active
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 0
        session.rollback()
    with Session(migrated_engine) as session:
        assert session.get(Finding, request.finding_id).status is FindingStatus.OPEN
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 0


def test_rehashed_forged_baseline_is_read_as_blocked_and_cannot_be_approved(migrated_engine):
    proposal = propose(migrated_engine).value
    for binding in (
        "profile_sha256",
        "catalog_sha256",
        "control_definition_sha256",
        "state_sha256",
        "inventory_sha256",
        "default_kms_key_id",
    ):
        document = proposal.content.model_dump(mode="json")
        proposal_id = uuid4()
        document["proposal_id"] = str(proposal_id)
        document["baseline"][binding] = (
            "forged-key" if binding == "default_kms_key_id" else "0" * 64
        )
        digest = canonical_json_sha256(document)
        # Model a privileged direct INSERT, without disabling immutable history/provenance
        # guards. Even a matching recomputed digest must not substitute the retained baseline.
        with Session(migrated_engine) as session, session.begin():
            session.execute(
                insert(RemediationProposal).values(
                    proposal_id=proposal_id,
                    finding_id=proposal.content.finding_id,
                    occurrence_id=proposal.content.baseline.occurrence_id,
                    account_id=proposal.content.account_id,
                    actor_issuer=PROPOSER.issuer,
                    actor_subject=PROPOSER.subject,
                    actor_roles=["ANALYST"],
                    content=document,
                    proposal_sha256=digest,
                    created_at=NOW,
                    expires_at=proposal.content.expires_at,
                )
            )
        with Session(migrated_engine) as session:
            service = RemediationService(session, clock=lambda: NOW)
            view = service.get_proposal(proposal_id, VIEWER)
            assert view.approval_status is ApprovalStatus.PROPOSED
            assert BlockingReason.INVALID_PROVENANCE in view.blocking_reasons
            session.rollback()
            with pytest.raises(RemediationError) as raised:
                service.decide(
                    proposal_id,
                    DecisionRequest(
                        proposal_sha256=digest,
                        decision="APPROVE",
                        reason="Cannot approve substituted baseline.",
                    ),
                    APPROVER,
                    uuid4(),
                )
            assert raised.value.code == "remediation_ineligible"
            assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0


@pytest.mark.parametrize("principal", [PROPOSER, VIEWER])
def test_approval_authority_is_enforced_in_service(migrated_engine, principal):
    request, _ = seed(migrated_engine)
    proposal = propose(migrated_engine, request).value
    with Session(migrated_engine) as session:
        with pytest.raises(RemediationError):
            RemediationService(session, clock=lambda: NOW).decide(
                proposal.content.proposal_id,
                DecisionRequest(
                    proposal_sha256=proposal.proposal_sha256,
                    decision="APPROVE",
                    reason="Cannot grant approval.",
                ),
                principal,
                uuid4(),
            )
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0


@pytest.mark.parametrize("principal", [ADMIN, APPROVER])
@pytest.mark.parametrize("decision", ["APPROVE", "REJECT"])
def test_self_decision_denied_even_with_all_capabilities(migrated_engine, principal, decision):
    proposal = propose(migrated_engine, principal=principal).value
    with Session(migrated_engine) as session:
        with pytest.raises(RemediationError) as raised:
            approve(session, proposal, principal=principal, decision=decision)
        assert raised.value.code == "remediation_separation_required"
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0


def test_same_subject_from_different_verified_issuer_is_distinct(migrated_engine):
    proposal = propose(migrated_engine, principal=ADMIN).value
    other = Principal(ADMIN.subject, ADMIN.role_names, "https://other-trusted-issuer.test")
    with Session(migrated_engine) as session:
        assert approve(session, proposal, principal=other).value.actor.issuer == other.issuer


@pytest.mark.parametrize("delta,allowed", [(-1, True), (0, False), (1, False)])
def test_approval_exact_expiry_boundary(migrated_engine, delta, allowed):
    proposal = propose(migrated_engine).value
    at = proposal.content.expires_at + timedelta(microseconds=delta)
    with Session(migrated_engine) as session:
        if allowed:
            approve(session, proposal, at=at)
        else:
            with pytest.raises(RemediationError) as raised:
                approve(session, proposal, at=at)
            assert raised.value.code == "remediation_ineligible"
            assert RemediationService(session, clock=lambda: at).get_proposal(
                proposal.content.proposal_id, VIEWER
            ).blocking_reasons == (BlockingReason.EXPIRED,)


@pytest.mark.parametrize("kind", ["FAIL", "PASS", "INSUFFICIENT_EVIDENCE"])
@pytest.mark.parametrize("same_time", [False, True])
def test_any_newer_or_ambiguous_equal_time_assessment_invalidates(migrated_engine, kind, same_time):
    proposal = propose(migrated_engine).value
    options = {"default": kind == "PASS"}
    if kind == "INSUFFICIENT_EVIDENCE":
        options["setting_error"] = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "GetEbsEncryptionByDefault"
        )
    observed = OBSERVED if same_time else OBSERVED + timedelta(seconds=1)
    with patch("tests.ec2_fixtures.OBSERVED", observed):
        bundle = ec2_bundle(**options)
    with Session(migrated_engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(migrated_engine) as session:
        actual = session.scalar(
            select(ControlAssessment).where(
                ControlAssessment.scan_id == bundle["snapshot"].scan_id,
                ControlAssessment.control_id == proposal.content.control_id,
            )
        )
        assert actual.assessment_result.value == kind
        session.rollback()
        with pytest.raises(RemediationError) as raised:
            approve(session, proposal)
        assert raised.value.code == "remediation_ineligible"
        current = RemediationService(session, clock=lambda: NOW).get_proposal(
            proposal.content.proposal_id, VIEWER
        )
        assert BlockingReason.STALE_TARGET in current.blocking_reasons
        assert current.approval_status is ApprovalStatus.PROPOSED


def test_staleness_query_never_filters_out_non_decisive_results(migrated_engine):
    # EC2-004 never legitimately evaluates N/A. The strict query nevertheless has no result
    # filter, protecting against every future or directly persisted assessment state.
    from app.remediation.provenance import has_newer_assessment

    proposal = propose(migrated_engine).value
    statements = []

    class QueryProbe:
        def scalar(self, statement):
            statements.append(str(statement.compile()))
            return uuid4()

    with Session(migrated_engine) as session:
        finding = session.get(Finding, proposal.content.finding_id)
        assert has_newer_assessment(QueryProbe(), finding, proposal.content.baseline)
    assert "assessment_result" not in statements[0]


def test_newer_scan_omitting_control_does_not_rewrite_history_or_resolve(migrated_engine):
    proposal = propose(migrated_engine).value
    with patch("tests.ec2_fixtures.OBSERVED", OBSERVED + timedelta(seconds=1)):
        bundle = ec2_bundle(profile=ec2_profile(version="6.3.1", enabled_controls=("EC2-001",)))
    with Session(migrated_engine) as session:
        persist_scan_result(session, **bundle)
        session.commit()
        service = RemediationService(session, clock=lambda: NOW)
        assert service.get_proposal(proposal.content.proposal_id, VIEWER).blocking_reasons == ()
        assert session.get(Finding, proposal.content.finding_id).status is FindingStatus.OPEN


def test_optional_kms_failure_does_not_change_fail_but_blocks_proposal(migrated_engine):
    request, _ = seed(
        migrated_engine,
        kms_error=ClientError({"Error": {"Code": "AccessDenied"}}, "GetEbsDefaultKmsKeyId"),
    )
    with pytest.raises(RemediationError) as raised:
        propose(migrated_engine, request)
    assert raised.value.code == "remediation_provenance_conflict"
    with Session(migrated_engine) as session:
        assert session.get(Finding, request.finding_id).status is FindingStatus.OPEN
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 0


@pytest.mark.parametrize("status", ["ACKNOWLEDGED", "FALSE_POSITIVE"])
def test_governance_change_requires_new_proposal(migrated_engine, status):
    proposal = propose(migrated_engine).value
    with Session(migrated_engine) as session:
        set_finding_disposition(
            session,
            finding_id=proposal.content.finding_id,
            status=FindingStatus(status),
            actor_id="risk-owner",
            at=NOW,
        )
        session.commit()
        with pytest.raises(RemediationError, match="ineligible"):
            approve(session, proposal)
        view = RemediationService(session, clock=lambda: NOW).get_proposal(
            proposal.content.proposal_id, VIEWER
        )
        assert BlockingReason.STALE_GOVERNANCE in view.blocking_reasons


@pytest.mark.parametrize("approved", [False, True])
@pytest.mark.parametrize("same_timestamp", [False, True])
@pytest.mark.parametrize("intermediate", ["ACKNOWLEDGED", "FALSE_POSITIVE"])
def test_governance_round_trip_never_revives_old_authority(
    migrated_engine, approved, same_timestamp, intermediate
):
    request, _ = seed(migrated_engine)
    proposal = propose(migrated_engine, request).value
    approval = None
    if approved:
        with Session(migrated_engine) as session:
            approval = approve(session, proposal).value
    first_at = NOW + timedelta(seconds=1)
    second_at = first_at if same_timestamp else NOW + timedelta(seconds=2)
    checked_at = NOW + timedelta(seconds=3)
    for status, at in ((FindingStatus(intermediate), first_at), (FindingStatus.OPEN, second_at)):
        with Session(migrated_engine) as session, session.begin():
            set_finding_disposition(
                session,
                finding_id=request.finding_id,
                status=status,
                actor_id="risk-owner",
                at=at,
            )
        with Session(migrated_engine) as session:
            view = RemediationService(session, clock=lambda: checked_at).get_proposal(
                proposal.content.proposal_id, VIEWER
            )
            assert BlockingReason.STALE_GOVERNANCE in view.blocking_reasons
            assert view.approval_status is (
                ApprovalStatus.APPROVED if approved else ApprovalStatus.PROPOSED
            )
    with Session(migrated_engine) as session:
        if approval is None:
            with pytest.raises(RemediationError) as raised:
                approve(session, proposal, at=checked_at)
            assert raised.value.code == "remediation_ineligible"
            assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0
        else:
            view = RemediationService(session, clock=lambda: checked_at).get_proposal(
                proposal.content.proposal_id, VIEWER
            )
            assert len(view.decisions) == 1
            assert view.decisions[0].decision_id == approval.decision_id
            session.rollback()
            RemediationService(session, clock=lambda: checked_at).revoke(
                proposal.content.proposal_id,
                RevocationRequest(
                    proposal_sha256=proposal.proposal_sha256,
                    approval_decision_id=approval.decision_id,
                    reason="Remove stale authority.",
                ),
                APPROVER,
                uuid4(),
            )
    fresh = propose(migrated_engine, request, at=checked_at).value
    assert fresh.content.governance_sha256 != proposal.content.governance_sha256
    assert fresh.blocking_reasons == ()
    with Session(migrated_engine) as session:
        approve(session, fresh, at=checked_at)
        assert session.get(Finding, request.finding_id).status is FindingStatus.OPEN


def test_unrelated_finding_history_does_not_stale_proposal(migrated_engine):
    proposal = propose(migrated_engine).value
    other, _ = seed(migrated_engine, region="us-west-2")
    with Session(migrated_engine) as session, session.begin():
        set_finding_disposition(
            session,
            finding_id=other.finding_id,
            status=FindingStatus.ACKNOWLEDGED,
            actor_id="other-risk-owner",
            at=NOW,
        )
    with Session(migrated_engine) as session:
        view = RemediationService(session, clock=lambda: NOW).get_proposal(
            proposal.content.proposal_id, VIEWER
        )
        assert view.blocking_reasons == ()


def test_active_exception_blocks_creation_and_later_approval(migrated_engine):
    request, _ = seed(migrated_engine)
    proposal = propose(migrated_engine, request).value
    with Session(migrated_engine) as session:
        create_finding_exception(
            session,
            finding_id=request.finding_id,
            reason="Review exception.",
            approved_by="risk-owner",
            created_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )
        session.commit()
        with pytest.raises(RemediationError, match="ineligible"):
            approve(session, proposal)
        with pytest.raises(RemediationError, match="ineligible"):
            RemediationService(session, clock=lambda: NOW).propose(request, PROPOSER, uuid4())
        view = RemediationService(session, clock=lambda: NOW).get_proposal(
            proposal.content.proposal_id, VIEWER
        )
        assert BlockingReason.ACTIVE_EXCEPTION in view.blocking_reasons


def test_cross_region_occurrence_and_wrong_digest_are_rejected(migrated_engine):
    request, _ = seed(migrated_engine)
    other, _ = seed(migrated_engine, region="us-west-2")
    mismatched = request.model_copy(update={"occurrence_id": other.occurrence_id})
    with pytest.raises(RemediationError):
        propose(migrated_engine, mismatched)
    proposal = propose(migrated_engine, request).value
    with Session(migrated_engine) as session:
        with pytest.raises(RemediationError) as raised:
            RemediationService(session, clock=lambda: NOW).decide(
                proposal.content.proposal_id,
                DecisionRequest(
                    proposal_sha256="0" * 64, decision="APPROVE", reason="Wrong digest."
                ),
                APPROVER,
                uuid4(),
            )
        assert raised.value.code == "remediation_provenance_conflict"


@pytest.mark.parametrize("initial", ["APPROVE", "REJECT"])
def test_terminal_initial_decision_and_idempotent_replays(migrated_engine, initial):
    proposal = propose(migrated_engine).value
    key = uuid4()
    with Session(migrated_engine) as session:
        first = approve(session, proposal, key=key, decision=initial)
        replay = approve(session, proposal, key=key, decision=initial, at=NOW + timedelta(days=2))
        assert replay.replayed and replay.value == first.value
        with pytest.raises(RemediationError):
            approve(session, proposal, decision=initial)
        with pytest.raises(RemediationError) as raised:
            approve(
                session, proposal, key=key, decision="REJECT" if initial == "APPROVE" else "APPROVE"
            )
        assert raised.value.code == "remediation_idempotency_conflict"


def test_revocation_can_remove_expired_authority_and_is_idempotent(migrated_engine):
    proposal = propose(migrated_engine).value
    with Session(migrated_engine) as session:
        approval = approve(session, proposal).value
        key = uuid4()
        request = RevocationRequest(
            proposal_sha256=proposal.proposal_sha256,
            approval_decision_id=approval.decision_id,
            reason="Remove expired authorization.",
        )
        service = RemediationService(session, clock=lambda: NOW + timedelta(days=2))
        first = service.revoke(proposal.content.proposal_id, request, APPROVER, key)
        assert (
            service.revoke(proposal.content.proposal_id, request, APPROVER, key).value
            == first.value
        )
        with pytest.raises(RemediationError):
            approve(session, proposal)
        with pytest.raises(RemediationError):
            service.revoke(proposal.content.proposal_id, request, APPROVER, uuid4())


def test_new_assessment_preserves_approval_history_but_allows_revocation(migrated_engine):
    proposal = propose(migrated_engine).value
    with Session(migrated_engine) as session:
        approval = approve(session, proposal).value
    with patch("tests.ec2_fixtures.OBSERVED", OBSERVED + timedelta(seconds=1)):
        bundle = ec2_bundle()
    with Session(migrated_engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(migrated_engine) as session:
        service = RemediationService(session, clock=lambda: NOW)
        current = service.get_proposal(proposal.content.proposal_id, VIEWER)
        assert current.approval_status is ApprovalStatus.APPROVED
        assert BlockingReason.STALE_TARGET in current.blocking_reasons
        session.rollback()
        service.revoke(
            proposal.content.proposal_id,
            RevocationRequest(
                proposal_sha256=proposal.proposal_sha256,
                approval_decision_id=approval.decision_id,
                reason="Stale approval must not remain actionable.",
            ),
            ADMIN,
            uuid4(),
        )
        assert (
            service.get_proposal(proposal.content.proposal_id, VIEWER).approval_status
            is ApprovalStatus.REVOKED
        )


def test_rejection_can_close_expired_proposal(migrated_engine):
    proposal = propose(migrated_engine).value
    with Session(migrated_engine) as session:
        assert (
            approve(session, proposal, at=NOW + timedelta(days=2), decision="REJECT").value.kind
            == "REJECT"
        )


def test_proposer_with_approve_capability_may_remove_but_not_grant_authority(migrated_engine):
    proposal = propose(migrated_engine, principal=ADMIN).value
    with Session(migrated_engine) as session:
        approval = approve(session, proposal).value
        result = RemediationService(session, clock=lambda: NOW).revoke(
            proposal.content.proposal_id,
            RevocationRequest(
                proposal_sha256=proposal.proposal_sha256,
                approval_decision_id=approval.decision_id,
                reason="Proposer cancels the approved change window.",
            ),
            ADMIN,
            uuid4(),
        )
        assert result.value.kind == "REVOKE"


@pytest.mark.parametrize("table", [RemediationProposal, RemediationDecision, RemediationRequest])
@pytest.mark.parametrize("operation", ["update", "delete"])
def test_history_guards_reject_mutation(migrated_engine, table, operation):
    proposal = propose(migrated_engine).value
    with Session(migrated_engine) as session:
        approve(session, proposal)
        statement = (
            delete(table)
            if operation == "delete"
            else update(table).values(
                {next(iter(table.__table__.primary_key.columns)).name: uuid4()}
            )
        )
        with pytest.raises(IntegrityError, match="immutable"):
            session.execute(statement)
        session.rollback()


def test_direct_sql_rejects_self_approval_and_foreign_revocation(migrated_engine):
    proposal = propose(migrated_engine).value
    with Session(migrated_engine) as session:
        values = dict(
            decision_id=uuid4(),
            proposal_id=proposal.content.proposal_id,
            kind="APPROVE",
            proposal_sha256=proposal.proposal_sha256,
            actor_issuer=PROPOSER.issuer,
            actor_subject=PROPOSER.subject,
            actor_roles=["ADMIN"],
            reason="Forged self approval.",
            created_at=NOW,
        )
        with pytest.raises(IntegrityError):
            session.execute(insert(RemediationDecision).values(**values))
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                insert(RemediationDecision).values(
                    **{
                        **values,
                        "decision_id": uuid4(),
                        "kind": "REVOKE",
                        "actor_subject": ADMIN.subject,
                        "approval_decision_id": uuid4(),
                    }
                )
            )
        session.rollback()


def test_direct_sql_rejects_another_proposals_real_approval_reference(migrated_engine):
    request, _ = seed(migrated_engine)
    first = propose(migrated_engine, request).value
    second = propose(migrated_engine, request).value
    with Session(migrated_engine) as session:
        approve(session, first)
        other_approval = approve(session, second).value
        with pytest.raises(IntegrityError):
            session.execute(
                insert(RemediationDecision).values(
                    decision_id=uuid4(),
                    proposal_id=first.content.proposal_id,
                    kind="REVOKE",
                    proposal_sha256=first.proposal_sha256,
                    approval_decision_id=other_approval.decision_id,
                    actor_issuer=ADMIN.issuer,
                    actor_subject=ADMIN.subject,
                    actor_roles=["ADMIN"],
                    reason="Wrong proposal reference.",
                    created_at=NOW,
                )
            )
        session.rollback()


def test_audit_failure_rolls_back_proposal_and_idempotency(migrated_engine, monkeypatch):
    request, _ = seed(migrated_engine)

    def fail(*args, **kwargs):
        raise RuntimeError("simulated audit persistence failure")

    monkeypatch.setattr("app.services.remediation_service.append_audit_event", fail)
    with pytest.raises(RuntimeError, match="simulated"):
        propose(migrated_engine, request)
    with Session(migrated_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 0
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 0


def test_audit_failure_rolls_back_decision_and_retry_ledger(migrated_engine, monkeypatch):
    proposal = propose(migrated_engine).value

    def fail(*args, **kwargs):
        raise RuntimeError("simulated decision audit failure")

    monkeypatch.setattr("app.services.remediation_service.append_audit_event", fail)
    with Session(migrated_engine) as session:
        with pytest.raises(RuntimeError, match="simulated"):
            approve(session, proposal)
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0
        assert session.scalar(select(func.count()).select_from(RemediationRequest)) == 1


def test_retry_recovery_database_error_is_sanitized_and_atomic(migrated_engine, monkeypatch):
    request, _ = seed(migrated_engine)
    calls = 0

    def replay(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OperationalError("sensitive SQL", {}, RuntimeError("sensitive DB detail"))
        return None

    def fail_audit(*args, **kwargs):
        raise IntegrityError("sensitive SQL", {}, RuntimeError("sensitive DB detail"))

    monkeypatch.setattr(RemediationService, "_replay", replay)
    monkeypatch.setattr(RemediationService, "_audit", fail_audit)
    with Session(migrated_engine) as session:
        with pytest.raises(RemediationError) as raised:
            RemediationService(session, clock=lambda: NOW).propose(request, PROPOSER, uuid4())
        assert raised.value.code == "remediation_database_unavailable"
        assert "sensitive" not in str(raised.value)
        assert not session.in_transaction()
    with Session(migrated_engine) as session:
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 0


def test_reads_emit_no_mutation_and_never_acquire_aws_credentials(migrated_engine, monkeypatch):
    proposal = propose(migrated_engine).value
    statements = []

    def capture(_conn, _cursor, sql, _parameters, _context, _many):
        statements.append(sql)

    def forbidden(*args, **kwargs):
        raise AssertionError("8A must never acquire AWS credentials or submit work")

    monkeypatch.setattr("boto3.Session", forbidden)
    monkeypatch.setattr("app.services.scan_executor.InProcessScanExecutor.submit", forbidden)
    event.listen(migrated_engine, "before_cursor_execute", capture)
    try:
        with Session(migrated_engine) as session:
            service = RemediationService(session, clock=lambda: NOW + timedelta(days=2))
            assert (
                BlockingReason.EXPIRED
                in service.get_proposal(proposal.content.proposal_id, VIEWER).blocking_reasons
            )
            assert service.list_proposals(VIEWER).total == 1
    finally:
        event.remove(migrated_engine, "before_cursor_execute", capture)
    assert all(sql.lstrip().upper().startswith("SELECT") for sql in statements)


@pytest.mark.parametrize("read_method", ["detail", "list"])
@pytest.mark.parametrize("autoflush", [False, True])
@pytest.mark.parametrize("pending", ["insert", "update", "delete"])
def test_reads_reject_pending_changes_without_sql_or_caller_state_loss(
    migrated_engine, read_method, autoflush, pending
):
    proposal = propose(migrated_engine).value
    statements = []

    def capture(_conn, _cursor, sql, _parameters, _context, _many):
        statements.append(sql)

    with Session(migrated_engine, autoflush=autoflush) as session:
        finding = session.get(Finding, proposal.content.finding_id)
        event_ids = set(session.scalars(select(AuditEvent.event_id)).all())
        if pending == "insert":
            pending_event = AuditEvent(
                event_id=uuid4(),
                event_type=AuditEventType.FINDING_ACKNOWLEDGED,
                actor_type="user",
                actor_id="caller-owned",
                target_type="finding",
                target_id=finding.finding_id,
                timestamp=NOW,
                event_metadata={"previous_status": "OPEN", "status": "ACKNOWLEDGED"},
            )
            session.add(pending_event)
        elif pending == "update":
            finding.status = FindingStatus.ACKNOWLEDGED
        else:
            session.delete(finding)
        transaction = session.get_transaction()
        event.listen(migrated_engine, "before_cursor_execute", capture)
        try:
            with pytest.raises(RemediationError) as raised:
                service = RemediationService(session, clock=lambda: NOW)
                if read_method == "detail":
                    service.get_proposal(proposal.content.proposal_id, VIEWER)
                else:
                    service.list_proposals(VIEWER)
            assert raised.value.code == "remediation_state_conflict"
        finally:
            event.remove(migrated_engine, "before_cursor_execute", capture)
        assert statements == []
        assert session.get_transaction() is transaction and transaction.is_active
        assert session.autoflush is autoflush
        if pending == "insert":
            assert pending_event in session.new
        elif pending == "update":
            assert finding.status is FindingStatus.ACKNOWLEDGED
            assert finding in session.dirty and session.is_modified(finding)
        else:
            assert finding in session.deleted
        session.rollback()
    with Session(migrated_engine) as session:
        assert session.get(Finding, proposal.content.finding_id).status is FindingStatus.OPEN
        assert set(session.scalars(select(AuditEvent.event_id)).all()) == event_ids


@pytest.mark.parametrize("read_method", ["detail", "list"])
@pytest.mark.parametrize("autoflush", [False, True])
@pytest.mark.parametrize("caller_state", ["explicit", "read", "flushed"])
def test_reads_preserve_a_clean_caller_transaction(
    migrated_engine, read_method, autoflush, caller_state
):
    proposal = propose(migrated_engine).value
    statements = []

    def capture(_conn, _cursor, sql, _parameters, _context, _many):
        statements.append(sql)

    with Session(migrated_engine, autoflush=autoflush) as session:
        if caller_state == "explicit":
            session.begin()
        elif caller_state == "read":
            session.get(Finding, proposal.content.finding_id)
        else:
            set_finding_disposition(
                session,
                finding_id=proposal.content.finding_id,
                status=FindingStatus.ACKNOWLEDGED,
                actor_id="caller-owned-governance",
                at=NOW,
            )
        assert not session.new and not session.dirty and not session.deleted
        transaction = session.get_transaction()
        event.listen(migrated_engine, "before_cursor_execute", capture)
        try:
            service = RemediationService(session, clock=lambda: NOW)
            if read_method == "detail":
                view = service.get_proposal(proposal.content.proposal_id, VIEWER)
            else:
                page = service.list_proposals(VIEWER)
                assert page.total == 1
                view = page.items[0]
        finally:
            event.remove(migrated_engine, "before_cursor_execute", capture)
        assert (BlockingReason.STALE_GOVERNANCE in view.blocking_reasons) is (
            caller_state == "flushed"
        )
        assert statements and all(sql.lstrip().upper().startswith("SELECT") for sql in statements)
        assert session.get_transaction() is transaction and transaction.is_active
        assert session.autoflush is autoflush
        session.rollback()
    with Session(migrated_engine) as session:
        assert session.get(Finding, proposal.content.finding_id).status is FindingStatus.OPEN
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 0
