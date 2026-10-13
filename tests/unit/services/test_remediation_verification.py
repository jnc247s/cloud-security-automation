"""Offline admission, exact-policy scan and sealed receipt boundaries."""

from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Finding, Scan
from app.models.enums import AuditEventType, FindingStatus, ScanStatus
from app.models.remediation_verification import (
    RemediationVerification,
    RemediationVerificationReceipt,
)
from app.remediation.verification_contracts import VerificationRequest, VerificationScope
from app.services.errors import RemediationError
from app.services.remediation_verification_service import (
    RemediationVerificationService,
    VerificationSubmissionError,
)
from tests.fakes import client_error
from tests.remediation_fixtures import VIEWER
from tests.unit.services.test_scan_service import RecordingExecutor
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.verification_fixtures import SCOPE, VerificationHarness, provider


@pytest.mark.parametrize(
    "changes",
    [
        {"reason": " "},
        {"reason": "x" * 2001},
        {"reason": "ok", "scan_id": str(uuid4())},
        {"reason": "ok", "region": "us-east-1"},
    ],
)
def test_closed_request(changes):
    with pytest.raises(ValidationError):
        VerificationRequest(**changes)


def test_scope_is_independently_default_off_and_explicit():
    assert not VerificationScope().enabled
    with pytest.raises(ValidationError):
        VerificationScope(enabled=True)


@pytest.mark.parametrize("enabled,outcome", [(True, "VERIFIED"), (False, "NOT_VERIFIED")])
@pytest.mark.parametrize("key", [None, "reviewed-key"])
def test_normal_completed_postcondition(migrated_engine, enabled, outcome, key):
    harness = VerificationHarness(migrated_engine, key=key)
    executor = RecordingExecutor()
    result = harness.request(executor=executor).value
    assert result.receipt is None and result.content.attempt == 1
    assert executor.submissions == [result.content.scan_id]
    assert result.content.profile_version == "6.3.0"
    harness.run(result.content.scan_id, read_provider=provider(enabled=enabled, key=key))
    completed = harness.view(result.content.verification_id)
    assert completed.receipt.outcome.value == outcome
    assert completed.receipt.evidence.technical_result.value == ("PASS" if enabled else "FAIL")
    with Session(migrated_engine) as session:
        finding = session.get(Finding, harness.proposal.content.finding_id)
        assert finding.status is (FindingStatus.RESOLVED if enabled else FindingStatus.OPEN)
        assert session.get(Scan, result.content.scan_id).status is ScanStatus.COMPLETED
    assert harness.view(result.content.verification_id) == completed


@pytest.mark.parametrize("key", ["unexpected-key", "another-key"])
def test_technical_pass_and_finding_resolution_do_not_override_kms_inconclusive(
    migrated_engine, key
):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    harness.run(value.content.scan_id, read_provider=provider(enabled=True, key=key))
    receipt = harness.view(value.content.verification_id).receipt
    assert receipt.outcome.value == "INCONCLUSIVE" and receipt.reason.value == "KMS_CONTEXT_CHANGED"
    assert receipt.evidence.technical_result.value == "PASS"
    with Session(migrated_engine) as session:
        assert (
            session.get(Finding, harness.proposal.content.finding_id).status
            is FindingStatus.RESOLVED
        )


def test_partial_collection_is_inconclusive_even_with_explicit_technical_pass(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    harness.run(
        value.content.scan_id,
        read_provider=provider(
            enabled=True, kms_error=client_error("AccessDenied", "GetEbsDefaultKmsKeyId")
        ),
    )
    receipt = harness.view(value.content.verification_id).receipt
    assert receipt.scan_status is ScanStatus.PARTIAL
    assert receipt.outcome.value == "INCONCLUSIVE" and receipt.reason.value == "SCAN_INCOMPLETE"
    assert receipt.evidence is None


@pytest.mark.parametrize("denial", ["disabled", "scope", "queued", "capability", "active"])
def test_denial_has_no_admission_effects(migrated_engine, denial):
    harness = VerificationHarness(migrated_engine, acknowledge=denial != "queued")
    if denial == "active":
        harness.request()
    with Session(migrated_engine) as session:
        before = (
            session.scalar(select(func.count()).select_from(Scan)),
            session.scalar(select(func.count()).select_from(AuditEvent)),
        )
    options = {
        "disabled": {"scope": VerificationScope()},
        "scope": {"scope": SCOPE.model_copy(update={"region": "us-east-1"})},
        "capability": {"principal": VIEWER},
    }.get(denial, {})
    executor = RecordingExecutor()
    with pytest.raises(RemediationError):
        harness.request(executor=executor, **options)
    assert executor.submissions == []
    with Session(migrated_engine) as session:
        assert (
            session.scalar(select(func.count()).select_from(Scan)),
            session.scalar(select(func.count()).select_from(AuditEvent)),
        ) == before


def test_replay_namespace_conflict_current_capability_and_three_attempt_bound(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    key = uuid4()
    value = harness.request(key=key).value
    executor = RecordingExecutor()
    replay = harness.request(key=key, executor=executor, scope=VerificationScope())
    assert replay.replayed and replay.value == value and executor.submissions == []
    with pytest.raises(RemediationError) as error:
        harness.request(key=key, reason="Different intent.")
    assert error.value.code == "remediation_idempotency_conflict"
    with pytest.raises(RemediationError) as error:
        harness.request(key=key, principal=VIEWER)
    assert error.value.code == "insufficient_capability"
    for attempt in range(1, 4):
        if attempt > 1:
            value = harness.request().value
        assert value.content.attempt == attempt
        harness.run(value.content.scan_id, read_provider=provider(enabled=False))
    with pytest.raises(RemediationError) as error:
        harness.request()
    assert error.value.code == "remediation_verification_limit"


def test_wrong_scanner_identity_fails_before_any_collection(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    read_provider = provider(enabled=True)
    read_provider.account_id = "999999999999"
    harness.run(value.content.scan_id, read_provider=read_provider)
    assert read_provider.client_requests == []
    receipt = harness.view(value.content.verification_id).receipt
    assert receipt.scan_status is ScanStatus.FAILED and receipt.outcome.value == "INCONCLUSIVE"
    assert receipt.inventory_sha256 is None


def test_disabled_recovery_cannot_construct_provider(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    read_provider = harness.run(value.content.scan_id, allowed=False)
    assert read_provider.client_requests == []
    assert harness.view(value.content.verification_id).receipt.scan_status is ScanStatus.FAILED


def test_submission_failure_seals_receipt_and_replay_never_requeues(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    key = uuid4()
    with pytest.raises(VerificationSubmissionError) as error:
        harness.request(key=key, executor=RecordingExecutor(RuntimeError("synthetic-secret-error")))
    value = harness.view(error.value.verification_id)
    assert value.receipt.scan_status is ScanStatus.FAILED
    assert value.receipt.outcome.value == "INCONCLUSIVE"
    executor = RecordingExecutor()
    replay = harness.request(key=key, executor=executor)
    assert replay.value == value and replay.replayed and not executor.submissions


def test_original_authority_expiry_does_not_deny_observing_acknowledged_write(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    harness.clock.advance(2 * 86400)
    value = harness.request().value
    harness.run(value.content.scan_id)
    assert harness.view(value.content.verification_id).receipt.outcome.value == "VERIFIED"


def test_read_rejects_pending_caller_writes_before_sql_and_preserves_them(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    with Session(migrated_engine) as session:
        finding = session.get(Finding, harness.proposal.content.finding_id)
        finding.status = FindingStatus.ACKNOWLEDGED
        statements = []

        def capture(*args):
            statements.append(args[2])

        event.listen(migrated_engine, "before_cursor_execute", capture)
        try:
            with pytest.raises(RemediationError):
                RemediationVerificationService(session).get_verification(
                    value.content.verification_id, VIEWER
                )
        finally:
            event.remove(migrated_engine, "before_cursor_execute", capture)
        assert not statements and finding in session.dirty and session.in_transaction()


def test_receipt_failure_rolls_back_complete_result_and_findings(migrated_engine, monkeypatch):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    from app.services import remediation_verification_service as implementation

    original = implementation.append_audit_event

    def deny(session, kind, *args, **kwargs):
        if kind is AuditEventType.REMEDIATION_VERIFICATION_COMPLETED:
            raise RuntimeError("injected receipt audit failure")
        return original(session, kind, *args, **kwargs)

    monkeypatch.setattr(implementation, "append_audit_event", deny)
    harness.run(value.content.scan_id)
    with Session(migrated_engine) as session:
        assert session.get(Scan, value.content.scan_id).status is ScanStatus.RUNNING
        assert (
            session.get(Finding, harness.proposal.content.finding_id).status is FindingStatus.OPEN
        )
        assert session.scalar(select(func.count()).select_from(RemediationVerificationReceipt)) == 0
        assert session.scalar(select(func.count()).select_from(RemediationVerification)) == 1
    monkeypatch.setattr(implementation, "append_audit_event", original)
    harness.run(value.content.scan_id)
    assert harness.view(value.content.verification_id).receipt.outcome.value == "VERIFIED"


def test_equal_acknowledgment_observation_is_not_verified(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    harness.clock.advance(-1)
    value = harness.request().value
    harness.run(value.content.scan_id, observe_at=harness.clock())
    receipt = harness.view(value.content.verification_id).receipt
    assert receipt.scan_status is ScanStatus.COMPLETED
    assert receipt.outcome.value == "INCONCLUSIVE"
    assert receipt.reason.value == "OBSERVATION_NOT_LATER"


def test_wrong_provider_region_fails_before_collection(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    read_provider = provider(enabled=True)
    read_provider.region_name = "us-east-1"
    harness.run(value.content.scan_id, read_provider=read_provider)
    assert read_provider.client_requests == []
    assert harness.view(value.content.verification_id).receipt.scan_status is ScanStatus.FAILED


@pytest.mark.parametrize("late_ack", [False, True])
def test_quarantine_is_never_verification_eligibility(migrated_engine, late_ack):
    from app.remediation.worker_contracts import RegionalObservation

    harness = VerificationHarness(migrated_engine, acknowledge=False)
    claim = harness.worker("claim", harness.execution_id)
    assert harness.worker("begin_read", claim)
    assert harness.worker(
        "write_intent",
        claim,
        RegionalObservation(
            encryption_by_default=False,
            default_kms_key_id=None,
            default_kms_key_expected_absence=True,
        ),
        harness.clock(),
    )
    harness.worker("quarantine", harness.execution_id)
    if late_ack:
        harness.worker("acknowledge", claim, "offline-late-receipt")
    with pytest.raises(RemediationError) as error:
        harness.request()
    assert error.value.code == "remediation_verification_ineligible"


def test_acknowledged_write_remains_verifiable_after_revocation(migrated_engine):
    from app.remediation.contracts import RevocationRequest
    from app.services.remediation_service import RemediationService
    from tests.remediation_fixtures import APPROVER

    harness = VerificationHarness(migrated_engine)
    with Session(migrated_engine) as session:
        RemediationService(session, clock=harness.clock).revoke(
            harness.proposal.content.proposal_id,
            RevocationRequest(
                proposal_sha256=harness.proposal.proposal_sha256,
                approval_decision_id=harness.execution_request.approval_decision_id,
                reason="End the old write grant.",
            ),
            APPROVER,
            uuid4(),
        )
    value = harness.request().value
    harness.run(value.content.scan_id)
    assert harness.view(value.content.verification_id).receipt.outcome.value == "VERIFIED"


def test_recovery_resubmits_the_same_durable_scan_identity(migrated_engine):
    from app.services.scan_executor import InProcessScanExecutor

    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    executor = InProcessScanExecutor(session_factory=harness.session_factory)
    submitted = []
    executor.submit = submitted.append
    try:
        assert executor.resume_pending() == 1
        assert submitted == [value.content.scan_id]
    finally:
        executor.shutdown()
    harness.run(value.content.scan_id)
    completed = harness.view(value.content.verification_id)
    harness.run(value.content.scan_id)
    assert harness.view(value.content.verification_id) == completed


def test_collected_account_is_independently_checked_before_result_writes(
    migrated_engine, monkeypatch
):
    from app.models import Resource, ResourceSnapshot
    from app.services.inventory_service import InventoryService

    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    original = InventoryService.collect

    def substituted(self, *, scan_id):
        # Synthetic identity changes only after the executor's provider/STS guard.
        self.client_provider.account_id = "999999999999"
        return original(self, scan_id=scan_id)

    monkeypatch.setattr(InventoryService, "collect", substituted)
    harness.run(value.content.scan_id)
    with Session(migrated_engine) as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(Resource)
                .where(Resource.aws_account_id == "999999999999")
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(ResourceSnapshot)
                .where(ResourceSnapshot.scan_id == value.content.scan_id)
            )
            == 0
        )
    receipt = harness.view(value.content.verification_id).receipt
    assert receipt.scan_status is ScanStatus.FAILED and receipt.inventory_sha256 is None
    assert receipt.outcome.value == "INCONCLUSIVE"
