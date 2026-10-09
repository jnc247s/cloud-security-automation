"""Migration-backed worker contracts; synthetic AWS only, including crash recovery."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditEvent, Finding, Scan
from app.models.enums import AuditEventType, FindingStatus
from app.models.remediation_execution import RemediationWorkerClaim
from app.remediation.contracts import RevocationRequest
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.worker_aws import WorkerAwsCode, WorkerAwsError
from app.remediation.worker_config import WorkerScope
from app.remediation.worker_contracts import (
    RegionalObservation,
    WorkerBlockingReason,
    WorkerEventKind,
    WriteAcknowledgment,
)
from app.remediation.worker_driver import RemediationWorker, WorkerResult
from app.services.errors import RemediationError
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import RemediationService
from app.services.remediation_worker_service import RemediationWorkerService
from tests.execution_fixtures import admit, approved
from tests.remediation_fixtures import APPROVER, NOW, VIEWER, seed
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine

WRITER_SCOPE = WorkerScope(
    enabled=True,
    account_id="123456789012",
    region="us-east-1",
    role_arn="arn:aws:iam::123456789012:role/remediation-writer",
)


class Clock:
    at = NOW
    elapsed = 0.0

    def __call__(self):
        return self.at

    def advance(self, seconds):
        self.at += timedelta(seconds=seconds)
        self.elapsed += seconds


class Harness:
    def __init__(self, engine, *, default_key=None):
        self.engine = engine
        self.clock = Clock()
        self.sessions = []
        source = None
        if default_key is not None:
            source, _ = seed(engine, kms_error={"KmsKeyId": default_key})
        self.proposal, self.request, _ = approved(engine, request=source)
        self.initial = admit(engine, self.proposal, self.request).value
        self.execution_id = self.initial.content.execution_id

    def service(self, method, *args, **kwargs):
        with Session(self.engine) as session:
            return getattr(
                RemediationWorkerService(
                    session,
                    scope=WRITER_SCOPE,
                    clock=self.clock,
                ),
                method,
            )(*args, **kwargs)

    def view(self):
        with Session(self.engine) as session:
            return RemediationExecutionService(session, clock=self.clock).get_execution(
                self.execution_id,
                VIEWER,
            )

    def observation(self, enabled=False, **changes):
        baseline = self.proposal.content.baseline
        return RegionalObservation(
            encryption_by_default=enabled,
            default_kms_key_id=changes.get("key", baseline.default_kms_key_id),
            default_kms_key_expected_absence=changes.get(
                "absent",
                baseline.default_kms_key_expected_absence,
            ),
        )

    def intent(self):
        claim = self.service("claim", self.execution_id)
        assert self.service("begin_read", claim)
        assert self.service("write_intent", claim, self.observation(), self.clock())
        return claim

    def session_factory(self):
        session = Session(self.engine, expire_on_commit=False, autoflush=False)
        self.sessions.append(session)
        return session

    def driver(self, aws):
        def factory(scope):
            assert scope == WRITER_SCOPE
            assert not any(session.in_transaction() for session in self.sessions)
            aws.calls.append("factory")
            return aws

        return RemediationWorker(
            self.session_factory,
            scope=WRITER_SCOPE,
            aws_factory=factory,
            clock=self.clock,
            monotonic=lambda: self.clock.elapsed,
            pause=self.clock.advance,
        )

    def revoke(self):
        with Session(self.engine) as session:
            RemediationService(session, clock=self.clock).revoke(
                self.proposal.content.proposal_id,
                RevocationRequest(
                    proposal_sha256=self.proposal.proposal_sha256,
                    approval_decision_id=self.request.approval_decision_id,
                    reason="Withdraw approved authority.",
                ),
                APPROVER,
                uuid4(),
            )


class FakeWriter:
    def __init__(
        self,
        harness,
        *,
        reads=None,
        write_error=None,
        before_write=None,
        before_read=None,
        identity_error=None,
    ):
        self.harness = harness
        self.reads = list(reads or [harness.observation(), harness.observation(True)])
        self.write_error = write_error
        self.before_write = before_write
        self.before_read = before_read
        self.identity_error = identity_error
        self.calls = []

    def network(self, name):
        assert not any(session.in_transaction() for session in self.harness.sessions)
        self.calls.append(name)

    def verify_identity(self):
        self.network("identity")
        if self.identity_error:
            raise WorkerAwsError(self.identity_error)

    def observe(self):
        self.network("observe")
        if self.before_read:
            self.before_read()
        value = self.reads.pop(0) if len(self.reads) > 1 else self.reads[0]
        if isinstance(value, Exception):
            raise value
        return value

    def enable(self):
        self.network("enable")
        assert self.harness.view().phase is ExecutionPhase.WRITE_INTENT
        if self.before_write:
            self.before_write()
        if self.write_error:
            raise self.write_error
        return WriteAcknowledgment(request_id="synthetic-request-id")

    def close(self):
        self.network("close")


@pytest.fixture
def harness(migrated_engine):
    return Harness(migrated_engine)


def test_success_is_unverified_separate_service_audit_and_no_finding_or_scan_change(harness):
    with Session(harness.engine) as session:
        scans = tuple(session.scalars(select(Scan.scan_id)))
    aws = FakeWriter(harness)
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.ACKNOWLEDGED
    view = harness.view()
    assert view.phase is ExecutionPhase.ACKNOWLEDGED and not view.reservation_held
    assert [e.content.kind.value for e in view.events] == [
        "REQUESTED",
        "CLAIMED",
        "WRITE_INTENT",
        "ACKNOWLEDGED",
        "OBSERVED",
    ]
    assert view.events[0] == harness.initial.events[0]
    assert view.content == harness.initial.content
    assert view.events[-1].content.observation.encryption_by_default is True
    assert aws.calls == ["factory", "identity", "observe", "enable", "identity", "observe", "close"]
    serialized = view.model_dump_json()
    assert (
        "token" not in serialized and "lease" not in serialized and "generation" not in serialized
    )
    with Session(harness.engine) as session:
        assert (
            session.get(Finding, harness.proposal.content.finding_id).status is FindingStatus.OPEN
        )
        assert tuple(session.scalars(select(Scan.scan_id))) == scans
        for entry in view.events[1:]:
            audit = session.get(AuditEvent, entry.audit_event_id)
            assert audit.actor_type == "service"
            assert audit.event_metadata["schema_version"] == "2.0.0"
            assert "capability" not in audit.event_metadata["actor"]
            assert "token" not in str(audit.event_metadata)


@pytest.mark.parametrize("observation", ["true", "changed-key", "absence"])
def test_changed_precondition_never_dispatches_or_claims_success(migrated_engine, observation):
    harness = Harness(
        migrated_engine,
        default_key="approved-present-key" if observation == "absence" else None,
    )
    value = (
        harness.observation(True)
        if observation == "true"
        else harness.observation(key=None, absent=True)
        if observation == "absence"
        else harness.observation(key="different-nonblank-key", absent=False)
    )
    aws = FakeWriter(harness, reads=[value])
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.NO_WRITE
    view = harness.view()
    assert view.phase is ExecutionPhase.NO_WRITE and not view.reservation_held
    assert view.events[-1].content.blocking_reasons == (WorkerBlockingReason.PRECONDITION_CHANGED,)
    assert "enable" not in aws.calls


@pytest.mark.parametrize(
    "code",
    [WorkerAwsCode.SCOPE_MISMATCH, WorkerAwsCode.READ_DENIED, WorkerAwsCode.INCOMPLETE_RESPONSE],
)
def test_permanent_read_failure_has_no_retry_write_or_claimed_effect(harness, code):
    aws = FakeWriter(harness, reads=[WorkerAwsError(code)])
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.NO_WRITE
    assert aws.calls.count("observe") == 1 and "enable" not in aws.calls
    assert not harness.view().reservation_held


def test_transient_precondition_read_budget_is_durable_three_total(harness):
    aws = FakeWriter(harness, reads=[WorkerAwsError(WorkerAwsCode.READ_TRANSIENT)])
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.NO_WRITE
    assert aws.calls.count("observe") == 3 and "enable" not in aws.calls
    with Session(harness.engine) as session:
        assert session.get(RemediationWorkerClaim, harness.execution_id).read_attempts == 3


def test_pre_intent_claim_fencing_and_retry_budget_survive_reclaim(harness):
    old = harness.service("claim", harness.execution_id)
    assert harness.service("begin_read", old)
    assert harness.service("claim", harness.execution_id) is None
    harness.clock.advance(30)
    new = harness.service("claim", harness.execution_id)
    assert new is not None and new.token != old.token
    assert not harness.service("begin_read", old)
    assert not harness.service("write_intent", old, harness.observation(), harness.clock())
    assert harness.service("begin_read", new)
    assert harness.service("begin_read", new)
    assert not harness.service("begin_read", new)
    assert harness.view().phase is ExecutionPhase.NO_WRITE
    with Session(harness.engine) as session:
        claim = session.get(RemediationWorkerClaim, harness.execution_id)
        assert claim.generation == 2 and claim.read_attempts == 3


@pytest.mark.parametrize("when", ["before-claim", "during-read", "after-intent"])
def test_revocation_cutoff_is_intent_commit_not_acknowledgment(harness, when):
    if when == "before-claim":
        harness.revoke()
    aws = FakeWriter(
        harness,
        before_read=harness.revoke if when == "during-read" else None,
        before_write=harness.revoke if when == "after-intent" else None,
    )
    result = harness.driver(aws).run(harness.execution_id)
    if when == "after-intent":
        assert result is WorkerResult.ACKNOWLEDGED and aws.calls.count("enable") == 1
    else:
        assert result is WorkerResult.NO_WRITE and "enable" not in aws.calls
    assert "APPROVAL_REVOKED" in harness.view().blocking_reasons


@pytest.mark.parametrize("seconds", [30, 300])
def test_lease_and_grant_equality_block_intent(harness, seconds):
    claim = harness.service("claim", harness.execution_id)
    harness.clock.advance(seconds)
    assert not harness.service("write_intent", claim, harness.observation(), harness.clock())
    assert all(e.content.kind is not WorkerEventKind.WRITE_INTENT for e in harness.view().events)
    assert harness.view().reservation_held is (seconds == 30)


@pytest.mark.parametrize(
    "error",
    [WorkerAwsError(WorkerAwsCode.WRITE_UNCERTAIN), RuntimeError("synthetic-sensitive-error")],
)
def test_unknown_write_is_sticky_quarantine_even_if_readback_is_true(harness, error):
    aws = FakeWriter(harness, write_error=error)
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.QUARANTINED
    view = harness.view()
    assert view.phase is ExecutionPhase.QUARANTINED and view.reservation_held
    assert view.events[-1].content.observation.encryption_by_default is True
    assert "synthetic-sensitive-error" not in view.model_dump_json()
    assert aws.calls.count("enable") == 1
    harness.clock.advance(600)
    recovery = FakeWriter(harness, reads=[harness.observation(True)])
    assert harness.driver(recovery).run(harness.execution_id) is WorkerResult.QUARANTINED
    assert "enable" not in recovery.calls and harness.view().reservation_held
    assert recovery.calls == []  # The durable thirty-second observation window is over.


def test_crash_during_sdk_call_leaves_intent_and_recovery_never_resends(harness):
    aws = FakeWriter(harness, write_error=SystemExit("synthetic process death"))
    with pytest.raises(SystemExit):
        harness.driver(aws).run(harness.execution_id)
    assert harness.view().phase is ExecutionPhase.WRITE_INTENT
    harness.clock.advance(600)
    recovery = FakeWriter(harness, reads=[harness.observation(True)])
    assert harness.driver(recovery).run(harness.execution_id) is WorkerResult.QUARANTINED
    assert "enable" not in recovery.calls
    assert harness.view().reservation_held


def test_crash_before_sdk_still_never_reclaims_post_intent_and_late_ack_is_sticky(harness):
    claim = harness.intent()
    harness.clock.advance(600)
    assert harness.service("claim", harness.execution_id) is None
    assert harness.service("quarantine", harness.execution_id)
    assert harness.service("acknowledge", claim, "late-original-receipt")
    assert harness.view().phase is ExecutionPhase.QUARANTINED
    assert harness.view().reservation_held
    assert not harness.service("acknowledge", claim, "duplicate-receipt")


def test_readback_budget_and_window_do_not_reset_on_restart(harness):
    claim = harness.intent()
    assert harness.service("acknowledge", claim, "completed-receipt")
    for number in (1, 2, 3):
        budget = harness.service("begin_readback", harness.execution_id)
        assert budget == (number, NOW + timedelta(seconds=30))
        assert harness.service(
            "record_observation",
            harness.execution_id,
            observation=harness.observation(),
            observed_at=harness.clock(),
            polls=number,
        )
    assert harness.service("begin_readback", harness.execution_id) is None
    assert not harness.view().reservation_held


def test_readback_response_after_deadline_is_not_a_desired_observation(harness):
    def slow_read():
        if aws.calls.count("observe") > 1:
            harness.clock.advance(30)

    aws = FakeWriter(harness, before_read=slow_read)
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.ACKNOWLEDGED
    assert harness.view().events[-1].content.kind is WorkerEventKind.OBSERVATION_FAILED
    assert aws.calls.count("observe") == 2


def test_acknowledgment_commit_failure_retains_intent_for_read_only_recovery(harness):
    from app.services import remediation_worker_service as module

    real = module.append_audit_event

    def fault(session, kind, *args, **kwargs):
        if kind is AuditEventType.REMEDIATION_EXECUTION_ACKNOWLEDGED:
            raise RuntimeError("synthetic receipt commit fault")
        return real(session, kind, *args, **kwargs)

    aws = FakeWriter(harness)
    with patch.object(module, "append_audit_event", side_effect=fault), pytest.raises(RuntimeError):
        harness.driver(aws).run(harness.execution_id)
    assert harness.view().phase is ExecutionPhase.WRITE_INTENT
    assert aws.calls.count("enable") == 1
    recovery = FakeWriter(harness, reads=[harness.observation(True)])
    assert harness.driver(recovery).run(harness.execution_id) is WorkerResult.QUARANTINED
    assert "enable" not in recovery.calls and harness.view().reservation_held


@pytest.mark.parametrize("mutation", ["token", "generation", "lease", "intent", "delete"])
def test_database_rejects_post_intent_owner_reclaim_or_erase(harness, mutation):
    harness.intent()
    values = {
        "token": {"token_sha256": "f" * 64},
        "generation": {"generation": 2},
        "lease": {"lease_until": NOW + timedelta(seconds=60)},
        "intent": {"write_intent_event_id": None},
    }
    with Session(harness.engine) as session, pytest.raises(IntegrityError):
        statement = (
            delete(RemediationWorkerClaim)
            if mutation == "delete"
            else update(RemediationWorkerClaim).values(**values[mutation])
        )
        session.execute(
            statement.where(RemediationWorkerClaim.execution_id == harness.execution_id)
        )
        session.commit()
    assert harness.view().phase is ExecutionPhase.WRITE_INTENT


def test_caller_transaction_is_never_rolled_back_or_flushed(harness):
    with Session(harness.engine) as session:
        session.begin()
        pending = AuditEvent(event_id=uuid4())
        session.add(pending)
        service = RemediationWorkerService(session, scope=WRITER_SCOPE, clock=harness.clock)
        with pytest.raises(RemediationError, match="current state"):
            service.claim(harness.execution_id)
        assert session.in_transaction() and pending in session.new
        with session.no_autoflush:
            assert session.scalar(select(func.count()).select_from(RemediationWorkerClaim)) == 0
        assert session.in_transaction() and pending in session.new


def test_disabled_driver_never_constructs_database_or_credentials():
    def forbidden(*args):
        raise AssertionError("No database or AWS construction")

    worker = RemediationWorker(forbidden, scope=WorkerScope(), aws_factory=forbidden)
    assert worker.run(uuid4()) is WorkerResult.DISABLED


def test_late_dispatch_after_committed_intent_never_calls_sdk(harness):
    aws = FakeWriter(harness)
    driver = harness.driver(aws)
    original = driver._db

    def delayed(method, *args, **kwargs):
        value = original(method, *args, **kwargs)
        if method == "write_intent" and value:
            harness.clock.advance(300)
        return value

    driver._db = delayed
    assert driver.run(harness.execution_id) is WorkerResult.QUARANTINED
    assert "enable" not in aws.calls and harness.view().reservation_held
    assert harness.view().events[-1].content.blocking_reasons == (
        WorkerBlockingReason.LATE_DISPATCH,
    )


@pytest.mark.parametrize("key", [None, " approved legacy key with spaces "])
def test_present_and_expected_absence_baselines_remain_supported(migrated_engine, key):
    harness = Harness(migrated_engine, default_key=key)
    aws = FakeWriter(harness)
    assert harness.driver(aws).run(harness.execution_id) is WorkerResult.ACKNOWLEDGED
    assert harness.view().events[2].content.observation.default_kms_key_id == key


def test_observation_older_than_fenced_claim_cannot_create_intent(harness):
    claim = harness.service("claim", harness.execution_id)
    assert harness.service("begin_read", claim)
    with pytest.raises(RemediationError, match="current state"):
        harness.service("write_intent", claim, harness.observation(), NOW - timedelta(seconds=1))
    assert harness.view().phase is ExecutionPhase.CLAIMED


def test_readback_receipt_is_not_duplicated_for_one_durable_poll(harness):
    claim = harness.intent()
    harness.service("acknowledge", claim, "completed-receipt")
    number, _ = harness.service("begin_readback", harness.execution_id)
    assert harness.service(
        "record_observation",
        harness.execution_id,
        observation=harness.observation(True),
        observed_at=NOW,
        polls=number,
    )
    assert not harness.service("record_observation", harness.execution_id, polls=number)
    assert harness.view().events[-1].content.kind is WorkerEventKind.OBSERVED


def test_separate_worker_does_not_load_application_settings():
    with patch("app.config.get_settings", side_effect=AssertionError("No scanner configuration")):
        RemediationWorker(sessionmaker(), scope=WorkerScope())
