"""Signed authority and real worker/SDK fault journeys; every transport is intercepted."""

import json
import os
from collections import deque
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import UUID, uuid4
from xml.sax.saxutils import escape

import pytest
from botocore.awsrequest import AWSResponse
from botocore.client import BaseClient
from botocore.exceptions import ReadTimeoutError
from sqlalchemy import and_, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database import session as database_session
from app.database.base import Base
from app.database.governance import set_finding_disposition
from app.database.integrity import canonical_json_sha256
from app.database.persistence import append_audit_event, persist_scan_result
from app.models import (
    AuditEvent,
    Control,
    ControlAssessment,
    Finding,
    FindingOccurrence,
    RemediationProposal,
    Resource,
    ResourceSnapshot,
)
from app.models.enums import AuditEventType, FindingStatus
from app.models.remediation_execution import (
    RemediationAdmissionGuard,
    RemediationTargetReservation,
    RemediationWorkerClaim,
)
from app.remediation.contracts import (
    ACTION_ID,
    ACTION_VERSION,
    BlockingReason,
    DecisionView,
    ProposalRequest,
)
from app.remediation.execution_contracts import ADMISSION_CAPACITY, ExecutionPhase, ExecutionView
from app.remediation.provenance import utc
from app.remediation.worker_aws import EbsDefaultWriter, _WorkloadSession
from app.remediation.worker_contracts import RegionalObservation, WorkerEventKind
from app.remediation.worker_driver import RemediationWorker, WorkerResult
from app.services import remediation_service as authority_module
from app.services.errors import RemediationError
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import RemediationService
from app.services.remediation_worker_service import RemediationWorkerService
from tests.dashboard_fixtures import dashboard_client, sign_in
from tests.ec2_fixtures import ec2_bundle
from tests.remediation_fixtures import NOW, seed
from tests.worker_http import (
    ACCOUNT,
    REGION,
    SCOPE,
    assert_history,
    database_state,
    history_projection,
    protected_state,
    signed_headers,
)

IDENTITY = "GetCallerIdentity"
ENCRYPTION = "GetEbsEncryptionByDefault"
KEY = "GetEbsDefaultKmsKeyId"
ENABLE = "EnableEbsEncryptionByDefault"
READ_FALSE = ((IDENTITY, "ok"), (ENCRYPTION, False), (KEY, None))
READ_TRUE = ((IDENTITY, "ok"), (ENCRYPTION, True), (KEY, None))
PREINTENT_CASES = (
    "expiry",
    "revoked",
    "governance",
    "newer-assessment",
    "equal-assessment",
    "during-read-revoke",
    "permanent-read",
    "transient-budget",
    "changed-precondition",
)
UNCERTAIN_CASES = ("timeout", "503", "malformed", "invalid-xml")
RECOVERY_CASES = (
    "before-dispatch",
    "during-dispatch",
    "ack-rollback",
    "ack-return-lost",
    "late-dispatch",
)
GUARD_CASES = ("newer-detection", "denial-side-effects")


class DomainClock:
    def __init__(self):
        self.at, self.seconds = NOW, 0.0

    def __call__(self):
        return self.at

    def advance(self, seconds):
        self.at += timedelta(seconds=seconds)
        self.seconds += seconds


class Payload:
    def __init__(self, body):
        self.body = body.encode()

    def stream(self, **_kwargs):
        yield self.body


class SignedFaultJourney:
    def __init__(self, engine, client, issuer, executor, clock, sessions, transport):
        self.engine, self.client, self.issuer = engine, client, issuer
        self.executor, self.clock, self.sessions = executor, clock, sessions
        self.transport = transport
        self.revocation = None
        self.source, _ = seed(engine)
        self.protected = protected_state(database_state(engine))
        self.other_audits = self._other_audits()
        self.initial, self.admission, self.body, self.requester = self.signed_grant(self.source)
        self.execution_id = self.initial.content.execution_id
        self.detail = "/api/v1/remediation-executions/" + str(self.execution_id)
        transport.journey = self
        assert transport.calls == [] and executor.submissions == []

    def signed_grant(self, source, *, expected_status=202):
        before = database_state(self.engine)
        proposal = self.client.post(
            "/api/v1/remediations",
            json=source.model_dump(mode="json"),
            headers=signed_headers(self.issuer, "proposer", "ANALYST"),
        )
        assert proposal.status_code == 201, proposal.text
        proposal = proposal.json()
        route = "/api/v1/remediations/" + proposal["content"]["proposal_id"]
        approval = self.client.post(
            route + "/decisions",
            json={
                "proposal_sha256": proposal["proposal_sha256"],
                "decision": "APPROVE",
                "reason": "Independent review of workload and exact key context.",
            },
            headers=signed_headers(self.issuer, "approver", "APPROVER"),
        )
        assert approval.status_code == 201, approval.text
        body = {
            "proposal_sha256": proposal["proposal_sha256"],
            "approval_decision_id": approval.json()["decision_id"],
            "reason": "Execute the reviewed fixed action.",
        }
        for name, value in {
            "REMEDIATION_ADMISSION_ENABLED": "true",
            "REMEDIATION_ACCOUNT_ID": proposal["content"]["account_id"],
            "REMEDIATION_REGION": REGION,
        }.items():
            self.transport.monkeypatch.setenv(name, value)
        get_settings.cache_clear()
        requester = signed_headers(self.issuer, "requester", "ADMIN")
        admission = route + "/executions"
        before_admission = database_state(self.engine)
        response = self.client.post(admission, json=body, headers=requester)
        assert response.status_code == expected_status, response.text
        after = database_state(self.engine)
        if expected_status != 202:
            assert after == before_admission, "failed admission changed persistence"
        self._authority_delta(before, after, proposal, approval.json(), expected_status == 202)
        if expected_status != 202:
            return response
        assert response.headers["cache-control"] == "no-store"
        initial = ExecutionView.model_validate(response.json())
        assert initial.phase is ExecutionPhase.QUEUED and initial.reservation_held
        assert initial.content.expires_at == min(
            initial.content.proposal.expires_at, self.clock() + timedelta(minutes=5)
        )
        assert len(initial.events) == 1
        assert_history(self.engine, initial, initial, self.issuer)
        return initial, admission, body, requester

    def _authority_delta(self, before, after, proposal, approval, admitted):
        """Permit exact new authority rows, never changed old/protected rows or stray audit."""
        increments = {
            "remediation_proposals": 1,
            "remediation_decisions": 1,
            # Execution admission's idempotency lives in its immutable execution row;
            # only proposal/approval use the separate authority request ledger.
            "remediation_requests": 2,
            "remediation_executions": int(admitted),
            "remediation_execution_events": int(admitted),
            "remediation_target_reservations": int(admitted),
            "audit_events": 2 + int(admitted),
        }
        for name, old_rows in before.items():
            columns = tuple(column.name for column in Base.metadata.tables[name].primary_key)

            def key(row, columns=columns):
                return tuple(getattr(row, column) for column in columns)

            current = {key(row): row for row in after[name]}
            assert all(current.get(key(row)) == row for row in old_rows), (
                "unexpected signed authority persistence changes"
            )
            assert len(after[name]) == len(old_rows) + increments.get(name, 0), (
                f"unexpected signed authority persistence changes in {name}"
            )
        old_ids = {row.event_id for row in before["audit_events"]}
        added = [row for row in after["audit_events"] if row.event_id not in old_ids]
        proposal_id = UUID(proposal["content"]["proposal_id"])
        authorities = [row for row in added if row.target_type == "remediation"]
        assert len(authorities) == 2
        for kind, actor, decision in (
            (AuditEventType.REMEDIATION_PROPOSED, proposal["content"]["proposer"], None),
            (AuditEventType.REMEDIATION_APPROVED, approval["actor"], approval["decision_id"]),
        ):
            matched = [row for row in authorities if row.event_type is kind]
            assert len(matched) == 1
            row = matched[0]
            assert row.target_id == proposal_id and row.actor_type == "human"
            assert row.actor_id == canonical_json_sha256([actor["issuer"], actor["subject"]])
            assert row.metadata == {
                "schema_version": "1.0.0",
                "actor": actor,
                "proposal_id": str(proposal_id),
                "proposal_sha256": proposal["proposal_sha256"],
                "decision_id": decision,
            }
        # Initial authority is our owned history. Later capacity authority is unrelated and
        # must be allowed explicitly, not absorbed by a snapshot after all API operations.
        if hasattr(self, "initial"):
            self.other_audits.update({row.event_id: row for row in added})
            assert self._other_audits() == self.other_audits, "unexpected unrelated audit changes"

    def evidence_fixture(self, before, *, account=ACCOUNT):
        """Advance expectations only immediately after trusted offline scan persistence."""
        assert protected_state(before) == self.protected
        old_audits = {row.event_id: row for row in before["audit_events"]}
        after = database_state(self.engine)
        new_audits = {row.event_id: row for row in after["audit_events"]}
        assert all(new_audits.get(key) == row for key, row in old_audits.items())
        for name, rows in before.items():
            if name.startswith("remediation_"):
                assert after[name] == rows
        old_scans = {row.scan_id for row in before["scans"]}
        new_scans = {row.scan_id for row in after["scans"]} - old_scans
        assert len(new_scans) == 1
        finding_ids = {
            row.finding_id
            for row in after["findings"]
            if row.aws_account_id == account and row.region == REGION
        }
        additions = {key: row for key, row in new_audits.items() if key not in old_audits}
        assert additions and all(
            (row.target_type == "scan" and row.target_id in new_scans)
            or (row.target_type == "finding" and row.target_id in finding_ids)
            for row in additions.values()
        )
        self.protected = protected_state(after)
        self.other_audits.update(additions)
        assert self._other_audits() == self.other_audits, "unexpected unrelated audit changes"

    def expect_governance_audits(self, rows):
        """Only the two actual fixture rows may extend the original unrelated-audit baseline."""
        assert len(rows) == 2
        assert {row.event_type for row in rows} == {
            AuditEventType.FINDING_ACKNOWLEDGED,
            AuditEventType.FINDING_UPDATED,
        }
        assert {tuple(sorted(row.metadata.items())) for row in rows} == {
            tuple(sorted({"previous_status": "OPEN", "status": "ACKNOWLEDGED"}.items())),
            tuple(sorted({"previous_status": "ACKNOWLEDGED", "status": "OPEN"}.items())),
        }
        for row in rows:
            assert row.target_type == "finding" and row.target_id == self.source.finding_id
            assert row.actor_type == "user" and row.actor_id == "offline-risk-owner"
            assert utc(row.timestamp) == self.clock()
            assert row.event_id not in self.other_audits
        self.other_audits.update({row.event_id: row for row in rows})

    def read(self):
        return self.client.get(self.detail, headers=signed_headers(self.issuer, "reader", "VIEWER"))

    def view(self):
        response = self.read()
        history_projection(response)
        return ExecutionView.model_validate(response.json())

    def service(self, name, *args, **kwargs):
        with self.sessions() as session:
            service = RemediationWorkerService(session, scope=SCOPE, clock=self.clock)
            return getattr(service, name)(*args, **kwargs)

    def run(self, script=()):
        assert not self.transport.script
        self.transport.script.extend(script)
        self.transport.started = True
        return RemediationWorker(
            self.sessions,
            scope=SCOPE,
            aws_factory=EbsDefaultWriter.from_ecs,
            clock=self.clock,
            monotonic=lambda: self.clock.seconds,
            pause=self.clock.advance,
        ).run(self.execution_id)

    def revoke(self):
        response = self.client.post(
            self.admission.removesuffix("/executions") + "/revocations",
            json={
                "proposal_sha256": self.initial.content.proposal_sha256,
                "approval_decision_id": str(self.initial.content.approval.decision_id),
                "reason": "Revoke this exact approved authority.",
            },
            headers=signed_headers(self.issuer, "approver", "APPROVER"),
        )
        assert response.status_code == 201, response.text
        self.revocation = DecisionView.model_validate(response.json())

    def _other_audits(self):
        with self.engine.connect() as connection:
            return {
                row.event_id: row
                for row in connection.execute(select(AuditEvent.__table__)).all()
                if not (
                    hasattr(self, "initial")
                    and (
                        (
                            row.target_type == "remediation"
                            and row.target_id == self.initial.content.proposal.proposal_id
                        )
                        or (
                            row.target_type == "remediation_execution"
                            and row.target_id == self.execution_id
                        )
                    )
                )
            }

    def govern(self):
        before = database_state(self.engine)
        with Session(self.engine) as session, session.begin():
            for status in (FindingStatus.ACKNOWLEDGED, FindingStatus.OPEN):
                set_finding_disposition(
                    session,
                    finding_id=self.source.finding_id,
                    status=status,
                    actor_id="offline-risk-owner",
                    at=self.clock(),
                )
        after = database_state(self.engine)
        for table, rows in before.items():
            if table not in {"findings", "audit_events"}:
                assert after[table] == rows
        original = {row.event_id for row in before["audit_events"]}
        added = [row for row in after["audit_events"] if row.event_id not in original]
        assert len(added) == 2
        assert {row.metadata["status"] for row in added} == {"ACKNOWLEDGED", "OPEN"}
        assert all(row.target_id == self.source.finding_id for row in added)
        assert protected_state(after) == self.protected
        self.expect_governance_audits(added)

    def check(self, phase, held):
        assert not self.transport.script, "unconsumed planned transport responses"
        assert not self.transport.violations, "a forbidden I/O or transaction boundary occurred"
        current = self.view()
        assert current.phase is phase and current.reservation_held is held
        assert_history(self.engine, self.initial, current, self.issuer, revocation=self.revocation)
        assert protected_state(database_state(self.engine)) == self.protected
        assert self._other_audits() == self.other_audits, "unexpected unrelated audit changes"
        with Session(self.engine) as session:
            assert session.get(Finding, self.source.finding_id).status is FindingStatus.OPEN
            target = session.scalar(
                select(RemediationTargetReservation).where(
                    RemediationTargetReservation.account_id == ACCOUNT,
                    RemediationTargetReservation.region == REGION,
                )
            )
            assert target.execution_id == (self.execution_id if held else None)
            audits = session.scalars(
                select(AuditEvent).where(
                    AuditEvent.target_type == "remediation_execution",
                    AuditEvent.target_id == self.execution_id,
                )
            ).all()
            assert len(audits) == len(current.events)
        assert self.executor.submissions == []
        assert "offline-provider-sensitive-marker" not in current.model_dump_json()
        return current

    def check_reads_and_replay(self):
        before = database_state(self.engine)
        calls = tuple(self.transport.calls)
        expected = history_projection(self.read())
        assert history_projection(self.read()) == expected
        listed = self.client.get(
            "/api/v1/remediation-executions",
            params={"proposal_id": str(self.initial.content.proposal.proposal_id)},
            headers=signed_headers(self.issuer, "reader", "VIEWER"),
        )
        assert listed.status_code == 200 and listed.headers["cache-control"] == "no-store"
        assert listed.json()["total"] == 1 and len(listed.json()["items"]) == 1
        assert (
            ExecutionView.model_validate(listed.json()["items"][0]).model_dump(
                mode="json", exclude={"validity_checked_at"}
            )
            == expected
        )
        self.transport.monkeypatch.setenv("REMEDIATION_ADMISSION_ENABLED", "false")
        get_settings.cache_clear()
        assert (
            history_projection(
                self.client.post(self.admission, json=self.body, headers=self.requester)
            )
            == expected
        )
        lost = signed_headers(
            self.issuer, "requester", "VIEWER", key=UUID(self.requester["Idempotency-Key"])
        )
        assert self.client.post(self.admission, json=self.body, headers=lost).status_code == 403
        assert (
            self.client.post(
                self.admission, json={**self.body, "reason": "Different"}, headers=self.requester
            ).status_code
            == 409
        )
        assert self.client.get(self.detail).status_code == 401
        for claims in ({"iss": "https://wrong.example.test"}, {"aud": "wrong"}, {"exp": 1}):
            assert (
                self.client.get(
                    self.detail, headers=signed_headers(self.issuer, "reader", "VIEWER", **claims)
                ).status_code
                == 401
            )
        sign_in(self.client, self.issuer)
        assert self.client.get(self.detail).status_code == 401
        assert self.client.post(self.admission, json=self.body).status_code == 401
        assert database_state(self.engine) == before and tuple(self.transport.calls) == calls


@contextmanager
def signed_fault_journey(engine, monkeypatch, tmp_path):
    clock = DomainClock()
    real_init = RemediationService.__init__

    def init(service, session, *, clock=None):
        return real_init(service, session, clock=clock or domain_clock)

    domain_clock = clock
    monkeypatch.setattr(RemediationService, "__init__", init)
    for name in tuple(os.environ):
        if (
            name.upper().startswith(("AWS_", "REMEDIATION_WORKER_"))
            or name.upper() == "BOTO_CONFIG"
        ):
            monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/fault-test")
    state = SimpleNamespace(
        monkeypatch=monkeypatch,
        script=deque(),
        calls=[],
        sessions=[],
        transactions=set(),
        started=False,
        journey=None,
        violations=[],
        on_operation=None,
        after_send=None,
        on_send=None,
        lock_probes=[],
    )

    class TrackedSession(Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            state.sessions.append(self)

    sessions = sessionmaker(
        bind=engine, class_=TrackedSession, autoflush=False, expire_on_commit=False
    )

    def begin(connection):
        state.transactions.add(id(connection))

    def end(connection):
        state.transactions.discard(id(connection))

    def boundary(label):
        try:
            assert state.started, "API must not start a worker or provider"
            assert not state.transactions
            assert not any(session.in_transaction() for session in state.sessions)
            if engine.dialect.name == "postgresql":
                intent = state.journey.initial.content.proposal
                with Session(engine) as probe, probe.begin():
                    for model, predicate in (
                        (RemediationAdmissionGuard, RemediationAdmissionGuard.guard_id == 1),
                        (Resource, Resource.resource_id == intent.resource_id),
                        (Finding, Finding.finding_id == intent.finding_id),
                        (
                            RemediationProposal,
                            RemediationProposal.proposal_id == intent.proposal_id,
                        ),
                        (
                            RemediationTargetReservation,
                            and_(
                                RemediationTargetReservation.account_id == ACCOUNT,
                                RemediationTargetReservation.region == REGION,
                                RemediationTargetReservation.action_id == intent.action_id,
                            ),
                        ),
                        (
                            RemediationWorkerClaim,
                            RemediationWorkerClaim.execution_id == state.journey.execution_id,
                        ),
                    ):
                        assert probe.scalar(
                            select(model).where(predicate).with_for_update(nowait=True)
                        )
                state.lock_probes.append(label)
            state.calls.append(label)
        except BaseException:
            state.violations.append(label)
            raise

    def capture(model, params, **_kwargs):
        boundary("sdk:" + model.name)
        assert params == {}
        if model.name == ENABLE:
            current = state.journey.view()
            assert current.phase is ExecutionPhase.WRITE_INTENT and current.reservation_held
            entry = current.events[-1]
            assert entry.content.kind is WorkerEventKind.WRITE_INTENT
            with Session(engine) as session:
                audit = session.get(AuditEvent, entry.audit_event_id)
                assert audit.actor_type == "service"
                assert audit.event_metadata["event_sha256"] == entry.event_sha256
        if state.on_operation:
            state.on_operation(model.name)

    def send(_transport, request, **_kwargs):
        if request.url == "http://169.254.170.2/v2/credentials/fault-test":
            boundary("metadata")
            assert request.method == "GET"
            return SimpleNamespace(
                status_code=200,
                content=json.dumps(
                    {
                        "AccessKeyId": "offline-test-access-key",
                        "SecretAccessKey": "offline-test-secret-key",
                        "Token": "offline-test-session-token",
                        "Expiration": "2099-01-01T00:00:00Z",
                    }
                ).encode(),
            )
        try:
            assert request.method == "POST"
            assert request.url in {
                f"https://sts.{REGION}.amazonaws.com/",
                f"https://ec2.{REGION}.amazonaws.com/",
            }
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            action = parse_qs(body)["Action"][0]
            boundary("wire:" + action)
            assert state.script, "unexpected transport attempt"
            expected, response = state.script.popleft()
            assert action == expected
        except BaseException:
            state.violations.append("unplanned-transport")
            raise
        if state.on_send:
            state.on_send(action)
        if response == "death":
            raise SystemExit("synthetic process death")
        if response == "timeout":
            raise ReadTimeoutError(endpoint_url=request.url)
        code = 200
        if response in {"503", "denied", "transient"}:
            code = 503 if response == "503" else 400
            error = {
                "503": "ServiceUnavailable",
                "denied": "AccessDenied",
                "transient": "Throttling",
            }[response]
            xml = (
                f"<Response><Errors><Error><Code>{error}</Code>"
                "<Message>offline-provider-sensitive-marker</Message></Error></Errors>"
                "<RequestID>offline-error</RequestID></Response>"
            )
        elif response == "invalid-xml":
            xml = "<broken-offline-receipt"
        elif action == IDENTITY:
            xml = (
                "<GetCallerIdentityResponse xmlns='https://sts.amazonaws.com/doc/2011-06-15/'>"
                "<GetCallerIdentityResult><UserId>ROLEID:offline-test</UserId>"
                f"<Account>{ACCOUNT}</Account><Arn>arn:aws:sts::{ACCOUNT}:assumed-role/"
                "remediation-worker/offline-test</Arn></GetCallerIdentityResult>"
                "<ResponseMetadata><RequestId>offline-identity</RequestId></ResponseMetadata>"
                "</GetCallerIdentityResponse>"
            )
        else:
            field = (
                (f"<kmsKeyId>{escape(response)}</kmsKeyId>" if response is not None else "")
                if action == KEY
                else (
                    "<ebsEncryptionByDefault>false</ebsEncryptionByDefault>"
                    if response == "malformed"
                    else f"<ebsEncryptionByDefault>{str(response).lower()}</ebsEncryptionByDefault>"
                )
            )
            xml = (
                f"<{action}Response xmlns='http://ec2.amazonaws.com/doc/2016-11-15/'>"
                f"<requestId>offline-write-receipt</requestId>{field}</{action}Response>"
            )
        result = AWSResponse(request.url, code, {"content-type": "text/xml"}, Payload(xml))
        if state.after_send:
            state.after_send(action)
        return result

    real_create, real_close = _WorkloadSession.create_client, BaseClient.close
    real_worker_init = RemediationWorker.__init__

    def worker_init(worker, *args, **kwargs):
        if not state.started:
            state.violations.append("api-worker-construction")
            raise AssertionError("API must not construct a worker")
        return real_worker_init(worker, *args, **kwargs)

    def create_client(session, name, **kwargs):
        boundary("client:" + name)
        sdk = real_create(session, name, **kwargs)
        assert name in {"sts", "ec2"} and sdk.meta.region_name == REGION
        assert sdk.meta.endpoint_url == f"https://{name}.{REGION}.amazonaws.com"
        assert sdk.meta.config.retries == {"mode": "standard", "total_max_attempts": 1}
        assert (sdk.meta.config.connect_timeout, sdk.meta.config.read_timeout) == (2, 5)
        sdk.meta.events.register("before-parameter-build.*.*", capture)
        return sdk

    def close(sdk):
        boundary("close:" + sdk.meta.service_model.service_name)
        return real_close(sdk)

    def forbidden(*_args, **_kwargs):
        state.violations.append("host-configuration")
        raise AssertionError("host AWS configuration is forbidden")

    monkeypatch.setattr("botocore.httpsession.URLLib3Session.send", send)
    monkeypatch.setattr("botocore.configloader.load_config", forbidden)
    monkeypatch.setattr("botocore.configloader.raw_config_parse", forbidden)
    monkeypatch.setattr(_WorkloadSession, "create_client", create_client)
    monkeypatch.setattr(BaseClient, "close", close)
    monkeypatch.setattr(RemediationWorker, "__init__", worker_init)
    for name, callback in (("begin", begin), ("commit", end), ("rollback", end)):
        event.listen(engine, name, callback)
    try:
        with dashboard_client(engine, monkeypatch, tmp_path) as (
            client,
            issuer,
            _browser,
            executor,
        ):
            monkeypatch.setattr(database_session, "SessionLocal", sessions)
            journey = SignedFaultJourney(engine, client, issuer, executor, clock, sessions, state)
            yield journey
            assert not state.script and not state.violations
            assert not state.transactions and not any(s.in_transaction() for s in state.sessions)
    finally:
        for name, callback in (("begin", begin), ("commit", end), ("rollback", end)):
            event.remove(engine, name, callback)


def false_observation():
    return RegionalObservation(
        encryption_by_default=False, default_kms_key_id=None, default_kms_key_expected_absence=True
    )


def exercise_preintent(engine, monkeypatch, tmp_path, case):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:
        script = ()
        if case == "expiry":
            journey.clock.advance(300)
        elif case == "revoked":
            journey.revoke()
        elif case == "governance":
            journey.govern()
        elif case in {"newer-assessment", "equal-assessment"}:
            baseline_at = journey.initial.content.proposal.baseline.observed_at
            observed = baseline_at + timedelta(seconds=1 if case == "newer-assessment" else 0)
            with monkeypatch.context() as fixture_patch:
                fixture_patch.setattr("tests.ec2_fixtures.OBSERVED", observed)
                bundle = ec2_bundle()
            before_fixture = database_state(engine)
            with Session(engine) as session, session.begin():
                persist_scan_result(session, **bundle)
            with Session(engine) as session:
                snapshot = session.scalar(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == bundle["snapshot"].scan_id,
                        ResourceSnapshot.resource_id
                        == journey.initial.content.proposal.resource_id,
                    )
                )
                assert utc(snapshot.observed_at) == observed
                assert (utc(snapshot.observed_at) > baseline_at) is (case == "newer-assessment")
            journey.evidence_fixture(before_fixture)
            assert BlockingReason.STALE_TARGET in journey.view().blocking_reasons, (
                "expected STALE_TARGET after strictly newer evidence"
                if case == "newer-assessment"
                else "expected STALE_TARGET after equal-time evidence"
            )
        elif case == "during-read-revoke":
            script = READ_FALSE

            def revoke(action):
                if action == KEY:
                    journey.revoke()

            journey.transport.after_send = revoke
        elif case == "permanent-read":
            script = ((IDENTITY, "ok"), (ENCRYPTION, "denied"))
        elif case == "transient-budget":
            script = ((IDENTITY, "ok"), (ENCRYPTION, "transient")) * 3
        elif case == "changed-precondition":
            script = ((IDENTITY, "ok"), (ENCRYPTION, True), (KEY, None))
        else:
            raise AssertionError("unknown fault case")
        assert journey.run(script) is WorkerResult.NO_WRITE
        current = journey.check(ExecutionPhase.NO_WRITE, False)
        assert "sdk:" + ENABLE not in journey.transport.calls
        assert "wire:" + ENABLE not in journey.transport.calls
        if not script:
            assert journey.transport.calls == []
        with Session(engine) as session:
            claim = session.get(RemediationWorkerClaim, journey.execution_id)
            assert (claim.read_attempts if claim else 0) == (
                3 if case == "transient-budget" else int(bool(script))
            )
        assert current.events[-1].content.blocking_reasons
        if case in {"newer-assessment", "equal-assessment"}:
            assert BlockingReason.STALE_TARGET in current.events[-1].content.blocking_reasons
        journey.check_reads_and_replay()


def exercise_uncertain(engine, monkeypatch, tmp_path, case):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:
        assert journey.run((*READ_FALSE, (ENABLE, case), *READ_TRUE)) is WorkerResult.QUARANTINED
        current = journey.check(ExecutionPhase.QUARANTINED, True)
        assert current.events[-1].content.observation.encryption_by_default is True
        assert [e.content.kind.value for e in current.events] == [
            "REQUESTED",
            "CLAIMED",
            "WRITE_INTENT",
            "QUARANTINED",
            "OBSERVED",
        ]
        assert journey.transport.calls.count("sdk:" + ENABLE) == 1
        assert journey.transport.calls.count("wire:" + ENABLE) == 1
        journey.clock.advance(600)
        calls = tuple(journey.transport.calls)
        assert journey.run() is WorkerResult.QUARANTINED
        assert tuple(journey.transport.calls) == calls
        assert journey.service("claim", journey.execution_id) is None
        journey.check(ExecutionPhase.QUARANTINED, True)
        journey.check_reads_and_replay()


def exercise_recovery(engine, monkeypatch, tmp_path, case):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:
        token = []
        real_intent = RemediationWorkerService.write_intent

        def intent(service, claim, *args, **kwargs):
            result = real_intent(service, claim, *args, **kwargs)
            assert result
            token.append(claim)
            if case == "before-dispatch":
                raise SystemExit("synthetic post-intent death")
            if case == "late-dispatch":
                journey.clock.advance(300)
            return result

        monkeypatch.setattr(RemediationWorkerService, "write_intent", intent)
        script = (*READ_FALSE, (ENABLE, "death")) if case == "during-dispatch" else READ_FALSE
        if case == "ack-rollback":
            real_append = RemediationWorkerService._append

            def append(service, *args, **kwargs):
                result = real_append(service, *args, **kwargs)
                if args[2] is WorkerEventKind.ACKNOWLEDGED:
                    raise RuntimeError("synthetic acknowledgment rollback")
                return result

            monkeypatch.setattr(RemediationWorkerService, "_append", append)
            script = (*READ_FALSE, (ENABLE, True))
        if case == "ack-return-lost":
            real_ack = RemediationWorkerService.acknowledge

            def lost_return(service, *args, **kwargs):
                assert real_ack(service, *args, **kwargs)
                raise RuntimeError("synthetic lost committed acknowledgment return")

            monkeypatch.setattr(RemediationWorkerService, "acknowledge", lost_return)
            script = (*READ_FALSE, (ENABLE, True))
        if case == "late-dispatch":
            assert journey.run(script) is WorkerResult.QUARANTINED
        else:
            with pytest.raises(
                RuntimeError if case in {"ack-rollback", "ack-return-lost"} else SystemExit
            ):
                journey.run(script)
        monkeypatch.setattr(RemediationWorkerService, "write_intent", real_intent)
        if case == "ack-rollback":
            monkeypatch.setattr(RemediationWorkerService, "_append", real_append)
        if case == "ack-return-lost":
            monkeypatch.setattr(RemediationWorkerService, "acknowledge", real_ack)
            journey.check(ExecutionPhase.ACKNOWLEDGED, False)
            journey.clock.advance(600)
            assert journey.run(READ_TRUE) is WorkerResult.ACKNOWLEDGED
            assert journey.service("claim", journey.execution_id) is None
            assert not journey.service("acknowledge", token[0], "duplicate-receipt")
            journey.check(ExecutionPhase.ACKNOWLEDGED, False)
            assert journey.transport.calls.count("sdk:" + ENABLE) == 1
            assert journey.transport.calls.count("wire:" + ENABLE) == 1
            journey.check_reads_and_replay()
            return
        phase = (
            ExecutionPhase.QUARANTINED if case == "late-dispatch" else ExecutionPhase.WRITE_INTENT
        )
        journey.check(phase, True)
        journey.clock.advance(600)
        assert journey.run(READ_TRUE) is WorkerResult.QUARANTINED
        assert journey.service("claim", journey.execution_id) is None
        assert journey.service("acknowledge", token[0], "late-original-receipt")
        assert not journey.service("acknowledge", token[0], "duplicate-receipt")
        current = journey.check(ExecutionPhase.QUARANTINED, True)
        assert current.events[-1].content.kind is WorkerEventKind.ACKNOWLEDGED
        attempts = int(case in {"during-dispatch", "ack-rollback"})
        assert journey.transport.calls.count("sdk:" + ENABLE) == attempts
        assert journey.transport.calls.count("wire:" + ENABLE) == attempts
        with Session(engine) as session:
            claim = session.get(RemediationWorkerClaim, journey.execution_id)
            assert claim.generation == 1 and claim.read_attempts == 1
            assert claim.write_intent_event_id is not None
        journey.check_reads_and_replay()


def exercise_reclaim(engine, monkeypatch, tmp_path):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:
        first = journey.service("claim", journey.execution_id)
        assert first and journey.service("begin_read", first)
        assert journey.service("claim", journey.execution_id) is None
        journey.clock.advance(30)
        second = journey.service("claim", journey.execution_id)
        assert second and second.token != first.token
        assert not journey.service("begin_read", first)
        assert not journey.service("write_intent", first, false_observation(), journey.clock())
        assert not journey.service("acknowledge", first, "old-owner-receipt")
        assert journey.service("begin_read", second)
        assert journey.service("begin_read", second)
        journey.clock.advance(30)
        assert journey.run() is WorkerResult.NO_WRITE
        current = journey.check(ExecutionPhase.NO_WRITE, False)
        assert current.events[-1].content.blocking_reasons[0].value == "READ_BUDGET_EXHAUSTED"
        with Session(engine) as session:
            claim = session.get(RemediationWorkerClaim, journey.execution_id)
            assert claim.generation == 2 and claim.read_attempts == 3
        assert journey.transport.calls == []
        journey.check_reads_and_replay()


def exercise_readback(engine, monkeypatch, tmp_path, *, late=False):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:
        assert (
            journey.run((*READ_FALSE, (ENABLE, "timeout"), (IDENTITY, "denied")))
            is WorkerResult.QUARANTINED
        )
        with Session(engine) as session:
            original = utc(
                session.get(RemediationWorkerClaim, journey.execution_id).readback_started_at
            )
        if late:

            def delayed(action):
                if action == KEY:
                    journey.clock.advance(30)

            journey.transport.after_send = delayed
            assert journey.run(READ_TRUE) is WorkerResult.QUARANTINED
            assert journey.view().events[-1].content.kind is WorkerEventKind.OBSERVATION_FAILED
        else:
            for _ in (2, 3):
                assert journey.run(((IDENTITY, "denied"),)) is WorkerResult.QUARANTINED
            assert [
                e.content.polls
                for e in journey.view().events
                if e.content.schema_version == "2.0.0" and e.content.polls
            ] == [1, 2, 3]
        assert journey.service("begin_readback", journey.execution_id) is None
        calls = tuple(journey.transport.calls)
        assert journey.run() is WorkerResult.QUARANTINED
        assert tuple(journey.transport.calls) == calls
        assert not journey.service("record_observation", journey.execution_id, polls=1)
        current = journey.check(ExecutionPhase.QUARANTINED, True)
        with Session(engine) as session:
            claim = session.get(RemediationWorkerClaim, journey.execution_id)
            assert utc(claim.readback_started_at) == original
            assert claim.readback_attempts == (2 if late else 3)
        assert journey.transport.calls.count("wire:" + ENABLE) == 1
        assert not any(
            e.content.schema_version == "2.0.0"
            and e.content.observation
            and e.content.observation.encryption_by_default is True
            for e in current.events
        )
        journey.check_reads_and_replay()


def exercise_after_intent_revoke(engine, monkeypatch, tmp_path):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:

        def revoke(action):
            if action == ENABLE:
                journey.revoke()

        journey.transport.on_operation = revoke
        assert journey.run((*READ_FALSE, (ENABLE, True), *READ_TRUE)) is WorkerResult.ACKNOWLEDGED
        current = journey.check(ExecutionPhase.ACKNOWLEDGED, False)
        assert "APPROVAL_REVOKED" in {reason.value for reason in current.blocking_reasons}
        assert journey.transport.calls.count("wire:" + ENABLE) == 1
        journey.check_reads_and_replay()


def source_for_account(engine, account):
    """Trusted offline evidence only; every human authority is still created via signed HTTP."""
    bundle = ec2_bundle(account=account)
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        finding = session.scalar(
            select(Finding)
            .join(Control)
            .where(
                Control.control_key == "EC2-004",
                Finding.aws_account_id == account,
                Finding.region == REGION,
            )
        )
        occurrence = session.scalar(
            select(FindingOccurrence).where(
                FindingOccurrence.finding_id == finding.finding_id,
                FindingOccurrence.scan_id == bundle["snapshot"].scan_id,
            )
        )
        return ProposalRequest(
            finding_id=finding.finding_id,
            occurrence_id=occurrence.occurrence_id,
            action_id=ACTION_ID,
            action_version=ACTION_VERSION,
            reason="Reviewed offline capacity target.",
        )


def exercise_capacity(engine, monkeypatch, tmp_path):
    with signed_fault_journey(engine, monkeypatch, tmp_path) as journey:
        assert ADMISSION_CAPACITY == 32
        assert (
            journey.run((*READ_FALSE, (ENABLE, "timeout"), *READ_TRUE)) is WorkerResult.QUARANTINED
        )
        journey.clock.advance(600)
        journey.check(ExecutionPhase.QUARANTINED, True)
        calls = tuple(journey.transport.calls)
        # The same signed target remains busy after expiry; no TTL reap of possible effect.
        conflict = journey.signed_grant(journey.source, expected_status=409)
        assert conflict.json()["detail"]["code"] == "remediation_execution_target_reserved"
        for number in range(ADMISSION_CAPACITY - 1):
            account = f"{100000000000 + number:012d}"
            before_fixture = database_state(engine)
            source = source_for_account(engine, account)
            journey.evidence_fixture(before_fixture, account=account)
            journey.signed_grant(source)
        before_fixture = database_state(engine)
        source = source_for_account(engine, "999999999999")
        journey.evidence_fixture(before_fixture, account="999999999999")
        before = database_state(engine)
        denied = journey.signed_grant(source, expected_status=503)
        assert denied.json()["detail"]["code"] == "remediation_execution_capacity"
        after = database_state(engine)
        # Proposal/approval are deliberately created, but failed admission adds nothing.
        for table in (
            "remediation_executions",
            "remediation_execution_events",
            "remediation_target_reservations",
            "remediation_worker_claims",
        ):
            assert after[table] == before[table]
        assert (
            sum(row.execution_id is not None for row in after["remediation_target_reservations"])
            == 32
        )
        journey.check(ExecutionPhase.QUARANTINED, True)
        assert tuple(journey.transport.calls) == calls
        journey.check_reads_and_replay()


def exercise_guard_rejection(engine, monkeypatch, tmp_path, case):
    """Negative regressions: bad runtime effects must make the acceptance helper fail."""
    if case == "newer-detection":

        def equal_only(session, finding, baseline):
            return (
                session.scalar(
                    select(ControlAssessment.assessment_id)
                    .join(
                        ResourceSnapshot,
                        ResourceSnapshot.snapshot_id == ControlAssessment.resource_snapshot_id,
                    )
                    .where(
                        ControlAssessment.resource_id == finding.resource_id,
                        ControlAssessment.control_id == finding.control_id,
                        ControlAssessment.assessment_id != baseline.assessment_id,
                        ResourceSnapshot.observed_at == baseline.observed_at,
                    )
                    .limit(1)
                )
                is not None
            )

        monkeypatch.setattr(authority_module, "has_newer_assessment", equal_only)
        with pytest.raises(
            AssertionError, match="expected STALE_TARGET after strictly newer evidence"
        ):
            exercise_preintent(engine, monkeypatch, tmp_path, "newer-assessment")
    elif case == "denial-side-effects":
        original = RemediationExecutionService.admit

        def bad_denial(service, *args, **kwargs):
            try:
                return original(service, *args, **kwargs)
            except RemediationError as error:
                if error.code == "remediation_execution_capacity":
                    with Session(engine) as session, session.begin():
                        finding = session.scalar(
                            select(Finding)
                            .join(Control)
                            .where(
                                Finding.aws_account_id == ACCOUNT,
                                Control.control_key == "EC2-004",
                            )
                        )
                        finding.last_detected_at = utc(finding.last_detected_at) + timedelta(
                            seconds=1
                        )
                        append_audit_event(
                            session,
                            AuditEventType.SCAN_STARTED,
                            "scan",
                            uuid4(),
                            service.authority._now(),
                            actor_type="service",
                            actor_id="unexpected-worker",
                            metadata={"probe": True},
                        )
                raise

        monkeypatch.setattr(RemediationExecutionService, "admit", bad_denial)
        with pytest.raises(AssertionError, match="failed admission changed persistence"):
            exercise_capacity(engine, monkeypatch, tmp_path)
    else:
        raise AssertionError("unknown guard probe")
