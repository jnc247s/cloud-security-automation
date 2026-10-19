"""Signed authority -> real database/worker/adapter -> READ; all provider I/O is synthetic."""

import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import jwt
from botocore.client import BaseClient
from botocore.stub import Stubber
from sqlalchemy import and_, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database import session as database_session
from app.database.base import Base
from app.database.integrity import canonical_json_sha256
from app.models import AuditEvent, Finding, RemediationProposal, Resource
from app.models.enums import AuditEventType, FindingStatus
from app.models.remediation_execution import (
    RemediationAdmissionGuard,
    RemediationTargetReservation,
    RemediationWorkerClaim,
)
from app.remediation.execution_contracts import ExecutionPhase, ExecutionView
from app.remediation.worker_aws import EbsDefaultWriter, _WorkloadSession
from app.remediation.worker_config import WorkerScope
from app.remediation.worker_driver import RemediationWorker, WorkerResult
from tests.dashboard_fixtures import AUDIENCE, dashboard_client, sign_in
from tests.remediation_fixtures import seed

ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/security/remediation-worker"
SCOPE = WorkerScope(enabled=True, account_id=ACCOUNT, region=REGION, role_arn=ROLE)
METADATA = {"HTTPStatusCode": 200, "RequestId": "offline-reviewed-write-1"}
CASES = (
    ("acknowledged", None),
    ("acknowledged", f"arn:aws:kms:{REGION}:{ACCOUNT}:key/existing-key"),
    ("acknowledged", " legacy non-ARN key id "),
    ("already-enabled", None),
    ("changed-key", "reviewed-key"),
    ("missing-key", "reviewed-key"),
    ("unexpected-key", None),
)
_AUTHORITY_TABLES = {
    "remediation_proposals",
    "remediation_decisions",
    "remediation_requests",
    "remediation_executions",
    "remediation_execution_events",
    "remediation_admission_guard",
    "remediation_target_reservations",
    "remediation_worker_claims",
}


def database_state(engine):
    """Compare complete persisted values, not just finding/count summaries."""
    with engine.connect() as connection:
        return {
            table.name: tuple(connection.execute(select(table).order_by(*table.primary_key)).all())
            for table in Base.metadata.sorted_tables
        }


def protected_state(state):
    return {
        name: rows
        for name, rows in state.items()
        if name not in _AUTHORITY_TABLES and name != "audit_events"
    }


def signed_headers(issuer, subject, role, *, key=None, **overrides):
    token = jwt.encode(
        {
            "iss": issuer.issuer,
            "aud": AUDIENCE,
            "sub": subject,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "cognito:groups": [role],
            **overrides,
        },
        issuer.key,
        algorithm="RS256",
        headers={"kid": "dashboard-test"},
    )
    return {"Authorization": "Bearer " + token, "Idempotency-Key": str(key or uuid4())}


def history_projection(response):
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    value = ExecutionView.model_validate(response.json())
    # Only this derived time changes between otherwise identical authorized reads/replays.
    return value.model_dump(mode="json", exclude={"validity_checked_at"})


@contextmanager
def offline_worker_boundary(engine, monkeypatch, *, outcome, baseline_key):
    """Retain actual factory/SDK/SQL behavior; forbid every unplanned transport or host file."""
    for name in tuple(os.environ):
        if (
            name.upper().startswith(("AWS_", "REMEDIATION_WORKER_"))
            or name.upper() == "BOTO_CONFIG"
        ):
            monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/offline-test")
    calls, sessions, transactions, stubbers = [], [], set(), []
    state = SimpleNamespace(started=False, execution=None, enable_receipt_checks=0, lock_probes=[])

    class TrackedSession(Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            sessions.append(self)

    session_factory = sessionmaker(
        bind=engine, class_=TrackedSession, autoflush=False, expire_on_commit=False
    )

    def begin(connection):
        transactions.add(id(connection))

    def end(connection):
        transactions.discard(id(connection))

    def quiescent():
        assert not transactions, "an engine transaction spans provider/AWS I/O"
        assert not any(session.in_transaction() for session in sessions)

    def boundary(label):
        assert state.started, "API/admission must not construct or invoke a worker/provider"
        quiescent()
        # Real, separate-session NOWAIT probes prove the complete worker lock set is free.
        # SQLite's shared in-memory connection is not evidence of PostgreSQL lock behavior.
        if engine.dialect.name == "postgresql":
            intent = state.execution.content.proposal
            with Session(engine) as probe, probe.begin():
                for model, predicate in (
                    (RemediationAdmissionGuard, RemediationAdmissionGuard.guard_id == 1),
                    (Resource, Resource.resource_id == intent.resource_id),
                    (Finding, Finding.finding_id == intent.finding_id),
                    (RemediationProposal, RemediationProposal.proposal_id == intent.proposal_id),
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
                        RemediationWorkerClaim.execution_id == state.execution.content.execution_id,
                    ),
                ):
                    assert probe.scalar(select(model).where(predicate).with_for_update(nowait=True))
            state.lock_probes.append(label)
        quiescent()
        calls.append(label)

    payload = json.dumps(
        {
            "AccessKeyId": "offline-test-access-key",
            "SecretAccessKey": "offline-test-secret-key",
            "Token": "offline-test-session-token",
            "Expiration": "2099-01-01T00:00:00Z",
        }
    ).encode()

    def send(_transport, request, **kwargs):
        # STS/EC2 must be intercepted by Stubber; this is the only permitted metadata I/O.
        assert request.url == "http://169.254.170.2/v2/credentials/offline-test"
        assert request.method == "GET"
        boundary("metadata")
        return SimpleNamespace(status_code=200, content=payload)

    def forbidden_file(*args, **kwargs):
        raise AssertionError("worker must not read host AWS profiles/configuration")

    def capture(model, params, **kwargs):
        assert params == {}, "caller-selected AWS parameters are forbidden"
        boundary(model.name)
        if model.name == "EnableEbsEncryptionByDefault":
            # READ uses its real provenance/journal/audit validator and a separate HTTP session.
            current = ExecutionView.model_validate(state.read().json())
            assert current.phase is ExecutionPhase.WRITE_INTENT and current.reservation_held
            assert current.events[-1].content.kind.value == "WRITE_INTENT"
            assert current.events[-1].content.observation.encryption_by_default is False
            assert current.events[-1].content.actor.expected_role_arn == ROLE
            with Session(engine) as receipt:
                audit = receipt.get(AuditEvent, current.events[-1].audit_event_id)
                assert audit.actor_type == "service"
                assert audit.event_metadata["event_sha256"] == current.events[-1].event_sha256
            state.enable_receipt_checks += 1
            quiescent()

    real_create_client = _WorkloadSession.create_client

    def create_client(session, service_name, **kwargs):
        assert service_name in {"sts", "ec2"}
        boundary("client:" + service_name)
        sdk = real_create_client(session, service_name, **kwargs)
        assert sdk.meta.region_name == REGION
        assert sdk.meta.endpoint_url == f"https://{service_name}.{REGION}.amazonaws.com"
        assert sdk.meta.config.retries == {"mode": "standard", "total_max_attempts": 1}
        assert sdk.meta.config.connect_timeout == 2 and sdk.meta.config.read_timeout == 5
        sdk.meta.events.register("before-parameter-build.*.*", capture)
        stubber = Stubber(sdk)
        if service_name == "sts":
            for _ in range(2 if outcome == "acknowledged" else 1):
                stubber.add_response(
                    "get_caller_identity",
                    {
                        "Account": ACCOUNT,
                        "Arn": (
                            f"arn:aws:sts::{ACCOUNT}:assumed-role/remediation-worker/offline-test"
                        ),
                        "UserId": "ROLEID:offline-test",
                        "ResponseMetadata": METADATA,
                    },
                    {},
                )
        else:
            observed_key = baseline_key
            if outcome in {"changed-key", "unexpected-key"}:
                observed_key = "unreviewed-key"
            elif outcome == "missing-key":
                observed_key = None
            stubber.add_response(
                "get_ebs_encryption_by_default",
                {
                    "EbsEncryptionByDefault": outcome == "already-enabled",
                    "ResponseMetadata": METADATA,
                },
                {},
            )
            stubber.add_response(
                "get_ebs_default_kms_key_id",
                {"KmsKeyId": observed_key, "ResponseMetadata": METADATA}
                if observed_key is not None
                else {"ResponseMetadata": METADATA},
                {},
            )
            if outcome == "acknowledged":
                stubber.add_response(
                    "enable_ebs_encryption_by_default",
                    {"EbsEncryptionByDefault": True, "ResponseMetadata": METADATA},
                    {},
                )
                stubber.add_response(
                    "get_ebs_encryption_by_default",
                    {"EbsEncryptionByDefault": True, "ResponseMetadata": METADATA},
                    {},
                )
                stubber.add_response(
                    "get_ebs_default_kms_key_id",
                    {"KmsKeyId": baseline_key, "ResponseMetadata": METADATA}
                    if baseline_key is not None
                    else {"ResponseMetadata": METADATA},
                    {},
                )
        stubber.activate()
        stubbers.append(stubber)
        return sdk

    real_close = BaseClient.close

    def close(sdk):
        boundary("close:" + sdk.meta.service_model.service_name)
        return real_close(sdk)

    real_worker_init = RemediationWorker.__init__

    def worker_init(worker, *args, **kwargs):
        assert state.started, "API/admission must not construct remediation orchestration"
        return real_worker_init(worker, *args, **kwargs)

    monkeypatch.setattr("botocore.httpsession.URLLib3Session.send", send)
    monkeypatch.setattr("botocore.configloader.load_config", forbidden_file)
    monkeypatch.setattr("botocore.configloader.raw_config_parse", forbidden_file)
    monkeypatch.setattr(_WorkloadSession, "create_client", create_client)
    monkeypatch.setattr(BaseClient, "close", close)
    monkeypatch.setattr(RemediationWorker, "__init__", worker_init)
    for name, callback in (("begin", begin), ("commit", end), ("rollback", end)):
        event.listen(engine, name, callback)
    try:
        yield state, calls, session_factory, quiescent
        for stubber in stubbers:
            stubber.assert_no_pending_responses()
        quiescent()
    finally:
        for stubber in stubbers:
            stubber.deactivate()
        for name, callback in (("begin", begin), ("commit", end), ("rollback", end)):
            event.remove(engine, name, callback)


def assert_history(engine, initial, current, issuer, *, revocation=None, human_identities=None):
    identities = (
        human_identities
        if human_identities is not None
        else (
            (issuer.issuer, "proposer"),
            (issuer.issuer, "approver"),
            (issuer.issuer, "requester"),
        )
    )
    assert type(identities) is tuple and len(identities) == 3
    assert all(
        type(pair) is tuple and len(pair) == 2 and all(type(v) is str and v for v in pair)
        for pair in identities
    )
    assert len(set(identities)) == 3
    assert current.content == initial.content
    assert current.execution_sha256 == initial.execution_sha256
    assert current.execution_sha256 == canonical_json_sha256(
        current.content.model_dump(mode="json")
    )
    assert current.events[0] == initial.events[0]
    previous = None
    with Session(engine) as session:
        humans = (
            (current.content.proposal.proposer, identities[0], "ANALYST", "PROPOSE"),
            (current.content.approval.actor, identities[1], "APPROVER", "APPROVE"),
            (current.content.requested_by, identities[2], "ADMIN", "EXECUTE"),
        )
        for actor, (actor_issuer, subject), role, capability in humans:
            assert actor.model_dump(mode="json") == {
                "issuer": actor_issuer,
                "subject": subject,
                "roles": [role],
                "capability": capability,
            }
        authority_audits = session.scalars(
            select(AuditEvent).where(
                AuditEvent.target_type == "remediation",
                AuditEvent.target_id == current.content.proposal.proposal_id,
            )
        ).all()
        assert len(authority_audits) == (2 if revocation is None else 3)
        for actor, (actor_issuer, subject), _role, capability in humans[:2]:
            audit = next(
                audit
                for audit in authority_audits
                if audit.event_metadata["actor"]["subject"] == subject
                and audit.event_metadata["actor"]["issuer"] == actor_issuer
                and audit.event_type
                is (
                    AuditEventType.REMEDIATION_PROPOSED
                    if capability == "PROPOSE"
                    else AuditEventType.REMEDIATION_APPROVED
                )
            )
            assert audit.actor_type == "human"
            assert audit.actor_id == canonical_json_sha256([actor_issuer, subject])
            assert audit.event_type is (
                AuditEventType.REMEDIATION_PROPOSED
                if capability == "PROPOSE"
                else AuditEventType.REMEDIATION_APPROVED
            )
            assert audit.event_metadata == {
                "schema_version": "1.0.0",
                "actor": actor.model_dump(mode="json"),
                "proposal_id": str(current.content.proposal.proposal_id),
                "proposal_sha256": current.content.proposal_sha256,
                "decision_id": (
                    str(current.content.approval.decision_id) if capability == "APPROVE" else None
                ),
            }
        if revocation is not None:
            assert revocation.kind.value == "REVOKE"
            assert revocation.approval_decision_id == current.content.approval.decision_id
            assert revocation.proposal_sha256 == current.content.proposal_sha256
            revoked = [
                audit
                for audit in authority_audits
                if audit.event_type is AuditEventType.REMEDIATION_REVOKED
            ]
            assert len(revoked) == 1
            audit = revoked[0]
            actor = revocation.actor.model_dump(mode="json")
            assert actor == {
                "issuer": identities[1][0],
                "subject": identities[1][1],
                "roles": ["APPROVER"],
                "capability": "APPROVE",
            }
            assert audit.actor_type == "human"
            assert audit.actor_id == canonical_json_sha256(list(identities[1]))
            assert audit.event_metadata == {
                "schema_version": "1.0.0",
                "actor": actor,
                "proposal_id": str(current.content.proposal.proposal_id),
                "proposal_sha256": current.content.proposal_sha256,
                "decision_id": str(revocation.decision_id),
            }
        for number, entry in enumerate(current.events, 1):
            content = entry.content.model_dump(mode="json")
            assert entry.content.sequence == number
            assert entry.content.previous_event_sha256 == previous
            assert entry.event_sha256 == canonical_json_sha256(content)
            audit = session.get(AuditEvent, entry.audit_event_id)
            assert audit.actor_type == ("human" if number == 1 else "service")
            actor = content["actor"]
            if number == 1:
                assert actor == {
                    "issuer": identities[2][0],
                    "subject": identities[2][1],
                    "roles": ["ADMIN"],
                    "capability": "EXECUTE",
                }
                assert audit.actor_id == canonical_json_sha256(list(identities[2]))
            else:
                assert actor == {"service_id": "remediation-worker", "expected_role_arn": ROLE}
                assert audit.actor_id == canonical_json_sha256(actor)
            assert audit.event_metadata == {
                "schema_version": content["schema_version"],
                "actor": actor,
                "execution_id": str(current.content.execution_id),
                "execution_sha256": current.execution_sha256,
                "execution_event_id": str(entry.content.event_id),
                "event_sha256": entry.event_sha256,
                "sequence": number,
                "kind": entry.content.kind.value,
            }
            previous = entry.event_sha256

    def private_fields(value):
        if isinstance(value, dict):
            assert not set(value) & {
                "token",
                "token_sha256",
                "lease_until",
                "generation",
                "read_attempts",
                "readback_attempts",
                "readback_started_at",
                "write_intent_event_id",
                "credentials",
                "access_token",
                "secret_access_key",
                "session_token",
            }
            for item in value.values():
                private_fields(item)
        elif isinstance(value, list):
            for item in value:
                private_fields(item)

    private_fields(current.model_dump(mode="json"))


def exercise_worker_http(engine, monkeypatch, tmp_path, *, outcome, baseline_key):
    source, _ = seed(
        engine, kms_error={"KmsKeyId": baseline_key} if baseline_key is not None else {}
    )
    original = database_state(engine)
    with offline_worker_boundary(
        engine, monkeypatch, outcome=outcome, baseline_key=baseline_key
    ) as (
        state,
        calls,
        sessions,
        quiescent,
    ):
        with dashboard_client(engine, monkeypatch, tmp_path) as (
            client,
            issuer,
            _browser,
            executor,
        ):
            monkeypatch.setattr(database_session, "SessionLocal", sessions)
            proposer = signed_headers(issuer, "proposer", "ANALYST")
            approver = signed_headers(issuer, "approver", "APPROVER")
            requester = signed_headers(issuer, "requester", "ADMIN")
            reader = signed_headers(issuer, "reader", "VIEWER")
            proposal_response = client.post(
                "/api/v1/remediations", json=source.model_dump(mode="json"), headers=proposer
            )
            assert proposal_response.status_code == 201, proposal_response.text
            proposal = proposal_response.json()
            route = "/api/v1/remediations/" + proposal["content"]["proposal_id"]
            decision_body = {
                "proposal_sha256": proposal["proposal_sha256"],
                "decision": "APPROVE",
                "reason": "Reviewed exact intent, workload and key context.",
            }
            assert (
                client.post(
                    route + "/decisions",
                    json=decision_body,
                    headers=signed_headers(issuer, "proposer", "ADMIN"),
                ).status_code
                == 403
            )
            approval = client.post(route + "/decisions", json=decision_body, headers=approver)
            assert approval.status_code == 201, approval.text
            body = {
                "proposal_sha256": proposal["proposal_sha256"],
                "approval_decision_id": approval.json()["decision_id"],
                "reason": "Execute only the independently approved single action.",
            }
            admission = route + "/executions"
            assert client.post(admission, json=body, headers=requester).status_code == 503
            for name, value in {
                "REMEDIATION_ADMISSION_ENABLED": "true",
                "REMEDIATION_ACCOUNT_ID": ACCOUNT,
                "REMEDIATION_REGION": REGION,
            }.items():
                monkeypatch.setenv(name, value)
            get_settings.cache_clear()
            for subject in ("proposer", "approver"):
                assert (
                    client.post(
                        admission, json=body, headers=signed_headers(issuer, subject, "ADMIN")
                    ).status_code
                    == 403
                )
            assert client.post(admission, json=body).status_code == 401
            assert client.post(admission, json=body, headers=reader).status_code == 403
            for overrides in (
                {"iss": "https://untrusted.example.test"},
                {"aud": "wrong"},
                {"exp": datetime.now(UTC) - timedelta(seconds=1)},
            ):
                assert (
                    client.post(
                        admission,
                        json=body,
                        headers=signed_headers(issuer, "requester", "ADMIN", **overrides),
                    ).status_code
                    == 401
                )
            assert (
                client.post(
                    admission,
                    json=body,
                    headers={"Authorization": requester["Authorization"]},
                ).status_code
                == 422
            )
            for caller_field in (
                "region",
                "account_id",
                "role_arn",
                "credentials",
                "endpoint_url",
                "action_id",
                "desired_state",
            ):
                assert (
                    client.post(
                        admission, json={**body, caller_field: "forbidden"}, headers=requester
                    ).status_code
                    == 422
                )
            accepted = client.post(admission, json=body, headers=requester)
            assert accepted.status_code == 202, accepted.text
            assert accepted.headers["cache-control"] == "no-store"
            initial = ExecutionView.model_validate(accepted.json())
            assert initial.phase is ExecutionPhase.QUEUED and initial.reservation_held
            assert (initial.content.proposal.account_id, initial.content.proposal.region) == (
                ACCOUNT,
                REGION,
            )
            assert initial.content.proposal.baseline.default_kms_key_id == baseline_key
            assert initial.content.proposal.baseline.default_kms_key_expected_absence is (
                baseline_key is None
            )
            assert initial.content.expires_at == min(
                initial.content.proposal.expires_at,
                initial.content.created_at + timedelta(minutes=5),
            )
            assert len(initial.events) == 1 and initial.events[0].content.schema_version == "1.0.0"
            assert executor.submissions == [] and calls == []
            quiescent()
            detail = "/api/v1/remediation-executions/" + str(initial.content.execution_id)
            state.execution = initial
            state.read = lambda: client.get(detail, headers=reader)
            state.started = True

            def factory(scope):
                assert scope == SCOPE
                quiescent()
                return EbsDefaultWriter.from_ecs(scope)

            result = RemediationWorker(sessions, scope=SCOPE, aws_factory=factory).run(
                initial.content.execution_id
            )
            current = ExecutionView.model_validate(state.read().json())
            success = outcome == "acknowledged"
            assert result is (WorkerResult.ACKNOWLEDGED if success else WorkerResult.NO_WRITE)
            assert current.phase is (
                ExecutionPhase.ACKNOWLEDGED if success else ExecutionPhase.NO_WRITE
            )
            assert not current.reservation_held and current.blocking_reasons == ()
            expected_kinds = (
                ["REQUESTED", "CLAIMED", "WRITE_INTENT", "ACKNOWLEDGED", "OBSERVED"]
                if success
                else ["REQUESTED", "CLAIMED", "NO_WRITE"]
            )
            assert [entry.content.kind.value for entry in current.events] == expected_kinds
            assert calls == [
                "metadata",
                "client:sts",
                "client:ec2",
                "GetCallerIdentity",
                "GetEbsEncryptionByDefault",
                "GetEbsDefaultKmsKeyId",
            ] + (
                [
                    "EnableEbsEncryptionByDefault",
                    "GetCallerIdentity",
                    "GetEbsEncryptionByDefault",
                    "GetEbsDefaultKmsKeyId",
                ]
                if success
                else []
            ) + ["close:sts", "close:ec2"]
            assert state.enable_receipt_checks == int(success)
            if engine.dialect.name == "postgresql":
                assert state.lock_probes == calls
            if success:
                assert current.events[-1].content.observation.encryption_by_default is True
                assert current.events[-1].content.polls == 1
            else:
                assert [reason.value for reason in current.events[-1].content.blocking_reasons] == [
                    "PRECONDITION_CHANGED"
                ]
            assert_history(engine, initial, current, issuer)
            terminal = database_state(engine)
            assert protected_state(terminal) == protected_state(original)
            # Existing non-remediation audit rows retain their complete bytes and ordering.
            old_audit = {row.event_id: row for row in original["audit_events"]}
            new_audit = {row.event_id: row for row in terminal["audit_events"]}
            assert all(new_audit[key] == value for key, value in old_audit.items())
            assert len(new_audit) - len(old_audit) == 2 + len(current.events)
            assert all(
                str(row.event_type).startswith("REMEDIATION_")
                and row.target_type in {"remediation", "remediation_execution"}
                for key, row in new_audit.items()
                if key not in old_audit
            )
            with Session(engine) as session:
                assert session.get(Finding, source.finding_id).status is FindingStatus.OPEN

            expected = history_projection(state.read())
            assert history_projection(state.read()) == expected
            assert client.get(detail).status_code == 401
            listed = client.get(
                "/api/v1/remediation-executions",
                headers=reader,
                params={"proposal_id": str(initial.content.proposal.proposal_id)},
            )
            assert listed.status_code == 200 and listed.headers["cache-control"] == "no-store"
            assert listed.json()["total"] == 1
            assert len(listed.json()["items"]) == 1
            assert (
                ExecutionView.model_validate(listed.json()["items"][0]).model_dump(
                    mode="json", exclude={"validity_checked_at"}
                )
                == expected
            )
            monkeypatch.setenv("REMEDIATION_ADMISSION_ENABLED", "false")
            get_settings.cache_clear()
            assert (
                history_projection(client.post(admission, json=body, headers=requester)) == expected
            )
            lost_role = signed_headers(
                issuer, "requester", "VIEWER", key=UUID(requester["Idempotency-Key"])
            )
            assert client.post(admission, json=body, headers=lost_role).status_code == 403
            assert (
                client.post(
                    admission, json={**body, "reason": "Changed"}, headers=requester
                ).status_code
                == 409
            )
            sign_in(client, issuer)
            assert client.get(detail).status_code == 401
            assert client.post(admission, json=body).status_code == 401
            assert executor.submissions == []
            assert database_state(engine) == terminal
            assert calls.count("EnableEbsEncryptionByDefault") == int(success)
        quiescent()
