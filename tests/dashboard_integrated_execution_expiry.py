"""Closed elapsed-grant fixture; no persisted timestamp, JWT or installed-worker clock edits."""

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import RLock
from uuid import UUID


def historical_execution_source(engine):
    """Collect genuinely historical facts before persistence, never backdate retained rows."""
    if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
        raise ValueError("Integrated historical source rejected")
    from unittest.mock import patch

    from tests import verification_acceptance

    class HistoricalDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is not UTC:
                raise ValueError("Integrated historical source rejected")
            return datetime.now(UTC) - timedelta(seconds=600)

    if verification_acceptance.datetime is not datetime:
        raise ValueError("Integrated historical source rejected")
    with patch.object(verification_acceptance, "datetime", HistoricalDateTime):
        return verification_acceptance.full_scope_source(engine)


class ExecutionExpiryClock:
    def __init__(self, issuer, *, clock=lambda: datetime.now(UTC)):
        self.issuer, self.clock, self.shift = issuer, clock, -301
        self._lock, self._active, self._installed_type = RLock(), False, None

    def __call__(self):
        with self._lock:
            value = self.clock()
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("Integrated execution clock rejected")
            return value.astimezone(UTC) + timedelta(seconds=self.shift)

    @contextmanager
    def installed(self):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
            raise ValueError("Integrated execution clock rejected")
        from unittest.mock import patch

        from app.services import remediation_service

        owner = self

        class OwnedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                if tz is not UTC:
                    raise ValueError("Integrated execution clock rejected")
                return owner()

        with self._lock:
            if self._active or remediation_service.datetime is not datetime:
                raise ValueError("Integrated execution clock rejected")
            self._active, self._installed_type = True, OwnedDateTime
        try:
            with patch.object(remediation_service, "datetime", OwnedDateTime):
                yield self
        finally:
            with self._lock:
                self._active, self._installed_type = False, None

    def expire_after_commit(self, store, key):
        from app.dashboard.operations import OperationKind, OperationState
        from app.dashboard.store import SessionStore
        from app.services import remediation_service

        if type(store) is not SessionStore or type(key) is not UUID or key.version != 4:
            raise ValueError("Integrated execution clock rejected")
        # Caller closes the independent committed-grant/audit proof before taking these locks.
        with store._lock, self._lock:
            target = store._operations.get(key)
            owner = store._sessions.get(target.session_id) if target else None
            if (
                not self._active
                or remediation_service.datetime is not self._installed_type
                or type(self.shift) is not int
                or self.shift != -301
                or target is None
                or owner is None
                or target.actor != (self.issuer, "requester")
                or (owner.principal.issuer, owner.principal.subject) != target.actor
                or owner.principal.role_names != frozenset({"ADMIN"})
                or target.input.kind is not OperationKind.REQUEST_EXECUTION
                or target.state is not OperationState.IN_FLIGHT
                or target.attempts != 1
                or target.result is not None
                or target.expires_at != min(target.prepared_at + 300, owner.expires)
                or target.expires_at <= store.clock()
            ):
                raise ValueError("Integrated execution clock rejected")
            self.shift = 0  # Restore real UTC; the separate installed worker always uses real UTC.


class CommittedExecutionExpiry:
    """Return the genuine admitted reply after independently proving it, then elapse the grant."""

    def __init__(self, engine, *, issuer, store, clock):
        self.engine, self.issuer, self.store, self.clock = engine, issuer, store, clock
        self._lock, self._active = RLock(), False
        self.requests, self.execution_id = [], None  # Only UUID/body digests, never tokens.

    def _prove(self, response, key, encoded):
        from types import SimpleNamespace

        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        from app.models.remediation_execution import RemediationExecution
        from app.remediation.execution_contracts import AdmissionScope, ExecutionView
        from app.security.authentication import Principal
        from app.services.remediation_execution_service import RemediationExecutionService
        from tests.worker_http import ACCOUNT, REGION, assert_history

        view = ExecutionView.model_validate(response.json())
        assert view.content.idempotency_key == key
        assert view.phase.value == "QUEUED" and view.reservation_held
        assert not view.blocking_reasons and len(view.events) == 1
        assert view.events[0].content.kind.value == "REQUESTED"
        assert view.content.expires_at == view.content.created_at + timedelta(seconds=300)
        assert json.loads(encoded) == {
            "proposal_sha256": view.content.proposal_sha256,
            "approval_decision_id": str(view.content.approval.decision_id),
            "reason": view.content.reason,
        }
        with Session(self.engine) as session:
            assert session.scalar(select(func.count()).select_from(RemediationExecution)) == 1
            current = RemediationExecutionService(
                session, scope=AdmissionScope(enabled=True, account_id=ACCOUNT, region=REGION)
            ).get_execution(
                view.content.execution_id,
                Principal("expiry-proof-reader", frozenset({"VIEWER"}), self.issuer),
            )
            assert current.content == view.content and current.events == view.events
            assert current.execution_sha256 == view.execution_sha256
            assert current.phase.value == "QUEUED" and not current.blocking_reasons
        assert_history(self.engine, view, current, SimpleNamespace(issuer=self.issuer))
        return view.content.execution_id

    @contextmanager
    def installed(self):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
            raise ValueError("Integrated execution-expiry gate rejected")
        from unittest.mock import patch

        import httpx2 as httpx

        with self._lock:
            if self._active:
                raise ValueError("Integrated execution-expiry gate rejected")
            self._active = True
        original = httpx.AsyncClient.post

        async def forward(client, url, *args, **kwargs):
            prefix, suffix = "/api/v1/remediations/", "/executions"
            if type(url) is not str or not url.startswith(prefix) or not url.endswith(suffix):
                return await original(client, url, *args, **kwargs)
            identifier = url[len(prefix) : -len(suffix)]
            parsed = UUID(identifier)
            if str(parsed) != identifier or parsed.version != 4:
                raise ValueError("Integrated execution-expiry gate rejected")
            if not isinstance(client._transport, httpx.ASGITransport):
                raise ValueError("Integrated execution-expiry gate rejected")
            raw, key = kwargs["content"], kwargs["headers"]["Idempotency-Key"]
            if type(raw) not in (str, bytes):
                raise ValueError("Integrated execution-expiry gate rejected")
            encoded = raw.encode("utf-8") if type(raw) is str else raw
            parsed_key = UUID(key)
            if len(encoded) > 12288 or str(parsed_key) != key or parsed_key.version != 4:
                raise ValueError("Integrated execution-expiry gate rejected")
            with self._lock:
                self.requests.append((parsed_key, hashlib.sha256(encoded).hexdigest()))
            response = await original(client, url, *args, **kwargs)
            if response.status_code == 202:
                identifier = self._prove(response, parsed_key, encoded)
                self.clock.expire_after_commit(self.store, parsed_key)
                self.execution_id = identifier
            return response

        try:
            with patch.object(httpx.AsyncClient, "post", forward):
                yield self
        finally:
            with self._lock:
                self._active = False

    def assert_complete(self):
        if self.clock.shift != 0 or type(self.execution_id) is not UUID or len(self.requests) != 1:
            raise ValueError("Incomplete integrated execution-expiry proof")


def assert_expired_execution(parent, before_reader, expected):
    """Independent whole-database no-intent proof; never reuse a post-intent quarantine proof."""
    from types import SimpleNamespace

    from tests.dashboard_integrated_scenarios import reader_scenario
    from tests.worker_http import assert_history, database_state

    def require(value):
        if not value:
            raise ValueError("Invalid integrated expired-execution proof")

    parent._owned()
    require(expected == parent.scenario == reader_scenario("execution-expiry"))
    require(parent.worker_dispatched is True and parent.expired_execution is not None)
    require(parent.acknowledged_execution is None and parent.quarantined_execution is None)
    require(type(parent.expiry_before) is dict and type(parent.before_worker) is dict)
    require(type(before_reader) is dict and type(parent.worker_report) is dict)
    before, admitted, after = (
        parent.expiry_before,
        parent.before_worker,
        database_state(parent.engine),
    )
    require(set(before) == set(admitted) == set(after))
    require(before_reader == after)
    authority = {
        "remediation_proposals",
        "remediation_decisions",
        "remediation_requests",
        "remediation_executions",
        "remediation_execution_events",
        "remediation_admission_guard",
        "remediation_target_reservations",
        "audit_events",
    }
    require(all(before[name] == admitted[name] for name in before if name not in authority))
    require(
        all(
            not before[name]
            for name in authority
            - {"audit_events", "remediation_admission_guard", "remediation_target_reservations"}
        )
    )
    require(len(admitted["remediation_proposals"]) == len(admitted["remediation_decisions"]) == 1)
    require(len(admitted["remediation_requests"]) == 2)
    require(
        len(admitted["remediation_executions"])
        == len(admitted["remediation_execution_events"])
        == 1
    )
    require(len(admitted["audit_events"]) == len(before["audit_events"]) + 3)
    require(all(row in admitted["audit_events"] for row in before["audit_events"]))
    worker = {"remediation_execution_events", "remediation_target_reservations", "audit_events"}
    require(all(admitted[name] == after[name] for name in admitted if name not in worker))
    require(len(after["remediation_execution_events"]) == 2)
    require(
        all(
            row in after["remediation_execution_events"]
            for row in admitted["remediation_execution_events"]
        )
    )
    require(len(after["audit_events"]) == len(admitted["audit_events"]) + 1)
    require(all(row in after["audit_events"] for row in admitted["audit_events"]))
    old, new = admitted["remediation_target_reservations"], after["remediation_target_reservations"]
    require(len(old) == len(new) == 1)
    require(old[0].execution_id == parent.expired_execution and new[0].execution_id is None)
    require(
        {k: v for k, v in old[0]._mapping.items() if k != "execution_id"}
        == {k: v for k, v in new[0]._mapping.items() if k != "execution_id"}
    )
    require(after["remediation_worker_claims"] == ())
    current, initial = parent._execution(parent.expired_execution), parent.initial_execution
    parent._bind(current)
    require(initial.phase.value == "QUEUED" and initial.reservation_held)
    require([r.value for r in initial.blocking_reasons] == ["EXECUTION_EXPIRED"])
    require(initial.validity_checked_at >= initial.content.expires_at)
    require(current.phase.value == "NO_WRITE" and current.reservation_held is False)
    require(
        current.content == parent.worker_history.content
        and current.events == parent.worker_history.events
    )
    assert_history(parent.engine, initial, current, SimpleNamespace(issuer=parent.issuer))
    require([e.content.kind.value for e in current.events] == ["REQUESTED", "NO_WRITE"])
    require([e.content.schema_version for e in current.events] == ["1.0.0", "2.0.0"])
    require([r.value for r in current.events[-1].content.blocking_reasons] == ["EXECUTION_EXPIRED"])
    report = parent.worker_report
    require(report["exit_code"] == 0 and report["stdout"] == "NO_WRITE\n")
    require(report["calls"] == report["wire_actions"] == report["lock_probes"] == [])
    require(report["enable_invocations"] == report["intent_checks"] == 0)
    require(database_state(parent.engine) == after)  # READ proof cannot mutate or reap.
