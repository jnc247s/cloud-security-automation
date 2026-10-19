"""Closed test-service clock, never global/JWT/session time or mutable authority history."""

import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import RLock
from uuid import UUID

from tests.dashboard_integrated_loss import CommittedProposalReplyLoss


class ProposalExpiryClock:
    def __init__(self, issuer, *, clock=lambda: datetime.now(UTC)):
        self.issuer, self.clock, self.shift = issuer, clock, 0
        self._lock, self._active, self._installed_type = RLock(), False, None

    def __call__(self):
        with self._lock:
            value = self.clock()
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("Integrated proposal clock rejected")
            return value.astimezone(UTC) + timedelta(seconds=self.shift)

    @contextmanager
    def installed(self):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
            raise ValueError("Integrated proposal clock rejected")
        from unittest.mock import patch

        from app.services import remediation_service

        owner = self

        class OwnedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                if tz is not UTC:
                    raise ValueError("Integrated proposal clock rejected")
                return owner()

        with self._lock:
            if self._active or remediation_service.datetime is not datetime:
                raise ValueError("Integrated proposal clock rejected")
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
            raise ValueError("Integrated proposal clock rejected")
        # The independent SQL proof has already closed. No SQL/JWT work under these short locks.
        with store._lock, self._lock:
            target = store._operations.get(key)
            owner = store._sessions.get(target.session_id) if target else None
            if (
                not self._active
                or remediation_service.datetime is not self._installed_type
                or type(self.shift) is not int
                or self.shift != 0
                or len(store._operations) != 1
                or target is None
                or owner is None
                or target.actor != (self.issuer, "proposer")
                or (owner.principal.issuer, owner.principal.subject) != target.actor
                or owner.principal.role_names != frozenset({"ANALYST"})
                or target.input.kind is not OperationKind.PROPOSE
                or target.state is not OperationState.IN_FLIGHT
                or target.attempts != 1
                or target.result is not None
                or target.expires_at != min(target.prepared_at + 300, owner.expires)
                or target.expires_at <= store.clock()
            ):
                raise ValueError("Integrated proposal clock rejected")
            self.shift = 86401  # Only derived service eligibility changes; no deadlines/rows do.


class CommittedProposalExpiry(CommittedProposalReplyLoss):
    def __init__(self, engine, *, issuer, store, clock):
        super().__init__(engine, issuer=issuer)
        self.store, self.clock, self.proposal_id = store, clock, None

    def _prove(self, response, key):
        self.proposal_id = super()._prove(response, key)
        return self.proposal_id

    def _after_proof(self, key):
        self.clock.expire_after_commit(self.store, key)

    def assert_complete(self):
        if (
            self.clock.shift != 86401
            or type(self.proposal_id) is not UUID
            or self.proposal_id.version != 4
            or self.losses != 1
            or len(self.requests) != 2
            or self.requests[0] != self.requests[1]
        ):
            raise ValueError("Incomplete integrated proposal-expiry proof")
