"""Owned test-store clock: one fixed elapsed interval after independently proven commit.

No application clock, JWT validation, deadline, domain authority or public interface is patched.
"""

from threading import RLock
from time import time
from uuid import UUID

from tests.dashboard_integrated_loss import CommittedProposalReplyLoss


class PreparationExpiryClock:
    def __init__(self, issuer, capacity, *, clock=time):
        if type(capacity) is not int or capacity not in {16, 256}:
            raise ValueError("Integrated preparation clock rejected")
        self.issuer, self.capacity, self.clock = issuer, capacity, clock
        self._lock, self.shift = RLock(), 0

    def __call__(self):
        with self._lock:
            return self.clock() + self.shift

    def expire_after_commit(self, store, key):
        from app.dashboard.operations import OperationKind, OperationState
        from app.dashboard.store import SessionStore

        if type(store) is not SessionStore or type(key) is not UUID or key.version != 4:
            raise ValueError("Integrated preparation clock rejected")
        with store._lock, self._lock:
            target = store._operations.get(key)
            owner = store._sessions.get(target.session_id) if target else None
            if (
                type(store) is not SessionStore
                or store.clock is not self
                or self.shift != 0
                or len(store._operations) != self.capacity
                or target is None
                or owner is None
                or target.actor != (self.issuer, "proposer")
                or (owner.principal.issuer, owner.principal.subject) != target.actor
                or target.input.kind is not OperationKind.PROPOSE
                or target.state is not OperationState.IN_FLIGHT
                or target.attempts != 1
                or target.result is not None
                or target.expires_at != target.prepared_at + 300
                or target.expires_at <= self()
                or owner.expires <= self() + 301
                or any(
                    value.actor != target.actor
                    or value.input.kind is not OperationKind.PROPOSE
                    or value.expires_at != value.prepared_at + 300
                    or (
                        value is not target
                        and (
                            value.state is not OperationState.PREPARED
                            or value.attempts != 0
                            or value.result is not None
                        )
                    )
                    or value.expires_at > self() + 301
                    for value in store._operations.values()
                )
            ):
                raise ValueError("Integrated preparation clock rejected")
            self.shift = 301  # No deadline/state mutation; ordinary store reads perform expiry.


class CommittedPreparationExpiry(CommittedProposalReplyLoss):
    def __init__(self, engine, *, issuer, store, clock):
        super().__init__(engine, issuer=issuer)
        self.store, self.clock = store, clock

    def _after_proof(self, key):
        self.clock.expire_after_commit(self.store, key)

    def assert_complete(self):
        if self.clock.shift != 301 or self.losses != 1 or len(self.requests) != 1:
            raise ValueError("Incomplete integrated preparation-expiry proof")
