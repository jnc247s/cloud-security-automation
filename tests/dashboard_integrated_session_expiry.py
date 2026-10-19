"""Closed idle-clock and real-wall-time token-expiry fixtures; no authentication replacement."""

import os
from threading import RLock
from time import time
from uuid import UUID

from tests.dashboard_integrated_loss import CommittedProposalReplyLoss


def make_expiry_issuer(scenario, *, issuer, audience, clock=time):
    if os.environ.get("DASHBOARD_BROWSER_TEST") != "1" or scenario not in {
        "idle-expiry",
        "token-expiry",
    }:
        raise ValueError("Integrated expiry issuer rejected")
    from tests.dashboard_fixtures import ControlledIssuer

    class InitialLifetimeIssuer(ControlledIssuer):
        first_token, first_deadline = None, None

        def token_response(self, form):
            identity = self.grants.get(form.get("code", [""])[0], (self.role, self.subject))
            if identity != ("ANALYST", "proposer") or self.first_token is not None:
                return super().token_response(form)
            if self.access_overrides:
                raise ValueError("Integrated expiry issuer rejected")
            deadline = int(clock()) + (3600 if scenario == "idle-expiry" else 10)
            self.access_overrides["exp"] = deadline
            try:
                status, body = super().token_response(form)
            finally:
                self.access_overrides.clear()
            if status == 200:
                self.first_token, self.first_deadline = body["access_token"], deadline
            return status, body

    return InitialLifetimeIssuer(issuer=issuer, audience=audience)


class IdleExpiryClock:
    def __init__(self, issuer, *, clock=time):
        self.issuer, self.clock, self.shift = issuer, clock, 0
        self.completed, self.expired_at = False, None
        self._lock = RLock()

    def __call__(self):
        with self._lock:
            return self.clock() + self.shift

    def expire_after_commit(self, store, key):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
            raise ValueError("Integrated idle expiry rejected")
        from app.dashboard.operations import OperationKind, OperationState
        from app.dashboard.store import SessionStore

        if type(store) is not SessionStore or type(key) is not UUID or key.version != 4:
            raise ValueError("Integrated idle expiry rejected")
        # Independent committed SQL/audit proof is closed before this short store-only section.
        with store._lock, self._lock:
            target = store._operations.get(key)
            owner = store._sessions.get(target.session_id) if target else None
            now = self()
            if (
                store.clock is not self
                or self.shift != 0
                or self.completed
                or target is None
                or owner is None
                or target.actor != (self.issuer, "proposer")
                or (owner.principal.issuer, owner.principal.subject) != target.actor
                or owner.principal.role_names != frozenset({"ANALYST"})
                or target.input.kind is not OperationKind.PROPOSE
                or target.state is not OperationState.IN_FLIGHT
                or target.attempts != 1
                or target.result is not None
                or target.expires_at
                != min(target.prepared_at + 300, owner.expires, owner.idle_expires)
                or target.expires_at <= now
                or not now < owner.idle_expires <= now + 900
                or owner.expires <= now + 901
            ):
                raise ValueError("Integrated idle expiry rejected")
            self.shift = 901
            try:
                self.expired_at = self()
                if store.get(target.session_id, touch=False) is not None:
                    raise ValueError("Integrated idle expiry rejected")
                if target.session_id in store._sessions or key in store._operations:
                    raise ValueError("Integrated idle expiry rejected")
                self.completed = True
            finally:
                # Only test time is restored for a fresh explicit login. Removed sessions and
                # coordination stay removed; neither tokens nor deadlines are rewritten.
                self.shift = 0


class CommittedSessionExpiry(CommittedProposalReplyLoss):
    def __init__(self, engine, *, issuer, store, scenario, clock=None):
        if scenario not in {"idle-expiry", "token-expiry"}:
            raise ValueError("Integrated session expiry rejected")
        super().__init__(engine, issuer=issuer.issuer)
        self.signer, self.store, self.scenario, self.clock = issuer, store, scenario, clock
        self.old_session_id, self.key, self.proposal_id = None, None, None

    def _prove(self, response, key):
        from app.config import get_settings
        from app.dashboard.operations import OperationKind, OperationState
        from app.security.authentication import get_authentication_backend

        identifier = super()._prove(response, key)
        with self.store._lock:
            target = self.store._operations.get(key)
            owner = self.store._sessions.get(target.session_id) if target else None
            if (
                target is None
                or owner is None
                or target.actor != (self.issuer, "proposer")
                or target.input.kind is not OperationKind.PROPOSE
                or target.state is not OperationState.IN_FLIGHT
                or target.attempts != 1
                or target.result is not None
                or owner.access_token != self.signer.first_token
                or owner.expires != self.signer.first_deadline
            ):
                raise ValueError("Integrated session expiry rejected")
            self.old_session_id = target.session_id
        # Actual signature/issuer/audience/roles/time validation, outside store/SQL locks.
        actor = get_authentication_backend(get_settings()).authenticate(self.signer.first_token)
        if (actor.issuer, actor.subject, actor.role_names) != (
            self.issuer,
            "proposer",
            frozenset({"ANALYST"}),
        ):
            raise ValueError("Integrated session expiry rejected")
        self.key, self.proposal_id = key, identifier
        return identifier

    def _after_proof(self, key):
        if self.scenario == "idle-expiry":
            self.clock.expire_after_commit(self.store, key)

    def assert_complete(self):
        from app.config import get_settings
        from app.security.authentication import AuthenticationError, get_authentication_backend

        if (
            self.losses != 1
            or len(self.requests) != 1
            or self.old_session_id is None
            or self.old_session_id in self.store._sessions
            or self.key in self.store._operations
            or type(self.proposal_id) is not UUID
        ):
            raise ValueError("Incomplete integrated session-expiry proof")
        backend = get_authentication_backend(get_settings())
        if self.scenario == "idle-expiry":
            if not self.clock.completed or self.clock.shift != 0:
                raise ValueError("Incomplete integrated session-expiry proof")
            actor = backend.authenticate(self.signer.first_token)
            if actor.subject != "proposer":
                raise ValueError("Incomplete integrated session-expiry proof")
        else:
            if self.signer.first_deadline > time():
                raise ValueError("Incomplete integrated session-expiry proof")
            try:
                backend.authenticate(self.signer.first_token)
            except AuthenticationError:
                return
            raise ValueError("Incomplete integrated session-expiry proof")
