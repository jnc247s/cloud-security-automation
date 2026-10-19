"""Closed test-only signed capability loss, never an authentication replacement or grant.

Only the session owning an already committed native proposal's in-flight coordination can be
changed. Tokens stay in server memory. Capability narrowing preserves identity; the separate
closed identity-substitution cases change one signed claim without changing session authority.
"""

import os
from uuid import UUID

from tests.dashboard_integrated_loss import CommittedProposalReplyLoss


def narrow_operation_to_viewer(store, issuer, key):
    import jwt

    from app.dashboard.operations import OperationKind, OperationState
    from app.dashboard.store import SessionStore
    from app.security.authentication import Principal

    try:
        if type(store) is not SessionStore or type(key) is not UUID or key.version != 4:
            raise ValueError
        with store._lock:
            operation = store._operations.get(key)
            if (
                operation is None
                or operation.state is not OperationState.IN_FLIGHT
                or operation.attempts != 1
                or operation.result is not None
                or operation.input.kind is not OperationKind.PROPOSE
                or operation.actor != (issuer.issuer, "proposer")
            ):
                raise ValueError
            session = store._sessions.get(operation.session_id)
            if session is None or (
                session.principal.issuer,
                session.principal.subject,
                session.principal.role_names,
            ) != (issuer.issuer, "proposer", frozenset({"ANALYST"})):
                raise ValueError
            original = session.access_token
            cached_principal = session.principal
        # No store lock or SQL connection is held across signature work. Actual application
        # authentication is unchanged and must verify this replacement JWT on every later call.
        claims = jwt.decode(
            original,
            issuer.key.public_key(),
            algorithms=["RS256"],
            audience=issuer.audience,
            issuer=issuer.issuer,
        )
        if (
            claims.get("sub") != "proposer"
            or claims.get("token_use") != "access"
            or claims.get("cognito:groups") != ["ANALYST"]
        ):
            raise ValueError
        narrowed = jwt.encode(
            {**claims, "cognito:groups": ["VIEWER"]},
            issuer.key,
            algorithm="RS256",
            headers={"kid": "dashboard-test"},
        )
        with store._lock:
            if (
                store._operations.get(key) is not operation
                or store._sessions.get(operation.session_id) is not session
                or session.access_token != original
                or session.principal != cached_principal
            ):
                raise ValueError
            session.access_token = narrowed
            # Deliberately false cached hint. It cannot confer authority over the signed VIEWER.
            session.principal = Principal("proposer", frozenset({"ADMIN"}), issuer.issuer)
    except (ValueError, TypeError, AttributeError, jwt.PyJWTError):
        raise ValueError("Integrated signed capability loss rejected") from None


class CommittedProposalCapabilityLoss(CommittedProposalReplyLoss):
    def __init__(self, engine, *, issuer, store):
        super().__init__(engine, issuer=issuer.issuer)
        self.signer, self.store, self.narrowed = issuer, store, False

    def _after_proof(self, key):
        if self.narrowed:
            raise ValueError("Integrated capability loss already applied")
        narrow_operation_to_viewer(self.store, self.signer, key)
        self.narrowed = True

    def assert_complete(self):
        if not self.narrowed or self.losses != 1 or len(self.requests) != 1:
            raise ValueError("Incomplete integrated capability-loss proof")


def replace_operation_identity(store, issuer, key, scenario):
    import jwt

    from app.dashboard.operations import OperationKind, OperationState
    from app.dashboard.store import SessionStore

    try:
        if (
            os.environ.get("DASHBOARD_BROWSER_TEST") != "1"
            or type(scenario) is not str
            or scenario not in {"subject-replacement", "issuer-rejection"}
            or type(store) is not SessionStore
            or type(key) is not UUID
            or key.version != 4
        ):
            raise ValueError
        with store._lock:
            operation = store._operations.get(key)
            session = store._sessions.get(operation.session_id) if operation else None
            if (
                operation is None
                or session is None
                or operation.actor != (issuer.issuer, "proposer")
                or operation.input.kind is not OperationKind.PROPOSE
                or operation.state is not OperationState.IN_FLIGHT
                or operation.attempts != 1
                or operation.result is not None
                or (
                    session.principal.issuer,
                    session.principal.subject,
                    session.principal.role_names,
                )
                != (issuer.issuer, "proposer", frozenset({"ANALYST"}))
                or operation.expires_at <= store.clock()
            ):
                raise ValueError
            original, principal, expires = session.access_token, session.principal, session.expires
        # No SQL connection or store lock spans actual signature verification/signing.
        claims = jwt.decode(
            original,
            issuer.key.public_key(),
            algorithms=["RS256"],
            audience=issuer.audience,
            issuer=issuer.issuer,
        )
        if (
            claims.get("sub") != "proposer"
            or claims.get("token_use") != "access"
            or claims.get("cognito:groups") != ["ANALYST"]
            or claims.get("exp") != expires
        ):
            raise ValueError
        change = (
            {"sub": "replacement-subject"}
            if scenario == "subject-replacement"
            else {"iss": "http://127.0.0.1:9032/untrusted-issuer"}
        )
        replacement = jwt.encode(
            {**claims, **change}, issuer.key, algorithm="RS256", headers={"kid": "dashboard-test"}
        )
        with store._lock:
            if (
                store._operations.get(key) is not operation
                or store._sessions.get(operation.session_id) is not session
                or session.access_token != original
                or session.principal != principal
                or session.expires != expires
                or operation.expires_at <= store.clock()
            ):
                raise ValueError
            session.access_token = replacement
        return operation.session_id, original, replacement
    except (ValueError, TypeError, AttributeError, jwt.PyJWTError):
        raise ValueError("Integrated identity substitution rejected") from None


class CommittedIdentitySubstitution(CommittedProposalReplyLoss):
    def __init__(self, engine, *, issuer, store, scenario):
        if (
            os.environ.get("DASHBOARD_BROWSER_TEST") != "1"
            or type(scenario) is not str
            or scenario
            not in {
                "subject-replacement",
                "issuer-rejection",
            }
        ):
            raise ValueError("Integrated identity substitution rejected")
        super().__init__(engine, issuer=issuer.issuer)
        self.signer, self.store, self.scenario = issuer, store, scenario
        self.old_session_id, self.key, self.proposal_id = None, None, None
        self.original_token, self.replacement_token = None, None

    def _prove(self, response, key):
        self.proposal_id = super()._prove(response, key)
        return self.proposal_id

    def _after_proof(self, key):
        if self.key is not None:
            raise ValueError("Integrated identity substitution already applied")
        self.key = key
        self.old_session_id, self.original_token, self.replacement_token = (
            replace_operation_identity(self.store, self.signer, key, self.scenario)
        )

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
            raise ValueError("Incomplete integrated identity-substitution proof")
        backend = get_authentication_backend(get_settings())
        original = backend.authenticate(self.original_token)
        if (original.issuer, original.subject, original.role_names) != (
            self.issuer,
            "proposer",
            frozenset({"ANALYST"}),
        ):
            raise ValueError("Incomplete integrated identity-substitution proof")
        if self.scenario == "subject-replacement":
            replacement = backend.authenticate(self.replacement_token)
            if (replacement.issuer, replacement.subject, replacement.role_names) == (
                self.issuer,
                "replacement-subject",
                frozenset({"ANALYST"}),
            ):
                return
        else:
            try:
                backend.authenticate(self.replacement_token)
            except AuthenticationError:
                return
        raise ValueError("Incomplete integrated identity-substitution proof")
