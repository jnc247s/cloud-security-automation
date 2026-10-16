"""Bounded, process-local secrets. A restart deliberately ends all sessions."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from hmac import compare_digest
from secrets import token_urlsafe
from threading import RLock
from time import time
from uuid import UUID, uuid4

from app.dashboard.operations import (
    OperationExpired,
    OperationInput,
    OperationState,
    OperationUnavailable,
    PreparedOperation,
    ResultReference,
)
from app.security.authentication import Principal


def matches_opaque(expected: str, supplied: str) -> bool:
    """Protocol tokens are bounded ASCII; malformed input is a rejection, not an error."""
    return (
        len(supplied) == len(expected) and supplied.isascii() and compare_digest(expected, supplied)
    )


class CapacityError(Exception):
    """The boundary is at capacity; never evict another user's active session."""


@dataclass(frozen=True)
class Login:
    csrf: str = field(repr=False)
    expires: float
    state: str | None = field(default=None, repr=False)
    verifier: str | None = field(default=None, repr=False)
    nonce: str | None = field(default=None, repr=False)


@dataclass
class BrowserSession:
    access_token: str = field(repr=False)
    principal: Principal
    csrf: str = field(repr=False)
    expires: float
    idle_expires: float
    context: str


class SessionStore:
    """All lookup/create/consume operations are serialized and expiry is fail closed."""

    def __init__(self, *, clock: Callable[[], float] = time):
        self.clock = clock
        self._lock = RLock()
        self._logins: dict[str, Login] = {}
        self._sessions: dict[str, BrowserSession] = {}
        self._operations: dict[UUID, PreparedOperation] = {}

    def _expire(self) -> None:
        now = self.clock()
        self._logins = {k: v for k, v in self._logins.items() if v.expires > now}
        self._sessions = {
            k: v for k, v in self._sessions.items() if min(v.expires, v.idle_expires) > now
        }
        self._operations = {
            key: (
                replace(value, state=OperationState.EXPIRED)
                if value.state == OperationState.PREPARED and value.expires_at <= now
                else value
            )
            for key, value in self._operations.items()
            if value.session_id in self._sessions
        }

    def login(self, browser: str | None = None) -> tuple[str, Login]:
        with self._lock:
            self._expire()
            if browser in self._logins:
                return browser, self._logins[browser]
            if len(self._logins) >= 100:
                raise CapacityError
            browser = token_urlsafe(32)
            login = Login(token_urlsafe(32), self.clock() + 300)
            self._logins[browser] = login
            return browser, login

    def begin(self, browser: str, csrf: str) -> Login | None:
        with self._lock:
            self._expire()
            login = self._logins.get(browser)
            if not login or not matches_opaque(login.csrf, csrf) or login.state is not None:
                return None
            pending = Login(
                login.csrf, login.expires, token_urlsafe(32), token_urlsafe(48), token_urlsafe(32)
            )
            self._logins[browser] = pending
            return pending

    def consume(self, browser: str, state: str) -> Login | None:
        with self._lock:
            self._expire()
            login = self._logins.pop(browser, None)
            if not login or not login.state or not matches_opaque(login.state, state):
                return None
            return login

    def discard_login(self, browser: str) -> None:
        with self._lock:
            self._logins.pop(browser, None)

    def create(self, access_token: str, principal: Principal, token_expires: float) -> str:
        with self._lock:
            self._expire()
            if len(self._sessions) >= 1000:
                raise CapacityError
            now = self.clock()
            if token_expires <= now:
                raise ValueError("expired access token")
            identifier = token_urlsafe(32)
            self._sessions[identifier] = BrowserSession(
                access_token,
                principal,
                token_urlsafe(32),
                min(now + 3600, token_expires),
                now + 900,
                token_urlsafe(32),
            )
            return identifier

    def get(self, identifier: str, *, touch: bool = True) -> BrowserSession | None:
        with self._lock:
            self._expire()
            session = self._sessions.get(identifier)
            if session and touch:
                session.idle_expires = self.clock() + 900
            return session

    def revoke(self, identifier: str) -> None:
        with self._lock:
            self._sessions.pop(identifier, None)
            self._operations = {
                key: value
                for key, value in self._operations.items()
                if value.session_id != identifier
            }

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._logins.clear()
            self._operations.clear()

    def _operation_session(self, identifier: str, actor: Principal) -> BrowserSession:
        self._expire()
        session = self._sessions.get(identifier)
        if not session or (session.principal.issuer, session.principal.subject) != (
            actor.issuer,
            actor.subject,
        ):
            raise OperationUnavailable
        return session

    def prepare(
        self, identifier: str, actor: Principal, operation: OperationInput
    ) -> PreparedOperation:
        """Ephemeral coordination only; callers must freshly authorize every request."""
        with self._lock:
            session = self._operation_session(identifier, actor)
            count = sum(value.session_id == identifier for value in self._operations.values())
            if count >= 16 or len(self._operations) >= 256:
                raise CapacityError
            now = self.clock()
            prepared = PreparedOperation(
                uuid4(),
                identifier,
                (actor.issuer, actor.subject),
                operation,
                now,
                min(now + 300, session.expires, session.idle_expires),
            )
            self._operations[prepared.operation_id] = prepared
            return prepared

    def operations(self, identifier: str, actor: Principal) -> tuple[PreparedOperation, ...]:
        with self._lock:
            self._operation_session(identifier, actor)
            return tuple(
                value for value in self._operations.values() if value.session_id == identifier
            )

    def operation(self, identifier: str, actor: Principal, operation_id: UUID) -> PreparedOperation:
        with self._lock:
            self._operation_session(identifier, actor)
            value = self._operations.get(operation_id)
            if (
                not value
                or value.session_id != identifier
                or value.actor != (actor.issuer, actor.subject)
            ):
                raise OperationUnavailable
            return value

    def claim(
        self, identifier: str, actor: Principal, operation_id: UUID
    ) -> tuple[PreparedOperation, bool]:
        """Claim under one lock, then release it before any network/domain work."""
        with self._lock:
            value = self.operation(identifier, actor, operation_id)
            if value.state in {OperationState.IN_FLIGHT, OperationState.CONFIRMED}:
                return value, False
            if value.expires_at <= self.clock():
                raise OperationExpired
            claimed = replace(value, state=OperationState.IN_FLIGHT, attempts=value.attempts + 1)
            self._operations[operation_id] = claimed
            return claimed, True

    def settle(
        self,
        identifier: str,
        actor: Principal,
        operation_id: UUID,
        attempt: int,
        result: ResultReference | None,
    ) -> PreparedOperation:
        """Only validated READ references confirm; all other dispatched outcomes are uncertain."""
        with self._lock:
            value = self.operation(identifier, actor, operation_id)
            if value.state != OperationState.IN_FLIGHT or value.attempts != attempt:
                return value
            settled = replace(
                value,
                state=OperationState.CONFIRMED if result else OperationState.UNCONFIRMED,
                result=result,
            )
            self._operations[operation_id] = settled
            return settled
