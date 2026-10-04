"""Bounded, process-local secrets. A restart deliberately ends all sessions."""

from collections.abc import Callable
from dataclasses import dataclass, field
from hmac import compare_digest
from secrets import token_urlsafe
from threading import RLock
from time import time

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

    def _expire(self) -> None:
        now = self.clock()
        self._logins = {k: v for k, v in self._logins.items() if v.expires > now}
        self._sessions = {
            k: v for k, v in self._sessions.items() if min(v.expires, v.idle_expires) > now
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

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._logins.clear()
