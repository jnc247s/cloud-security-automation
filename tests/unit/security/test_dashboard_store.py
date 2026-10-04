"""Session lifetime, memory bounds, one-time transactions and restart behavior."""

import pytest

from app.dashboard.store import CapacityError, SessionStore
from app.security.authentication import Principal

PRINCIPAL = Principal("test-reader", frozenset({"VIEWER"}), "test-issuer")


@pytest.mark.parametrize("deadline", [900, 3600, 200])
def test_session_idle_absolute_and_access_token_lifetimes(deadline):
    now = [0.0]
    store = SessionStore(clock=lambda: now[0])
    token_expiry = 200 if deadline == 200 else 10000
    identifier = store.create("ephemeral-test-token", PRINCIPAL, token_expiry)
    if deadline == 3600:
        for instant in range(800, 3600, 800):
            now[0] = instant
            assert store.get(identifier)
    now[0] = deadline
    assert store.get(identifier) is None


def test_status_does_not_extend_idle_time_and_restart_clears_everything():
    now = [0.0]
    store = SessionStore(clock=lambda: now[0])
    identifier = store.create("ephemeral-test-token", PRINCIPAL, 10000)
    browser, _ = store.login()
    now[0] = 800
    assert store.get(identifier, touch=False).idle_expires == 900
    store.clear()
    assert store.get(identifier) is None
    assert store.consume(browser, "anything") is None
    assert SessionStore().get(identifier) is None


def test_bounded_logins_expire_and_are_bound_to_browser_and_csrf():
    now = [0.0]
    store = SessionStore(clock=lambda: now[0])
    browser, login = store.login()
    assert store.begin(browser, "wrong") is None
    pending = store.begin(browser, login.csrf)
    assert pending and pending.state and pending.verifier and pending.nonce
    assert store.begin(browser, login.csrf) is None
    assert store.consume("another-browser", pending.state) is None
    assert store.consume(browser, pending.state) == pending
    assert store.consume(browser, pending.state) is None
    for _ in range(100):
        store.login()
    with pytest.raises(CapacityError):
        store.login()
    now[0] = 300
    assert store.login()


def test_session_capacity_rejects_instead_of_evicting_other_users():
    store = SessionStore(clock=lambda: 0)
    first = store.create("ephemeral-test-token", PRINCIPAL, 10000)
    for _ in range(999):
        store.create("ephemeral-test-token", PRINCIPAL, 10000)
    with pytest.raises(CapacityError):
        store.create("ephemeral-test-token", PRINCIPAL, 10000)
    assert store.get(first)


def test_opaque_secrets_are_not_in_store_repr():
    store = SessionStore(clock=lambda: 0)
    identifier = store.create("must-not-log-this-token", PRINCIPAL, 10000)
    assert "must-not-log" not in repr(store.get(identifier))
    browser, _ = store.login()
    pending = store.begin(browser, store.login(browser)[1].csrf)
    assert pending.verifier not in repr(pending)


@pytest.mark.parametrize("malformed", ["\u00ff" * 43, "x" * 10000, ""])
def test_malformed_protocol_values_reject_and_consume_state_once(malformed):
    store = SessionStore()
    browser, login = store.login()
    assert store.begin(browser, malformed) is None
    pending = store.begin(browser, login.csrf)
    assert store.consume(browser, malformed) is None
    assert store.consume(browser, pending.state) is None
