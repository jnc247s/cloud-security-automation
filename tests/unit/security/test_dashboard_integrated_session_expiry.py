"""Owned idle clock and initial test-token lifetimes; no live provider or authority seed."""

import json
from uuid import uuid4

import pytest


@pytest.mark.parametrize(
    "fault",
    [None, "key", "state", "actor", "role", "kind", "token-first", "foreign-clock", "again"],
)
def test_idle_expiry_uses_normal_store_expiry_without_rewriting_any_deadline(monkeypatch, fault):
    from app.dashboard.operations import parse_preparation
    from app.dashboard.store import SessionStore
    from app.security.authentication import Principal
    from tests.dashboard_integrated_session_expiry import IdleExpiryClock

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    clock = IdleExpiryClock("test-issuer", clock=lambda: 1000.0)
    store = SessionStore(clock=clock)
    actor = Principal("proposer", frozenset({"ANALYST"}), "test-issuer")
    identifier = store.create("synthetic", actor, 1500.0 if fault == "token-first" else 4600.0)
    document = dict(
        schema_version="1.0.0",
        operation="PROPOSE",
        input=dict(
            finding_id=str(uuid4()), occurrence_id=str(uuid4()), reason="Retain committed history."
        ),
    )
    if fault == "kind":
        document.update(
            operation="DECIDE",
            target_id=str(uuid4()),
            input=dict(proposal_sha256="a" * 64, decision="APPROVE", reason="No idle bypass."),
        )
    prepared = store.prepare(identifier, actor, parse_preparation(json.dumps(document).encode()))
    if fault != "state":
        store.claim(identifier, actor, prepared.operation_id)
    owner = store._sessions[identifier]
    original = (owner.access_token, owner.expires, owner.idle_expires, owner.csrf, owner.context)
    if fault in {"actor", "role"}:
        owner.principal = Principal(
            "other" if fault == "actor" else "proposer",
            frozenset({"ADMIN"}) if fault == "role" else actor.role_names,
            actor.issuer,
        )
    if fault == "foreign-clock":
        store.clock = lambda: 1000.0
    if fault not in {None, "again"}:
        with pytest.raises(ValueError, match="Integrated idle expiry rejected"):
            clock.expire_after_commit(store, uuid4() if fault == "key" else prepared.operation_id)
        assert identifier in store._sessions and prepared.operation_id in store._operations
    else:
        clock.expire_after_commit(store, prepared.operation_id)
        assert identifier not in store._sessions and prepared.operation_id not in store._operations
        assert clock.completed is True and clock.expired_at == 1901.0
        assert store.get(identifier) is None  # Restoring test time cannot resurrect a session.
        assert (
            owner.access_token,
            owner.expires,
            owner.idle_expires,
            owner.csrf,
            owner.context,
        ) == original
        if fault == "again":
            with pytest.raises(ValueError, match="Integrated idle expiry rejected"):
                clock.expire_after_commit(store, prepared.operation_id)
    assert clock() == 1000.0 and clock.shift == 0


@pytest.mark.parametrize("scenario,seconds", [("idle-expiry", 3600), ("token-expiry", 10)])
def test_only_first_proposer_gets_a_closed_initial_lifetime(monkeypatch, scenario, seconds):
    from tests.dashboard_fixtures import ControlledIssuer
    from tests.dashboard_integrated_session_expiry import make_expiry_issuer

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    observed = []
    monkeypatch.setattr(
        ControlledIssuer,
        "token_response",
        lambda self, _form: (
            observed.append(dict(self.access_overrides)) or (200, {"access_token": "synthetic"})
        ),
    )
    issuer = make_expiry_issuer(
        scenario, issuer="test-issuer", audience="test-audience", clock=lambda: 1000.0
    )
    issuer.grants["first"] = ("ANALYST", "proposer")
    issuer.grants["second"] = ("ANALYST", "proposer")
    assert issuer.token_response({"code": ["first"]})[0] == 200
    assert issuer.token_response({"code": ["second"]})[0] == 200
    assert observed == [{"exp": 1000 + seconds}, {}]
    assert issuer.first_token == "synthetic" and issuer.first_deadline == 1000 + seconds
    assert issuer.access_overrides == {}


@pytest.mark.parametrize("flag", [None, "true"])
def test_session_expiry_seams_require_exact_test_mode_before_importing_app(monkeypatch, flag):
    from tests.dashboard_integrated_session_expiry import IdleExpiryClock, make_expiry_issuer

    monkeypatch.delenv("DASHBOARD_BROWSER_TEST", raising=False)
    if flag is not None:
        monkeypatch.setenv("DASHBOARD_BROWSER_TEST", flag)
    with pytest.raises(ValueError, match="Integrated idle expiry rejected"):
        IdleExpiryClock("test-issuer").expire_after_commit(object(), uuid4())
    with pytest.raises(ValueError, match="Integrated expiry issuer rejected"):
        make_expiry_issuer("token-expiry", issuer="test-issuer", audience="test-audience")
