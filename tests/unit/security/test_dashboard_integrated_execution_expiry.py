"""Closed historical-source/domain-clock guards, not installed-worker acceptance."""

import json
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest


@pytest.mark.parametrize(
    "fault", [None, "clipped", "key", "state", "actor", "role", "kind", "inactive", "repeated"]
)
def test_execution_clock_only_changes_domain_time_for_owned_inflight_admission(monkeypatch, fault):
    from app.dashboard.operations import parse_preparation
    from app.dashboard.store import SessionStore
    from app.security.authentication import Principal
    from app.services import remediation_service
    from tests.dashboard_integrated_execution_expiry import ExecutionExpiryClock

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    now = datetime(2026, 10, 17, tzinfo=UTC)
    clock = ExecutionExpiryClock("test-issuer", clock=lambda: now)
    store = SessionStore(clock=lambda: 1000.0)
    actor = Principal("requester", frozenset({"ADMIN"}), "test-issuer")
    identifier = store.create("synthetic", actor, 1299.0 if fault == "clipped" else 4600.0)
    document = dict(
        schema_version="1.0.0",
        operation="REQUEST_EXECUTION" if fault != "kind" else "DECIDE",
        target_id=str(uuid4()),
        input=dict(
            proposal_sha256="a" * 64,
            reason="Expired admission never becomes fresh authority.",
            **(
                {"approval_decision_id": str(uuid4())}
                if fault != "kind"
                else {"decision": "APPROVE"}
            ),
        ),
    )
    prepared = store.prepare(identifier, actor, parse_preparation(json.dumps(document).encode()))
    if fault != "state":
        store.claim(identifier, actor, prepared.operation_id)
    if fault in {"actor", "role"}:
        store._sessions[identifier].principal = Principal(
            "other" if fault == "actor" else "requester",
            frozenset({"VIEWER"}) if fault == "role" else actor.role_names,
            actor.issuer,
        )
    before = dict(store._operations)
    owner = store._sessions[identifier]
    credentials = (owner.access_token, owner.csrf, owner.context, owner.expires, owner.idle_expires)
    with nullcontext() if fault == "inactive" else clock.installed():
        assert clock() == now - timedelta(seconds=301)
        if fault not in {None, "clipped", "repeated"}:
            with pytest.raises(ValueError, match="Integrated execution clock rejected"):
                clock.expire_after_commit(
                    store, uuid4() if fault == "key" else prepared.operation_id
                )
            assert clock.shift == -301
        else:
            assert remediation_service.RemediationService(object()).clock() == clock()
            clock.expire_after_commit(store, prepared.operation_id)
            assert clock() == now
            assert remediation_service.RemediationService(object()).clock() == now
            if fault == "repeated":
                with pytest.raises(ValueError, match="Integrated execution clock rejected"):
                    clock.expire_after_commit(store, prepared.operation_id)
        assert store._operations == before and store.clock() == 1000.0
        assert credentials == (
            owner.access_token,
            owner.csrf,
            owner.context,
            owner.expires,
            owner.idle_expires,
        )
    assert remediation_service.datetime is datetime


@pytest.mark.parametrize("flag", [None, "true"])
def test_execution_clock_and_historical_source_require_exact_test_mode(monkeypatch, flag):
    from tests.dashboard_integrated_execution_expiry import (
        ExecutionExpiryClock,
        historical_execution_source,
    )

    monkeypatch.delenv("DASHBOARD_BROWSER_TEST", raising=False)
    if flag is not None:
        monkeypatch.setenv("DASHBOARD_BROWSER_TEST", flag)
    with pytest.raises(ValueError, match="Integrated execution clock rejected"):
        with ExecutionExpiryClock("test-issuer").installed():
            pytest.fail("No application import or clock patch without exact test mode")
    with pytest.raises(ValueError, match="Integrated historical source rejected"):
        historical_execution_source(object())


def test_historical_source_uses_original_factory_and_restores_only_its_clock(monkeypatch):
    from tests import verification_acceptance
    from tests.dashboard_integrated_execution_expiry import historical_execution_source

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    engine, result, observed = object(), object(), []

    def factory(value):
        assert value is engine
        observed.append(verification_acceptance.datetime.now(UTC))
        return result

    monkeypatch.setattr(verification_acceptance, "full_scope_source", factory)
    before = datetime.now(UTC)
    assert historical_execution_source(engine) is result
    after = datetime.now(UTC)
    assert before - timedelta(seconds=600) <= observed[0] <= after - timedelta(seconds=600)
    assert verification_acceptance.datetime is datetime


def test_execution_clock_rejects_nested_installation_and_naive_time(monkeypatch):
    from app.services import remediation_service
    from tests.dashboard_integrated_execution_expiry import ExecutionExpiryClock

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    clock = ExecutionExpiryClock("test-issuer")
    with clock.installed():
        with pytest.raises(ValueError, match="Integrated execution clock rejected"):
            with clock.installed():
                pytest.fail("No nested clock")
    assert remediation_service.datetime is datetime
    with pytest.raises(ValueError, match="Integrated execution clock rejected"):
        ExecutionExpiryClock("test-issuer", clock=lambda: datetime(2026, 10, 17))()
