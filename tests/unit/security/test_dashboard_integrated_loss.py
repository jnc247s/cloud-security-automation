"""Transport-only unit guards; native/PostgreSQL tests separately prove real signed commit."""

import asyncio
from uuid import UUID, uuid4

import httpx2 as httpx
import pytest
from starlette.responses import JSONResponse

from tests.dashboard_integrated_loss import CommittedProposalReplyLoss


@pytest.mark.parametrize(
    "fault", [None, "clipped", "key", "state", "actor", "role", "kind", "not-installed", "repeated"]
)
def test_proposal_clock_changes_only_owned_service_time_after_commit(fault, monkeypatch):
    import json
    from contextlib import nullcontext
    from datetime import UTC, datetime, timedelta

    from app.dashboard.operations import parse_preparation
    from app.dashboard.store import SessionStore
    from app.security.authentication import Principal
    from app.services import remediation_service
    from tests.dashboard_integrated_authority_expiry import ProposalExpiryClock

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    now = datetime(2026, 10, 17, tzinfo=UTC)
    clock = ProposalExpiryClock("test-issuer", clock=lambda: now)
    store = SessionStore(clock=lambda: 1000.0)
    actor = Principal("proposer", frozenset({"ANALYST"}), "test-issuer")
    identifier = store.create("synthetic", actor, 1299.0 if fault == "clipped" else 4600.0)
    document = dict(
        schema_version="1.0.0",
        operation="PROPOSE",
        input=dict(finding_id=str(uuid4()), occurrence_id=str(uuid4()), reason="Expired authority"),
    )
    if fault == "kind":
        document.update(
            operation="DECIDE",
            target_id=str(uuid4()),
            input=dict(proposal_sha256="a" * 64, decision="APPROVE", reason="Expired authority"),
        )
    value = store.prepare(identifier, actor, parse_preparation(json.dumps(document).encode()))
    if fault != "state":
        store.claim(identifier, actor, value.operation_id)
    if fault in {"actor", "role"}:
        store._sessions[identifier].principal = Principal(
            "other" if fault == "actor" else "proposer",
            frozenset({"ADMIN"}) if fault == "role" else actor.role_names,
            actor.issuer,
        )
    before, session = dict(store._operations), store._sessions[identifier]
    private = (
        session.access_token,
        session.csrf,
        session.context,
        session.expires,
        session.idle_expires,
    )
    assert remediation_service.datetime is datetime
    with nullcontext() if fault == "not-installed" else clock.installed():
        if fault not in {None, "clipped", "repeated"}:
            with pytest.raises(ValueError, match="Integrated proposal clock rejected"):
                clock.expire_after_commit(store, uuid4() if fault == "key" else value.operation_id)
            assert clock.shift == 0
        else:
            assert remediation_service.RemediationService(object()).clock() == now
            clock.expire_after_commit(store, value.operation_id)
            assert clock() == now + timedelta(days=1, seconds=1)
            assert remediation_service.RemediationService(object()).clock() == clock()
            if fault == "repeated":
                with pytest.raises(ValueError, match="Integrated proposal clock rejected"):
                    clock.expire_after_commit(store, value.operation_id)
        assert store.clock() == 1000.0 and store._operations == before
        assert private == (
            session.access_token,
            session.csrf,
            session.context,
            session.expires,
            session.idle_expires,
        )
    assert remediation_service.datetime is datetime


def test_proposal_clock_rejects_nested_installation_and_naive_time(monkeypatch):
    from datetime import UTC, datetime

    from app.services import remediation_service
    from tests.dashboard_integrated_authority_expiry import ProposalExpiryClock

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    clock = ProposalExpiryClock("test-issuer", clock=lambda: datetime(2026, 10, 17, tzinfo=UTC))
    with clock.installed():
        with pytest.raises(ValueError, match="Integrated proposal clock rejected"):
            with clock.installed():
                raise AssertionError("No nested clock")
    assert remediation_service.datetime is datetime
    invalid = ProposalExpiryClock("test-issuer", clock=lambda: datetime(2026, 10, 17))
    with pytest.raises(ValueError, match="Integrated proposal clock rejected"):
        invalid()


@pytest.mark.parametrize("flag", [None, "true"])
def test_proposal_clock_requires_explicit_browser_test_mode(monkeypatch, flag):
    from tests.dashboard_integrated_authority_expiry import ProposalExpiryClock

    monkeypatch.delenv("DASHBOARD_BROWSER_TEST", raising=False)
    if flag is not None:
        monkeypatch.setenv("DASHBOARD_BROWSER_TEST", flag)
    with pytest.raises(ValueError, match="Integrated proposal clock rejected"):
        with ProposalExpiryClock("test-issuer").installed():
            raise AssertionError("No implicit test mode")


@pytest.mark.parametrize(
    "count,fault",
    [(16, None), (256, None), (16, "capacity"), (16, "state"), (16, "actor"), (16, "clock")],
)
def test_elapsed_preparation_clock_never_renews_or_evicts(count, fault):
    import json

    from app.dashboard.operations import OperationExpired, parse_preparation
    from app.dashboard.store import CapacityError, SessionStore
    from app.security.authentication import Principal
    from tests.dashboard_integrated_expiry import PreparationExpiryClock

    clock = PreparationExpiryClock("test-issuer", count, clock=lambda: 1000.0)
    store = SessionStore(clock=clock)
    actor = Principal("proposer", frozenset({"ANALYST"}), "test-issuer")
    inputs = parse_preparation(
        json.dumps(
            dict(
                schema_version="1.0.0",
                operation="PROPOSE",
                input=dict(
                    finding_id=str(uuid4()),
                    occurrence_id=str(uuid4()),
                    reason="Reviewed expiry target",
                ),
            )
        ).encode()
    )
    sessions, records = [], []
    for index in range(count - (fault == "capacity")):
        if index % 16 == 0:
            sessions.append(store.create("synthetic", actor, 4600.0))
        records.append(store.prepare(sessions[-1], actor, inputs))
    target = records[0]
    if fault != "state":
        store.claim(sessions[0], actor, target.operation_id)
    if fault == "actor":
        store._sessions[sessions[0]].principal = Principal("other", actor.role_names, actor.issuer)
    if fault == "clock":
        store.clock = lambda: 1000.0
    before = dict(store._operations)
    if fault:
        with pytest.raises(ValueError, match="Integrated preparation clock rejected"):
            clock.expire_after_commit(store, target.operation_id)
        assert clock() == 1000.0 and store._operations == before
    else:
        clock.expire_after_commit(store, target.operation_id)
        assert clock() == 1301.0 and store._operations == before
        settled = store.settle(sessions[0], actor, target.operation_id, 1, None)
        assert (
            settled.state.value == "UNCONFIRMED"
            and settled.attempts == 1
            and settled.result is None
        )
        current = [
            value for identifier in sessions for value in store.operations(identifier, actor)
        ]
        assert (
            len(current) == count
            and sum(value.state.value == "EXPIRED" for value in current) == count - 1
        )
        for value in current:
            assert value.prepared_at == 1000.0 and value.expires_at == 1300.0
        with pytest.raises(OperationExpired):
            store.claim(sessions[0], actor, target.operation_id)
        with pytest.raises(CapacityError):
            store.prepare(sessions[0], actor, inputs)
        with pytest.raises(ValueError, match="Integrated preparation clock rejected"):
            clock.expire_after_commit(store, target.operation_id)


@pytest.mark.parametrize("scenario", ["subject-replacement", "issuer-rejection"])
@pytest.mark.parametrize(
    "fault", [None, "key", "state", "actor", "role", "signature", "mode", "environment", "deadline"]
)
def test_signed_identity_substitution_is_closed_owned_and_preserves_coordination(
    monkeypatch, scenario, fault
):
    import time

    import jwt

    from app.dashboard.operations import OperationState, parse_preparation
    from app.dashboard.store import SessionStore
    from app.security.authentication import Principal
    from tests.dashboard_fixtures import ControlledIssuer
    from tests.dashboard_integrated_identity import replace_operation_identity

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    issuer, now = ControlledIssuer(), int(time.time())
    store = SessionStore(clock=lambda: now)
    principal = Principal("proposer", frozenset({"ANALYST"}), issuer.issuer)
    claims = dict(
        iss=issuer.issuer,
        sub="proposer",
        aud=issuer.audience,
        iat=now,
        exp=now + 300,
        token_use="access",
        **{"cognito:groups": ["ANALYST"]},
    )
    if fault == "role":
        claims["cognito:groups"] = ["ADMIN"]
    signing_key = ControlledIssuer().key if fault == "signature" else issuer.key
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "dashboard-test"})
    identifier = store.create(token, principal, now + (301 if fault == "deadline" else 300))
    value = store.prepare(
        identifier,
        principal,
        parse_preparation(
            b'{"schema_version":"1.0.0","operation":"PROPOSE","input":{'
            b'"finding_id":"12345678-1234-4123-8123-123456789abc",'
            b'"occurrence_id":"22345678-1234-4123-8123-123456789abc","reason":"Reviewed target"}}'
        ),
    )
    if fault != "state":
        store.claim(identifier, principal, value.operation_id)
    session = store._sessions[identifier]
    if fault == "actor":
        session.principal = Principal("other", frozenset({"ANALYST"}), issuer.issuer)
    if fault == "environment":
        monkeypatch.delenv("DASHBOARD_BROWSER_TEST")
    snapshot = (
        session.csrf,
        session.context,
        session.principal,
        session.expires,
        session.idle_expires,
        dict(store._operations),
        dict(store._sessions),
    )
    if fault:
        with pytest.raises(ValueError, match="Integrated identity substitution rejected"):
            replace_operation_identity(
                store,
                issuer,
                uuid4() if fault == "key" else value.operation_id,
                "verified" if fault == "mode" else scenario,
            )
        assert session.access_token == token
    else:
        owner, original, replacement = replace_operation_identity(
            store, issuer, value.operation_id, scenario
        )
        assert owner == identifier and original == token and replacement == session.access_token
        changed = jwt.decode(
            replacement,
            issuer.key.public_key(),
            algorithms=["RS256"],
            audience=issuer.audience,
            options={"verify_iss": False},
        )
        expected = {
            **claims,
            **(
                {"sub": "replacement-subject"}
                if scenario == "subject-replacement"
                else {"iss": "http://127.0.0.1:9032/untrusted-issuer"}
            ),
        }
        assert changed == expected and replacement != original
        assert store._operations[value.operation_id].state is OperationState.IN_FLIGHT
        with pytest.raises(ValueError, match="Integrated identity substitution rejected"):
            replace_operation_identity(store, issuer, value.operation_id, scenario)
        assert session.access_token == replacement
    assert snapshot == (
        session.csrf,
        session.context,
        session.principal,
        session.expires,
        session.idle_expires,
        dict(store._operations),
        dict(store._sessions),
    )


@pytest.mark.parametrize("fault", [None, "key", "state", "actor", "role", "signature"])
def test_signed_capability_loss_changes_only_owned_token_and_untrusted_hint(fault):
    import time

    import jwt

    from app.dashboard.operations import OperationState, parse_preparation
    from app.dashboard.store import SessionStore
    from app.security.authentication import Principal
    from tests.dashboard_fixtures import ControlledIssuer
    from tests.dashboard_integrated_identity import narrow_operation_to_viewer

    issuer = ControlledIssuer()
    now = int(time.time())
    store = SessionStore(clock=lambda: now)
    principal = Principal("proposer", frozenset({"ANALYST"}), issuer.issuer)
    claims = dict(
        iss=issuer.issuer,
        sub=principal.subject,
        aud=issuer.audience,
        iat=now,
        exp=now + 300,
        token_use="access",
        **{"cognito:groups": ["ANALYST"]},
    )
    if fault == "role":
        claims["cognito:groups"] = ["ADMIN"]
    signing_key = ControlledIssuer().key if fault == "signature" else issuer.key
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "dashboard-test"})
    identifier = store.create(token, principal, now + 300)
    value = store.prepare(
        identifier,
        principal,
        parse_preparation(
            b'{"schema_version":"1.0.0","operation":"PROPOSE","input":{'
            b'"finding_id":"12345678-1234-4123-8123-123456789abc",'
            b'"occurrence_id":"22345678-1234-4123-8123-123456789abc",'
            b'"reason":"Reviewed target"}}'
        ),
    )
    if fault != "state":
        store.claim(identifier, principal, value.operation_id)
    if fault == "actor":
        store._sessions[identifier].principal = Principal(
            "other", frozenset({"ANALYST"}), issuer.issuer
        )
    session = store._sessions[identifier]
    snapshot = (
        session.csrf,
        session.context,
        session.expires,
        session.idle_expires,
        store._operations[value.operation_id],
    )
    if fault:
        with pytest.raises(ValueError, match="Integrated signed capability loss rejected"):
            narrow_operation_to_viewer(
                store, issuer, uuid4() if fault == "key" else value.operation_id
            )
        assert session.access_token == token
    else:
        narrow_operation_to_viewer(store, issuer, value.operation_id)
        signed = jwt.decode(
            session.access_token,
            issuer.key.public_key(),
            algorithms=["RS256"],
            audience=issuer.audience,
            issuer=issuer.issuer,
        )
        assert signed == {**claims, "cognito:groups": ["VIEWER"]}
        assert session.principal.role_names == frozenset({"ADMIN"})
        assert (
            session.principal.subject == principal.subject
            and session.principal.issuer == principal.issuer
        )
        assert store._operations[value.operation_id].state is OperationState.IN_FLIGHT
    assert snapshot == (
        session.csrf,
        session.context,
        session.expires,
        session.idle_expires,
        store._operations[value.operation_id],
    )


@pytest.mark.parametrize("binary", [False, True], ids=["text", "bff-utf8-bytes"])
def test_only_first_committed_reply_is_lost_and_original_request_is_unchanged(monkeypatch, binary):
    gate, calls, proofs = CommittedProposalReplyLoss(None, issuer="test-issuer"), [], []
    key, body = str(uuid4()), '{"reason":"synthetic private test input"}'
    wire_body = body.encode() if binary else body

    async def app(scope, receive, send):
        request = await receive()
        calls.append((scope["path"], request["body"]))
        await JSONResponse({}, status_code=201 if len(calls) == 1 else 200)(scope, receive, send)

    monkeypatch.setattr(
        gate, "_prove", lambda response, value: proofs.append((response.status_code, value))
    )

    async def story():
        original = httpx.AsyncClient.post
        with gate.installed():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://internal.invalid",
                trust_env=False,
            ) as client:
                with pytest.raises(
                    httpx.ReadTimeout, match="Synthetic committed proposal response loss"
                ):
                    await client.post(
                        "/api/v1/remediations", content=wire_body, headers={"Idempotency-Key": key}
                    )
                assert gate.losses == 1 and len(calls) == 1
                replay = await client.post(
                    "/api/v1/remediations", content=wire_body, headers={"Idempotency-Key": key}
                )
                assert replay.status_code == 200
        assert httpx.AsyncClient.post is original

    asyncio.run(asyncio.wait_for(story(), timeout=3))
    assert gate.losses == 1 and proofs == [(201, UUID(key))]
    assert len(gate.requests) == 2 and gate.requests[0] == gate.requests[1]
    assert calls == [("/api/v1/remediations", body.encode())] * 2


@pytest.mark.parametrize("status", [400, 401, 403, 409, 500])
def test_denied_or_failed_request_is_not_fabricated_as_committed_loss(monkeypatch, status):
    gate = CommittedProposalReplyLoss(None, issuer="test-issuer")

    async def app(scope, receive, send):
        await JSONResponse({}, status_code=status)(scope, receive, send)

    def forbidden(*_args):
        raise AssertionError("Rejected response is not committed authority")

    monkeypatch.setattr(gate, "_prove", forbidden)

    async def story():
        with gate.installed():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://internal.invalid",
                trust_env=False,
            ) as client:
                result = await client.post(
                    "/api/v1/remediations", content="{}", headers={"Idempotency-Key": str(uuid4())}
                )
                assert result.status_code == status

    asyncio.run(asyncio.wait_for(story(), timeout=3))
    assert gate.losses == 0


@pytest.mark.parametrize("body", [None, {}, bytearray(b"{}")])
def test_coercive_or_streaming_bodies_do_not_reach_bearer_transport(body):
    gate, calls = CommittedProposalReplyLoss(None, issuer="test-issuer"), []

    async def forbidden(*_args):
        calls.append(True)
        raise AssertionError("Invalid test transport body reached the API")

    async def story():
        with gate.installed():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=forbidden),
                base_url="http://internal.invalid",
                trust_env=False,
            ) as client:
                with pytest.raises(ValueError, match="Invalid integrated proposal transport"):
                    await client.post(
                        "/api/v1/remediations",
                        content=body,
                        headers={"Idempotency-Key": str(uuid4())},
                    )

    asyncio.run(asyncio.wait_for(story(), timeout=3))
    assert calls == [] and gate.losses == 0 and gate.requests == ()


@pytest.mark.parametrize("binary", [False, True])
def test_committed_reply_stays_held_until_real_duplicate_inflight_response(monkeypatch, binary):
    import json

    from tests.dashboard_integrated_loss import CommittedProposalInFlight, InFlightObserver

    gate = CommittedProposalInFlight(None, issuer="test-issuer")
    assert gate.stage == "WAITING"
    key, body, calls = str(uuid4()), {"reason": "Frozen input"}, []
    monkeypatch.setattr(gate, "_prove", lambda *_args: uuid4())

    async def bearer(scope, receive, send):
        calls.append((await receive())["body"])
        await JSONResponse({}, status_code=201)(scope, receive, send)

    async def duplicate(scope, receive, send):
        await JSONResponse(
            {
                "schema_version": "1.0.0",
                "operation_id": key,
                "operation": "PROPOSE",
                "target_id": None,
                "input": body,
                "actor": {"issuer": "test-issuer", "subject": "proposer"},
                "risk_summary": "test risk",
                "prepared_at": 1.0,
                "expires_at": 301.0,
                "state": "IN_FLIGHT",
                "attempts": 1,
                "result": None,
            }
        )(scope, receive, send)

    async def story():
        with gate.installed():
            async with (
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=bearer),
                    base_url="http://internal.invalid",
                    trust_env=False,
                ) as client,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=InFlightObserver(duplicate, gate=gate)),
                    base_url="http://internal.invalid",
                    trust_env=False,
                ) as browser,
            ):
                encoded = json.dumps(body)
                pending = asyncio.create_task(
                    client.post(
                        "/api/v1/remediations",
                        content=encoded.encode() if binary else encoded,
                        headers={"Idempotency-Key": key},
                    )
                )
                try:
                    while not gate.held:
                        await asyncio.sleep(0.001)
                    assert gate.stage == "HELD"
                    assert not pending.done() and len(calls) == 1
                    response = await browser.post(
                        f"/dashboard/api/remediation-operations/{key}/submit", json={}
                    )
                    assert response.json()["state"] == "IN_FLIGHT"
                    assert gate.released  # ASGI forwarded and validated the real duplicate body.
                    assert (await pending).status_code == 201
                    gate.assert_complete()
                    assert gate.stage == "RETURNED"
                finally:
                    if not pending.done():
                        pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
        assert gate.losses == 0 and len(gate.requests) == 1

    try:
        asyncio.run(asyncio.wait_for(story(), timeout=3))
    except TimeoutError as error:
        error.add_note(
            f"In-flight unit state: stage={gate.stage}; held={gate.held}; "
            f"released={gate.released}; observed={gate._observed}; "
            f"returned={gate._returned}; requests={len(gate.requests)}"
        )
        raise


@pytest.mark.parametrize("other_thread", [False, True])
def test_valid_inflight_response_notifies_waiter_without_another_poll_tick(
    monkeypatch, other_thread
):
    import json

    from tests.dashboard_integrated_loss import CommittedProposalInFlight

    gate, key = CommittedProposalInFlight(None, issuer="test-issuer"), uuid4()
    body = {"reason": "Frozen input"}
    gate._requests = [(key, "synthetic-body-digest")]
    monkeypatch.setattr(gate, "_prove", lambda *_args: None)
    original_sleep = asyncio.sleep

    async def story():
        poll_tick = asyncio.Event()

        async def withheld_tick(delay, *args, **kwargs):
            if delay == 0.005:
                # Model a delayed polling timer, not a delayed authenticated response. A valid
                # observed duplicate must itself notify the waiter; no clock budget is extended.
                await poll_tick.wait()
            else:
                await original_sleep(delay, *args, **kwargs)

        monkeypatch.setattr(asyncio, "sleep", withheld_tick)
        pending = asyncio.create_task(
            gate._committed(httpx.Response(201, json={}), key, json.dumps(body).encode())
        )
        try:
            await original_sleep(0)
            assert gate.held and not pending.done() and not gate.released
            value = dict(
                schema_version="1.0.0",
                operation_id=str(key),
                operation="PROPOSE",
                target_id=None,
                input=body,
                actor={"issuer": "test-issuer", "subject": "proposer"},
                risk_summary="risk",
                prepared_at=1.0,
                expires_at=301.0,
                state="IN_FLIGHT",
                attempts=1,
                result=None,
            )
            args = (f"/dashboard/api/remediation-operations/{key}/submit", 200, value)
            accepted = (
                await asyncio.to_thread(gate.observe_duplicate, *args)
                if other_thread
                else gate.observe_duplicate(*args)
            )
            assert accepted and gate.released and not poll_tick.is_set()
            await pending
            gate.assert_complete()
            assert not poll_tick.is_set() and len(gate.requests) == 1 and gate.losses == 0
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

    asyncio.run(asyncio.wait_for(story(), timeout=3))


def test_cancelled_inflight_wait_clears_signal_without_fabricating_completion(monkeypatch):
    import json

    from tests.dashboard_integrated_loss import CommittedProposalInFlight

    gate, key = CommittedProposalInFlight(None, issuer="test-issuer"), uuid4()
    gate._requests = [(key, "synthetic-body-digest")]
    monkeypatch.setattr(gate, "_prove", lambda *_args: None)

    async def story():
        pending = asyncio.create_task(
            gate._committed(
                httpx.Response(201, json={}), key, json.dumps({"reason": "Frozen"}).encode()
            )
        )
        await asyncio.sleep(0)
        assert gate.held and gate._release_event is not None
        assert gate._wait_loop is asyncio.get_running_loop()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert gate._release_event is gate._wait_loop is None
        assert not gate.released and not gate._returned and gate.stage == "HELD"
        with pytest.raises(ValueError, match="Incomplete integrated in-flight proof"):
            gate.assert_complete()

    asyncio.run(asyncio.wait_for(story(), timeout=3))


@pytest.mark.parametrize(
    "fault", ["key", "actor", "input", "state", "attempts", "result", "extra", "path", "status"]
)
def test_inflight_gate_refuses_unbound_or_noninflight_release(fault):
    from tests.dashboard_integrated_loss import CommittedProposalInFlight

    gate = CommittedProposalInFlight(None, issuer="test-issuer")
    key = uuid4()
    gate._held_key, gate._held_input = key, {"reason": "Frozen input"}
    gate._requests = [(key, "synthetic-body-digest")]
    value = dict(
        schema_version="1.0.0",
        operation_id=str(key),
        operation="PROPOSE",
        target_id=None,
        input=gate._held_input,
        actor={"issuer": "test-issuer", "subject": "proposer"},
        risk_summary="risk",
        prepared_at=1.0,
        expires_at=301.0,
        state="IN_FLIGHT",
        attempts=1,
        result=None,
    )
    path, status = f"/dashboard/api/remediation-operations/{key}/submit", 200
    if fault == "key":
        value["operation_id"] = str(uuid4())
    elif fault == "actor":
        value["actor"] = {"issuer": "other", "subject": "proposer"}
    elif fault == "input":
        value["input"] = {"reason": "Changed"}
    elif fault == "state":
        value["state"] = "CONFIRMED"
    elif fault == "attempts":
        value["attempts"] = True
    elif fault == "result":
        value["result"] = {"result_id": str(uuid4())}
    elif fault == "extra":
        value["extra"] = "ignored"
    elif fault == "path":
        path = path.replace(str(key), str(uuid4()))
    else:
        status = 403
    assert not gate.observe_duplicate(path, status, value)
    assert not gate.released
    with pytest.raises(ValueError, match="Incomplete integrated in-flight proof"):
        gate.assert_complete()
