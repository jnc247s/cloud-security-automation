"""Preparation is typed ephemeral coordination, not authorization or cancellation."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from uuid import UUID, uuid4

import pytest

from app.dashboard.operations import (
    MAX_PREPARATION_BYTES,
    InvalidPreparation,
    OperationExpired,
    OperationKind,
    OperationState,
    OperationUnavailable,
    ResultReference,
    parse_preparation,
)
from app.dashboard.store import CapacityError, SessionStore
from app.remediation.contracts import ACTION_ID, ACTION_VERSION
from app.security.authentication import Principal
from app.security.authorization import Capability

ACTOR = Principal("human", frozenset({"ADMIN"}), "https://issuer.example.test")
TARGET = str(uuid4())
FINDING = str(uuid4())
OCCURRENCE = str(uuid4())
APPROVAL = str(uuid4())


def document(operation="PROPOSE"):
    body = {"reason": "  Review workload and KMS compatibility.  "}
    result = {"schema_version": "1.0.0", "operation": operation, "input": body}
    if operation == "PROPOSE":
        body.update(finding_id=FINDING, occurrence_id=OCCURRENCE)
    else:
        result["target_id"] = TARGET
        if operation != "REQUEST_VERIFICATION":
            body["proposal_sha256"] = "a" * 64
        if operation == "DECIDE":
            body["decision"] = "APPROVE"
        if operation in {"REVOKE", "REQUEST_EXECUTION"}:
            body["approval_decision_id"] = APPROVAL
    return result


def preparation(operation="PROPOSE"):
    return parse_preparation(json.dumps(document(operation)).encode())


def store_with_session(*, token_expiry=10000, now=None):
    now = [0.0] if now is None else now
    store = SessionStore(clock=lambda: now[0])
    session_id = store.create("must-not-be-stored-in-an-operation", ACTOR, token_expiry)
    return store, session_id, now


@pytest.mark.parametrize(
    ("operation", "path", "capability"),
    [
        ("PROPOSE", "/api/v1/remediations", Capability.PROPOSE),
        ("DECIDE", f"/api/v1/remediations/{TARGET}/decisions", Capability.APPROVE),
        ("REVOKE", f"/api/v1/remediations/{TARGET}/revocations", Capability.APPROVE),
        ("REQUEST_EXECUTION", f"/api/v1/remediations/{TARGET}/executions", Capability.EXECUTE),
        (
            "REQUEST_VERIFICATION",
            f"/api/v1/remediation-executions/{TARGET}/verifications",
            Capability.EXECUTE,
        ),
    ],
    ids=["propose", "decision", "revocation", "execution", "verification"],
)
def test_closed_fixed_paths_and_normalized_frozen_body(operation, path, capability):
    value = preparation(operation)
    assert value.kind == OperationKind(operation)
    assert value.path == path and value.capability == capability
    body = json.loads(value.body_json)
    assert body["reason"] == "Review workload and KMS compatibility."
    if operation == "PROPOSE":
        assert body == {
            "reason": "Review workload and KMS compatibility.",
            "finding_id": FINDING,
            "occurrence_id": OCCURRENCE,
            "action_id": ACTION_ID,
            "action_version": ACTION_VERSION,
        }
    with pytest.raises(FrozenInstanceError):
        value.body_json = "{}"


@pytest.mark.parametrize("operation", list(OperationKind))
@pytest.mark.parametrize("extra", ["url", "method", "role", "credentials", "idempotency_key"])
def test_no_generic_forwarding_or_browser_selected_security_inputs(operation, extra):
    request = document(operation)
    request[extra] = "must-not-be-accepted"
    with pytest.raises(InvalidPreparation):
        parse_preparation(json.dumps(request).encode())


@pytest.mark.parametrize(
    "extra", ["action_id", "action_version", "desired_state", "account_id", "endpoint", "roles"]
)
def test_proposal_action_scope_and_authority_are_not_browser_parameters(extra):
    request = document()
    request["input"][extra] = "not-allowed"
    with pytest.raises(InvalidPreparation):
        parse_preparation(json.dumps(request).encode())


@pytest.mark.parametrize("value", [True, 1, 1.2, None, [], {}])
@pytest.mark.parametrize("field", ["reason", "finding_id", "occurrence_id"])
def test_rejects_coercive_input_scalars(field, value):
    request = document()
    request["input"][field] = value
    with pytest.raises(InvalidPreparation):
        parse_preparation(json.dumps(request).encode())


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"null",
        b"[]",
        b'{"operation":"PROPOSE","operation":"DECIDE"}',
        b'{"input":{"reason":"one","reason":"two"}}',
        b'{"secret":"do-not-echo", "number":NaN}',
        b'{"number":Infinity}',
        b'{"number":-Infinity}',
        b'{"reason":"\xff"}',
        b'{"reason":"\\ud800"}',
        b"\xef\xbb\xbf{}",
        "{}".encode("utf-16"),
        b"[" * 2000 + b"]" * 2000,
        b" " * (MAX_PREPARATION_BYTES + 1),
    ],
    ids=[
        "empty-object",
        "null",
        "array",
        "duplicate-operation",
        "duplicate-input",
        "nan",
        "positive-infinity",
        "negative-infinity",
        "invalid-utf8",
        "lone-surrogate",
        "bom",
        "utf16",
        "depth",
        "oversized",
    ],
)
def test_malformed_and_duplicate_json_is_sanitized(raw):
    with pytest.raises(InvalidPreparation) as caught:
        parse_preparation(raw)
    assert "do-not-echo" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "operation", ["PROPOSE", "DECIDE", "REVOKE", "REQUEST_EXECUTION", "REQUEST_VERIFICATION"]
)
def test_unsupported_version_unknown_operation_and_blank_reason_reject(operation):
    for changed in (
        {"schema_version": "2.0.0"},
        {"schema_version": 1},
        {"operation": "ARBITRARY"},
        {"input": {**document(operation)["input"], "reason": "  "}},
    ):
        with pytest.raises(InvalidPreparation):
            parse_preparation(json.dumps({**document(operation), **changed}).encode())


def test_unicode_reason_uses_utf8_byte_budget_and_existing_reason_limit():
    request = document()
    request["input"]["reason"] = "\U0001f512" * 2000
    raw = json.dumps(request, ensure_ascii=False).encode()
    assert len(raw) < MAX_PREPARATION_BYTES
    assert json.loads(parse_preparation(raw).body_json)["reason"] == request["input"]["reason"]
    request["input"]["reason"] += "x"
    with pytest.raises(InvalidPreparation):
        parse_preparation(json.dumps(request, ensure_ascii=False).encode())


def test_same_session_reload_sees_frozen_state_without_secrets_or_mutable_references():
    store, session_id, _ = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation())
    assert isinstance(value.operation_id, UUID)
    assert value.operation_id.version == 4
    assert value.state == OperationState.PREPARED and value.attempts == 0
    assert store.operations(session_id, ACTOR) == (value,)
    assert store.operation(session_id, ACTOR, value.operation_id) == value
    assert set(vars(value)) == {
        "operation_id",
        "session_id",
        "actor",
        "input",
        "prepared_at",
        "expires_at",
        "state",
        "attempts",
        "result",
    }
    for private in [
        session_id,
        ACTOR.subject,
        ACTOR.issuer,
        "Review workload",
        "must-not-be-stored",
    ]:
        assert private not in repr(value)
    with pytest.raises(FrozenInstanceError):
        value.state = OperationState.CONFIRMED


@pytest.mark.parametrize(
    "actor",
    [
        Principal("different", ACTOR.role_names, ACTOR.issuer),
        Principal(ACTOR.subject, ACTOR.role_names, "https://other.example.test"),
    ],
)
def test_actor_is_full_issuer_subject_pair_not_display_name(actor):
    store, session_id, _ = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation())
    with pytest.raises(OperationUnavailable):
        store.operations(session_id, actor)
    with pytest.raises(OperationUnavailable):
        store.claim(session_id, actor, value.operation_id)
    with pytest.raises(OperationUnavailable):
        store.prepare(session_id, actor, preparation())
    assert store.operation(session_id, ACTOR, value.operation_id) == value


def test_different_session_cannot_recover_or_claim_even_same_identity():
    store, session_id, _ = store_with_session()
    other = store.create("another-token", ACTOR, 10000)
    value = store.prepare(session_id, ACTOR, preparation())
    assert store.operations(other, ACTOR) == ()
    with pytest.raises(OperationUnavailable):
        store.operation(other, ACTOR, value.operation_id)
    with pytest.raises(OperationUnavailable):
        store.claim(other, ACTOR, value.operation_id)


@pytest.mark.parametrize(
    "token_expiry,prepared_at,deadline", [(10000, 0, 300), (120, 0, 120), (10000, 800, 900)]
)
def test_nonrenewing_five_minute_preparation_and_existing_session_deadlines(
    token_expiry, prepared_at, deadline
):
    store, session_id, now = store_with_session(token_expiry=token_expiry)
    now[0] = prepared_at
    value = store.prepare(session_id, ACTOR, preparation())
    assert value.expires_at == deadline
    assert store.get(session_id, touch=False).idle_expires == 900
    if deadline == token_expiry:
        now[0] = deadline
        with pytest.raises(OperationUnavailable):
            store.claim(session_id, ACTOR, value.operation_id)
    else:
        store.get(session_id)  # Even ordinary session activity cannot renew preparation.
        now[0] = deadline
        assert (
            store.operation(session_id, ACTOR, value.operation_id).state == OperationState.EXPIRED
        )
        with pytest.raises(OperationExpired):
            store.claim(session_id, ACTOR, value.operation_id)


def test_in_flight_claim_is_atomic_and_never_dispatches_twice_concurrently():
    store, session_id, _ = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation())
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: store.claim(session_id, ACTOR, value.operation_id), range(32))
        )
    assert sum(dispatch for _, dispatch in results) == 1
    assert all(
        result.attempts == 1 and result.state == OperationState.IN_FLIGHT for result, _ in results
    )


def test_explicit_uncertain_retry_preserves_key_actor_body_and_rejects_old_settlement():
    store, session_id, _ = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation())
    first, dispatch = store.claim(session_id, ACTOR, value.operation_id)
    assert dispatch
    uncertain = store.settle(session_id, ACTOR, value.operation_id, first.attempts, None)
    assert uncertain.state == OperationState.UNCONFIRMED
    # Role metadata is not cached authorization; routes must check current capabilities.
    fresh_actor = Principal(ACTOR.subject, frozenset({"ANALYST"}), ACTOR.issuer)
    second, dispatch = store.claim(session_id, fresh_actor, value.operation_id)
    assert dispatch and second.attempts == 2
    assert (second.actor, second.operation_id, second.input) == (
        first.actor,
        first.operation_id,
        first.input,
    )
    assert store.settle(session_id, ACTOR, value.operation_id, first.attempts, None) == second
    reference = ResultReference(uuid4())
    confirmed = store.settle(session_id, ACTOR, value.operation_id, second.attempts, reference)
    assert confirmed.state == OperationState.CONFIRMED and confirmed.result == reference
    assert store.claim(session_id, ACTOR, value.operation_id) == (confirmed, False)
    assert store.settle(session_id, ACTOR, value.operation_id, second.attempts, None) == confirmed


@pytest.mark.parametrize("complete_before_expiry", [False, True])
def test_forwarded_uncertainty_survives_expiry_without_a_renewed_grant(complete_before_expiry):
    store, session_id, now = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation())
    first, _ = store.claim(session_id, ACTOR, value.operation_id)
    if complete_before_expiry:
        store.settle(session_id, ACTOR, value.operation_id, first.attempts, None)
    now[0] = 300
    if not complete_before_expiry:
        assert (
            store.operation(session_id, ACTOR, value.operation_id).state == OperationState.IN_FLIGHT
        )
        store.settle(session_id, ACTOR, value.operation_id, first.attempts, None)
    assert (
        store.operation(session_id, ACTOR, value.operation_id).state == OperationState.UNCONFIRMED
    )
    with pytest.raises(OperationExpired):
        store.claim(session_id, ACTOR, value.operation_id)
    assert (
        store.operation(session_id, ACTOR, value.operation_id).state == OperationState.UNCONFIRMED
    )


@pytest.mark.parametrize("invalidate", ["logout", "idle", "token", "shutdown"])
def test_session_loss_removes_coordination_and_late_results_cannot_restore_it(invalidate):
    store, session_id, now = store_with_session(
        token_expiry=200 if invalidate == "token" else 10000
    )
    value = store.prepare(session_id, ACTOR, preparation())
    first, _ = store.claim(session_id, ACTOR, value.operation_id)
    if invalidate == "logout":
        store.revoke(session_id)
    elif invalidate == "shutdown":
        store.clear()
    else:
        now[0] = 900 if invalidate == "idle" else 200
    with pytest.raises(OperationUnavailable):
        store.settle(
            session_id, ACTOR, value.operation_id, first.attempts, ResultReference(uuid4())
        )
    assert store._operations == {}
    with pytest.raises(OperationUnavailable):
        SessionStore().operations(session_id, ACTOR)


def test_trusted_history_can_confirm_a_dispatched_result_after_preparation_expiry():
    store, session_id, now = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation("REQUEST_VERIFICATION"))
    first, _ = store.claim(session_id, ACTOR, value.operation_id)
    now[0] = 300
    reference = ResultReference(uuid4(), uuid4())
    confirmed = store.settle(session_id, ACTOR, value.operation_id, first.attempts, reference)
    assert confirmed.state == OperationState.CONFIRMED and confirmed.result == reference
    assert store.claim(session_id, ACTOR, value.operation_id) == (confirmed, False)


def test_settlement_never_confirms_a_prepared_or_expired_unsubmitted_operation():
    store, session_id, now = store_with_session()
    value = store.prepare(session_id, ACTOR, preparation())
    reference = ResultReference(uuid4())
    assert store.settle(session_id, ACTOR, value.operation_id, 0, reference) == value
    now[0] = 300
    unused = store.settle(session_id, ACTOR, value.operation_id, 0, reference)
    assert unused.state == OperationState.EXPIRED and unused.result is None


def test_capacity_never_evicts_expired_or_uncertain_entries_of_a_live_session():
    store, session_id, now = store_with_session()
    values = [store.prepare(session_id, ACTOR, preparation()) for _ in range(16)]
    first, _ = store.claim(session_id, ACTOR, values[0].operation_id)
    store.settle(session_id, ACTOR, first.operation_id, first.attempts, None)
    for instant in [0, 300]:
        now[0] = instant
        with pytest.raises(CapacityError):
            store.prepare(session_id, ACTOR, preparation())
        assert len(store.operations(session_id, ACTOR)) == 16
        assert (
            store.operation(session_id, ACTOR, first.operation_id).state
            == OperationState.UNCONFIRMED
        )


def test_global_capacity_rejects_without_eviction_and_only_session_loss_reclaims_it():
    store, first, _ = store_with_session()
    identifiers = [first] + [store.create("another-token", ACTOR, 10000) for _ in range(16)]
    for session_id in identifiers[:16]:
        for _ in range(16):
            store.prepare(session_id, ACTOR, preparation())
    with pytest.raises(CapacityError):
        store.prepare(identifiers[-1], ACTOR, preparation())
    assert sum(len(store.operations(identifier, ACTOR)) for identifier in identifiers) == 256
    store.revoke(first)
    assert store.prepare(identifiers[-1], ACTOR, preparation())
