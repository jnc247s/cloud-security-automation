"""Pure test-parent command guards. These do not authorize or launch an installed worker."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier
from uuid import UUID, uuid4

import pytest

from tests.dashboard_integrated_protocol import (
    MAX_CONTROL_BYTES,
    ControlFence,
    ControlKind,
    ControlProtocolError,
    parse_control,
)

OWNER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REQUEST = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TARGET = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
FOREIGN = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
VERSION1 = "eeeeeeee-eeee-1eee-8eee-eeeeeeeeeeee"


def message(command="RUN_WORKER"):
    value = {
        "schema_version": "1.0.0",
        "instance_id": OWNER,
        "request_id": REQUEST,
        "command": command,
    }
    if command == "RUN_WORKER":
        value["execution_id"] = TARGET
    elif command == "RELEASE_READER":
        value["verification_id"] = TARGET
    elif command in {"RESTART_AUTHORITY", "COLLECT_STALE", "CHANGE_GOVERNANCE"}:
        value["proposal_id"] = TARGET
    return value


def encoded(value):
    return json.dumps(value, ensure_ascii=True).encode("utf-8")


@pytest.mark.parametrize("kind", list(ControlKind))
def test_only_fixed_owned_commands_parse_as_frozen_values(kind):
    result = parse_control(encoded(message(kind)), expected_instance=OWNER)
    assert str(result.instance_id) == OWNER and str(result.request_id) == REQUEST
    assert result.kind is kind
    assert (str(result.target_id) if result.target_id else None) == (
        None if kind is ControlKind.STOP else TARGET
    )
    with pytest.raises(FrozenInstanceError):
        result.target_id = uuid4()


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 1),
        ("schema_version", "2.0.0"),
        ("instance_id", FOREIGN),
        ("instance_id", True),
        ("request_id", None),
        ("request_id", VERSION1),
        ("request_id", REQUEST.upper()),
        ("execution_id", " " + TARGET),
        ("execution_id", "https://untrusted.invalid/target"),
        ("execution_id", 1),
        ("command", "docker"),
        ("command", "run_worker"),
        ("command", ["RUN_WORKER"]),
        ("command", "RUN_WORKER\u0000"),
    ],
)
def test_identity_version_target_and_command_are_not_coerced(field, value):
    document = message()
    document[field] = value
    with pytest.raises(ControlProtocolError, match="^Invalid integrated test control message$"):
        parse_control(encoded(document), expected_instance=OWNER)


@pytest.mark.parametrize(
    "field",
    ["argv", "url", "environment", "database_url", "credentials", "role", "verification_id"],
)
def test_extra_security_or_other_command_fields_are_rejected_without_echo(field):
    document = message()
    document[field] = "synthetic-sensitive-control-input"
    with pytest.raises(ControlProtocolError) as error:
        parse_control(encoded(document), expected_instance=OWNER)
    assert str(error.value) == "Invalid integrated test control message"
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "field", ["schema_version", "instance_id", "request_id", "command", "execution_id"]
)
def test_required_fields_cannot_be_omitted(field):
    document = message()
    del document[field]
    with pytest.raises(ControlProtocolError):
        parse_control(encoded(document), expected_instance=OWNER)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        b"[]",
        b"null",
        b'{"command":"STOP","command":"RUN_WORKER"}',
        b'{"extra":{"x":1,"x":2}}',
        b'{"extra":NaN}',
        b'{"extra":Infinity}',
        b'{"extra":-Infinity}',
        b'{"instance_id":"\\ud800"}',
        b"[" * 1024 + b"]" * 1024,
    ],
    ids=[
        "empty",
        "invalid-utf8",
        "array",
        "null",
        "duplicate-root",
        "duplicate-nested",
        "nan",
        "positive-infinity",
        "negative-infinity",
        "surrogate",
        "depth",
    ],
)
def test_malformed_duplicate_nonfinite_and_unbounded_input_is_sanitized(raw):
    with pytest.raises(ControlProtocolError, match="^Invalid integrated test control message$"):
        parse_control(raw, expected_instance=OWNER)


def test_exact_byte_budget_is_enforced_before_parsing():
    raw = encoded(message())
    maximum = raw + b" " * (MAX_CONTROL_BYTES - len(raw))
    assert parse_control(maximum, expected_instance=OWNER).kind is ControlKind.RUN_WORKER
    with pytest.raises(ControlProtocolError):
        parse_control(maximum + b" ", expected_instance=OWNER)


@pytest.mark.parametrize("owner", [None, True, "not-an-owner", VERSION1, OWNER.upper()])
def test_parent_owner_itself_must_be_a_canonical_uuid4(owner):
    with pytest.raises(ControlProtocolError):
        parse_control(encoded(message()), expected_instance=owner)


def test_stop_and_reader_release_never_accept_an_execution_target():
    for command in ("STOP", "RELEASE_READER"):
        document = message(command)
        document["execution_id"] = TARGET
        with pytest.raises(ControlProtocolError):
            parse_control(encoded(document), expected_instance=OWNER)


def test_input_is_bytes_only_and_foreign_instance_is_not_a_shared_channel():
    with pytest.raises(ControlProtocolError):
        parse_control(json.dumps(message()), expected_instance=OWNER)
    with pytest.raises(ControlProtocolError):
        parse_control(encoded(message()), expected_instance=FOREIGN)


def control(document=None):
    return parse_control(
        encoded(message() if document is None else document), expected_instance=OWNER
    )


def test_concurrent_claims_dispatch_once_without_locking_external_work():
    fence, command, barrier = ControlFence(), control(), Barrier(8)

    def claim():
        barrier.wait(timeout=3)
        return fence.claim(command)

    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = [pool.submit(claim) for _ in range(8)]
        values = [value.result(timeout=5) for value in pending]
    assert sum(claimed for _, claimed in values) == 1
    assert all(
        reply.state == "IN_FLIGHT" and reply.effects_canceled is False for reply, _ in values
    )


@pytest.mark.parametrize(
    "state",
    ["UNCONFIRMED", "REJECTED", "WORKER_ACKNOWLEDGED", "WORKER_QUARANTINED", "READER_RELEASED"],
)
def test_identical_control_replay_never_claims_again(state):
    kind = "RELEASE_READER" if state == "READER_RELEASED" else "RUN_WORKER"
    fence, command = ControlFence(), control(message(kind))
    assert fence.claim(command)[1] is True
    settled = fence.finish(command, state)
    assert fence.claim(command) == (settled, False)


def test_control_conflicts_cannot_replace_request_or_target():
    fence, command = ControlFence(), control()
    assert fence.claim(command)[1]
    changed = message()
    changed["execution_id"] = FOREIGN
    with pytest.raises(ControlProtocolError):
        fence.claim(control(changed))
    changed = message()
    changed["request_id"] = FOREIGN
    with pytest.raises(ControlProtocolError):
        fence.claim(control(changed))
    assert fence.claim(command)[1] is False


def test_capacity_keeps_uncertain_messages_instead_of_evicting():
    fence, original = ControlFence(), None
    for number in range(32):
        document = message()
        document["request_id"] = str(UUID(int=number + 1, version=4))
        document["execution_id"] = str(UUID(int=number + 101, version=4))
        command = control(document)
        original = original or command
        assert fence.claim(command)[1]
        fence.finish(command, "UNCONFIRMED")
    with pytest.raises(ControlProtocolError):
        fence.claim(control())
    assert fence.claim(original)[0].state == "UNCONFIRMED"
    assert fence.claim(original)[1] is False


def test_close_never_claims_cancellation_or_restores_late_results():
    fence, command = ControlFence(), control()
    assert fence.claim(command)[1]
    stop = message("STOP")
    stop["request_id"] = FOREIGN
    stopped = fence.close(control(stop))
    assert stopped.state == "CLOSED" and stopped.effects_canceled is False
    late = fence.finish(command, "WORKER_ACKNOWLEDGED")
    assert late.state == "CLOSED" and late.effects_canceled is False
    assert fence.claim(command)[1] is False
    assert fence.closed is True


def test_missing_repeated_or_mismatched_settlement_fails_closed():
    fence, command = ControlFence(), control()
    with pytest.raises(ControlProtocolError):
        fence.finish(command, "WORKER_ACKNOWLEDGED")
    assert fence.claim(command)[1]
    document = message()
    document["execution_id"] = FOREIGN
    with pytest.raises(ControlProtocolError):
        fence.finish(control(document), "WORKER_ACKNOWLEDGED")
    fence.finish(command, "UNCONFIRMED")
    with pytest.raises(ControlProtocolError):
        fence.finish(command, "WORKER_ACKNOWLEDGED")


@pytest.mark.parametrize("state", ["VERIFIED", "CANCELED", "PREPARED", "IN_FLIGHT", "unknown"])
def test_control_settlement_cannot_invent_domain_verdicts(state):
    fence, command = ControlFence(), control()
    assert fence.claim(command)[1]
    with pytest.raises(ControlProtocolError):
        fence.finish(command, state)


def test_no_write_is_a_closed_non_canceling_worker_reply_and_is_replay_fenced():
    fence, command = ControlFence(), control()
    assert fence.claim(command)[1]
    reply = fence.finish(command, "WORKER_NO_WRITE")
    assert reply.effects_canceled is False
    assert fence.claim(command) == (reply, False)


def test_owned_authority_restart_is_proposal_bound_non_canceling_and_replay_fenced():
    fence = ControlFence()
    command = control(message("RESTART_AUTHORITY"))
    assert command.kind is ControlKind.RESTART_AUTHORITY and str(command.target_id) == TARGET
    assert fence.claim(command)[1]
    reply = fence.finish(command, "AUTHORITY_RESTARTED")
    assert reply.effects_canceled is False and fence.claim(command) == (reply, False)
    with pytest.raises(ControlProtocolError):
        fence.finish(command, "AUTHORITY_RESTARTED")


@pytest.mark.parametrize("state", ["WORKER_ACKNOWLEDGED", "READER_RELEASED", "CANCELED"])
def test_authority_restart_cannot_claim_worker_reader_or_cancellation_outcomes(state):
    fence, command = ControlFence(), control(message("RESTART_AUTHORITY"))
    assert fence.claim(command)[1]
    with pytest.raises(ControlProtocolError):
        fence.finish(command, state)


def test_only_explicit_stop_can_close_private_coordination():
    fence = ControlFence()
    with pytest.raises(ControlProtocolError):
        fence.close(control())
    assert fence.closed is False


@pytest.mark.parametrize(
    "kind,state",
    [
        ("RUN_WORKER", "READER_RELEASED"),
        ("RELEASE_READER", "WORKER_ACKNOWLEDGED"),
        ("RELEASE_READER", "WORKER_QUARANTINED"),
        ("STOP", "UNCONFIRMED"),
    ],
)
def test_settlement_is_bound_to_the_original_control_kind(kind, state):
    fence, command = ControlFence(), control(message(kind))
    assert fence.claim(command)[1]
    with pytest.raises(ControlProtocolError):
        fence.finish(command, state)


@pytest.mark.parametrize(
    "message,expected",
    [
        ("offline Docker operation unavailable", "RUNTIME_DOCKER_UNAVAILABLE"),
        ("offline Docker operation failed", "RUNTIME_DOCKER_FAILED"),
        ("owned process terminal state mismatch", "RUNTIME_TERMINAL"),
        ("unexpected container process stderr", "RUNTIME_STDERR"),
        ("missing or malformed offline process report", "RUNTIME_REPORT"),
        ("owned worker network is not internal", "RUNTIME_SECURITY"),
        ("owned image default startup metadata mismatch", "RUNTIME_IMAGE"),
        ("synthetic-sensitive-provider-output", "RUNTIME"),
        ("invalid offline process proof [TRANSPORT_COUNTS]", "RUNTIME_PROOF_TRANSPORT_COUNTS"),
        (
            "invalid offline process proof [CHILD_THREAD_EXCEPTION]",
            "RUNTIME_PROOF_CHILD_THREAD_EXCEPTION",
        ),
        ("invalid offline process proof [synthetic-sensitive-data]", "RUNTIME"),
        ({"synthetic": "sensitive-token"}, "RUNTIME"),
    ],
)
def test_dispatch_diagnostics_never_reflect_untrusted_error_content(message, expected):
    from tests.dashboard_integrated_protocol import classify_control_failure

    assert classify_control_failure(RuntimeError(message)) == expected
