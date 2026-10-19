"""Closed read-only reply protocol cannot substitute a permit, target, owner or result."""

import json
from uuid import uuid4

import pytest

from tests.dashboard_integrated_guardian import wire
from tests.dashboard_integrated_mailbox import parse_reply, payload, publish, receive
from tests.dashboard_integrated_protocol import ControlProtocolError, ControlReply, parse_control


def message(kind="RUN_WORKER"):
    instance = str(uuid4())
    return parse_control(wire(instance, kind, uuid4(), uuid4()), expected_instance=instance)


@pytest.mark.parametrize(
    "kind,state",
    [
        ("RUN_WORKER", "WORKER_ACKNOWLEDGED"),
        ("RUN_WORKER", "WORKER_QUARANTINED"),
        ("RUN_WORKER", "WORKER_NO_WRITE"),
        ("RELEASE_READER", "READER_RELEASED"),
        ("RESTART_AUTHORITY", "AUTHORITY_RESTARTED"),
        ("COLLECT_STALE", "STALE_OBSERVATION_PERSISTED"),
        ("CHANGE_GOVERNANCE", "GOVERNANCE_CHANGED"),
        ("STOP", "CLOSED"),
    ],
)
def test_reply_round_trip_is_immutable_and_bound(tmp_path, kind, state):
    expected = message(kind)
    reply = ControlReply(expected, state)
    publish(tmp_path, reply)
    publish(tmp_path, reply)  # Exact replay cannot replace the original file.
    assert receive(tmp_path, expected, timeout=0.1) == reply
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize(
    "kind", ["RELEASE_READER", "RESTART_AUTHORITY", "COLLECT_STALE", "CHANGE_GOVERNANCE", "STOP"]
)
def test_no_write_worker_reply_cannot_settle_reader_or_stop(kind):
    expected = message(kind)
    with pytest.raises(ControlProtocolError, match="Invalid integrated parent reply"):
        parse_reply(payload(ControlReply(expected, "WORKER_NO_WRITE")), expected)


@pytest.mark.parametrize("kind", ["COLLECT_STALE", "CHANGE_GOVERNANCE"])
def test_parent_only_stale_collection_cannot_receive_a_child_gate_permit(tmp_path, kind):
    expected = message(kind)
    publish(tmp_path, ControlReply(expected, "IN_FLIGHT"), permit=True)
    with pytest.raises(ControlProtocolError, match="Invalid integrated reader permit"):
        receive(tmp_path, expected, permit=True, timeout=0.1)


@pytest.mark.parametrize("kind", ["RELEASE_READER", "RESTART_AUTHORITY"])
def test_only_bound_fixed_reader_or_restart_permit_can_open_its_gate(tmp_path, kind):
    expected = message(kind)
    publish(tmp_path, ControlReply(expected, "IN_FLIGHT"), permit=True)
    assert receive(tmp_path, expected, permit=True, timeout=0.1) is None
    with pytest.raises(ControlProtocolError):
        parse_reply(payload(ControlReply(expected, "WORKER_ACKNOWLEDGED")), expected)


@pytest.mark.parametrize(
    "field,value",
    [
        ("instance_id", "12345678-1234-4123-8123-123456789abc"),
        ("request_id", "22345678-1234-4123-8123-123456789abc"),
        ("execution_id", "32345678-1234-4123-8123-123456789abc"),
        ("command", "STOP"),
        ("state", "READER_RELEASED"),
        ("effects_canceled", True),
        ("effects_canceled", 0),
        ("argv", []),
    ],
)
def test_wrong_parent_reply_cannot_confirm(field, value):
    expected = message()
    body = json.loads(payload(ControlReply(expected, "WORKER_ACKNOWLEDGED")))
    body[field] = value
    with pytest.raises(ControlProtocolError, match="Invalid integrated parent reply"):
        parse_reply(json.dumps(body).encode(), expected)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"x" * 2049,
        b"\xff",
        b"{}",
        b'{"state":"CLOSED","state":"WORKER_ACKNOWLEDGED"}',
        b"NaN",
        b"[]",
    ],
)
def test_malformed_or_duplicate_parent_reply_is_sanitized(raw):
    with pytest.raises(ControlProtocolError, match="Invalid integrated parent reply"):
        parse_reply(raw, message())


def test_reader_permit_is_not_a_result_and_result_cannot_be_replaced(tmp_path):
    expected = message("RELEASE_READER")
    publish(tmp_path, ControlReply(expected, "IN_FLIGHT"), permit=True)
    assert receive(tmp_path, expected, permit=True, timeout=0.1) is None
    with pytest.raises(ControlProtocolError, match="deadline"):
        receive(tmp_path, expected, timeout=0.01)
    reply = ControlReply(expected, "READER_RELEASED")
    publish(tmp_path, reply)
    with pytest.raises(ControlProtocolError, match="conflict"):
        publish(tmp_path, ControlReply(expected, "UNCONFIRMED"))
    assert receive(tmp_path, expected, timeout=0.1) == reply


def test_forged_permit_for_other_target_is_rejected(tmp_path):
    expected = message("RELEASE_READER")
    filename = tmp_path / ("permit-" + str(expected.request_id) + ".json")
    filename.write_bytes(
        wire(str(expected.instance_id), "RELEASE_READER", expected.request_id, uuid4())
    )
    with pytest.raises(ControlProtocolError, match="Invalid integrated reader permit"):
        receive(tmp_path, expected, permit=True, timeout=0.1)


def test_closed_coordination_is_not_persistence_proof(tmp_path):
    from tests.dashboard_integrated_mailbox import proof_present

    stopped = message("STOP")
    reply = ControlReply(stopped, "CLOSED")
    publish(tmp_path, reply)
    assert receive(tmp_path, stopped, timeout=0.1) == reply
    assert proof_present(tmp_path, stopped) is False
    publish(tmp_path, reply, proof=True)
    assert proof_present(tmp_path, stopped) is True


def test_failed_proof_still_closes_without_fabricating_success(tmp_path):
    from tests.dashboard_integrated_container import close_for_teardown
    from tests.dashboard_integrated_mailbox import proof_present

    stopped = message("STOP")
    reply = ControlReply(stopped, "CLOSED")
    calls = []

    def failed():
        calls.append(True)
        raise AssertionError("synthetic-sensitive-proof-diagnostic")

    assert close_for_teardown(tmp_path, reply, failed) is False
    assert calls == [True] and proof_present(tmp_path, stopped) is False
    assert receive(tmp_path, stopped, timeout=0.1) == reply


@pytest.mark.parametrize("kind", ["RUN_WORKER", "RELEASE_READER"])
def test_work_reply_cannot_be_published_as_completed_storage_proof(tmp_path, kind):
    with pytest.raises(ControlProtocolError):
        publish(tmp_path, ControlReply(message(kind), "CLOSED"), proof=True)
    assert list(tmp_path.iterdir()) == []
