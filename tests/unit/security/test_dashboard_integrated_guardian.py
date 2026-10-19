"""Private child transport stays bounded, portable, redacted and non-authorizing."""

import io
import json
import queue
import threading
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.dashboard_integrated_guardian import OwnedServer, reply_wire, wire
from tests.dashboard_integrated_protocol import ControlReply, parse_control


@pytest.mark.parametrize("fault", [None, "same-pid", "close", "start", "ready", "handle"])
def test_restart_replaces_only_exact_closed_child_and_never_retries_uncertain_work(
    monkeypatch, fault
):
    from tests import dashboard_integrated_guardian as guardian
    from tests.dashboard_integrated_authority_restart import RestartableAuthorityServer

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    instance, created = str(uuid4()), []
    env = {
        "DASHBOARD_BROWSER_TEST": "1",
        "DASHBOARD_INTEGRATED_INSTANCE": instance,
        "DASHBOARD_INTEGRATED_SCENARIO": "cross-issuer",
    }

    class FakeServer:
        def __init__(self, values):
            if created and fault == "start":
                raise RuntimeError("Synthetic owned-child startup failure")
            self.env, self.closed = dict(values), False
            self.child = SimpleNamespace(
                pid=100 if fault == "same-pid" else 100 + len(created),
                poll=lambda: 0 if self.closed else None,
            )
            if created and fault == "handle":
                self.child = created[0].child
            created.append(self)

        def wait(self, expected, timeout):
            assert expected == b"INTEGRATED_SERVER_READY" and timeout == 30
            if fault == "ready":
                raise RuntimeError("Synthetic owned-child readiness failure")

        def close(self, value):
            assert value == instance
            self.closed = True
            if self is created[0] and fault == "close":
                raise RuntimeError("Synthetic owned-child shutdown failure")

    monkeypatch.setattr(guardian, "OwnedServer", FakeServer)
    owner = RestartableAuthorityServer(env)
    message = parse_control(
        wire(instance, "RESTART_AUTHORITY", uuid4(), uuid4()), expected_instance=instance
    )
    if fault in {None, "same-pid"}:
        owner.restart(message)
        assert owner.completed is True and len(created) == 2
        assert created[0].closed and not created[1].closed
        assert created[1].child is not created[0].child
        assert created[1].env["DASHBOARD_INTEGRATED_IDENTITY_PHASE"] == "secondary"
    else:
        with pytest.raises((RuntimeError, ValueError)):
            owner.restart(message)
        assert owner.completed is False
    assert owner.attempted is True and "DASHBOARD_INTEGRATED_IDENTITY_PHASE" not in env
    count = len(created)
    with pytest.raises(ValueError, match="Integrated authority restart rejected"):
        owner.restart(message)
    assert len(created) == count
    if owner.current is not created[0] or fault != "close":
        owner.close(instance)
    assert all(child.closed for child in created)


@pytest.mark.parametrize(
    "fault", ["owner", "kind", "scenario", "callback", "attempted", "worker", "restarted", "ack"]
)
def test_restart_dispatch_guards_reject_before_sql_or_any_owned_child_effect(monkeypatch, fault):
    from tests.dashboard_integrated_authority_restart import restart_bound_authority

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    instance = str(uuid4())
    parent = SimpleNamespace(
        instance=instance,
        scenario=SimpleNamespace(name="cross-issuer"),
        restart_authority=lambda _message: pytest.fail("No child effect"),
        restart_dispatched=False,
        worker_dispatched=False,
        identity_restarted=False,
        acknowledged_execution=None,
    )
    kind = "RUN_WORKER" if fault == "kind" else "RESTART_AUTHORITY"
    owner = str(uuid4()) if fault == "owner" else instance
    message = parse_control(wire(owner, kind, uuid4(), uuid4()), expected_instance=owner)
    if fault == "scenario":
        parent.scenario.name = "verified"
    elif fault == "callback":
        parent.restart_authority = None
    elif fault == "attempted":
        parent.restart_dispatched = True
    elif fault == "worker":
        parent.worker_dispatched = True
    elif fault == "restarted":
        parent.identity_restarted = True
    elif fault == "ack":
        parent.acknowledged_execution = uuid4()
    with pytest.raises(ValueError, match="Integrated authority restart unavailable"):
        restart_bound_authority(parent, message)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_child_ready_metadata_accepts_native_line_endings(ending):
    server = object.__new__(OwnedServer)
    server.child = SimpleNamespace(stdout=io.BytesIO(b"INTEGRATED_SERVER_READY" + ending))
    server.events, server.invalid = queue.Queue(maxsize=8), threading.Event()
    server._read()
    assert not server.invalid.is_set()
    assert server.events.get_nowait() == b"INTEGRATED_SERVER_READY"


def test_arbitrary_child_diagnostics_are_not_forwarded():
    server = object.__new__(OwnedServer)
    server.child = SimpleNamespace(stdout=io.BytesIO(b"synthetic-sensitive-diagnostic\n"))
    server.events, server.invalid = queue.Queue(maxsize=8), threading.Event()
    server._read()
    assert server.events.empty() and not server.invalid.is_set()


@pytest.mark.parametrize(
    "raw",
    [b"{}", "{}\n", b"{}\n{}\n", b"x" * 2048 + b"\n"],
    ids=["missing-line-end", "wrong-type", "multiple-frames", "oversized"],
)
def test_child_transport_rejects_incomplete_multiple_or_oversized_frames_before_write(raw):
    server = object.__new__(OwnedServer)
    output = io.BytesIO()
    server.child = SimpleNamespace(stdin=output, poll=lambda: None)
    with pytest.raises(ValueError, match="Owned integrated server frame rejected"):
        server.send(raw)
    assert output.getvalue() == b""


def test_child_transport_sends_canonical_frame_without_altering_bytes():
    server = object.__new__(OwnedServer)
    output = io.BytesIO()
    server.child = SimpleNamespace(stdin=output, poll=lambda: None)
    raw = wire(str(uuid4()), "STOP", uuid4())
    server.send(raw)
    assert output.getvalue() == raw


@pytest.mark.parametrize(
    "identities",
    [
        [("a", "p"), ("b", "p"), ("b", "r")],
        (("a", "p"), ("a", "p"), ("b", "r")),
        (("a", "p"), ("b", "r")),
        ((None, "p"), ("b", "p"), ("b", "r")),
        (("a", "p"), ("b", ""), ("b", "r")),
    ],
)
def test_history_proof_requires_three_explicit_distinct_full_pairs_before_sql(identities):
    from tests.worker_http import assert_history

    with pytest.raises(AssertionError):
        assert_history(None, None, None, SimpleNamespace(issuer="a"), human_identities=identities)


@pytest.mark.parametrize("raw", [b"x" * 2049, b"INTEGRATED_SERVER_READY\n" * 9])
def test_transport_limits_fail_closed(raw):
    server = object.__new__(OwnedServer)
    server.child = SimpleNamespace(stdout=io.BytesIO(raw))
    server.events, server.invalid = queue.Queue(maxsize=8), threading.Event()
    server._read()
    assert server.invalid.is_set()


@pytest.mark.parametrize(
    "kind",
    [
        "RUN_WORKER",
        "RELEASE_READER",
        "RESTART_AUTHORITY",
        "COLLECT_STALE",
        "CHANGE_GOVERNANCE",
        "STOP",
    ],
)
def test_private_reply_contains_only_bound_control_metadata(kind):
    instance, key, target = str(uuid4()), uuid4(), uuid4()
    message = parse_control(wire(instance, kind, key, target), expected_instance=instance)
    reply = json.loads(
        reply_wire(ControlReply(message, "CLOSED")).removeprefix("INTEGRATED_REPLY=")
    )
    assert reply["instance_id"] == instance and reply["request_id"] == str(key)
    assert reply["command"] == kind and reply["effects_canceled"] is False
    assert set(reply) == {
        "schema_version",
        "instance_id",
        "request_id",
        "command",
        "state",
        "effects_canceled",
    } | (
        {
            {
                "RUN_WORKER": "execution_id",
                "RELEASE_READER": "verification_id",
                "RESTART_AUTHORITY": "proposal_id",
                "COLLECT_STALE": "proposal_id",
                "CHANGE_GOVERNANCE": "proposal_id",
            }[kind]
        }
        if kind != "STOP"
        else set()
    )
