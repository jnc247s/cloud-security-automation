"""Closed observation cases and ownership guards precede collection and SQL."""

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID

import pytest

INSTANCE = "12345678-1234-4123-8123-123456789abc"
KEY = UUID("22345678-1234-4123-8123-123456789abc")
TARGET = UUID("32345678-1234-4123-8123-123456789abc")


def test_explicit_approved_admission_case_reuses_only_the_fixed_newer_fail_observation():
    from tests.dashboard_integrated_staleness import stale_case

    assert stale_case("admission-stale") == stale_case("stale-newer-fail")


@pytest.mark.parametrize("timing", ["newer", "equal"])
@pytest.mark.parametrize("result", ["fail", "pass", "insufficient"])
def test_stale_case_chooses_only_fixed_facts_and_normal_finding_policy(timing, result):
    from tests.dashboard_integrated_staleness import stale_case

    case = stale_case("stale-" + timing + "-" + result)
    assert case.offset == (1 if timing == "newer" else 0)
    assert case.assessment == (
        "INSUFFICIENT_EVIDENCE" if result == "insufficient" else result.upper()
    )
    assert case.scan_status == ("PARTIAL" if result == "insufficient" else "COMPLETED")
    assert case.finding == ("RESOLVED" if timing == "newer" and result == "pass" else "OPEN")
    with pytest.raises(FrozenInstanceError):
        case.offset = 2


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        {},
        [],
        "",
        "stale",
        "stale-newer-pass ",
        "STALE-newer-pass",
        "https://untrusted.invalid",
    ],
)
def test_untrusted_stale_case_cannot_select_facts(value):
    from tests.dashboard_integrated_staleness import stale_case

    with pytest.raises(ValueError, match="Invalid integrated stale case"):
        stale_case(value)


@pytest.mark.parametrize(
    "fault", [None, "environment", "kind", "instance", "target", "dispatched", "worker", "scenario"]
)
def test_stale_collection_requires_owning_parent_before_sql_or_fact_work(monkeypatch, fault):
    from tests.dashboard_integrated_protocol import ControlKind, ControlMessage
    from tests.dashboard_integrated_staleness import collect_bound_stale_observation

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    touched = []

    def owned():
        touched.append("owned")
        raise RuntimeError("owned boundary")

    parent = SimpleNamespace(
        instance=INSTANCE,
        scenario=SimpleNamespace(name="stale-newer-fail"),
        stale_dispatched=False,
        worker_dispatched=False,
        _owned=owned,
    )
    message = ControlMessage(UUID(INSTANCE), KEY, ControlKind.COLLECT_STALE, TARGET)
    if fault == "environment":
        monkeypatch.delenv("DASHBOARD_BROWSER_TEST")
    elif fault == "kind":
        message = ControlMessage(UUID(INSTANCE), KEY, ControlKind.RUN_WORKER, TARGET)
    elif fault == "instance":
        message = ControlMessage(TARGET, KEY, ControlKind.COLLECT_STALE, TARGET)
    elif fault == "target":
        message = ControlMessage(UUID(INSTANCE), KEY, ControlKind.COLLECT_STALE, None)
    elif fault == "dispatched":
        parent.stale_dispatched = True
    elif fault == "worker":
        parent.worker_dispatched = True
    elif fault == "scenario":
        parent.scenario = SimpleNamespace(name="verified")
    if fault:
        with pytest.raises(ValueError):
            collect_bound_stale_observation(parent, message)
        assert touched == []
    else:
        with pytest.raises(RuntimeError, match="owned boundary"):
            collect_bound_stale_observation(parent, message)
        assert touched == ["owned"]


@pytest.mark.parametrize(
    "state", ["WORKER_ACKNOWLEDGED", "READER_RELEASED", "AUTHORITY_RESTARTED", "WORKER_NO_WRITE"]
)
def test_stale_parent_reply_cannot_impersonate_worker_reader_or_restart(state):
    import json

    from tests.dashboard_integrated_guardian import reply_wire
    from tests.dashboard_integrated_mailbox import parse_reply
    from tests.dashboard_integrated_protocol import (
        ControlFence,
        ControlKind,
        ControlMessage,
        ControlProtocolError,
        parse_control,
    )

    message = parse_control(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "instance_id": INSTANCE,
                "request_id": str(KEY),
                "command": "COLLECT_STALE",
                "proposal_id": str(TARGET),
            }
        ).encode(),
        expected_instance=INSTANCE,
    )
    assert message == ControlMessage(UUID(INSTANCE), KEY, ControlKind.COLLECT_STALE, TARGET)
    fence = ControlFence()
    assert fence.claim(message)[1]
    with pytest.raises(ControlProtocolError):
        fence.finish(message, state)
    reply = fence.finish(message, "STALE_OBSERVATION_PERSISTED")
    assert (
        parse_reply(reply_wire(reply).removeprefix("INTEGRATED_REPLY=").encode(), message) == reply
    )
    assert fence.claim(message) == (reply, False) and reply.effects_canceled is False
