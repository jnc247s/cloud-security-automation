"""Fixed governance/approved-authority fixtures cannot choose arbitrary mutations."""

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID

import pytest

OWNER = "12345678-1234-4123-8123-123456789abc"
KEY = UUID("22345678-1234-4123-8123-123456789abc")
TARGET = UUID("32345678-1234-4123-8123-123456789abc")


@pytest.mark.parametrize(
    "name,approved,status,blocker",
    [
        ("admission-stale", True, "OPEN", "STALE_TARGET"),
        ("governance-change", False, "ACKNOWLEDGED", "STALE_GOVERNANCE"),
        ("governance-round-trip", True, "OPEN", "STALE_GOVERNANCE"),
        ("governance-exception", False, "OPEN", "ACTIVE_EXCEPTION"),
    ],
)
def test_authority_cases_keep_historical_approval_and_current_governance_separate(
    name, approved, status, blocker
):
    from tests.dashboard_integrated_governance import authority_case

    case = authority_case(name)
    assert (case.approved, case.finding, case.blocker) == (approved, status, blocker)
    assert case.active_exception is (name == "governance-exception")
    assert case.dispositions == (
        ("ACKNOWLEDGED",)
        if name == "governance-change"
        else ("FALSE_POSITIVE", "OPEN")
        if name == "governance-round-trip"
        else ()
    )
    with pytest.raises(FrozenInstanceError):
        case.approved = False


@pytest.mark.parametrize(
    "name",
    [
        None,
        True,
        1,
        {},
        [],
        "",
        "governance",
        "governance-change ",
        "GOVERNANCE-change",
        "https://untrusted.invalid",
    ],
)
def test_untrusted_authority_case_cannot_choose_scope_status_or_exception(name):
    from tests.dashboard_integrated_governance import authority_case

    with pytest.raises(ValueError, match="Invalid integrated authority case"):
        authority_case(name)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "environment",
        "kind",
        "instance",
        "target",
        "dispatched",
        "worker",
        "scenario",
        "admission",
    ],
)
def test_governance_effect_requires_exact_owned_parent_before_sql(monkeypatch, fault):
    from tests.dashboard_integrated_governance import change_bound_governance
    from tests.dashboard_integrated_protocol import ControlKind, ControlMessage

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    touched = []

    def owned():
        touched.append("owned")
        raise RuntimeError("owned boundary")

    parent = SimpleNamespace(
        instance=OWNER,
        scenario=SimpleNamespace(name="governance-change"),
        governance_dispatched=False,
        worker_dispatched=False,
        _owned=owned,
    )
    message = ControlMessage(UUID(OWNER), KEY, ControlKind.CHANGE_GOVERNANCE, TARGET)
    if fault == "environment":
        monkeypatch.delenv("DASHBOARD_BROWSER_TEST")
    elif fault == "kind":
        message = ControlMessage(UUID(OWNER), KEY, ControlKind.COLLECT_STALE, TARGET)
    elif fault == "instance":
        message = ControlMessage(TARGET, KEY, ControlKind.CHANGE_GOVERNANCE, TARGET)
    elif fault == "target":
        message = ControlMessage(UUID(OWNER), KEY, ControlKind.CHANGE_GOVERNANCE, None)
    elif fault == "dispatched":
        parent.governance_dispatched = True
    elif fault == "worker":
        parent.worker_dispatched = True
    elif fault in {"scenario", "admission"}:
        parent.scenario = SimpleNamespace(
            name="verified" if fault == "scenario" else "admission-stale"
        )
    if fault:
        with pytest.raises(ValueError):
            change_bound_governance(parent, message)
        assert touched == []
    else:
        with pytest.raises(RuntimeError, match="owned boundary"):
            change_bound_governance(parent, message)
        assert touched == ["owned"]
