"""Reader facts are closed parent configuration, never arbitrary SDK/scanner parameters."""

from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from tests.dashboard_integrated_scenarios import reader_scenario


@pytest.mark.parametrize(
    "name,outcome,technical,finding",
    [
        ("cross-issuer", "VERIFIED", "PASS", "RESOLVED"),
        ("verified", "VERIFIED", "PASS", "RESOLVED"),
        ("verification-equal", "INCONCLUSIVE", "PASS", "RESOLVED"),
        ("verification-provenance", "INCONCLUSIVE", None, "RESOLVED"),
        ("feature-hints", "VERIFIED", "PASS", "RESOLVED"),
        ("history-versions", "VERIFIED", "PASS", "RESOLVED"),
        ("reply-reference", "VERIFIED", "PASS", "RESOLVED"),
        ("history-reference", "VERIFIED", "PASS", "RESOLVED"),
        ("revoked-after-ack", "VERIFIED", "PASS", "RESOLVED"),
        ("revoked-before-intent", "NO_VERIFICATION", None, "OPEN"),
        ("recovery-guards", "VERIFIED", "PASS", "RESOLVED"),
        ("in-flight", "VERIFIED", "PASS", "RESOLVED"),
        ("capacity-session", "VERIFIED", "PASS", "RESOLVED"),
        ("capacity-global", "VERIFIED", "PASS", "RESOLVED"),
        ("uncertain-submit", "VERIFIED", "PASS", "RESOLVED"),
        ("capability-loss", "VERIFIED", "PASS", "RESOLVED"),
        ("expiry-session", "VERIFIED", "PASS", "RESOLVED"),
        ("expiry-global", "VERIFIED", "PASS", "RESOLVED"),
        ("proposal-expiry", "NO_EXECUTION", None, "OPEN"),
        ("idle-expiry", "NO_EXECUTION", None, "OPEN"),
        ("token-expiry", "NO_EXECUTION", None, "OPEN"),
        ("subject-replacement", "NO_EXECUTION", None, "OPEN"),
        ("issuer-rejection", "NO_EXECUTION", None, "OPEN"),
        ("stale-newer-fail", "NO_EXECUTION", None, "OPEN"),
        ("stale-newer-pass", "NO_EXECUTION", None, "RESOLVED"),
        ("stale-newer-insufficient", "NO_EXECUTION", None, "OPEN"),
        ("stale-equal-fail", "NO_EXECUTION", None, "OPEN"),
        ("stale-equal-pass", "NO_EXECUTION", None, "OPEN"),
        ("stale-equal-insufficient", "NO_EXECUTION", None, "OPEN"),
        ("admission-stale", "NO_EXECUTION", None, "OPEN"),
        ("governance-change", "NO_EXECUTION", None, "ACKNOWLEDGED"),
        ("governance-round-trip", "NO_EXECUTION", None, "OPEN"),
        ("governance-exception", "NO_EXECUTION", None, "OPEN"),
        ("execution-expiry", "NO_VERIFICATION", None, "OPEN"),
        ("not-verified", "NOT_VERIFIED", "FAIL", "OPEN"),
        ("attempt-limit", "NOT_VERIFIED", "FAIL", "OPEN"),
        ("quarantine", "NO_VERIFICATION", None, "OPEN"),
        ("late-ack", "NO_VERIFICATION", None, "OPEN"),
        ("kms-changed", "INCONCLUSIVE", "PASS", "RESOLVED"),
        ("partial", "INCONCLUSIVE", None, "OPEN"),
    ],
)
def test_immutable_expectations_keep_verdict_technical_and_finding_separate(
    name, outcome, technical, finding
):
    value = reader_scenario(name)
    assert (value.outcome, value.technical, value.finding) == (outcome, technical, finding)
    assert value.response_loss is (
        name
        in {
            "uncertain-submit",
            "cross-issuer",
            "capability-loss",
            "expiry-session",
            "expiry-global",
            "proposal-expiry",
            "idle-expiry",
            "token-expiry",
            "subject-replacement",
            "issuer-rejection",
        }
    )
    quarantined = name in {"quarantine", "late-ack"}
    assert value.attempts == (
        0
        if name.startswith(("stale-", "governance-"))
        or name == "admission-stale"
        or quarantined
        or name
        in {
            "proposal-expiry",
            "execution-expiry",
            "revoked-before-intent",
            "idle-expiry",
            "token-expiry",
            "subject-replacement",
            "issuer-rejection",
        }
        else 3
        if name == "attempt-limit"
        else 1
    )
    assert value.worker == (
        "none"
        if name.startswith(("stale-", "governance-"))
        or name == "admission-stale"
        or name
        in {
            "proposal-expiry",
            "idle-expiry",
            "token-expiry",
            "subject-replacement",
            "issuer-rejection",
        }
        else "expired"
        if name == "execution-expiry"
        else "revoked"
        if name == "revoked-before-intent"
        else name
        if quarantined
        else "acknowledged"
    )
    with pytest.raises(FrozenInstanceError):
        value.outcome = "VERIFIED"


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        {},
        [],
        "",
        "VERIFIED",
        "verified ",
        "http://untrusted.test",
        "--enable-worker",
    ],
)
def test_untrusted_or_coercive_scenario_does_not_select_provider_behavior(value):
    with pytest.raises(ValueError, match="Invalid integrated reader scenario"):
        reader_scenario(value)


@pytest.mark.parametrize("name", ["quarantine", "late-ack"])
def test_quarantine_scenarios_cannot_construct_a_managed_reader(name):
    from tests.dashboard_integrated_scenarios import build_reader

    with pytest.raises(ValueError, match="No managed reader"):
        build_reader(name)


@pytest.mark.parametrize("scenario", ["proposal-expiry", "idle-expiry", "token-expiry"])
def test_proposal_expiry_has_neither_reader_nor_installed_worker_script(scenario):
    from tests.dashboard_integrated_scenarios import build_reader, build_worker_script

    with pytest.raises(ValueError, match="No managed reader"):
        build_reader(scenario)
    with pytest.raises(ValueError, match="No installed worker"):
        build_worker_script(scenario, None)


def test_execution_expiry_allows_no_provider_script_or_reader_dispatch():
    from tests.dashboard_integrated_coordinator import IntegratedCoordinator
    from tests.dashboard_integrated_scenarios import build_reader, build_worker_script

    assert build_worker_script("execution-expiry", None) == []
    with pytest.raises(ValueError, match="No managed reader"):
        build_reader("execution-expiry")
    parent = object.__new__(IntegratedCoordinator)
    parent.scenario = reader_scenario("execution-expiry")
    with pytest.raises(ValueError, match="No managed reader"):
        parent._release_reader(object())


@pytest.mark.parametrize("method", ["_run_worker", "_release_reader"])
def test_proposal_only_parent_rejects_dispatch_before_any_owned_effect(method):
    from tests.dashboard_integrated_coordinator import IntegratedCoordinator

    parent = object.__new__(IntegratedCoordinator)
    parent.scenario = reader_scenario("proposal-expiry")
    with pytest.raises(ValueError, match="No installed worker|No managed reader"):
        getattr(parent, method)(object())


@pytest.mark.parametrize(
    "identifier", [None, True, "", "not-an-id", "12345678-1234-1123-8123-123456789abc"]
)
def test_late_ack_fault_refuses_noncanonical_target_before_database(identifier):
    from tests.worker_process_harness import quarantine_before_ack

    with pytest.raises(ValueError, match="Invalid late acknowledgment test target"):
        quarantine_before_ack(object(), identifier)


def sequence_fixture(count=2):
    from types import SimpleNamespace

    execution, baseline = uuid4(), uuid4()
    values = [
        SimpleNamespace(
            content=SimpleNamespace(
                attempt=index + 1,
                execution_id=execution,
                baseline_scan_id=baseline,
                scan_id=uuid4(),
                verification_id=uuid4(),
            ),
            receipt=object() if index < count - 1 else None,
        )
        for index in range(count)
    ]
    managed = SimpleNamespace(
        submissions=[value.content.scan_id for value in values],
        boundaries=[
            (kind, value.content.scan_id, value.content.verification_id)
            for value in values
            for kind in ("submit", "provider")
        ],
    )
    return managed, values


@pytest.mark.parametrize("count", [1, 2, 3])
def test_reader_gate_requires_exact_sequential_managed_boundaries(count):
    from tests.dashboard_integrated_proof import assert_reader_sequence

    managed, values = sequence_fixture(count)
    assert_reader_sequence(managed, values, max_attempts=3)
    if count == 1:
        assert_reader_sequence(managed, values, max_attempts=1)


@pytest.mark.parametrize(
    "case",
    [
        "ordinal",
        "prior-pending",
        "latest-sealed",
        "foreign-execution",
        "foreign-baseline",
        "duplicate-scan",
        "duplicate-verification",
        "missing-submit",
        "extra-submit",
        "reordered-boundary",
        "missing-provider",
        "foreign-boundary",
        "fourth",
        "one-only",
        "coercive-limit",
    ],
)
def test_reader_gate_rejects_unsealed_substituted_or_extra_work(case):
    from tests.dashboard_integrated_proof import assert_reader_sequence

    managed, values = sequence_fixture(4 if case == "fourth" else 2)
    limit = 3
    if case == "ordinal":
        values[-1].content.attempt = 3
    elif case == "prior-pending":
        values[0].receipt = None
    elif case == "latest-sealed":
        values[-1].receipt = object()
    elif case == "foreign-execution":
        values[-1].content.execution_id = uuid4()
    elif case == "foreign-baseline":
        values[-1].content.baseline_scan_id = uuid4()
    elif case == "duplicate-scan":
        values[-1].content.scan_id = values[0].content.scan_id
    elif case == "duplicate-verification":
        values[-1].content.verification_id = values[0].content.verification_id
    elif case == "missing-submit":
        managed.submissions.pop()
    elif case == "extra-submit":
        managed.submissions.append(uuid4())
    elif case == "reordered-boundary":
        managed.boundaries.reverse()
    elif case == "missing-provider":
        managed.boundaries.pop()
    elif case == "foreign-boundary":
        managed.boundaries[-1] = ("provider", uuid4(), uuid4())
    elif case == "one-only":
        limit = 1
    elif case == "coercive-limit":
        limit = True
    with pytest.raises(ValueError, match="Managed reader sequence"):
        assert_reader_sequence(managed, values, max_attempts=limit)
