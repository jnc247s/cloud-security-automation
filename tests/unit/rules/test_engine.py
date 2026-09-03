"""Tests for deterministic security-rule orchestration."""

import pytest

from app.rules.base import SecurityRule
from app.rules.engine import RuleContractError, RuleEngine
from app.rules.registry import RuleRegistry
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import ResourceScope
from tests.unit.rules.factories import ACCOUNT_ID, REGION, snapshot


def _candidate(
    control_id: str,
    resource_id: str,
    *,
    account_id: str = ACCOUNT_ID,
    evidence: dict[str, object] | None = None,
) -> FindingCandidate:
    return FindingCandidate(
        control_id=control_id,
        title=f"{control_id} test finding",
        category=ControlCategory.NETWORK,
        severity=Severity.HIGH,
        account_id=account_id,
        service="ec2",
        resource_type="security_group",
        aws_resource_id=resource_id,
        scope=ResourceScope.REGIONAL,
        region=REGION,
        evidence=evidence or {"test": True},
        impact="Test impact.",
        recommendation="Test recommendation.",
    )


class FirstStaticRule(SecurityRule):
    control_id = "TEST-001"
    title = "First static rule"
    category = ControlCategory.NETWORK
    default_severity = Severity.HIGH
    impact = "Test impact."
    recommendation = "Test recommendation."

    def __init__(self, findings: tuple[FindingCandidate, ...]) -> None:
        self.findings = findings

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        return self.findings


class SecondStaticRule(FirstStaticRule):
    control_id = "TEST-002"
    title = "Second static rule"


def test_engine_returns_candidates_in_stable_identity_order() -> None:
    first_rule = FirstStaticRule(
        (
            _candidate("TEST-001", "sg-z"),
            _candidate("TEST-001", "sg-a"),
        )
    )
    second_rule = SecondStaticRule((_candidate("TEST-002", "sg-b"),))
    engine = RuleEngine(RuleRegistry((second_rule, first_rule)))

    first_result = engine.evaluate(snapshot())
    second_result = engine.evaluate(snapshot())

    assert first_result == second_result
    assert first_result == tuple(sorted(first_result, key=lambda finding: finding.identity))
    assert {(finding.control_id, finding.aws_resource_id) for finding in first_result} == {
        ("TEST-001", "sg-a"),
        ("TEST-001", "sg-z"),
        ("TEST-002", "sg-b"),
    }


def test_engine_rejects_candidate_with_wrong_control_id() -> None:
    rule = FirstStaticRule((_candidate("TEST-999", "sg-example"),))

    with pytest.raises(RuleContractError, match="TEST-001"):
        RuleEngine(RuleRegistry((rule,))).evaluate(snapshot())


def test_engine_rejects_candidate_for_another_account() -> None:
    rule = FirstStaticRule((_candidate("TEST-001", "sg-example", account_id="999999999999"),))

    with pytest.raises(RuleContractError, match="TEST-001"):
        RuleEngine(RuleRegistry((rule,))).evaluate(snapshot())


def test_engine_rejects_duplicate_candidate_identity_without_leaking_evidence() -> None:
    candidate = _candidate(
        "TEST-001",
        "sg-example",
        evidence={"sensitive_fact": "do-not-include-in-error"},
    )
    rule = FirstStaticRule((candidate, candidate.model_copy(deep=True)))

    with pytest.raises(RuleContractError) as error_info:
        RuleEngine(RuleRegistry((rule,))).evaluate(snapshot())

    assert "TEST-001" in str(error_info.value)
    assert "sg-example" in str(error_info.value)
    assert "do-not-include-in-error" not in str(error_info.value)
