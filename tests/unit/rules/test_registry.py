"""Tests for explicit security-rule registration."""

import pytest

from app.rules.base import SecurityRule
from app.rules.registry import RuleRegistry, build_default_registry
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot


class LaterRule(SecurityRule):
    """A stateless test rule with a lexically later control ID."""

    control_id = "TEST-002"
    title = "Later rule"
    category = ControlCategory.LOGGING
    default_severity = Severity.LOW
    description = "Test registry ordering."
    rationale = "Tests need deterministic rule ordering."
    impact = "None; this is a test rule."
    remediation_guidance = "No remediation is needed."

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        return ()


class EarlierRule(LaterRule):
    """A test rule that should sort ahead of LaterRule."""

    control_id = "TEST-001"
    title = "Earlier rule"


class DuplicateEarlierRule(EarlierRule):
    """A second implementation with an intentionally duplicate ID."""

    title = "Duplicate earlier rule"


def test_registry_sorts_rules_by_control_id_and_supports_lookup() -> None:
    earlier = EarlierRule()
    later = LaterRule()

    registry = RuleRegistry((later, earlier))

    assert registry.rules == (earlier, later)
    assert registry.get("TEST-001") is earlier
    assert registry.get("TEST-002") is later


def test_registry_rejects_duplicate_control_ids() -> None:
    with pytest.raises(ValueError, match="TEST-001"):
        RuleRegistry((EarlierRule(), DuplicateEarlierRule()))


def test_registry_missing_control_lookup_raises_key_error() -> None:
    registry = RuleRegistry((EarlierRule(),))

    with pytest.raises(KeyError, match="UNKNOWN-001"):
        registry.get("UNKNOWN-001")


def test_default_registry_explicitly_contains_all_sprint_two_controls() -> None:
    registry = build_default_registry()

    assert tuple(rule.control_id for rule in registry.rules) == (
        "IAM-001",
        "LOG-001",
        "NET-001",
        "NET-002",
        "S3-900",
    )
