"""Explicit security rule registration and lookup."""

from collections.abc import Iterable

from app.rules.audit_logging import MissingCloudTrailRule
from app.rules.base import SecurityRule
from app.rules.identity import IAMUserWithoutMFARule
from app.rules.network import PublicRDPRule, PublicSSHRule
from app.rules.storage import MissingBucketEncryptionRule


class RuleRegistry:
    """Own a unique, deterministically ordered collection of security rules."""

    def __init__(self, rules: Iterable[SecurityRule] = ()) -> None:
        self._rules: dict[str, SecurityRule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: SecurityRule) -> None:
        """Register one rule and reject ambiguous duplicate control IDs."""

        if rule.control_id in self._rules:
            raise ValueError(f"duplicate security control ID: {rule.control_id}")
        self._rules[rule.control_id] = rule

    @property
    def rules(self) -> tuple[SecurityRule, ...]:
        """Return rules ordered by control ID, independent of registration order."""

        return tuple(self._rules[key] for key in sorted(self._rules))

    def get(self, control_id: str) -> SecurityRule:
        """Look up one registered rule by its stable control ID."""

        return self._rules[control_id]


def build_default_registry() -> RuleRegistry:
    """Build an isolated registry containing the five Sprint 2 controls."""

    return RuleRegistry(
        (
            PublicSSHRule(),
            PublicRDPRule(),
            MissingBucketEncryptionRule(),
            IAMUserWithoutMFARule(),
            MissingCloudTrailRule(),
        )
    )


def resolve_catalog(catalog_id: str, version: str):
    """Resolve only explicitly supported releases, never a latest-version fallback."""

    from app.assessment.controls import build_default_control_catalog

    if (catalog_id, version) != ("aws-cloud-security-controls", "0.2.1"):
        raise ValueError("unsupported assessment catalog version")
    return build_default_control_catalog(), build_default_registry()
