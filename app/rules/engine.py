"""Deterministic orchestration for registered security controls."""

from app.rules.registry import RuleRegistry
from app.schemas.finding import FindingCandidate
from app.schemas.inventory import InventorySnapshot


class RuleContractError(RuntimeError):
    """Raised when a rule returns output that violates the engine contract."""


class RuleEngine:
    """Evaluate a normalized inventory without AWS, persistence, or side effects."""

    def __init__(self, registry: RuleRegistry) -> None:
        self.registry = registry

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        """Evaluate all rules and return validated findings in stable order."""

        findings: list[FindingCandidate] = []
        seen_identities: set[tuple[str, str, str, str, str, str, str]] = set()

        for rule in self.registry.rules:
            for candidate in rule.evaluate(snapshot):
                if not isinstance(candidate, FindingCandidate):
                    raise RuleContractError(f"{rule.control_id} returned a non-finding candidate")
                if candidate.control_id != rule.control_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned candidate for {candidate.control_id}"
                    )
                if candidate.account_id != snapshot.account_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned candidate for a different AWS account"
                    )
                if candidate.identity in seen_identities:
                    raise RuleContractError(
                        f"{rule.control_id} returned duplicate candidate identity for "
                        f"{candidate.aws_resource_id}"
                    )

                seen_identities.add(candidate.identity)
                findings.append(candidate)

        findings.sort(key=lambda finding: finding.identity)
        return tuple(findings)
