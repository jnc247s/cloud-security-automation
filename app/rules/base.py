"""Side-effect-free security rule contracts and shared helpers."""

from abc import ABC, abstractmethod
from typing import ClassVar

from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope


class RuleEvaluationError(RuntimeError):
    """Raised when a rule cannot safely interpret a required normalized fact."""

    def __init__(self, control_id: str, aws_resource_id: str, fact_path: str) -> None:
        self.control_id = control_id
        self.aws_resource_id = aws_resource_id
        self.fact_path = fact_path
        super().__init__(
            f"{control_id} cannot evaluate resource {aws_resource_id}: invalid fact at {fact_path}"
        )


class SecurityRule(ABC):
    """Base interface for deterministic inventory-level control evaluation."""

    control_id: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[ControlCategory]
    default_severity: ClassVar[Severity]
    impact: ClassVar[str]
    recommendation: ClassVar[str]

    @abstractmethod
    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        """Evaluate a complete snapshot without persistence or external calls."""

    def finding_for_resource(
        self,
        resource: NormalizedResource,
        evidence: dict[str, object],
    ) -> FindingCandidate:
        """Build a candidate using whitelisted evidence and stable resource identity."""

        return FindingCandidate(
            control_id=self.control_id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            aws_resource_id=resource.aws_resource_id,
            arn=resource.arn,
            name=resource.name,
            scope=resource.scope,
            region=resource.region,
            evidence=evidence,
            impact=self.impact,
            recommendation=self.recommendation,
        )

    def finding_for_account(
        self,
        snapshot: InventorySnapshot,
        evidence: dict[str, object],
        *,
        service: str,
    ) -> FindingCandidate:
        """Build a stable account-scoped candidate for absence-based controls."""

        return FindingCandidate(
            control_id=self.control_id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            account_id=snapshot.account_id,
            service=service,
            resource_type="aws_account",
            aws_resource_id=snapshot.account_id,
            name=snapshot.account_id,
            scope=ResourceScope.GLOBAL,
            evidence=evidence,
            impact=self.impact,
            recommendation=self.recommendation,
        )
