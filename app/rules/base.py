"""Side-effect-free security rule contracts and shared helpers."""

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import JsonValue

from app.assessment.identities import assessment_scan_id, resource_snapshot_id
from app.assessment.models import AssessmentCandidate, AssessmentResult, EvidenceArtifact
from app.assessment.profiles import AssessmentProfile
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

    def assess(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
    ) -> tuple[AssessmentCandidate, ...]:
        """Adapt a legacy failure-only rule to the four-state assessment contract.

        Built-in controls override this method so they can represent PASS,
        INSUFFICIENT_EVIDENCE, and NOT_APPLICABLE explicitly. Keeping this adapter makes the
        existing ``evaluate`` extension point backward compatible for third-party rules.
        """

        return tuple(
            self.assessment_for_target(
                snapshot,
                profile,
                result=AssessmentResult.FAIL,
                account_id=finding.account_id,
                service=finding.service,
                resource_type=finding.resource_type,
                aws_resource_id=finding.aws_resource_id,
                arn=finding.arn,
                name=finding.name,
                scope=finding.scope,
                region=finding.region,
                evidence=finding.evidence,
                reason="Legacy rule emitted a failure finding.",
                collector="legacy-rule-adapter",
                source_api="legacy FindingCandidate",
            )
            for finding in self.evaluate(snapshot)
        )

    def assessment_for_resource(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
        resource: NormalizedResource,
        *,
        result: AssessmentResult,
        evidence: dict[str, JsonValue] | None,
        reason: str,
        collector: str,
        source_api: str,
        missing_evidence: tuple[str, ...] = (),
    ) -> AssessmentCandidate:
        """Build a provenance-rich assessment for one normalized resource."""

        return self.assessment_for_target(
            snapshot,
            profile,
            result=result,
            account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            aws_resource_id=resource.aws_resource_id,
            arn=resource.arn,
            name=resource.name,
            scope=resource.scope,
            region=resource.region,
            evidence=evidence,
            reason=reason,
            collector=collector,
            source_api=source_api,
            missing_evidence=missing_evidence,
        )

    def assessment_for_account(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
        *,
        result: AssessmentResult,
        service: str,
        evidence: dict[str, JsonValue] | None,
        reason: str,
        collector: str,
        source_api: str,
        missing_evidence: tuple[str, ...] = (),
    ) -> AssessmentCandidate:
        """Build an account-scoped result for absence checks or non-applicability."""

        return self.assessment_for_target(
            snapshot,
            profile,
            result=result,
            account_id=snapshot.account_id,
            service=service,
            resource_type="aws_account",
            aws_resource_id=snapshot.account_id,
            arn=None,
            name=snapshot.account_id,
            scope=ResourceScope.GLOBAL,
            region=None,
            evidence=evidence,
            reason=reason,
            collector=collector,
            source_api=source_api,
            missing_evidence=missing_evidence,
        )

    def assessment_for_unavailable_collector(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
        *,
        collector: str,
        service: str,
        source_api: str,
    ) -> AssessmentCandidate:
        """Represent unrequested, failed, or partial collection as insufficient evidence."""

        status = snapshot.collection_status(collector)
        status_label = status.value if status is not None else "NOT_REQUESTED"
        return self.assessment_for_account(
            snapshot,
            profile,
            result=AssessmentResult.INSUFFICIENT_EVIDENCE,
            service=service,
            evidence=None,
            missing_evidence=(f"collector_outcomes.{collector}.SUCCEEDED",),
            reason=f"Collector {collector} did not succeed (status={status_label}).",
            collector=collector,
            source_api=source_api,
        )

    def require_collector_success(
        self,
        snapshot: InventorySnapshot,
        collector: str,
    ) -> None:
        """Keep the legacy failure-only interface from hiding incomplete collection."""

        if not snapshot.collector_succeeded(collector):
            raise RuleEvaluationError(
                self.control_id,
                snapshot.account_id,
                f"collector_outcomes.{collector}.SUCCEEDED",
            )

    def assessment_for_target(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
        *,
        result: AssessmentResult,
        account_id: str,
        service: str,
        resource_type: str,
        aws_resource_id: str,
        arn: str | None,
        name: str | None,
        scope: ResourceScope,
        region: str | None,
        evidence: dict[str, JsonValue] | None,
        reason: str,
        collector: str,
        source_api: str,
        missing_evidence: tuple[str, ...] = (),
    ) -> AssessmentCandidate:
        """Build one deterministic in-memory result without persistence or external calls."""

        scan_id = assessment_scan_id(snapshot)
        target_snapshot_id = resource_snapshot_id(
            scan_id=scan_id,
            account_id=account_id,
            service=service,
            resource_type=resource_type,
            scope=scope,
            region=region,
            aws_resource_id=aws_resource_id,
        )
        artifacts: tuple[EvidenceArtifact, ...] = ()
        if evidence is not None:
            artifacts = (
                EvidenceArtifact.for_assessment(
                    resource_snapshot_id=target_snapshot_id,
                    scan_id=scan_id,
                    control_id=self.control_id,
                    account_id=account_id,
                    service=service,
                    resource_type=resource_type,
                    aws_resource_id=aws_resource_id,
                    arn=arn,
                    scope=scope,
                    region=region,
                    collector=collector,
                    source="normalized-inventory",
                    source_api=source_api,
                    collected_at=snapshot.collected_at,
                    schema_name=f"control.{self.control_id.lower()}.evidence",
                    schema_version="1.0.0",
                    payload=evidence,
                ),
            )

        return AssessmentCandidate(
            control_id=self.control_id,
            result=result,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            profile_checksum=profile.calculate_content_checksum(),
            scan_id=scan_id,
            resource_snapshot_id=target_snapshot_id,
            account_id=account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            arn=arn,
            name=name,
            scope=scope,
            region=region,
            evidence_artifacts=artifacts,
            missing_evidence=missing_evidence,
            reason=reason,
        )

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
