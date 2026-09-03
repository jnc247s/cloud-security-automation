"""AWS audit logging controls."""

from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.assessment.profiles import AssessmentProfile
from app.rules.base import RuleEvaluationError, SecurityRule
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot


class MissingCloudTrailRule(SecurityRule):
    """LOG-001: detect an account inventory with no actively logging trail."""

    control_id = "LOG-001"
    title = "CloudTrail Missing"
    category = ControlCategory.LOGGING
    default_severity = Severity.HIGH
    impact = (
        "Without an actively logging CloudTrail trail, security investigations and audit "
        "reconstruction can have material visibility gaps."
    )
    recommendation = (
        "Configure and continuously monitor an actively logging CloudTrail trail; prefer a "
        "multi-Region trail that includes global service events."
    )

    def assess(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
    ) -> tuple[AssessmentCandidate, ...]:
        """Return one account-scoped CloudTrail assessment with explicit evidence state."""

        if not snapshot.collector_succeeded("cloudtrail_trails"):
            return (
                self.assessment_for_unavailable_collector(
                    snapshot,
                    profile,
                    collector="cloudtrail_trails",
                    service="cloudtrail",
                    source_api="cloudtrail:ListTrails,cloudtrail:GetTrailStatus",
                ),
            )

        trails = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "cloudtrail" and resource.resource_type == "cloudtrail_trail"
            ),
            key=lambda resource: resource.identity,
        )
        inactive_trails: list[dict[str, object]] = []
        active_trail_count = 0
        missing_evidence: list[str] = []

        for trail in trails:
            is_logging = trail.configuration.get("is_logging")
            if not isinstance(is_logging, bool):
                missing_evidence.append(
                    f"resources[{trail.aws_resource_id}].configuration.is_logging"
                )
                continue
            if is_logging:
                active_trail_count += 1
                continue
            inactive_trails.append(
                {
                    "trail_arn": trail.arn,
                    "trail_name": trail.name,
                    "home_region": trail.region,
                    "is_logging": False,
                }
            )

        if missing_evidence:
            return (
                self.assessment_for_account(
                    snapshot,
                    profile,
                    result=AssessmentResult.INSUFFICIENT_EVIDENCE,
                    service="cloudtrail",
                    evidence=None,
                    missing_evidence=tuple(missing_evidence),
                    reason=(
                        "One or more CloudTrail logging-status facts are unavailable or invalid."
                    ),
                    collector="cloudtrail_trails",
                    source_api="cloudtrail:ListTrails,cloudtrail:GetTrailStatus",
                ),
            )

        evidence = {
            "account_id": snapshot.account_id,
            "requested_region": snapshot.requested_region,
            "trail_count": len(trails),
            "active_trail_count": active_trail_count,
            "reason": (
                "active_trail_found"
                if active_trail_count
                else ("no_trails" if not trails else "no_active_trails")
            ),
            "inactive_trails": inactive_trails,
        }
        result = AssessmentResult.PASS if active_trail_count else AssessmentResult.FAIL
        return (
            self.assessment_for_account(
                snapshot,
                profile,
                result=result,
                service="cloudtrail",
                evidence=evidence,
                reason=(
                    "At least one collected CloudTrail trail is actively logging."
                    if active_trail_count
                    else "No collected CloudTrail trail is actively logging."
                ),
                collector="cloudtrail_trails",
                source_api="cloudtrail:ListTrails,cloudtrail:GetTrailStatus",
            ),
        )

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        self.require_collector_success(snapshot, "cloudtrail_trails")
        trails = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "cloudtrail" and resource.resource_type == "cloudtrail_trail"
            ),
            key=lambda resource: resource.identity,
        )
        inactive_trails: list[dict[str, object]] = []
        active_trail_count = 0

        for trail in trails:
            is_logging = trail.configuration.get("is_logging")
            if not isinstance(is_logging, bool):
                raise RuleEvaluationError(
                    self.control_id,
                    trail.aws_resource_id,
                    "configuration.is_logging",
                )
            if is_logging:
                active_trail_count += 1
                continue

            inactive_trails.append(
                {
                    "trail_arn": trail.arn,
                    "trail_name": trail.name,
                    "home_region": trail.region,
                    "is_logging": False,
                }
            )

        if active_trail_count:
            return ()

        evidence = {
            "account_id": snapshot.account_id,
            "requested_region": snapshot.requested_region,
            "trail_count": len(trails),
            "active_trail_count": 0,
            "reason": "no_trails" if not trails else "no_active_trails",
            "inactive_trails": inactive_trails,
        }
        return (
            self.finding_for_account(
                snapshot,
                evidence,
                service="cloudtrail",
            ),
        )
