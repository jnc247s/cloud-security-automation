"""AWS audit logging controls."""

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

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
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
