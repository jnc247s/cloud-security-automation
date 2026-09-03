"""IAM identity security controls."""

from collections.abc import Mapping

from app.rules.base import RuleEvaluationError, SecurityRule
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot


class IAMUserWithoutMFARule(SecurityRule):
    """IAM-001: detect IAM users with no assigned MFA device."""

    control_id = "IAM-001"
    title = "IAM User Without MFA"
    category = ControlCategory.IDENTITY
    default_severity = Severity.MEDIUM
    impact = (
        "A password-authenticated IAM user without MFA is more exposed to account takeover "
        "when a credential is compromised."
    )
    recommendation = (
        "Enroll the IAM user in MFA, migrate workforce access to IAM Identity Center where "
        "appropriate, or remove the user if it is no longer required."
    )

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        findings: list[FindingCandidate] = []
        resources = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "iam" and resource.resource_type == "iam_user"
            ),
            key=lambda resource: resource.identity,
        )

        for resource in resources:
            mfa_devices = resource.configuration.get("mfa_devices")
            if not isinstance(mfa_devices, list):
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    "configuration.mfa_devices",
                )
            if any(not isinstance(device, Mapping) for device in mfa_devices):
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    "configuration.mfa_devices",
                )
            if mfa_devices:
                continue

            findings.append(
                self.finding_for_resource(
                    resource,
                    {
                        "user_id": resource.aws_resource_id,
                        "user_name": resource.name,
                        "mfa_device_count": 0,
                        "privilege_assessment": "not_implemented",
                    },
                )
            )

        return tuple(findings)
