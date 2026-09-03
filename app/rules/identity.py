"""IAM identity security controls."""

from collections.abc import Mapping

from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.assessment.profiles import AssessmentProfile
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

    def assess(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
    ) -> tuple[AssessmentCandidate, ...]:
        """Assess MFA-device evidence for each collected IAM user."""

        if not snapshot.collector_succeeded("iam_users"):
            return (
                self.assessment_for_unavailable_collector(
                    snapshot,
                    profile,
                    collector="iam_users",
                    service="iam",
                    source_api="iam:ListMFADevices",
                ),
            )

        resources = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "iam" and resource.resource_type == "iam_user"
            ),
            key=lambda resource: resource.identity,
        )
        if not resources:
            return (
                self.assessment_for_account(
                    snapshot,
                    profile,
                    result=AssessmentResult.NOT_APPLICABLE,
                    service="iam",
                    evidence=None,
                    reason="The snapshot contains no IAM users.",
                    collector="iam_users",
                    source_api="iam:ListMFADevices",
                ),
            )

        assessments: list[AssessmentCandidate] = []
        for resource in resources:
            mfa_devices = resource.configuration.get("mfa_devices")
            error_path = _mfa_devices_error_path(mfa_devices)
            if error_path is not None:
                assessments.append(
                    self.assessment_for_resource(
                        snapshot,
                        profile,
                        resource,
                        result=AssessmentResult.INSUFFICIENT_EVIDENCE,
                        evidence=None,
                        missing_evidence=(error_path,),
                        reason="Required IAM MFA-device evidence is unavailable or invalid.",
                        collector="iam_users",
                        source_api="iam:ListMFADevices",
                    )
                )
                continue

            evidence = {
                "user_id": resource.aws_resource_id,
                "user_name": resource.name,
                "mfa_device_count": len(mfa_devices),
                "privilege_assessment": "not_implemented",
            }
            assessments.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    resource,
                    result=(AssessmentResult.PASS if mfa_devices else AssessmentResult.FAIL),
                    evidence=evidence,
                    reason=(
                        "At least one MFA device is assigned to the IAM user."
                        if mfa_devices
                        else "No MFA device is assigned to the IAM user."
                    ),
                    collector="iam_users",
                    source_api="iam:ListMFADevices",
                )
            )

        return tuple(assessments)

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        self.require_collector_success(snapshot, "iam_users")
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
            error_path = _mfa_devices_error_path(mfa_devices)
            if error_path is not None:
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    error_path,
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


def _mfa_devices_error_path(mfa_devices: object) -> str | None:
    """Return the first malformed fact needed to prove an MFA assignment."""

    if not isinstance(mfa_devices, list):
        return "configuration.mfa_devices"
    for index, device in enumerate(mfa_devices):
        if not isinstance(device, Mapping):
            return f"configuration.mfa_devices[{index}]"
        serial_number = device.get("SerialNumber")
        if not isinstance(serial_number, str) or not serial_number.strip():
            return f"configuration.mfa_devices[{index}].SerialNumber"
    return None
