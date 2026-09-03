"""S3 storage security controls."""

from collections.abc import Mapping

from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.assessment.profiles import AssessmentProfile
from app.rules.base import RuleEvaluationError, SecurityRule
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot

_S3_ENCRYPTION_ALGORITHMS = {"AES256", "aws:fsx", "aws:kms", "aws:kms:dsse"}


class MissingBucketEncryptionRule(SecurityRule):
    """S3-900: retain the legacy explicit default-encryption check without ID collision."""

    control_id = "S3-900"
    title = "Missing Bucket Encryption"
    category = ControlCategory.STORAGE
    default_severity = Severity.MEDIUM
    impact = (
        "Without an explicit default encryption configuration, the bucket cannot demonstrate "
        "the intended encryption policy from its collected configuration."
    )
    recommendation = (
        "Configure default server-side encryption that meets the organization's key-management "
        "requirements."
    )

    def assess(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
    ) -> tuple[AssessmentCandidate, ...]:
        """Assess every S3 bucket without interpreting absent facts as a pass."""

        if not snapshot.collector_succeeded("s3_buckets"):
            return (
                self.assessment_for_unavailable_collector(
                    snapshot,
                    profile,
                    collector="s3_buckets",
                    service="s3",
                    source_api="s3:GetBucketEncryption",
                ),
            )

        resources = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "s3" and resource.resource_type == "s3_bucket"
            ),
            key=lambda resource: resource.identity,
        )
        if not resources:
            return (
                self.assessment_for_account(
                    snapshot,
                    profile,
                    result=AssessmentResult.NOT_APPLICABLE,
                    service="s3",
                    evidence=None,
                    reason="The snapshot contains no S3 buckets.",
                    collector="s3_buckets",
                    source_api="s3:GetBucketEncryption",
                ),
            )

        assessments: list[AssessmentCandidate] = []
        for resource in resources:
            error_path = self._encryption_error_path(resource.configuration)
            if error_path is not None:
                assessments.append(
                    self.assessment_for_resource(
                        snapshot,
                        profile,
                        resource,
                        result=AssessmentResult.INSUFFICIENT_EVIDENCE,
                        evidence=None,
                        missing_evidence=(error_path,),
                        reason="Required S3 default-encryption evidence is unavailable or invalid.",
                        collector="s3_buckets",
                        source_api="s3:GetBucketEncryption",
                    )
                )
                continue

            encryption = resource.configuration["default_encryption"]
            is_configured = encryption is not None
            algorithms = (
                [
                    rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                    for rule in encryption["Rules"]
                ]
                if is_configured
                else []
            )
            evidence = {
                "bucket_name": resource.name or resource.aws_resource_id,
                "region": resource.region,
                "default_encryption": "configured" if is_configured else None,
                "encryption_rule_count": len(encryption["Rules"]) if is_configured else 0,
                "encryption_algorithms": algorithms,
            }
            assessments.append(
                self.assessment_for_resource(
                    snapshot,
                    profile,
                    resource,
                    result=(AssessmentResult.PASS if is_configured else AssessmentResult.FAIL),
                    evidence=evidence,
                    reason=(
                        "A non-empty default-encryption rule set was collected."
                        if is_configured
                        else "No explicit S3 default-encryption configuration was collected."
                    ),
                    collector="s3_buckets",
                    source_api="s3:GetBucketEncryption",
                )
            )

        return tuple(assessments)

    @staticmethod
    def _encryption_error_path(configuration: Mapping[str, object]) -> str | None:
        """Return the first missing or malformed required fact path, if any."""

        if "default_encryption" not in configuration:
            return "configuration.default_encryption"
        encryption = configuration["default_encryption"]
        if encryption is None:
            return None
        if not isinstance(encryption, Mapping):
            return "configuration.default_encryption"
        encryption_rules = encryption.get("Rules")
        if not isinstance(encryption_rules, list) or not encryption_rules:
            return "configuration.default_encryption.Rules"
        for index, rule in enumerate(encryption_rules):
            rule_path = f"configuration.default_encryption.Rules[{index}]"
            if not isinstance(rule, Mapping):
                return rule_path
            defaults = rule.get("ApplyServerSideEncryptionByDefault")
            if not isinstance(defaults, Mapping):
                return f"{rule_path}.ApplyServerSideEncryptionByDefault"
            algorithm = defaults.get("SSEAlgorithm")
            if algorithm not in _S3_ENCRYPTION_ALGORITHMS:
                return f"{rule_path}.ApplyServerSideEncryptionByDefault.SSEAlgorithm"
        return None

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        self.require_collector_success(snapshot, "s3_buckets")
        findings: list[FindingCandidate] = []
        resources = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "s3" and resource.resource_type == "s3_bucket"
            ),
            key=lambda resource: resource.identity,
        )

        for resource in resources:
            error_path = self._encryption_error_path(resource.configuration)
            if error_path is not None:
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    error_path,
                )

            encryption = resource.configuration["default_encryption"]
            if encryption is None:
                findings.append(
                    self.finding_for_resource(
                        resource,
                        {
                            "bucket_name": resource.name or resource.aws_resource_id,
                            "region": resource.region,
                            "default_encryption": None,
                        },
                    )
                )
                continue

        return tuple(findings)
