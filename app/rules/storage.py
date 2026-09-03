"""S3 storage security controls."""

from collections.abc import Mapping

from app.rules.base import RuleEvaluationError, SecurityRule
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot


class MissingBucketEncryptionRule(SecurityRule):
    """S3-002: detect an explicitly absent default encryption configuration."""

    control_id = "S3-002"
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

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
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
            if "default_encryption" not in resource.configuration:
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    "configuration.default_encryption",
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

            if not isinstance(encryption, Mapping):
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    "configuration.default_encryption",
                )

            encryption_rules = encryption.get("Rules")
            if not isinstance(encryption_rules, list) or not encryption_rules:
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    "configuration.default_encryption.Rules",
                )
            if any(not isinstance(rule, Mapping) for rule in encryption_rules):
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    "configuration.default_encryption.Rules",
                )

        return tuple(findings)
