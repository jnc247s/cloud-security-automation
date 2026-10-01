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

    if (catalog_id, version) == ("aws-cloud-security-controls", "0.2.1"):
        return build_default_control_catalog(), build_default_registry()
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.3.0"):
        from app.assessment.iam_controls import IAM_CONTROL_IDS, build_iam_control_catalog
        from app.rules.iam_credentials import IAMCredentialRule

        registry = build_default_registry()
        for control_id in IAM_CONTROL_IDS:
            registry.register(IAMCredentialRule(control_id))
        return build_iam_control_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.4.0"):
        from app.assessment.iam_policy_control import build_iam_policy_catalog
        from app.rules.iam_policy import IAMPolicyRule

        _, registry = resolve_catalog(catalog_id, "0.3.0")
        registry.register(IAMPolicyRule())
        return build_iam_policy_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.5.0"):
        from app.assessment.ec2_controls import build_ec2_catalog
        from app.assessment.ec2_evidence import EC2_CONTROL_IDS
        from app.rules.ec2 import EC2Rule

        _, registry = resolve_catalog(catalog_id, "0.4.0")
        for control_id in EC2_CONTROL_IDS:
            registry.register(EC2Rule(control_id))
        return build_ec2_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.6.0"):
        from app.assessment.security_group_controls import build_network_catalog
        from app.assessment.security_group_evidence import NETWORK_CONTROL_IDS
        from app.rules.security_groups import SecurityGroupRule

        _, registry = resolve_catalog(catalog_id, "0.5.0")
        for control_id in NETWORK_CONTROL_IDS:
            registry.register(SecurityGroupRule(control_id))
        return build_network_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.7.0"):
        from app.assessment.flow_log_control import build_flow_log_catalog
        from app.rules.flow_logs import VPCFlowLogRule

        _, registry = resolve_catalog(catalog_id, "0.6.0")
        registry.register(VPCFlowLogRule())
        return build_flow_log_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.8.0"):
        from app.assessment.s3_configuration_controls import build_s3_configuration_catalog
        from app.assessment.s3_configuration_evidence import S3_CONFIGURATION_IDS
        from app.rules.s3_configuration import S3ConfigurationRule

        _, registry = resolve_catalog(catalog_id, "0.7.0")
        for control_id in S3_CONFIGURATION_IDS:
            registry.register(S3ConfigurationRule(control_id))
        return build_s3_configuration_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.9.0"):
        from app.assessment.s3_exposure_control import build_exposure_catalog
        from app.rules.s3_exposure import S3ExposureRule

        _, registry = resolve_catalog(catalog_id, "0.8.0")
        registry.register(S3ExposureRule())
        return build_exposure_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.10.0"):
        from app.assessment.s3_sensitive_kms_control import build_sensitive_kms_catalog
        from app.rules.s3_sensitive_kms import S3SensitiveKMSRule

        _, registry = resolve_catalog(catalog_id, "0.9.0")
        registry.register(S3SensitiveKMSRule())
        return build_sensitive_kms_catalog(), registry
    if (catalog_id, version) == ("aws-cloud-security-controls", "0.11.0"):
        from app.assessment.cloudtrail_controls import build_cloudtrail_catalog
        from app.rules.cloudtrail import CloudTrailRule

        _, registry = resolve_catalog(catalog_id, "0.10.0")
        for control_id in ("LOG-002", "LOG-003"):
            registry.register(CloudTrailRule(control_id))
        return build_cloudtrail_catalog(), registry
    raise ValueError("unsupported assessment catalog version")
