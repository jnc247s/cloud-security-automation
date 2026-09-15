"""Normalized in-memory AWS resource contracts."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ResourceScope(StrEnum):
    """Whether a resource belongs to a region or has account-global scope."""

    GLOBAL = "global"
    REGIONAL = "regional"


_CANONICAL_RESOURCE_SCOPES: dict[tuple[str, str], ResourceScope] = {
    ("access-analyzer", "access_analyzer_finding"): ResourceScope.REGIONAL,
    ("cloudtrail", "cloudtrail_trail"): ResourceScope.REGIONAL,
    ("ec2", "ebs_volume"): ResourceScope.REGIONAL,
    ("ec2", "ec2_instance"): ResourceScope.REGIONAL,
    ("ec2", "security_group"): ResourceScope.REGIONAL,
    ("ec2", "subnet"): ResourceScope.REGIONAL,
    ("ec2", "vpc"): ResourceScope.REGIONAL,
    ("ec2", "vpc_flow_log"): ResourceScope.REGIONAL,
    ("iam", "iam_access_key"): ResourceScope.GLOBAL,
    ("iam", "iam_aws_managed_policy"): ResourceScope.GLOBAL,
    ("iam", "iam_customer_managed_policy"): ResourceScope.GLOBAL,
    ("iam", "iam_group"): ResourceScope.GLOBAL,
    ("iam", "iam_inline_policy"): ResourceScope.GLOBAL,
    ("iam", "iam_managed_policy_version"): ResourceScope.GLOBAL,
    ("iam", "iam_mfa_device"): ResourceScope.GLOBAL,
    ("iam", "iam_role"): ResourceScope.GLOBAL,
    ("iam", "iam_user"): ResourceScope.GLOBAL,
    ("kms", "kms_key"): ResourceScope.REGIONAL,
    ("s3", "s3_bucket"): ResourceScope.REGIONAL,
}


def canonical_resource_scope(service: str, resource_type: str) -> ResourceScope | None:
    """Return the accepted execution scope for a known Sprint 5 resource type."""

    return _CANONICAL_RESOURCE_SCOPES.get((service, resource_type))


class NormalizedResource(BaseModel):
    """Collector output that is independent of boto3 and future persistence models."""

    model_config = ConfigDict(frozen=True)

    account_id: str = Field(pattern=r"^(?:[0-9]{12}|aws)$")
    service: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    aws_resource_id: str = Field(min_length=1)
    arn: str | None = None
    name: str | None = None
    scope: ResourceScope
    region: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    raw_configuration: dict[str, Any] = Field(default_factory=dict)

    @field_validator("service", "resource_type", "aws_resource_id", "region")
    @classmethod
    def reject_identity_separator(cls, value: str | None) -> str | None:
        """Keep stable identity components unambiguous."""

        if value is not None and "\x1f" in value:
            raise ValueError("resource identity components must not contain unit separators")
        return value

    @model_validator(mode="after")
    def validate_scope_and_region(self) -> "NormalizedResource":
        """Require regional resources to have a region and global resources not to."""

        if self.scope is ResourceScope.REGIONAL and not self.region:
            raise ValueError("regional resources require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global resources must not define a region")
        signature = (self.service, self.resource_type)
        aws_owned_types = {
            ("iam", "iam_aws_managed_policy"),
            ("iam", "iam_managed_policy_version"),
        }
        if signature == ("iam", "iam_aws_managed_policy") and self.account_id != "aws":
            raise ValueError("AWS-managed IAM policies must use the aws owner sentinel")
        if self.account_id == "aws" and signature not in aws_owned_types:
            raise ValueError("the aws owner sentinel is valid only for AWS-owned IAM records")
        return self

    @property
    def identity(self) -> tuple[str, str, str, str, str, str]:
        """Return the stable composite identity used for deterministic ordering."""

        return (
            self.account_id,
            self.service,
            self.resource_type,
            self.scope.value,
            self.region or "global",
            self.aws_resource_id,
        )
