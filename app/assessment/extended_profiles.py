"""Explicit extended profile serialization; legacy profile bytes remain unchanged."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.assessment.profiles import AssessmentProfile
from app.assessment.s3_exposure import S3ExposureApprovalPolicy
from app.assessment.sensitive_buckets import SensitiveBucketClassifier

GOVERNED_RESOURCE_TYPES = frozenset(
    {
        "ec2_instance",
        "ebs_volume",
        "vpc",
        "subnet",
        "security_group",
        "vpc_flow_log",
        "s3_bucket",
        "iam_user",
        "iam_role",
        "iam_customer_managed_policy",
        "cloudtrail_trail",
    }
)
EXTENSION_FIELDS = (
    "max_unused_access_key_days",
    "high_risk_public_tcp_ports",
    "vpc_flow_log_required_environments",
    "acceptable_vpc_flow_log_traffic_types",
    "governed_resource_types",
    "s3_exposure_approvals",
    "sensitive_bucket_classifier",
)


class ExtendedAssessmentProfile(AssessmentProfile):
    """Schema 2 policy, never selected implicitly by an organization version number."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid", str_strip_whitespace=False)

    schema_version: Literal["2.0.0"]
    max_unused_access_key_days: int | None = Field(default=None, ge=1)
    high_risk_public_tcp_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] | None = None
    vpc_flow_log_required_environments: tuple[str, ...] | None = None
    acceptable_vpc_flow_log_traffic_types: tuple[Literal["REJECT", "ALL"], ...] | None = None
    governed_resource_types: tuple[str, ...] | None = None
    s3_exposure_approvals: S3ExposureApprovalPolicy | None = None
    sensitive_bucket_classifier: SensitiveBucketClassifier | None = None

    @field_validator(
        "high_risk_public_tcp_ports",
        "vpc_flow_log_required_environments",
        "acceptable_vpc_flow_log_traffic_types",
        "governed_resource_types",
    )
    @classmethod
    def validate_policy_sets(cls, values):
        if values is None:
            return None
        if len(values) != len(set(values)):
            raise ValueError("extended policy entries must be unique")
        if any(isinstance(value, str) and not value.strip() for value in values):
            raise ValueError("extended policy entries must not be blank")
        return tuple(sorted(values))

    @field_validator("governed_resource_types")
    @classmethod
    def validate_governed_types(cls, values):
        if values is not None and set(values) - GOVERNED_RESOURCE_TYPES:
            raise ValueError("unsupported governed resource type")
        return values

    @model_validator(mode="after")
    def require_enabled_policy(self) -> Self:
        required = {
            "IAM-003": ("max_unused_access_key_days",),
            "NET-004": ("high_risk_public_tcp_ports",),
            "NET-006": (
                "vpc_flow_log_required_environments",
                "acceptable_vpc_flow_log_traffic_types",
            ),
            "GOV-001": ("required_tags", "governed_resource_types"),
            "S3-002": ("s3_exposure_approvals",),
            "LOG-004": ("s3_exposure_approvals",),
            "S3-004": ("sensitive_bucket_classifier",),
        }
        for control_id in self.enabled_controls:
            for field in required.get(control_id, ()):
                value = getattr(self, field)
                if value is None or (value == () and field != "high_risk_public_tcp_ports"):
                    raise ValueError("enabled control requires explicit policy inputs")
        return self

    def calculate_content_checksum(self) -> str:
        content = canonical_profile_document(self)
        return hashlib.sha256(
            json.dumps(
                content, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()


def canonical_profile_document(profile: AssessmentProfile) -> dict:
    """Return complete policy content without inventing fields in legacy documents."""

    content = profile.model_dump(mode="json", exclude={"content_checksum"})
    for key in (
        "enabled_controls",
        "required_tags",
        "approved_management_cidrs",
        "public_ec2_exceptions",
    ):
        content[key] = sorted(content[key])
    return content


def validate_profile_document(document: dict, *, persisted: bool = False) -> AssessmentProfile:
    """Revalidate nested values, retaining strict JSON semantics and exact stored checksums."""

    if persisted and not isinstance(document.get("content_checksum"), str):
        raise ValueError("persisted profile checksum is required")
    model = ExtendedAssessmentProfile if "schema_version" in document else AssessmentProfile
    return model.model_validate_json(json.dumps(document, allow_nan=False))
