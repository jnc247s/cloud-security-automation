"""Versioned organization policy used by deterministic security assessments."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ControlId = Annotated[str, Field(pattern=r"^[A-Z0-9]+-\d{3}$")]
NonEmptyString = Annotated[str, Field(min_length=1)]

DEFAULT_PROFILE_ID = "default"
DEFAULT_PROFILE_VERSION = "1.0.0"
DEFAULT_ENABLED_CONTROLS = (
    "IAM-001",
    "LOG-001",
    "NET-001",
    "NET-002",
    "S3-900",
)


class AssessmentProfile(BaseModel):
    """Immutable, versioned policy inputs that can affect control outcomes.

    Thresholds in this profile are project or organization policy. They are not
    represented as universal NIST CSF requirements.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    profile_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    version: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
    enabled_controls: tuple[ControlId, ...]
    required_tags: tuple[NonEmptyString, ...]
    stale_key_days: int = Field(ge=1)
    approved_management_cidrs: tuple[NonEmptyString, ...]
    public_ec2_exceptions: tuple[NonEmptyString, ...]
    restricted_data_requires_kms: bool
    content_checksum: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 of the canonical profile identity and policy content.",
    )

    @field_validator(
        "enabled_controls",
        "required_tags",
        "approved_management_cidrs",
        "public_ec2_exceptions",
    )
    @classmethod
    def require_unique_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Reject ambiguous policy lists rather than silently deduplicating them."""

        if len(set(values)) != len(values):
            raise ValueError("profile policy entries must be unique")
        return values

    @field_validator("approved_management_cidrs")
    @classmethod
    def validate_management_cidrs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Require canonical IPv4 or IPv6 network notation."""

        for value in values:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as error:
                raise ValueError(f"invalid approved management CIDR: {value}") from error
            if str(network) != value:
                raise ValueError(f"approved management CIDR must be canonical: {value}")
        return values

    @model_validator(mode="after")
    def set_or_verify_content_checksum(self) -> AssessmentProfile:
        """Populate a stable checksum, or reject a checksum for different content."""

        expected_checksum = self.calculate_content_checksum()
        if self.content_checksum is None:
            object.__setattr__(self, "content_checksum", expected_checksum)
        elif self.content_checksum != expected_checksum:
            raise ValueError("content_checksum does not match assessment profile content")
        return self

    def calculate_content_checksum(self) -> str:
        """Return a deterministic SHA-256 checksum of policy-affecting fields."""

        canonical_content = {
            "approved_management_cidrs": sorted(self.approved_management_cidrs),
            "enabled_controls": sorted(self.enabled_controls),
            "profile_id": self.profile_id,
            "public_ec2_exceptions": sorted(self.public_ec2_exceptions),
            "required_tags": sorted(self.required_tags),
            "restricted_data_requires_kms": self.restricted_data_requires_kms,
            "stale_key_days": self.stale_key_days,
            "version": self.version,
        }
        serialized_content = json.dumps(
            canonical_content,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(serialized_content).hexdigest()


def create_default_assessment_profile(
    *,
    required_tags: tuple[str, ...] = ("Owner", "Environment"),
    stale_key_days: int = 90,
) -> AssessmentProfile:
    """Build the versioned default policy for the existing Sprint 2 controls."""

    return AssessmentProfile(
        profile_id=DEFAULT_PROFILE_ID,
        version=DEFAULT_PROFILE_VERSION,
        enabled_controls=DEFAULT_ENABLED_CONTROLS,
        required_tags=required_tags,
        stale_key_days=stale_key_days,
        approved_management_cidrs=(),
        public_ec2_exceptions=(),
        restricted_data_requires_kms=True,
    )


DEFAULT_ASSESSMENT_PROFILE = create_default_assessment_profile()
