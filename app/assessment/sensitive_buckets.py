"""Versioned policy for deterministic S3 sensitive-bucket classification.

This module defines a pure assessment contract. It deliberately has no collector, rule,
database, or application-registration side effects. A later S3-004 implementation can bind an
immutable instance to an assessment profile and persist that exact artifact with the assessment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SENSITIVE_BUCKET_CLASSIFIER_ID = "sensitive-bucket"
SENSITIVE_BUCKET_CLASSIFIER_SCHEMA_VERSION = "1.0.0"

_S3_BUCKET_ARN = re.compile(
    r"^arn:(?:aws|aws-[a-z0-9-]+):s3:::(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$"
)
_NAME_PATTERN = re.compile(r"^[a-z0-9*][a-z0-9.*-]{1,61}[a-z0-9*]$")


class BucketSensitivity(StrEnum):
    """The classifier's typed, control-independent conclusion."""

    SENSITIVE = "SENSITIVE"
    NOT_SENSITIVE = "NOT_SENSITIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class BucketSensitivityReason(StrEnum):
    """Stable reason identifiers for human-auditable classification results."""

    EXPLICIT_SENSITIVE_BUCKET = "explicit_sensitive_bucket"
    EXPLICIT_NON_SENSITIVE_OVERRIDE = "explicit_non_sensitive_override"
    SENSITIVE_NAME_PATTERN = "sensitive_name_pattern"
    SENSITIVE_TAG = "sensitive_tag"
    NO_SENSITIVE_SIGNAL = "no_sensitive_signal"
    REQUIRED_TAGS_UNAVAILABLE = "required_tags_unavailable"


class SensitiveBucketTagRule(BaseModel):
    """One exact, case-sensitive tag key/value pair that marks a bucket sensitive."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    key: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=256)

    @field_validator("key")
    @classmethod
    def reject_blank_key(cls, value: str) -> str:
        """Reject an invisible tag key without altering case or whitespace."""

        if not value.strip():
            raise ValueError("sensitive tag rule key must not be blank")
        return value


class BucketTag(BaseModel):
    """One normalized S3 bucket tag used as classifier evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    key: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=256)

    @field_validator("key")
    @classmethod
    def reject_blank_key(cls, value: str) -> str:
        """Reject an invisible tag key without normalizing evidence."""

        if not value.strip():
            raise ValueError("bucket tag key must not be blank")
        return value


class SensitiveBucketEvidence(BaseModel):
    """Normalized, reproducible inputs for one bucket classification.

    ``tags=None`` means tag collection was unavailable or incomplete. An empty tuple means the
    tag API completed and authoritatively returned no tags.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    bucket_arn: str
    tags: tuple[BucketTag, ...] | None = None

    @field_validator("bucket_arn")
    @classmethod
    def require_bucket_arn(cls, value: str) -> str:
        """Accept bucket ARNs only, excluding object and access-point ARNs."""

        _bucket_name(value)
        return value

    @field_validator("tags")
    @classmethod
    def require_unique_tag_keys(
        cls,
        values: tuple[BucketTag, ...] | None,
    ) -> tuple[BucketTag, ...] | None:
        """Reject ambiguous duplicate tag keys and canonicalize complete tag evidence."""

        if values is None:
            return None
        keys = [tag.key for tag in values]
        if len(keys) != len(set(keys)):
            raise ValueError("bucket tag keys must be unique")
        return tuple(sorted(values, key=lambda tag: (tag.key, tag.value)))


class BucketSensitivityResult(BaseModel):
    """Typed classifier output bound to the exact immutable policy artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    bucket_arn: str
    sensitivity: BucketSensitivity
    reason: BucketSensitivityReason
    classifier_id: Literal["sensitive-bucket"]
    classifier_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    classifier_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    matched_name_patterns: tuple[str, ...] = ()
    matched_tag_rules: tuple[SensitiveBucketTagRule, ...] = ()

    @field_validator("bucket_arn")
    @classmethod
    def require_bucket_arn(cls, value: str) -> str:
        """Keep reconstructed results bound to one exact bucket identity."""

        _bucket_name(value)
        return value

    @model_validator(mode="after")
    def validate_reason_matches_result(self) -> Self:
        """Reject internally contradictory reconstructed classifier results."""

        expected_sensitivity = {
            BucketSensitivityReason.EXPLICIT_SENSITIVE_BUCKET: BucketSensitivity.SENSITIVE,
            BucketSensitivityReason.EXPLICIT_NON_SENSITIVE_OVERRIDE: (
                BucketSensitivity.NOT_SENSITIVE
            ),
            BucketSensitivityReason.SENSITIVE_NAME_PATTERN: BucketSensitivity.SENSITIVE,
            BucketSensitivityReason.SENSITIVE_TAG: BucketSensitivity.SENSITIVE,
            BucketSensitivityReason.NO_SENSITIVE_SIGNAL: BucketSensitivity.NOT_SENSITIVE,
            BucketSensitivityReason.REQUIRED_TAGS_UNAVAILABLE: (
                BucketSensitivity.INSUFFICIENT_EVIDENCE
            ),
        }[self.reason]
        if self.sensitivity is not expected_sensitivity:
            raise ValueError("classifier result reason does not match sensitivity")
        if (
            self.reason is BucketSensitivityReason.SENSITIVE_NAME_PATTERN
            and not self.matched_name_patterns
        ):
            raise ValueError("name-pattern result requires a matched pattern")
        if self.reason is BucketSensitivityReason.SENSITIVE_TAG and not self.matched_tag_rules:
            raise ValueError("tag result requires a matched tag rule")
        return self


class SensitiveBucketClassifier(BaseModel):
    """Immutable, versioned, configuration-driven bucket classifier.

    Exact non-sensitive bucket entries are intentional overrides of broad name and tag rules.
    Exact sensitive and non-sensitive entries may never overlap.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    classifier_id: Literal["sensitive-bucket"] = SENSITIVE_BUCKET_CLASSIFIER_ID
    schema_version: Literal["1.0.0"] = SENSITIVE_BUCKET_CLASSIFIER_SCHEMA_VERSION
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    sensitive_bucket_arns: tuple[str, ...] = ()
    non_sensitive_bucket_arns: tuple[str, ...] = ()
    sensitive_name_patterns: tuple[str, ...] = ()
    sensitive_tag_rules: tuple[SensitiveBucketTagRule, ...] = ()
    content_checksum: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("sensitive_bucket_arns", "non_sensitive_bucket_arns")
    @classmethod
    def validate_bucket_arns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Require exact, unique bucket ARNs and canonicalize policy ordering."""

        for value in values:
            _bucket_name(value)
        if len(values) != len(set(values)):
            raise ValueError("classifier bucket ARNs must be unique")
        return tuple(sorted(values))

    @field_validator("sensitive_name_patterns")
    @classmethod
    def validate_name_patterns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Allow only auditable full-name patterns with ``*`` as the sole wildcard."""

        for value in values:
            if (
                not _NAME_PATTERN.fullmatch(value)
                or "*" not in value
                or "**" in value
                or ".." in value
            ):
                raise ValueError(
                    "sensitive bucket name patterns must be 3-63 lowercase bucket-name "
                    "characters, contain '*', and use '*' as the only wildcard"
                )
        if len(values) != len(set(values)):
            raise ValueError("sensitive bucket name patterns must be unique")
        return tuple(sorted(values))

    @field_validator("sensitive_tag_rules")
    @classmethod
    def validate_tag_rules(
        cls,
        values: tuple[SensitiveBucketTagRule, ...],
    ) -> tuple[SensitiveBucketTagRule, ...]:
        """Reject duplicate rules and canonicalize them without changing exact values."""

        identities = [(rule.key, rule.value) for rule in values]
        if len(identities) != len(set(identities)):
            raise ValueError("sensitive bucket tag rules must be unique")
        return tuple(sorted(values, key=lambda rule: (rule.key, rule.value)))

    @model_validator(mode="after")
    def validate_policy_and_checksum(self) -> Self:
        """Reject contradictory/vacuous policy and bind the artifact to its content."""

        overlap = set(self.sensitive_bucket_arns) & set(self.non_sensitive_bucket_arns)
        if overlap:
            raise ValueError(
                "a bucket ARN cannot be both sensitive and an explicit non-sensitive override"
            )
        if not (
            self.sensitive_bucket_arns or self.sensitive_name_patterns or self.sensitive_tag_rules
        ):
            raise ValueError("classifier requires at least one sensitive classification rule")

        expected_checksum = self.calculate_content_checksum()
        if self.content_checksum is None:
            object.__setattr__(self, "content_checksum", expected_checksum)
        elif not hmac.compare_digest(self.content_checksum, expected_checksum):
            raise ValueError("content_checksum does not match sensitive bucket classifier content")
        return self

    def calculate_content_checksum(self) -> str:
        """Return an order-independent SHA-256 identity including both versions."""

        content = {
            "classifier_id": self.classifier_id,
            "non_sensitive_bucket_arns": sorted(self.non_sensitive_bucket_arns),
            "schema_version": self.schema_version,
            "sensitive_bucket_arns": sorted(self.sensitive_bucket_arns),
            "sensitive_name_patterns": sorted(self.sensitive_name_patterns),
            "sensitive_tag_rules": sorted(
                ({"key": rule.key, "value": rule.value} for rule in self.sensitive_tag_rules),
                key=lambda rule: (rule["key"], rule["value"]),
            ),
            "version": self.version,
        }
        encoded = json.dumps(
            content,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def classify(self, evidence: SensitiveBucketEvidence) -> BucketSensitivityResult:
        """Classify one bucket with deterministic precedence and fail-closed evidence handling."""

        bucket_name = _bucket_name(evidence.bucket_arn)
        matched_patterns = tuple(
            pattern for pattern in self.sensitive_name_patterns if fnmatchcase(bucket_name, pattern)
        )
        available_tags = (
            {(tag.key, tag.value) for tag in evidence.tags} if evidence.tags is not None else None
        )
        matched_tag_rules = (
            tuple(
                rule
                for rule in self.sensitive_tag_rules
                if (rule.key, rule.value) in available_tags
            )
            if available_tags is not None
            else ()
        )

        if evidence.bucket_arn in self.sensitive_bucket_arns:
            sensitivity = BucketSensitivity.SENSITIVE
            reason = BucketSensitivityReason.EXPLICIT_SENSITIVE_BUCKET
        elif evidence.bucket_arn in self.non_sensitive_bucket_arns:
            sensitivity = BucketSensitivity.NOT_SENSITIVE
            reason = BucketSensitivityReason.EXPLICIT_NON_SENSITIVE_OVERRIDE
        elif matched_patterns:
            sensitivity = BucketSensitivity.SENSITIVE
            reason = BucketSensitivityReason.SENSITIVE_NAME_PATTERN
        elif matched_tag_rules:
            sensitivity = BucketSensitivity.SENSITIVE
            reason = BucketSensitivityReason.SENSITIVE_TAG
        elif self.sensitive_tag_rules and available_tags is None:
            sensitivity = BucketSensitivity.INSUFFICIENT_EVIDENCE
            reason = BucketSensitivityReason.REQUIRED_TAGS_UNAVAILABLE
        else:
            sensitivity = BucketSensitivity.NOT_SENSITIVE
            reason = BucketSensitivityReason.NO_SENSITIVE_SIGNAL

        return BucketSensitivityResult(
            bucket_arn=evidence.bucket_arn,
            sensitivity=sensitivity,
            reason=reason,
            classifier_id=self.classifier_id,
            classifier_version=self.version,
            classifier_checksum=self.content_checksum,
            matched_name_patterns=matched_patterns,
            matched_tag_rules=matched_tag_rules,
        )


def _bucket_name(bucket_arn: str) -> str:
    match = _S3_BUCKET_ARN.fullmatch(bucket_arn)
    if match is None or ".." in match.group("bucket"):
        raise ValueError("classifier inputs must use an exact S3 bucket ARN")
    return match.group("bucket")
