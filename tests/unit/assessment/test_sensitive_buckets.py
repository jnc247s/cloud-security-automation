"""Contract tests for deterministic, versioned sensitive-bucket classification."""

import json

import pytest
from pydantic import ValidationError

from app.assessment.sensitive_buckets import (
    BucketSensitivity,
    BucketSensitivityReason,
    BucketTag,
    SensitiveBucketClassifier,
    SensitiveBucketEvidence,
    SensitiveBucketTagRule,
)

SENSITIVE_ARN = "arn:aws:s3:::prod-customer-records"
NON_SENSITIVE_ARN = "arn:aws:s3:::prod-public-assets"
OTHER_ARN = "arn:aws:s3:::team-build-artifacts"


def _classifier(**overrides: object) -> SensitiveBucketClassifier:
    values: dict[str, object] = {
        "version": "1.0.0",
        "sensitive_bucket_arns": (SENSITIVE_ARN,),
        "non_sensitive_bucket_arns": (NON_SENSITIVE_ARN,),
        "sensitive_name_patterns": ("*-customer-records", "regulated-*-archive"),
        "sensitive_tag_rules": (
            SensitiveBucketTagRule(key="DataClassification", value="Restricted"),
            SensitiveBucketTagRule(key="Environment", value="Production"),
        ),
    }
    values.update(overrides)
    return SensitiveBucketClassifier.model_validate(values)


def _evidence(
    bucket_arn: str,
    *,
    tags: tuple[BucketTag, ...] | None = (),
) -> SensitiveBucketEvidence:
    return SensitiveBucketEvidence(bucket_arn=bucket_arn, tags=tags)


def test_explicit_sensitive_bucket_is_sensitive_without_tag_evidence() -> None:
    result = _classifier().classify(_evidence(SENSITIVE_ARN, tags=None))

    assert result.sensitivity is BucketSensitivity.SENSITIVE
    assert result.reason is BucketSensitivityReason.EXPLICIT_SENSITIVE_BUCKET
    assert result.classifier_id == "sensitive-bucket"
    assert result.classifier_version == "1.0.0"
    assert len(result.classifier_checksum) == 64


def test_explicit_non_sensitive_bucket_overrides_broad_pattern_and_tag_rule() -> None:
    classifier = _classifier(sensitive_name_patterns=("prod-*",))
    evidence = _evidence(
        NON_SENSITIVE_ARN,
        tags=(BucketTag(key="DataClassification", value="Restricted"),),
    )

    result = classifier.classify(evidence)

    assert result.sensitivity is BucketSensitivity.NOT_SENSITIVE
    assert result.reason is BucketSensitivityReason.EXPLICIT_NON_SENSITIVE_OVERRIDE
    assert result.matched_name_patterns == ("prod-*",)
    assert result.matched_tag_rules == (
        SensitiveBucketTagRule(key="DataClassification", value="Restricted"),
    )


def test_exact_case_sensitive_tag_match_is_sensitive() -> None:
    result = _classifier().classify(
        _evidence(
            OTHER_ARN,
            tags=(BucketTag(key="DataClassification", value="Restricted"),),
        )
    )

    assert result.sensitivity is BucketSensitivity.SENSITIVE
    assert result.reason is BucketSensitivityReason.SENSITIVE_TAG
    assert result.matched_tag_rules[0].model_dump() == {
        "key": "DataClassification",
        "value": "Restricted",
    }


@pytest.mark.parametrize(
    "tag",
    [
        BucketTag(key="dataclassification", value="Restricted"),
        BucketTag(key="DataClassification", value="restricted"),
        BucketTag(key="Owner", value="Security"),
    ],
)
def test_non_matching_or_case_different_complete_tag_evidence_is_not_sensitive(
    tag: BucketTag,
) -> None:
    result = _classifier().classify(_evidence(OTHER_ARN, tags=(tag,)))

    assert result.sensitivity is BucketSensitivity.NOT_SENSITIVE
    assert result.reason is BucketSensitivityReason.NO_SENSITIVE_SIGNAL
    assert result.matched_tag_rules == ()


def test_restricted_wildcard_matches_the_complete_bucket_name() -> None:
    result = _classifier().classify(
        _evidence("arn:aws-us-gov:s3:::regulated-legal-archive", tags=())
    )

    assert result.sensitivity is BucketSensitivity.SENSITIVE
    assert result.reason is BucketSensitivityReason.SENSITIVE_NAME_PATTERN
    assert result.matched_name_patterns == ("regulated-*-archive",)


def test_name_match_is_conclusive_when_configured_tag_evidence_is_missing() -> None:
    result = _classifier().classify(_evidence("arn:aws:s3:::regulated-finance-archive", tags=None))

    assert result.sensitivity is BucketSensitivity.SENSITIVE
    assert result.reason is BucketSensitivityReason.SENSITIVE_NAME_PATTERN


def test_missing_configured_tag_evidence_fails_closed() -> None:
    result = _classifier().classify(_evidence(OTHER_ARN, tags=None))

    assert result.sensitivity is BucketSensitivity.INSUFFICIENT_EVIDENCE
    assert result.reason is BucketSensitivityReason.REQUIRED_TAGS_UNAVAILABLE


def test_empty_tags_are_complete_evidence_not_missing_metadata() -> None:
    result = _classifier().classify(_evidence(OTHER_ARN, tags=()))

    assert result.sensitivity is BucketSensitivity.NOT_SENSITIVE
    assert result.reason is BucketSensitivityReason.NO_SENSITIVE_SIGNAL


def test_conflicting_exact_overrides_are_rejected() -> None:
    with pytest.raises(ValidationError, match="cannot be both sensitive"):
        _classifier(non_sensitive_bucket_arns=(SENSITIVE_ARN,))


def test_checksum_is_stable_and_order_independent() -> None:
    first = _classifier()
    second = _classifier(
        sensitive_bucket_arns=tuple(reversed(first.sensitive_bucket_arns)),
        non_sensitive_bucket_arns=tuple(reversed(first.non_sensitive_bucket_arns)),
        sensitive_name_patterns=tuple(reversed(first.sensitive_name_patterns)),
        sensitive_tag_rules=tuple(reversed(first.sensitive_tag_rules)),
    )

    assert first.content_checksum == second.content_checksum
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_classifier_version_and_content_changes_produce_new_identity() -> None:
    original = _classifier()
    new_version = _classifier(version="1.0.1")
    changed_policy = _classifier(sensitive_name_patterns=("regulated-*",))

    assert original.content_checksum != new_version.content_checksum
    assert original.content_checksum != changed_policy.content_checksum

    with pytest.raises(ValidationError, match="content_checksum does not match"):
        _classifier(
            sensitive_name_patterns=("regulated-*",),
            content_checksum=original.content_checksum,
        )


def test_historical_classifier_reconstructs_strictly_with_same_result() -> None:
    original = _classifier()
    evidence = _evidence(
        OTHER_ARN,
        tags=(BucketTag(key="Environment", value="Production"),),
    )

    serialized = original.model_dump_json()
    reconstructed = SensitiveBucketClassifier.model_validate_json(serialized)

    assert reconstructed == original
    assert reconstructed.classify(evidence) == original.classify(evidence)

    tampered = json.loads(serialized)
    tampered["version"] = "1.0.1"
    with pytest.raises(ValidationError, match="content_checksum does not match"):
        SensitiveBucketClassifier.model_validate_json(json.dumps(tampered))


def test_reconstructed_result_rejects_a_reason_that_contradicts_sensitivity() -> None:
    result = _classifier().classify(_evidence(SENSITIVE_ARN, tags=()))
    values = result.model_dump(mode="python")
    values["sensitivity"] = BucketSensitivity.NOT_SENSITIVE

    with pytest.raises(ValidationError, match="reason does not match sensitivity"):
        type(result).model_validate(values)


@pytest.mark.parametrize(
    "overrides, message",
    [
        (
            {"sensitive_bucket_arns": ("arn:aws:s3:::bucket/object",)},
            "exact S3 bucket ARN",
        ),
        (
            {"sensitive_bucket_arns": ("arn:aws:s3:us-east-1:123456789012:accesspoint/test",)},
            "exact S3 bucket ARN",
        ),
        ({"sensitive_bucket_arns": (SENSITIVE_ARN, SENSITIVE_ARN)}, "must be unique"),
        ({"sensitive_name_patterns": ("prod-?-data",)}, "only wildcard"),
        ({"sensitive_name_patterns": ("prod-[ab]-data",)}, "only wildcard"),
        ({"sensitive_name_patterns": ("exact-name",)}, "only wildcard"),
        (
            {
                "sensitive_tag_rules": (
                    SensitiveBucketTagRule(key="Class", value="Secret"),
                    SensitiveBucketTagRule(key="Class", value="Secret"),
                )
            },
            "must be unique",
        ),
        (
            {
                "sensitive_bucket_arns": (),
                "sensitive_name_patterns": (),
                "sensitive_tag_rules": (),
            },
            "at least one sensitive classification rule",
        ),
    ],
)
def test_invalid_classifier_configuration_is_rejected(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises((ValidationError, ValueError), match=message):
        _classifier(**overrides)


def test_classifier_and_evidence_are_strict_frozen_and_forbid_unknown_fields() -> None:
    classifier = _classifier()

    with pytest.raises(ValidationError, match="frozen"):
        classifier.version = "2.0.0"

    values = classifier.model_dump(exclude={"content_checksum"})
    values["undocumented_heuristic"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SensitiveBucketClassifier.model_validate(values)

    with pytest.raises(ValidationError):
        SensitiveBucketClassifier.model_validate(
            {
                "version": "1.0.0",
                "sensitive_bucket_arns": [SENSITIVE_ARN],
            }
        )


def test_evidence_rejects_ambiguous_tags_and_non_bucket_arns() -> None:
    with pytest.raises(ValidationError, match="tag keys must be unique"):
        _evidence(
            OTHER_ARN,
            tags=(
                BucketTag(key="Class", value="One"),
                BucketTag(key="Class", value="Two"),
            ),
        )

    with pytest.raises(ValidationError, match="exact S3 bucket ARN"):
        _evidence("arn:aws:s3:::team-build-artifacts/object", tags=())
