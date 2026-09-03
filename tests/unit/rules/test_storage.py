"""Tests for storage security controls."""

import pytest

from app.rules.base import RuleEvaluationError
from app.rules.storage import MissingBucketEncryptionRule
from app.schemas.finding import ControlCategory, Severity
from tests.unit.rules.factories import ACCOUNT_ID, REGION, resource, snapshot


def _bucket(default_encryption: object, *, bucket_name: str = "example-bucket"):
    return resource(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=bucket_name,
        arn=f"arn:aws:s3:::{bucket_name}",
        name=bucket_name,
        configuration={
            "bucket_region": REGION,
            "default_encryption": default_encryption,
            "public_access_block": None,
        },
    )


def test_s3_900_reports_explicitly_missing_default_encryption() -> None:
    bucket = _bucket(None)

    findings = MissingBucketEncryptionRule().evaluate(snapshot(bucket))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.control_id == "S3-900"
    assert finding.title == "Missing Bucket Encryption"
    assert finding.category is ControlCategory.STORAGE
    assert finding.severity is Severity.MEDIUM
    assert finding.account_id == ACCOUNT_ID
    assert finding.service == "s3"
    assert finding.resource_type == "s3_bucket"
    assert finding.aws_resource_id == "example-bucket"
    assert finding.region == REGION
    assert finding.evidence["bucket_name"] == "example-bucket"
    assert finding.evidence["default_encryption"] is None
    assert finding.impact
    assert finding.recommendation


@pytest.mark.parametrize(
    "encryption",
    [
        {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/security-data",
                    }
                }
            ]
        },
    ],
)
def test_s3_900_passes_for_a_nonempty_default_encryption_rule_set(
    encryption: dict[str, object],
) -> None:
    assert MissingBucketEncryptionRule().evaluate(snapshot(_bucket(encryption))) == ()


def test_s3_900_ignores_unrelated_resource_types() -> None:
    unrelated = resource(
        service="ec2",
        resource_type="security_group",
        aws_resource_id="sg-example",
        configuration={},
    )

    assert MissingBucketEncryptionRule().evaluate(snapshot(unrelated)) == ()


@pytest.mark.parametrize(
    "configuration",
    [
        {},
        {"default_encryption": "unknown"},
        {"default_encryption": {}},
        {"default_encryption": {"Rules": []}},
        {"default_encryption": {"Rules": [{}]}},
        {
            "default_encryption": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "unsupported"}}]
            }
        },
    ],
)
def test_s3_900_rejects_unknown_or_malformed_encryption_facts(
    configuration: dict[str, object],
) -> None:
    bucket = resource(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="malformed-bucket",
        configuration=configuration,
    )

    with pytest.raises(RuleEvaluationError) as error_info:
        MissingBucketEncryptionRule().evaluate(snapshot(bucket))

    error = error_info.value
    assert error.control_id == "S3-900"
    assert error.aws_resource_id == "malformed-bucket"
    assert "default_encryption" in error.fact_path
    assert "unknown" not in str(error)
