"""Tests for the immutable S3-002 bucket exposure approval artifact."""

import pytest
from pydantic import ValidationError

from app.assessment.s3_exposure import (
    S3_EXPOSURE_APPROVAL_POLICY_ID,
    S3_EXPOSURE_APPROVAL_SCHEMA_VERSION,
    S3BucketExposureApproval,
    S3ExposureApprovalPolicy,
)

FIRST_BUCKET = "arn:aws:s3:::first-security-evidence"
SECOND_BUCKET = "arn:aws-us-gov:s3:::second-security-evidence"
ACCOUNT_TOKEN = "account:111122223333"
USER_ARN = "arn:aws:iam::444455556666:user/security/auditor"
ROLE_ARN = "arn:aws-us-gov:iam::777788889999:role/security/reader"
CANONICAL_USER_TOKEN = f"canonical-user:{'a' * 64}"


def _approval(**overrides: object) -> S3BucketExposureApproval:
    values: dict[str, object] = {
        "bucket_arn": FIRST_BUCKET,
        "allow_public": False,
        "approved_external_principals": (ACCOUNT_TOKEN,),
    }
    values.update(overrides)
    return S3BucketExposureApproval.model_validate(values)


def _policy(**overrides: object) -> S3ExposureApprovalPolicy:
    values: dict[str, object] = {
        "policy_id": S3_EXPOSURE_APPROVAL_POLICY_ID,
        "schema_version": S3_EXPOSURE_APPROVAL_SCHEMA_VERSION,
        "version": "1.0.0",
        "bucket_approvals": (_approval(),),
    }
    values.update(overrides)
    return S3ExposureApprovalPolicy.model_validate(values)


def test_empty_policy_is_valid_and_exact_lookup_denies_by_default() -> None:
    policy = S3ExposureApprovalPolicy(
        policy_id=S3_EXPOSURE_APPROVAL_POLICY_ID,
        schema_version=S3_EXPOSURE_APPROVAL_SCHEMA_VERSION,
        version="1.0.0",
    )

    assert policy.policy_id == S3_EXPOSURE_APPROVAL_POLICY_ID
    assert policy.schema_version == S3_EXPOSURE_APPROVAL_SCHEMA_VERSION
    assert policy.bucket_approvals == ()
    assert policy.content_checksum is not None
    assert policy.get_bucket_approval(FIRST_BUCKET) is None


def test_exact_bucket_lookup_returns_only_canonicalized_policy_data() -> None:
    approval = _approval(
        allow_public=True,
        approved_external_principals=(ROLE_ARN, ACCOUNT_TOKEN, USER_ARN),
    )
    policy = _policy(bucket_approvals=(approval,))

    assert policy.get_bucket_approval(FIRST_BUCKET) == approval
    assert policy.get_bucket_approval(SECOND_BUCKET) is None
    assert approval.approved_external_principals == tuple(
        sorted((ACCOUNT_TOKEN, ROLE_ARN, USER_ARN))
    )


@pytest.mark.parametrize(
    ("token", "canonical"),
    [
        (ACCOUNT_TOKEN, ACCOUNT_TOKEN),
        ("arn:aws:iam::111122223333:root", ACCOUNT_TOKEN),
        (USER_ARN, USER_ARN),
        (ROLE_ARN, ROLE_ARN),
        (CANONICAL_USER_TOKEN, CANONICAL_USER_TOKEN),
    ],
)
def test_supported_principal_tokens_are_exact_and_root_is_canonicalized(
    token: str,
    canonical: str,
) -> None:
    approval = _approval(approved_external_principals=(token,))

    assert approval.approved_external_principals == (canonical,)


@pytest.mark.parametrize(
    "token",
    [
        "account:1234",
        f"canonical-user:{'A' * 64}",
        "arn:aws:iam::111122223333:role/security/*",
        "arn:aws:iam::111122223333:saml-provider/company",
        "arn:aws:sts::111122223333:assumed-role/security/session",
        "cloudtrail.amazonaws.com",
        "*",
    ],
)
def test_unsupported_or_noncanonical_principal_tokens_are_rejected(token: str) -> None:
    with pytest.raises(ValidationError, match="unsupported S3 exposure approval principal"):
        _approval(approved_external_principals=(token,))


def test_semantically_duplicate_principal_tokens_are_rejected() -> None:
    with pytest.raises(ValidationError, match="principal tokens must be unique"):
        _approval(
            approved_external_principals=(
                ACCOUNT_TOKEN,
                "arn:aws:iam::111122223333:root",
            )
        )


def test_duplicate_or_conflicting_bucket_records_are_rejected() -> None:
    first = _approval()
    conflicting = _approval(
        allow_public=True,
        approved_external_principals=(),
    )

    with pytest.raises(ValidationError, match="bucket records must be unique"):
        _policy(bucket_approvals=(first, first))
    with pytest.raises(ValidationError, match="bucket records must be unique"):
        _policy(bucket_approvals=(first, conflicting))


def test_vacuous_per_bucket_record_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must approve public or external exposure"):
        _approval(allow_public=False, approved_external_principals=())


@pytest.mark.parametrize(
    "bucket_arn",
    [
        "arn:aws:s3:::first-security-evidence/*",
        "arn:aws:s3:::First-Security-Evidence",
        "arn:aws:s3:us-east-1:111122223333:accesspoint/example",
        "arn:aws:s3:::first..security-evidence",
    ],
)
def test_bucket_records_and_lookup_require_exact_canonical_bucket_arns(
    bucket_arn: str,
) -> None:
    with pytest.raises((ValidationError, ValueError), match="exact canonical S3 bucket ARN"):
        _approval(bucket_arn=bucket_arn)
    with pytest.raises(ValueError, match="exact canonical S3 bucket ARN"):
        _policy().get_bucket_approval(bucket_arn)


def test_checksum_is_order_independent_for_records_and_principals() -> None:
    first = _approval(
        approved_external_principals=(ROLE_ARN, ACCOUNT_TOKEN, USER_ARN),
    )
    second = _approval(
        bucket_arn=SECOND_BUCKET,
        approved_external_principals=(CANONICAL_USER_TOKEN,),
    )
    forward = _policy(bucket_approvals=(first, second))
    reordered_first = _approval(
        approved_external_principals=(USER_ARN, ACCOUNT_TOKEN, ROLE_ARN),
    )
    reverse = _policy(bucket_approvals=(second, reordered_first))

    assert forward.bucket_approvals == reverse.bucket_approvals
    assert forward.content_checksum == reverse.content_checksum


def test_policy_version_changes_content_identity_and_schema_is_fixed() -> None:
    assert _policy(version="1.0.0").content_checksum != _policy(version="1.0.1").content_checksum

    with pytest.raises(ValidationError, match="schema_version"):
        _policy(schema_version="2.0.0")


def test_historical_json_reconstruction_and_checksum_tamper_rejection() -> None:
    historical = _policy(version="1.0.0")
    current = _policy(
        version="2.0.0",
        bucket_approvals=(
            _approval(allow_public=True, approved_external_principals=(ACCOUNT_TOKEN,)),
        ),
    )

    restored = S3ExposureApprovalPolicy.model_validate_json(historical.model_dump_json())
    assert restored == historical
    assert restored.version == "1.0.0"
    assert restored.content_checksum != current.content_checksum

    payload = historical.model_dump(mode="python")
    payload["bucket_approvals"][0]["allow_public"] = True
    with pytest.raises(ValidationError, match="content_checksum does not match"):
        S3ExposureApprovalPolicy.model_validate(payload)


def test_policy_models_are_strict_frozen_and_forbid_extra_fields() -> None:
    policy = _policy()

    with pytest.raises(ValidationError, match="frozen"):
        policy.version = "2.0.0"
    with pytest.raises(ValidationError):
        S3ExposureApprovalPolicy.model_validate({"version": "1.0.0", "bucket_approvals": []})

    payload = policy.model_dump(exclude={"content_checksum"})
    payload["unreviewed_default"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        S3ExposureApprovalPolicy.model_validate(payload)


def test_json_schema_exposes_version_checksum_and_bucket_policy_fields() -> None:
    policy_schema = S3ExposureApprovalPolicy.model_json_schema()
    approval_schema = S3BucketExposureApproval.model_json_schema()

    assert set(policy_schema["required"]) >= {"policy_id", "schema_version", "version"}
    assert {
        "bucket_arn",
        "allow_public",
    } <= set(approval_schema["required"])
    assert "approved_external_principals" in approval_schema["properties"]
