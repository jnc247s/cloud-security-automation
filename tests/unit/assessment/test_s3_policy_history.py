"""Tests for immutable history of the planned S3 policy artifacts."""

import pytest
from pydantic import ValidationError

from app.assessment.s3_exposure import (
    S3_EXPOSURE_APPROVAL_POLICY_ID,
    S3BucketExposureApproval,
    S3ExposureApprovalPolicy,
)
from app.assessment.s3_identity import S3BucketIdentity
from app.assessment.s3_policy_history import (
    S3ExposureApprovalPolicyHistory,
    SensitiveBucketClassifierHistory,
)
from app.assessment.sensitive_buckets import SensitiveBucketClassifier


def _bucket(*, account: str = "111122223333", region: str = "us-east-1") -> S3BucketIdentity:
    return S3BucketIdentity.for_bucket(
        aws_account_id=account,
        bucket_region=region,
        bucket_arn="arn:aws:s3:::regulated-records",
    )


def _approval_policy(
    *,
    version: str,
    allow_public: bool = False,
) -> S3ExposureApprovalPolicy:
    principals = () if allow_public else ("account:444455556666",)
    return S3ExposureApprovalPolicy.create(
        version=version,
        bucket_approvals=(
            S3BucketExposureApproval(
                bucket_identity=_bucket(),
                allow_public=allow_public,
                approved_external_principals=principals,
            ),
        ),
    )


def _classifier(*, version: str, pattern: str = "regulated-*") -> SensitiveBucketClassifier:
    return SensitiveBucketClassifier.create(
        version=version,
        sensitive_name_patterns=(pattern,),
    )


def test_exposure_policy_history_preserves_and_reconstructs_exact_versions() -> None:
    historical = _approval_policy(version="1.0.0")
    current = _approval_policy(version="2.0.0", allow_public=True)
    history = S3ExposureApprovalPolicyHistory(artifacts=(current, historical))

    reconstructed = S3ExposureApprovalPolicyHistory.model_validate_json(history.model_dump_json())

    assert reconstructed == history
    assert (
        reconstructed.get(
            policy_id=S3_EXPOSURE_APPROVAL_POLICY_ID,
            version="1.0.0",
        )
        == historical
    )
    assert (
        reconstructed.get(
            policy_id=S3_EXPOSURE_APPROVAL_POLICY_ID,
            version="9.9.9",
        )
        is None
    )


def test_exposure_policy_history_rejects_changed_or_duplicate_version() -> None:
    original = _approval_policy(version="1.0.0")
    changed = _approval_policy(version="1.0.0", allow_public=True)

    with pytest.raises(ValidationError, match="cannot be reused with different content"):
        S3ExposureApprovalPolicyHistory(artifacts=(original, changed))
    with pytest.raises(ValidationError, match="duplicate S3 exposure approval policy version"):
        S3ExposureApprovalPolicyHistory(artifacts=(original, original))

    payload = S3ExposureApprovalPolicyHistory(artifacts=(original,)).model_dump(mode="python")
    payload["artifacts"][0].pop("content_checksum")
    with pytest.raises(ValidationError, match="content_checksum"):
        S3ExposureApprovalPolicyHistory.model_validate(payload)


def test_classifier_history_preserves_and_reconstructs_exact_versions() -> None:
    historical = _classifier(version="1.0.0")
    current = _classifier(version="1.1.0", pattern="restricted-*")
    history = SensitiveBucketClassifierHistory(artifacts=(current, historical))

    reconstructed = SensitiveBucketClassifierHistory.model_validate_json(history.model_dump_json())

    assert reconstructed == history
    assert reconstructed.get(classifier_id="sensitive-bucket", version="1.0.0") == historical
    assert reconstructed.get(classifier_id="sensitive-bucket", version="9.9.9") is None


def test_classifier_history_rejects_changed_or_duplicate_version() -> None:
    original = _classifier(version="1.0.0")
    changed = _classifier(version="1.0.0", pattern="restricted-*")

    with pytest.raises(ValidationError, match="cannot be reused with different content"):
        SensitiveBucketClassifierHistory(artifacts=(original, changed))
    with pytest.raises(ValidationError, match="duplicate sensitive bucket classifier version"):
        SensitiveBucketClassifierHistory(artifacts=(original, original))

    payload = SensitiveBucketClassifierHistory(artifacts=(original,)).model_dump(mode="python")
    payload["artifacts"][0].pop("content_checksum")
    with pytest.raises(ValidationError, match="content_checksum"):
        SensitiveBucketClassifierHistory.model_validate(payload)


@pytest.mark.parametrize(
    "history_type",
    [S3ExposureApprovalPolicyHistory, SensitiveBucketClassifierHistory],
)
def test_artifact_histories_require_at_least_one_strict_immutable_definition(
    history_type: type[S3ExposureApprovalPolicyHistory] | type[SensitiveBucketClassifierHistory],
) -> None:
    with pytest.raises(ValidationError):
        history_type.model_validate({"artifacts": ()})
    with pytest.raises(ValidationError):
        history_type.model_validate({"artifacts": [], "latest": "1.0.0"})
