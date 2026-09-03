"""Tests for pre-persistence security finding candidates."""

import json

import pytest
from pydantic import ValidationError

from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.resource import ResourceScope


def _candidate(**overrides: object) -> FindingCandidate:
    values: dict[str, object] = {
        "control_id": "S3-002",
        "title": "Missing Bucket Encryption",
        "category": ControlCategory.STORAGE,
        "severity": Severity.MEDIUM,
        "account_id": "123456789012",
        "service": "s3",
        "resource_type": "s3_bucket",
        "aws_resource_id": "example-bucket",
        "arn": "arn:aws:s3:::example-bucket",
        "name": "example-bucket",
        "scope": ResourceScope.REGIONAL,
        "region": "us-east-1",
        "evidence": {
            "bucket_name": "example-bucket",
            "default_encryption": None,
        },
        "impact": "Objects may not use the intended default encryption configuration.",
        "recommendation": "Configure an approved default bucket encryption policy.",
    }
    values.update(overrides)
    return FindingCandidate.model_validate(values)


def test_candidate_has_stable_identity_and_json_safe_evidence() -> None:
    candidate = _candidate()
    equivalent_candidate = _candidate()

    assert candidate.identity == equivalent_candidate.identity
    assert candidate.identity != _candidate(control_id="S3-999").identity
    assert candidate.identity != _candidate(aws_resource_id="other-bucket").identity

    payload = json.loads(candidate.model_dump_json())
    assert payload["severity"] == "MEDIUM"
    assert payload["category"] == "storage"
    assert payload["evidence"] == {
        "bucket_name": "example-bucket",
        "default_encryption": None,
    }


def test_regional_candidate_requires_region() -> None:
    with pytest.raises(ValidationError, match="regional.*region"):
        _candidate(region=None)


def test_global_candidate_rejects_region() -> None:
    with pytest.raises(ValidationError, match="global.*region"):
        _candidate(scope=ResourceScope.GLOBAL, region="us-east-1")


def test_global_candidate_accepts_no_region() -> None:
    candidate = _candidate(
        service="cloudtrail",
        resource_type="aws_account",
        aws_resource_id="123456789012",
        arn=None,
        name=None,
        scope=ResourceScope.GLOBAL,
        region=None,
    )

    assert candidate.scope is ResourceScope.GLOBAL
    assert candidate.region is None
