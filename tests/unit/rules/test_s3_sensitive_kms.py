"""Approved S3-004 outcomes, exact classifier inputs and conditional key proofs."""

import pytest
from pydantic import ValidationError

from app.assessment.evidence_reader import AssessmentEvidenceReader
from app.assessment.execution import ExecutionContract
from app.assessment.models import AssessmentResult as R
from app.assessment.s3_identity import S3BucketIdentity
from app.assessment.sensitive_buckets import SensitiveBucketClassifier
from app.rules.registry import resolve_catalog
from app.rules.s3_sensitive_kms import S3SensitiveKMSRule, sensitive_kms_result
from tests.fakes import client_error
from tests.s3_configuration_fixtures import BUCKET
from tests.s3_sensitive_kms_fixtures import (
    KEY_ARN,
    KEY_ID,
    encryption_rule,
    key_response,
    sensitive_kms_bundle,
    sensitive_kms_profile,
)


def assert_result(expected, **options):
    bundle = sensitive_kms_bundle(**options)
    candidate = bundle["assessments"][0]
    assert candidate.control_id == "S3-004"
    assert candidate.result is expected
    assert bool(candidate.evidence_artifacts) == (expected in {R.PASS, R.FAIL})
    AssessmentEvidenceReader(bundle["snapshot"]).validate_candidate(
        S3SensitiveKMSRule().contract.execution_contract, candidate, profile=bundle["profile"]
    )
    return bundle


@pytest.mark.parametrize("algorithm", ["aws:kms", "aws:kms:dsse"])
def test_implicit_kms_has_no_invented_key(algorithm):
    bundle = assert_result(R.PASS, encryption_rules=[encryption_rule(algorithm)])
    proof = bundle["assessments"][0].evidence_artifacts[0].payload["source_proof"]
    assert proof["relationship_observation_ids"] == []
    assert proof["s3_sensitive_kms"]["keys"] == {}
    assert proof["classification"]["reason"] == "sensitive_tag"
    assert proof["classification"]["matched_tag_rules"] == [
        {"key": "DataClassification", "value": "Restricted"}
    ]
    assert not any(r.service == "kms" for r in bundle["snapshot"].resources)


@pytest.mark.parametrize("manager", ["AWS", "CUSTOMER"])
@pytest.mark.parametrize("reference", [KEY_ARN, KEY_ID, "alias/restricted"])
@pytest.mark.parametrize("algorithm", ["aws:kms", "aws:kms:dsse"])
def test_exact_explicit_key(manager, reference, algorithm):
    bundle = assert_result(
        R.PASS,
        encryption_rules=[encryption_rule(algorithm, reference)],
        kms_responses={"us-east-1": [key_response(manager=manager)]},
    )
    proof = bundle["assessments"][0].evidence_artifacts[0].payload["source_proof"]
    key = proof["s3_sensitive_kms"]["keys"][reference]
    assert key["key"]["key_manager"] == manager
    assert key["relationship_observation_id"] in proof["relationship_observation_ids"]
    assert key["source"] in proof["sources"]


def test_cross_account_key_preserves_owner():
    account = "111122223333"
    reference = f"arn:aws:kms:us-east-1:{account}:key/{KEY_ID}"
    bundle = assert_result(
        R.PASS,
        encryption_rules=[encryption_rule(reference=reference)],
        kms_responses={"us-east-1": [key_response(account=account)]},
    )
    key = next(r for r in bundle["snapshot"].resources if r.service == "kms")
    assert key.account_id == account != bundle["snapshot"].account_id


@pytest.mark.parametrize(
    "response",
    [client_error("AccessDeniedException", "DescribeKey"), {}, key_response(manager="UNKNOWN")],
    ids=["denied", "malformed", "unsupported-manager"],
)
def test_unresolved_key_is_insufficient(response):
    assert_result(
        R.INSUFFICIENT_EVIDENCE,
        encryption_rules=[encryption_rule(reference=KEY_ARN)],
        kms_responses={"us-east-1": [response]},
    )


def test_wrong_region_key_is_insufficient_even_when_resolved():
    reference = f"arn:aws:kms:eu-west-1:123456789012:key/{KEY_ID}"
    assert_result(
        R.INSUFFICIENT_EVIDENCE,
        encryption_rules=[encryption_rule(reference=reference)],
        kms_responses={"eu-west-1": [key_response(region="eu-west-1")]},
    )


@pytest.mark.parametrize(
    "options,expected",
    [
        ({}, R.FAIL),
        (
            {
                "encryption_response": client_error(
                    "ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"
                )
            },
            R.FAIL,
        ),
        ({"encryption_rules": [{"BlockedEncryptionTypes": {"EncryptionType": ["NONE"]}}]}, R.FAIL),
        ({"encryption_rules": [{"BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}}]}, R.FAIL),
        (
            {"encryption_rules": [encryption_rule("AES256"), encryption_rule()]},
            R.INSUFFICIENT_EVIDENCE,
        ),
        (
            {"encryption_rules": [encryption_rule(), encryption_rule("aws:kms:dsse")]},
            R.INSUFFICIENT_EVIDENCE,
        ),
        ({"encryption_rules": [encryption_rule("aws:fsx")]}, R.INSUFFICIENT_EVIDENCE),
        (
            {"encryption_response": client_error("AccessDenied", "GetBucketEncryption")},
            R.INSUFFICIENT_EVIDENCE,
        ),
        ({"encryption_response": {}}, R.INSUFFICIENT_EVIDENCE),
        (
            {"tag_response": client_error("AccessDenied", "GetBucketTagging")},
            R.INSUFFICIENT_EVIDENCE,
        ),
        ({"tag_response": {"TagSet": []}}, R.NOT_APPLICABLE),
        ({"tag_response": client_error("NoSuchTagSet", "GetBucketTagging")}, R.NOT_APPLICABLE),
        (
            {"tag_response": {"TagSet": [{"Key": "DataClassification", "Value": "restricted"}]}},
            R.NOT_APPLICABLE,
        ),
        ({"empty": True}, R.NOT_APPLICABLE),
        ({"discovery_error": client_error("AccessDenied", "ListBuckets")}, R.INSUFFICIENT_EVIDENCE),
    ],
)
def test_decision_table(options, expected):
    assert_result(expected, **options)


def test_non_sensitive_does_not_require_irrelevant_key():
    assert_result(
        R.NOT_APPLICABLE,
        tag_response={"TagSet": []},
        encryption_rules=[encryption_rule(reference=KEY_ARN)],
        kms_responses={"us-east-1": [client_error("AccessDeniedException", "DescribeKey")]},
    )


@pytest.mark.parametrize("unknown", [False, True])
def test_disabled_requirement_still_requires_classification(unknown):
    assert_result(
        R.INSUFFICIENT_EVIDENCE if unknown else R.NOT_APPLICABLE,
        profile=sensitive_kms_profile(restricted_data_requires_kms=False),
        **({"tag_response": client_error("AccessDenied", "GetBucketTagging")} if unknown else {}),
    )


@pytest.mark.parametrize("signal", ["exact", "name", "override"])
def test_classifier_precedence_with_unavailable_tags(signal):
    identity = S3BucketIdentity.for_bucket(
        aws_account_id="123456789012",
        bucket_region="us-east-1",
        bucket_arn=f"arn:aws:s3:::{BUCKET}",
    )
    classifier = SensitiveBucketClassifier.create(
        version="1.1.0",
        sensitive_buckets=(identity,) if signal == "exact" else (),
        sensitive_name_patterns=("offline-*",) if signal != "exact" else (),
        non_sensitive_buckets=(identity,) if signal == "override" else (),
        sensitive_tag_rules=sensitive_kms_profile().sensitive_bucket_classifier.sensitive_tag_rules,
    )
    assert_result(
        R.NOT_APPLICABLE if signal == "override" else R.FAIL,
        profile=sensitive_kms_profile(classifier=classifier),
        tag_response=client_error("AccessDenied", "GetBucketTagging"),
    )


def test_disappearance_invalidates_otherwise_non_sensitive():
    assert_result(
        R.INSUFFICIENT_EVIDENCE,
        tag_response={"TagSet": []},
        versioning_response=client_error("NoSuchBucket", "GetBucketVersioning"),
    )


def test_classifier_proof_is_recomputed_and_historical_policy_required():
    bundle = sensitive_kms_bundle()
    proof = bundle["assessments"][0].evidence_artifacts[0].model_dump()["payload"]["source_proof"]
    proof["classification"]["reason"] = "no_sensitive_signal"
    assert sensitive_kms_result(proof, bundle["profile"]) is R.FAIL
    assert proof["classification"]["reason"] == "sensitive_tag"
    with pytest.raises(ValueError):
        sensitive_kms_result(
            proof, sensitive_kms_profile().model_copy(update={"sensitive_bucket_classifier": None})
        )


def test_opt_in_registration_and_closed_execution():
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.10.0")
    old, old_registry = resolve_catalog("aws-cloud-security-controls", "0.9.0")
    assert len(registry.rules) == len(old_registry.rules) + 1
    assert all(c in catalog.controls for c in old.controls)
    with pytest.raises(KeyError):
        old_registry.get("S3-004")
    contract = registry.get("S3-004").contract.execution_contract
    for change in (
        {"schema_version": "1.6.0"},
        {"validation_strategy": "s3_exposure_v1"},
        {"required_sources": contract.required_sources[:-1]},
    ):
        document = contract.model_dump()
        document.update(change)
        with pytest.raises(ValidationError):
            ExecutionContract.model_validate(document)
