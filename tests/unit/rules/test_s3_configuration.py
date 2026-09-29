"""Approved 6E.1 truth tables, complete-source proof and prior-release compatibility."""

import json
from copy import deepcopy

import pytest

from app.assessment.models import AssessmentResult as R
from app.rules.registry import resolve_catalog
from tests.fakes import client_error
from tests.s3_configuration_fixtures import BUCKET, FLAGS, block, s3_bundle


def results(**options):
    return {a.control_id: a.result for a in s3_bundle(**options)["assessments"]}


@pytest.mark.parametrize(
    "account,bucket,expected",
    [
        (True, True, R.PASS),
        (True, False, R.PASS),
        (False, True, R.PASS),
        (False, False, R.FAIL),
        (True, "denied", R.PASS),
        ("denied", True, R.PASS),
        (False, "denied", R.INSUFFICIENT_EVIDENCE),
        ("denied", False, R.INSUFFICIENT_EVIDENCE),
        ("denied", "denied", R.INSUFFICIENT_EVIDENCE),
        ("absent", False, R.FAIL),
        (False, "absent", R.FAIL),
        ("absent", True, R.PASS),
    ],
)
def test_combined_protection(account, bucket, expected):
    def response(value):
        if value == "denied":
            return client_error("AccessDenied", "GetPublicAccessBlock")
        if value == "absent":
            return client_error("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")
        return block(value)

    assert (
        results(account=response(account), public_access_block_response=response(bucket))["S3-001"]
        is expected
    )


def test_mixed_flags_combine_individually():
    account, bucket = block(False), block(False)
    for index, key in enumerate(FLAGS):
        (account if index % 2 else bucket)["PublicAccessBlockConfiguration"][key] = True
    assert results(account=account, public_access_block_response=bucket)["S3-001"] is R.PASS
    bucket["PublicAccessBlockConfiguration"][FLAGS[0]] = False
    assert results(account=account, public_access_block_response=bucket)["S3-001"] is R.FAIL


def policy():
    return {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }


@pytest.mark.parametrize(
    "change,expected",
    [
        ({}, R.PASS),
        ({"Action": ["s3:*"]}, R.PASS),
        ({"Resource": "*"}, R.PASS),
        ({"Principal": {"AWS": ["*"]}}, R.PASS),
        ({"Condition": {"Bool": {"aws:SecureTransport": ["false"]}}}, R.PASS),
        ({"Effect": "Allow"}, R.FAIL),
        ({"Resource": f"arn:aws:s3:::{BUCKET}"}, R.INSUFFICIENT_EVIDENCE),
        ({"Action": "s3:GetObject"}, R.INSUFFICIENT_EVIDENCE),
        ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}, R.INSUFFICIENT_EVIDENCE),
        ({"Condition": {"Bool": {"aws:SecureTransport": "true"}}}, R.INSUFFICIENT_EVIDENCE),
        (
            {
                "Condition": {
                    "Bool": {"aws:SecureTransport": "false"},
                    "StringEquals": {"aws:SourceVpc": "vpc-example"},
                }
            },
            R.INSUFFICIENT_EVIDENCE,
        ),
    ],
)
def test_transport_table(change, expected):
    statement = policy() | change
    assert (
        results(policy_response={"Policy": json.dumps({"Statement": [statement]})})["S3-003"]
        is expected
    )


def test_split_denies_and_independent_supported_proof():
    first, second = policy(), policy()
    first["Resource"], second["Resource"] = first["Resource"][0], second["Resource"][1]
    unknown = deepcopy(first)
    unknown["Condition"] = {"StringEquals": {"custom:key": "value"}}
    assert (
        results(policy_response={"Policy": json.dumps({"Statement": [unknown, second, first]})})[
            "S3-003"
        ]
        is R.PASS
    )


@pytest.mark.parametrize(
    "code,expected", [("NoSuchBucketPolicy", R.FAIL), ("AccessDenied", R.INSUFFICIENT_EVIDENCE)]
)
def test_policy_absence_is_not_unavailability(code, expected):
    assert results(policy_response=client_error(code, "GetBucketPolicy"))["S3-003"] is expected


@pytest.mark.parametrize(
    "options",
    [
        {"location_response": client_error("AccessDenied", "GetBucketLocation")},
        {"location_response": client_error("NoSuchBucket", "GetBucketLocation")},
        {"discovery_error": client_error("AccessDenied", "ListBuckets")},
    ],
)
def test_missing_identity_or_discovery_is_not_na(options):
    assert set(results(**options).values()) == {R.INSUFFICIENT_EVIDENCE}


def test_empty_inventory_and_home_region():
    assert set(results(empty=True).values()) == {R.NOT_APPLICABLE}
    bundle = s3_bundle(location_constraint="EU")
    assert {a.region for a in bundle["assessments"]} == {"eu-west-1"}
    assert {a.result for a in bundle["assessments"]} == {R.PASS}


def test_old_catalog_unchanged_and_new_rules_opt_in():
    catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.8.0")
    previous, _ = resolve_catalog(catalog.catalog_id, "0.7.0")
    assert all(catalog.get(c.control_id) == c for c in previous.controls)
    assert catalog.framework_catalogs[:-1] == previous.framework_catalogs
    default, _ = resolve_catalog(catalog.catalog_id, "0.2.1")
    assert len(default.controls) == 5
    assert not {"S3-001", "S3-002", "S3-003", "S3-004"} & {c.control_id for c in default.controls}
