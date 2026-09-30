"""Canonical S3-002 cases run through collectors, graph admission and the real engine."""

import re
from pathlib import Path

import pytest

from app.assessment.models import AssessmentResult as R
from app.rules.registry import resolve_catalog
from tests.fakes import client_error
from tests.s3_configuration_fixtures import block
from tests.s3_exposure_fixtures import (
    ACCOUNT,
    CANONICAL,
    EXTERNAL,
    acl_response,
    exposure_bundle,
    exposure_profile,
    policy_response,
    statement,
)

PUBLIC = {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}
EXTERNAL_GRANTEE = {"Type": "CanonicalUser", "ID": CANONICAL}
DENIED = client_error("AccessDenied", "GetBucketPolicy")
PUBLIC_POLICY = {
    "policy_response": policy_response(statement()),
    "policy_status_response": {"PolicyStatus": {"IsPublic": True}},
}
EXTERNAL_POLICY = {"policy_response": policy_response(statement({"AWS": EXTERNAL}))}
PUBLIC_ACL = {"acl_response": acl_response(PUBLIC)}


def flag(name):
    value = block(False)
    value["PublicAccessBlockConfiguration"][name] = True
    return value


CASES = [
    ("private-policy-and-acl", {}, R.PASS),
    ("public-policy-unapproved", PUBLIC_POLICY, R.FAIL),
    ("public-acl-unapproved", PUBLIC_ACL, R.FAIL),
    (
        "public-policy-neutralized",
        PUBLIC_POLICY
        | {"account": DENIED, "public_access_block_response": flag("RestrictPublicBuckets")},
        R.PASS,
    ),
    (
        "public-acl-neutralized",
        {"account": flag("IgnorePublicAcls"), "public_access_block_response": DENIED},
        R.PASS,
    ),
    ("block-public-policy-only", PUBLIC_POLICY | {"account": flag("BlockPublicPolicy")}, R.FAIL),
    ("block-public-acls-only", PUBLIC_ACL | {"account": flag("BlockPublicAcls")}, R.FAIL),
    (
        "missing-policy-evidence",
        {"policy_response": {}, "policy_status_response": {}},
        R.INSUFFICIENT_EVIDENCE,
    ),
    ("missing-bpa-evidence", PUBLIC_POLICY | {"account": DENIED}, R.INSUFFICIENT_EVIDENCE),
    (
        "policy-access-denied",
        {"policy_response": DENIED, "policy_status_response": DENIED},
        R.INSUFFICIENT_EVIDENCE,
    ),
    (
        "status-proves-public-despite-body-denied",
        PUBLIC_POLICY | {"policy_response": DENIED},
        R.FAIL,
    ),
    (
        "bucket-deleted-during-scan",
        PUBLIC_POLICY | {"tag_response": client_error("NoSuchBucket", "GetBucketTagging")},
        R.INSUFFICIENT_EVIDENCE,
    ),
    (
        "conflicting-policy-evidence",
        {"policy_status_response": {"PolicyStatus": {"IsPublic": True}}},
        R.INSUFFICIENT_EVIDENCE,
    ),
    (
        "conflicting-acl-evidence",
        PUBLIC_ACL | {"account": flag("IgnorePublicAcls")},
        R.INSUFFICIENT_EVIDENCE,
    ),
    (
        "malformed-acl-evidence",
        {"acl_response": {"Owner": {"ID": "canonical-owner"}, "Grants": [{"Grantee": {}}]}},
        R.INSUFFICIENT_EVIDENCE,
    ),
    ("approved-public-policy", PUBLIC_POLICY | {"profile": exposure_profile(public=True)}, R.PASS),
    (
        "approved-external-policy",
        EXTERNAL_POLICY | {"profile": exposure_profile(principals=(f"account:{EXTERNAL}",))},
        R.PASS,
    ),
    ("unapproved-external-policy", EXTERNAL_POLICY, R.FAIL),
    (
        "external-acl-not-neutralized",
        {"acl_response": acl_response(EXTERNAL_GRANTEE), "account": flag("IgnorePublicAcls")},
        R.FAIL,
    ),
    (
        "unknown-plus-known-failure",
        {
            "policy_response": DENIED,
            "policy_status_response": DENIED,
            "acl_response": acl_response(EXTERNAL_GRANTEE),
        },
        R.FAIL,
    ),
    ("analyzer-only-finding", {}, R.PASS),
]


@pytest.mark.parametrize("case,options,expected", CASES, ids=[c[0] for c in CASES])
def test_canonical_cases(case, options, expected):
    if case == "analyzer-only-finding":
        from tests.fakes import FakePaginator
        from tests.s3_configuration_fixtures import BUCKET
        from tests.s3_exposure_fixtures import exposure_provider
        from tests.unit.collectors.test_access_analyzer import (
            _analyzer,
            _client,
            _detail_page,
            _finding,
        )

        provider = exposure_provider()
        # Supplementary findings must not replace direct bucket facts.
        finding = _finding(bucket_name=BUCKET)
        provider._clients[("accessanalyzer", "us-east-1")] = _client(
            analyzer_pages=[{"analyzers": [_analyzer("us-east-1")]}],
            finding_paginators=[FakePaginator([{"findings": [finding]}])],
            detail_paginators=[FakePaginator([_detail_page(finding)])],
        )
        options = {"provider": provider}
    bundle = exposure_bundle(**options)
    if case == "analyzer-only-finding":
        assert any(
            r.resource_type == "access_analyzer_finding" for r in bundle["snapshot"].resources
        )
    (candidate,) = bundle["assessments"]
    assert candidate.result is expected
    if expected in {R.PASS, R.FAIL}:
        proof = candidate.evidence_artifacts[0].payload["source_proof"]
        assert proof["schema_version"] == "1.6.0"
        assert len(proof["sources"]) == 8
        assert (
            proof["approval_policy"]["content_checksum"]
            == bundle["profile"].s3_exposure_approvals.content_checksum
        )


def test_every_canonical_case_has_runtime_coverage():
    document = Path("docs/controls/s3-002-exposure-aggregation.md").read_text(encoding="utf-8")
    section = document.split("<!-- s3-002-contract-cases:start -->")[1].split(
        "<!-- s3-002-contract-cases:end -->"
    )[0]
    assert set(re.findall(r"^\| `([^`]+)` \|", section, re.MULTILINE)) == {
        case for case, _, _ in CASES
    }
    assert len(CASES) == 21


@pytest.mark.parametrize(
    "principal,expected",
    [
        ({"AWS": ACCOUNT}, R.PASS),
        ({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, R.PASS),
        ({"AWS": f"arn:aws:iam::{ACCOUNT}:role/offline"}, R.PASS),
        ({"Service": "logging.s3.amazonaws.com"}, R.PASS),
        ({"AWS": f"arn:aws:iam::{EXTERNAL}:root"}, R.FAIL),
        ({"AWS": f"arn:aws:iam::{EXTERNAL}:role/offline"}, R.FAIL),
        ({"CanonicalUser": CANONICAL}, R.FAIL),
        ({"CanonicalUser": "canonical-owner"}, R.PASS),
        ({"Federated": "example.invalid"}, R.INSUFFICIENT_EVIDENCE),
        ({"AWS": f"arn:aws:iam::{EXTERNAL}:role/*"}, R.INSUFFICIENT_EVIDENCE),
        ({"AWS": f"account:{EXTERNAL}"}, R.INSUFFICIENT_EVIDENCE),
        ({"AWS": f"canonical-user:{CANONICAL}"}, R.INSUFFICIENT_EVIDENCE),
    ],
)
def test_principal_subset(principal, expected):
    assert (
        exposure_bundle(policy_response=policy_response(statement(principal)))["assessments"][
            0
        ].result
        is expected
    )


def test_external_survives_public_acl_conflict():
    bundle = exposure_bundle(
        acl_response=acl_response(PUBLIC, EXTERNAL_GRANTEE), account=flag("IgnorePublicAcls")
    )
    assert bundle["assessments"][0].result is R.FAIL


def test_external_policy_survives_public_acl_conflict():
    bundle = exposure_bundle(
        acl_response=acl_response(PUBLIC),
        account=flag("IgnorePublicAcls"),
        policy_response=policy_response(statement({"CanonicalUser": CANONICAL})),
    )
    assert bundle["assessments"][0].result is R.FAIL


def test_known_external_survives_unsupported_statement():
    bundle = exposure_bundle(
        policy_response=policy_response(
            statement({"Federated": "unknown"}), statement({"AWS": EXTERNAL})
        )
    )
    assert bundle["assessments"][0].result is R.FAIL


def test_exact_region_approval_and_empty_discovery():
    assert exposure_bundle(empty=True)["assessments"][0].result is R.NOT_APPLICABLE
    assert (
        exposure_bundle(discovery_error=DENIED)["assessments"][0].result is R.INSUFFICIENT_EVIDENCE
    )
    assert (
        exposure_bundle(**PUBLIC_POLICY, profile=exposure_profile(public=True, region="eu-west-1"))[
            "assessments"
        ][0].result
        is R.FAIL
    )
    candidate = exposure_bundle(
        **PUBLIC_POLICY,
        location_constraint="EU",
        profile=exposure_profile(public=True, region="eu-west-1"),
    )["assessments"][0]
    assert candidate.result is R.PASS and candidate.region == "eu-west-1"


def test_older_releases_and_defaults_unchanged():
    catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.9.0")
    previous, _ = resolve_catalog(catalog.catalog_id, "0.8.0")
    assert all(catalog.get(c.control_id) == c for c in previous.controls)
    assert catalog.framework_catalogs[:-1] == previous.framework_catalogs
    default, _ = resolve_catalog(catalog.catalog_id, "0.2.1")
    assert len(default.controls) == 5
    assert "S3-002" not in {c.control_id for c in previous.controls}


@pytest.mark.parametrize(
    "options,expected",
    [
        (
            PUBLIC_POLICY
            | {
                "profile": exposure_profile(public=True),
                "policy_response": policy_response(statement(), statement({"AWS": EXTERNAL})),
            },
            R.FAIL,
        ),
        (EXTERNAL_POLICY | {"account": block(True)}, R.FAIL),
        (
            {
                "acl_response": acl_response(EXTERNAL_GRANTEE),
                "profile": exposure_profile(principals=(f"canonical-user:{CANONICAL}",)),
            },
            R.PASS,
        ),
        (
            {
                "acl_response": acl_response(
                    {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"}
                )
            },
            R.PASS,
        ),
        (
            {
                "acl_response": acl_response(
                    {"Type": "AmazonCustomerByEmail", "EmailAddress": "offline@example.invalid"}
                )
            },
            R.INSUFFICIENT_EVIDENCE,
        ),
        (
            {
                "policy_response": policy_response(
                    statement({"AWS": EXTERNAL}, NotAction="s3:DeleteObject", Action=None)
                )
            },
            R.INSUFFICIENT_EVIDENCE,
        ),
        (
            {
                "policy_response": policy_response(
                    statement({"AWS": EXTERNAL}, Resource="arn:aws:s3:::other/*")
                )
            },
            R.INSUFFICIENT_EVIDENCE,
        ),
        (PUBLIC_ACL | {"account": DENIED}, R.FAIL),
        (PUBLIC_POLICY | {"acl_response": DENIED}, R.FAIL),
        (PUBLIC_POLICY | {"policy_status_response": DENIED}, R.INSUFFICIENT_EVIDENCE),
        (
            {"location_response": client_error("AccessDenied", "GetBucketLocation")},
            R.INSUFFICIENT_EVIDENCE,
        ),
    ],
)
def test_result_sensitive_boundaries(options, expected):
    assert exposure_bundle(**options)["assessments"][0].result is expected


@pytest.mark.parametrize("missing", [True, False])
def test_missing_or_forged_policy_cannot_default_to_no_exemptions(missing):
    from app.rules.s3_exposure import S3ExposureRule

    bundle = exposure_bundle()
    profile = bundle["profile"]
    policy = (
        None
        if missing
        else profile.s3_exposure_approvals.model_copy(update={"content_checksum": "0" * 64})
    )
    invalid = profile.model_copy(update={"s3_exposure_approvals": policy})
    assert S3ExposureRule().assess(bundle["snapshot"], invalid)[0].result is R.INSUFFICIENT_EVIDENCE


def test_closed_execution_contract():
    from pydantic import ValidationError

    from app.assessment.execution import ExecutionContract
    from app.assessment.s3_exposure_control import exposure_contract

    document = exposure_contract().technical.execution_contract.model_dump()
    for change in (
        {"schema_version": "1.5.0"},
        {"required_sources": document["required_sources"][:-1]},
        {"validation_strategy": "s3_bpa_v1"},
    ):
        with pytest.raises(ValidationError):
            ExecutionContract.model_validate(document | change)
