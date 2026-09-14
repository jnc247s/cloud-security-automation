"""Machine-check the canonical S3-002 Markdown decision contract."""

from pathlib import Path

import pytest

CONTRACT_PATH = (
    Path(__file__).resolve().parents[3] / "docs" / "controls" / "s3-002-exposure-aggregation.md"
)
CASE_START = "<!-- s3-002-contract-cases:start -->"
CASE_END = "<!-- s3-002-contract-cases:end -->"

EXPECTED_CASES = {
    "private-policy-and-acl": "PASS",
    "public-policy-unapproved": "FAIL",
    "public-acl-unapproved": "FAIL",
    "public-policy-neutralized": "PASS",
    "public-acl-neutralized": "PASS",
    "block-public-policy-only": "FAIL",
    "block-public-acls-only": "FAIL",
    "missing-policy-evidence": "INSUFFICIENT_EVIDENCE",
    "missing-bpa-evidence": "INSUFFICIENT_EVIDENCE",
    "policy-access-denied": "INSUFFICIENT_EVIDENCE",
    "status-proves-public-despite-body-denied": "FAIL",
    "bucket-deleted-during-scan": "INSUFFICIENT_EVIDENCE",
    "conflicting-policy-evidence": "INSUFFICIENT_EVIDENCE",
    "malformed-acl-evidence": "INSUFFICIENT_EVIDENCE",
    "approved-public-policy": "PASS",
    "approved-external-policy": "PASS",
    "unapproved-external-policy": "FAIL",
    "external-acl-not-neutralized": "FAIL",
    "unknown-plus-known-failure": "FAIL",
    "analyzer-only-finding": "PASS",
}


def _contract() -> str:
    return CONTRACT_PATH.read_text(encoding="utf-8")


def _decision_cases() -> dict[str, str]:
    contract = _contract()
    table = contract.split(CASE_START, maxsplit=1)[1].split(CASE_END, maxsplit=1)[0]
    cases: dict[str, str] = {}
    for line in table.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        case_id, _, result = cells
        assert case_id not in cases, f"duplicate S3-002 contract case: {case_id}"
        cases[case_id] = result
    return cases


def test_s3_002_representative_decision_table_is_complete_and_deterministic() -> None:
    assert _decision_cases() == EXPECTED_CASES
    assert set(EXPECTED_CASES.values()) == {"PASS", "FAIL", "INSUFFICIENT_EVIDENCE"}


@pytest.mark.parametrize(
    "required_text",
    [
        "`s3_exposure_approvals`",
        "`S3ExposureApprovalPolicy`",
        "policy_id: fixed string s3-exposure-approvals",
        "schema_version: fixed string 1.0.0",
        "`account:<12-digit-account-id>`",
        "`canonical-user:<canonical-user-id>`",
        "GetBucketPolicy",
        "GetBucketPolicyStatus",
        "GetBucketAcl",
        "s3control.GetPublicAccessBlock(AccountId=...)",
        "`scan_id`",
        "collector ID and version",
        "normalized-evidence schema version",
        "approval profile version/checksum",
    ],
)
def test_s3_002_contract_names_required_policy_sources_and_provenance(
    required_text: str,
) -> None:
    assert required_text in _contract()


def test_s3_002_contract_preserves_distinct_bpa_semantics() -> None:
    contract = _contract()

    assert "effective value is the logical OR" in contract
    assert "`BlockPublicAcls` | Prevents" in contract
    assert "`BlockPublicPolicy` | Prevents" in contract
    assert "`IgnorePublicAcls` | Neutralizes" in contract
    assert "`RestrictPublicBuckets` | When the whole bucket policy is public" in contract
    assert "It has no effect on fixed external delegation in a policy" in contract
    assert "external grant is not" in contract


def test_s3_002_contract_is_fail_closed_and_analyzer_is_supplementary() -> None:
    contract = _contract()

    assert "`CONFIRMED_UNAPPROVED` | any, including `UNKNOWN` | `FAIL`" in contract
    assert "`UNKNOWN` | no confirmed unapproved exposure | `INSUFFICIENT_EVIDENCE`" in contract
    assert "Analyzer facts are" in contract
    assert "supplementary in v1" in contract
    assert "never acts as an approval" in contract
    assert "object ACL enumeration" in contract
    assert "access point and Multi-Region Access Point policies" in contract


def test_s3_002_contract_does_not_claim_runtime_implementation() -> None:
    contract = _contract()

    assert "not implemented or enabled" in contract
    assert "does not add" in contract
    assert "an AWS collector or executable rule" in contract
