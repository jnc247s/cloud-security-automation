"""Machine-check the canonical S3-002 Markdown decision contract."""

from pathlib import Path

import pytest

CONTRACT_PATH = (
    Path(__file__).resolve().parents[3] / "docs" / "controls" / "s3-002-exposure-aggregation.md"
)
CASE_START = "<!-- s3-002-contract-cases:start -->"
CASE_END = "<!-- s3-002-contract-cases:end -->"

EXPECTED_CASES = {
    "private-policy-and-acl": ("Policy coherently absent; ACL owner-only", "PASS"),
    "public-policy-unapproved": (
        "`IsPublic=true`; effective restrict=false; public not approved; ACL safe",
        "FAIL",
    ),
    "public-acl-unapproved": (
        "Public group ACL; effective ignore=false; public not approved; policy safe",
        "FAIL",
    ),
    "public-policy-neutralized": (
        "Complete coherent policy; `IsPublic=true`; bucket restrict=true; account restrict "
        "missing; ACL safe",
        "PASS",
    ),
    "public-acl-neutralized": (
        "`GetBucketAcl` returns an effective owner-only ACL under account ignore=true; "
        "bucket ignore missing; policy safe",
        "PASS",
    ),
    "block-public-policy-only": (
        "`IsPublic=true`; only BlockPublicPolicy=true; public not approved; ACL safe",
        "FAIL",
    ),
    "block-public-acls-only": (
        "Public group ACL; only BlockPublicAcls=true; public not approved; policy safe",
        "FAIL",
    ),
    "missing-policy-evidence": (
        "Policy body/status incomplete with no confirmed violation; ACL safe",
        "INSUFFICIENT_EVIDENCE",
    ),
    "missing-bpa-evidence": (
        "Public policy; both effective restrict inputs not known true; public not approved; "
        "ACL safe",
        "INSUFFICIENT_EVIDENCE",
    ),
    "policy-access-denied": (
        "Policy body/status AccessDenied with no confirmed violation; ACL safe",
        "INSUFFICIENT_EVIDENCE",
    ),
    "status-proves-public-despite-body-denied": (
        "Body AccessDenied; status public; effective restrict=false; public not approved; ACL safe",
        "FAIL",
    ),
    "bucket-deleted-during-scan": (
        "NoSuchBucket after discovery",
        "INSUFFICIENT_EVIDENCE",
    ),
    "conflicting-policy-evidence": (
        "Declared absent body but successful public status",
        "INSUFFICIENT_EVIDENCE",
    ),
    "conflicting-acl-evidence": (
        "Effective public-group ACL grant together with effective ignore=true",
        "INSUFFICIENT_EVIDENCE",
    ),
    "malformed-acl-evidence": (
        "ACL contains malformed grantee; policy safe",
        "INSUFFICIENT_EVIDENCE",
    ),
    "approved-public-policy": (
        "Public policy; effective restrict=false; public approved; no external grant; ACL safe",
        "PASS",
    ),
    "approved-external-policy": (
        "Non-public policy grants account:111122223333; exact token approved; ACL safe",
        "PASS",
    ),
    "unapproved-external-policy": (
        "Non-public policy grants account:111122223333; token unapproved; ACL safe",
        "FAIL",
    ),
    "external-acl-not-neutralized": (
        "External canonical-user ACL grant unapproved; effective ignore=true; policy safe",
        "FAIL",
    ),
    "unknown-plus-known-failure": (
        "Policy incomplete; unapproved external canonical-user ACL grant",
        "FAIL",
    ),
    "analyzer-only-finding": (
        "Direct policy and ACL channels safe; supplementary active Analyzer finding exists",
        "PASS",
    ),
}


def _contract() -> str:
    return CONTRACT_PATH.read_text(encoding="utf-8")


def _decision_cases() -> dict[str, tuple[str, str]]:
    contract = _contract()
    table = contract.split(CASE_START, maxsplit=1)[1].split(CASE_END, maxsplit=1)[0]
    cases: dict[str, tuple[str, str]] = {}
    for line in table.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        case_id, facts, result = cells
        case_id = case_id.removeprefix("`").removesuffix("`")
        result = result.removeprefix("`").removesuffix("`")
        assert case_id not in cases, f"duplicate S3-002 contract case: {case_id}"
        cases[case_id] = (facts, result)
    return cases


def test_s3_002_representative_decision_table_is_complete_and_deterministic() -> None:
    assert _decision_cases() == EXPECTED_CASES
    assert {result for _, result in EXPECTED_CASES.values()} == {
        "PASS",
        "FAIL",
        "INSUFFICIENT_EVIDENCE",
    }


@pytest.mark.parametrize(
    "required_text",
    [
        "`s3_exposure_approvals`",
        "`S3ExposureApprovalPolicy`",
        "policy_id: fixed string s3-exposure-approvals",
        "schema_version: fixed string 1.0.0",
        "bucket_identity:",
        "aws_account_id: exact 12-digit owner account",
        "bucket_region: authoritative bucket home Region",
        "stable_resource_id: canonical UUID derived from account, Region, and bucket name",
        "`S3ExposureApprovalPolicyHistory`",
        "reconstruction requires the stored checksum",
        "`account:<12-digit-account-id>`",
        "`canonical-user:<canonical-user-id>`",
        "Same-owner principals",
        "GetBucketPolicy",
        "GetBucketPolicyStatus",
        "GetBucketAcl",
        "s3control.GetPublicAccessBlock(AccountId=...)",
        "`scan_id`",
        "collector ID and version",
        "normalized-evidence schema version",
        "approval profile version/checksum",
        "result-sensitive source-outcome contract",
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
    assert "separate effective external grant is still decisive" in contract


def test_s3_002_contract_is_fail_closed_and_analyzer_is_supplementary() -> None:
    contract = _contract()

    assert "`CONFIRMED_UNAPPROVED` | any, including `UNKNOWN` | `FAIL`" in contract
    assert "`UNKNOWN` | no confirmed unapproved exposure | `INSUFFICIENT_EVIDENCE`" in contract
    assert "Analyzer facts are" in contract
    assert "supplementary in v1" in contract
    assert "never acts as an approval" in contract
    assert "object ACL enumeration" in contract
    assert "access point and Multi-Region Access Point policies" in contract


def test_s3_002_contract_separates_5e_evidence_from_rule_implementation() -> None:
    contract = _contract()

    assert "not implemented or enabled" in contract
    assert "does not add" in contract
    assert "an executable rule" in contract
    assert "producer now collects its direct AWS evidence" in contract
