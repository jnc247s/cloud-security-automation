"""Guard the approved Sprint 5 preflight contracts and repository boundary."""

import re
from pathlib import Path

import pytest

from app.assessment.controls import build_default_control_catalog
from app.assessment.relationships import RelationshipType
from app.assessment.source_outcomes import EvidenceSourceState

ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "docs" / "controls" / "sprint-5-evidence-readiness.md"
CATALOG_PATH = ROOT / "docs" / "controls" / "catalog.md"
ACTIVE_PLAN_PATH = ROOT / "docs" / "exec-plans" / "active" / "sprint-5.md"
ROADMAP_PATH = ROOT / "ROADMAP.md"
RELATIONSHIP_ADR_PATH = (
    ROOT / "docs" / "design-decisions" / "0001-generic-resource-relationships.md"
)

EXPECTED_CONTROL_IDS = {
    "EC2-001",
    "EC2-002",
    "EC2-003",
    "EC2-004",
    "GOV-001",
    "IAM-001",
    "IAM-002",
    "IAM-003",
    "IAM-004",
    "IAM-005",
    "IAM-006",
    "LOG-001",
    "LOG-002",
    "LOG-003",
    "LOG-004",
    "NET-001",
    "NET-002",
    "NET-003",
    "NET-004",
    "NET-005",
    "NET-006",
    "S3-001",
    "S3-002",
    "S3-003",
    "S3-004",
}
EXECUTABLE_CONTROL_IDS = {"IAM-001", "LOG-001", "NET-001", "NET-002", "S3-900"}
PLANNED_CATALOG_IDS = {
    "EC2-001",
    "EC2-002",
    "EC2-003",
    "EC2-004",
    "GOV-001",
    "IAM-002",
    "IAM-003",
    "IAM-004",
    "IAM-005",
    "IAM-006",
    "LOG-002",
    "LOG-003",
    "LOG-004",
    "NET-003",
    "NET-004",
    "NET-005",
    "NET-006",
}
REQUIRED_RELATIONSHIP_TYPES = {
    "attached_inline_policy",
    "attached_managed_policy",
    "attached_to_security_group",
    "contains_subnet",
    "delivers_to_bucket",
    "encrypted_with",
    "has_access_key",
    "has_flow_log",
    "has_mfa_device",
    "in_subnet",
    "in_vpc",
    "member_of_group",
    "permissions_boundary",
    "references_resource",
    "selects_default_version",
    "uses_volume",
}
REQUIRED_CONTRACT_FIELDS = {
    "Status",
    "Scope/resource type",
    "Required evidence",
    "Relationships",
    "Assessment Profile",
    "PASS",
    "FAIL",
    "NOT_APPLICABLE",
    "INSUFFICIENT_EVIDENCE",
    "Limitations",
}
ALLOWED_MATRIX_STATES = {"CONTRACT_READY", "CURRENT", "EXPAND"}
CURRENT_CONTROL_IDS = {
    "EC2-001",
    "EC2-002",
    "EC2-003",
    "EC2-004",
    "GOV-001",
    "IAM-001",
    "IAM-002",
    "IAM-003",
    "IAM-004",
    "IAM-005",
    "IAM-006",
    "LOG-001",
    "NET-001",
    "NET-002",
    "NET-003",
    "NET-004",
    "NET-005",
    "NET-006",
    "S3-001",
    "S3-002",
    "S3-003",
    "S3-004",
}
CONTRACT_READY_CONTROL_IDS = {"LOG-004"}
EXPECTED_MATRIX_STATES = {
    control_id: (
        "CURRENT"
        if control_id in CURRENT_CONTROL_IDS
        else "CONTRACT_READY"
        if control_id in CONTRACT_READY_CONTROL_IDS
        else "EXPAND"
    )
    for control_id in EXPECTED_CONTROL_IDS
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _matrix_rows() -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    for line in _read(MATRIX_PATH).splitlines():
        if not re.match(r"^\| `[A-Z0-9]+-\d{3}` \|", line):
            continue
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        assert len(cells) == 6, f"matrix row must have six cells: {line}"
        control_id = cells[0].strip("`")
        assert control_id not in rows, f"duplicate matrix control: {control_id}"
        rows[control_id] = cells[1:]
    return rows


def _matrix_state(state_cell: str) -> str:
    match = re.fullmatch(
        r"[^|`]+ / `(?P<state>CURRENT|EXPAND|CONTRACT_READY)`",
        state_cell,
    )
    if match is None:
        raise ValueError(f"invalid matrix state cell: {state_cell}")
    return match.group("state")


def _planned_catalog_sections() -> dict[str, str]:
    catalog = _read(CATALOG_PATH)
    sections: dict[str, str] = {}
    pattern = re.compile(r"(?ms)^### `(?P<control_id>[A-Z0-9]+-\d{3})`.*?(?=^### |^## Evaluation)")
    for match in pattern.finditer(catalog):
        sections[match.group("control_id")] = match.group(0)
    return sections


def test_evidence_matrix_contains_exactly_25_unique_controls() -> None:
    rows = _matrix_rows()

    assert len(rows) == 25
    assert set(rows) == EXPECTED_CONTROL_IDS


def test_every_matrix_row_has_api_permission_scope_evidence_failure_and_state() -> None:
    for control_id, cells in _matrix_rows().items():
        api_permissions, scope, evidence, failure, state = cells
        assert all(cells), f"{control_id} has an empty readiness field"
        assert ":" in api_permissions or "matching read permissions" in api_permissions, (
            f"{control_id} lacks a named read-permission source"
        )
        assert "TBD" not in " ".join(cells)
        assert "BLOCKED" not in state
        assert scope != "unknown"
        assert evidence != "unknown"
        assert failure != "unknown"


def test_matrix_uses_closed_and_exact_per_control_state_vocabulary() -> None:
    states = {control_id: _matrix_state(cells[-1]) for control_id, cells in _matrix_rows().items()}

    assert set(states.values()) == ALLOWED_MATRIX_STATES
    assert states == EXPECTED_MATRIX_STATES
    with pytest.raises(ValueError, match="invalid matrix state cell"):
        _matrix_state("5Z / `GIBBERISH`")

    matrix = _read(MATRIX_PATH)
    for required_text in (
        "closed",
        "Only that fact is current",
        "collector, persistence, and integration work has not been implemented",
        "This is not an implementation-completion state",
        "`CONTRACT_READY` is orthogonal to evidence implementation",
        "No other matrix state is valid",
    ):
        assert required_text in matrix


def test_matrix_defines_common_provenance_failure_and_relationship_contracts() -> None:
    matrix = _read(MATRIX_PATH)

    for required_text in (
        "preallocated scan ID",
        "verified 12-digit collection account",
        "stable resource identity",
        "collector name",
        "AWS service/API source",
        "timezone-aware collection time",
        "schema/version",
        "collector outcome",
        "`INSUFFICIENT_EVIDENCE`, never `PASS`",
        "## Relationship requirements",
        "missing, incomplete, or unresolved required edge",
    ):
        assert required_text in matrix


def test_planned_catalog_contracts_keep_every_required_field() -> None:
    sections = _planned_catalog_sections()

    assert set(sections) == PLANNED_CATALOG_IDS
    for control_id, section in sections.items():
        for field in REQUIRED_CONTRACT_FIELDS:
            assert f"**{field}:**" in section, f"{control_id} lacks {field}"


def test_s3_contract_links_and_reserved_meanings_remain_canonical() -> None:
    catalog = _read(CATALOG_PATH)

    assert "`S3-002` | Unapproved public/external bucket exposure" in catalog
    assert "`S3-004` | Sensitive-data KMS requirement not met" in catalog
    assert "[S3-002 public and external exposure aggregation]" in catalog
    assert "[S3-004 sensitive-bucket classifier]" in catalog
    assert "obsolete prototype meaning" in catalog


def test_s3_exact_policy_entries_bind_full_stable_bucket_identity() -> None:
    matrix = _read(MATRIX_PATH)
    exposure_contract = _read(ROOT / "docs" / "controls" / "s3-002-exposure-aggregation.md")
    classifier_contract = _read(
        ROOT / "docs" / "controls" / "s3-004-sensitive-bucket-classifier.md"
    )

    for required_text in (
        "aws_account_id: exact 12-digit owner account",
        "bucket_region: authoritative bucket home Region",
        "stable_resource_id: canonical UUID derived from account, Region, and bucket name",
        "omit owner account and home Region",
        "S3ExposureApprovalPolicyHistory",
    ):
        assert required_text in exposure_contract
    for required_text in (
        "strict `S3BucketIdentity`",
        "owner account, authoritative bucket home Region",
        "`SensitiveBucketClassifierHistory`",
        "changing only account or home Region changes artifact identity",
        "reject a missing or mismatched checksum",
    ):
        assert required_text in classifier_contract
    assert "exact account/Region/ARN/stable bucket identity" in matrix


def test_s3_004_classifier_readiness_does_not_invent_sprint_6_kms_policy() -> None:
    matrix = _read(MATRIX_PATH)
    catalog = _read(CATALOG_PATH)
    active_plan = _read(ACTIVE_PLAN_PATH)
    classifier_contract = _read(
        ROOT / "docs" / "controls" / "s3-004-sensitive-bucket-classifier.md"
    )

    for factual_state in (
        "no-explicit-configuration",
        "`AES256`",
        "AWS-managed KMS",
        "customer-managed KMS",
        "unavailable",
        "malformed",
    ):
        assert factual_state in matrix
    assert "refers only to this" in matrix
    assert "evidence-facing classifier prerequisite" in matrix
    assert "No encryption state maps to Sprint 6 `PASS`/`FAIL`" in matrix
    assert "does not" in catalog
    assert "whether an AWS-managed or only a customer-managed KMS key" in catalog
    assert "not an invented final Sprint 6 KMS result policy" in active_plan
    assert "intentionally does not decide whether" in classifier_contract
    assert "false `restricted_data_requires_kms` setting yields" in classifier_contract


def test_result_sensitive_source_outcome_contract_is_closed_and_foundation_only() -> None:
    matrix = _read(MATRIX_PATH)
    active_plan = _read(ACTIVE_PLAN_PATH)
    adr = _read(ROOT / "docs" / "design-decisions" / "0002-result-sensitive-evidence-outcomes.md")

    assert {state.value for state in EvidenceSourceState} == {
        "PRESENT",
        "EXPECTED_ABSENCE",
        "UNAVAILABLE",
        "MALFORMED",
        "CONFLICT",
        "RESOURCE_DISAPPEARED",
    }
    assert "`PARTIAL` is never a generic completeness bypass" in matrix
    assert "Remaining graphless Sprint 0--4 collector" in active_plan
    assert "paths retain all-or-nothing behavior" in active_plan
    assert "Sprint 0--4 legacy collectors retain their accepted" in adr
    assert "graphless behavior" in adr
    assert "no Sprint 6 rule" in adr
    assert "consumes source outcomes yet" in adr
    for required_text in (
        "verified 12-digit collection account",
        "resource owner may be",
        "AWS-managed IAM policies",
        "controlled `aws` owner sentinel",
        "U+001F unit separator",
    ):
        assert required_text in adr


def test_required_relationship_vocabulary_is_controlled_and_documented() -> None:
    relationship_types = {item.value for item in RelationshipType}
    adr = _read(RELATIONSHIP_ADR_PATH)

    assert relationship_types == REQUIRED_RELATIONSHIP_TYPES
    for relationship_type in REQUIRED_RELATIONSHIP_TYPES:
        assert f"`{relationship_type}`" in adr
    for required_text in (
        "relationship_id",
        "observation_id",
        "collection_account_id",
        "source endpoint",
        "target endpoint",
        "collection time",
        "AWS API",
        "evidence",
        "schema version",
    ):
        assert required_text in adr
    assert "verified 12-digit collection account ID" in adr
    assert "closed scope map" in adr
    assert "AWS-managed IAM policies use the" in adr
    for persistence_contract in (
        "current blanket",
        "same-account persistence check",
        "unproven different owner",
        "Relaxing either the Python guard",
    ):
        assert persistence_contract in adr


def test_resolved_edges_require_top_level_resource_snapshot_endpoints() -> None:
    matrix_rows = _matrix_rows()
    matrix = _read(MATRIX_PATH)
    catalog = _read(CATALOG_PATH)
    adr = _read(RELATIONSHIP_ADR_PATH)

    for control_id in ("IAM-001", "IAM-002", "IAM-003", "IAM-004"):
        assert "`Resource` + `ResourceSnapshot`" in matrix_rows[control_id][2]

    assert "child evidence" not in matrix
    assert "may remain structured child evidence" not in catalog
    for required_text in (
        "Every endpoint of a persisted `RESOLVED` relationship is a top-level normalized",
        "none is a canonical edge endpoint when present only as an embedded child object",
        "Accepted Sprint 0--4 embedded IAM configuration remains available",
    ):
        assert required_text in matrix

    for required_text in (
        "every endpoint of a `RESOLVED` relationship must reference a",
        "top-level normalized `Resource` and its exact `ResourceSnapshot`",
        "including IAM access keys, MFA devices",
        "cannot substitute for either persisted endpoint",
        "target_stable_resource_id, target_resource_snapshot_id",
        "including IAM types, is exempt",
    ):
        assert required_text in adr

    assert "an access key present only inside legacy embedded user configuration" in catalog
    assert "device object alone is not a canonical relationship endpoint" in catalog


def test_5f_preflight_preserves_accepted_5e_and_does_not_start_runtime_work() -> None:
    executable_ids = {contract.control_id for contract in build_default_control_catalog().controls}
    roadmap = _read(ROADMAP_PATH)
    active_plan = _read(ACTIVE_PLAN_PATH)
    matrix = _read(MATRIX_PATH)
    runtime = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "app").rglob("*.py"))
    )

    assert executable_ids == EXECUTABLE_CONTROL_IDS
    assert "| Sprint 5 | AWS Evidence Expansion | **IN PROGRESS** |" in roadmap
    assert "| Sprint 6 | Production Security Controls | **PLANNED** |" in roadmap
    assert "`8ea9df86f8c6ae623ef41ebb836e6b3b7d052393`" in roadmap
    assert (
        "Current slice: **5F CloudTrail evidence expansion — PLANNED; PREFLIGHT COMPLETE**"
        in active_plan
    )
    assert "5D IAM Access Analyzer evidence slices" in roadmap
    assert "accepted on `main`" in roadmap
    assert "FOUNDATION_READY_FOR_5A" in active_plan
    assert "**5A EC2 and EBS evidence — COMPLETE**" in active_plan
    assert "**5B VPC, subnet, Flow Log, and network evidence — COMPLETE**" in active_plan
    assert "**5C IAM account and IAM policy evidence — COMPLETE**" in active_plan
    assert "**5D IAM Access Analyzer evidence — COMPLETE**" in active_plan
    assert "**5E S3 evidence expansion — COMPLETE**" in active_plan
    assert "pull request 22" in active_plan
    assert "This preflight adds no\ncollector and does not start 5F" in active_plan
    assert "supplemental Regional discovery only for the controlled Access Analyzer" in active_plan
    assert "evidence remains supplementary and non-decisive" in active_plan
    assert "bucket-Region discovery makes Analyzer coverage incomplete" in active_plan
    assert "complete `ListBuckets` enumeration" in matrix
    assert "honor each pending scan's persisted `requested_services`" in active_plan
    assert "resume with the accepted pre-5D collector set" in active_plan
    assert "completed pre-5D source manifests and evidence graphs valid" in active_plan
    assert "persisted readback coverage" in active_plan
    assert "explicitly triaged accepted limitations" in active_plan
    assert "must be resolved before any multi-tenant deployment" in active_plan
    for required_5e_contract in (
        '`("access-analyzer", "cloudtrail", "ec2", "iam", "kms", "s3")`',
        "Unknown tuples must fail before AWS work",
        "`s3_evidence` operational outcome",
        "whole `s3_buckets` rollup for new 5E scans",
        "authoritative same-scan S3",
        "`allows_supplemental_region` flag is not sufficient proof",
        "validated `DescribeKey.KeyMetadata.Arn`",
        "null `LocationConstraint` to `us-east-1`",
        "legacy `EU` value to `eu-west-1`",
        "An unrelated policy",
        "must not make otherwise complete\n  `S3-900` encryption evidence unavailable",
        "Do not register `S3-001` through `S3-004`",
    ):
        assert required_5e_contract in active_plan

    for required_5f_contract in (
        '`("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3")`',
        "persisted execution-version marker, not an AWS service or permission",
        "accepted 5E tuple without that marker remains a distinct pre-5F path",
        "Preserve the accepted `cloudtrail_trails` collector name",
        "separate `cloudtrail_evidence` operational outcome",
        "direct\n  pre-5F collector path remains unchanged",
        "omitted from both resource projections",
        "`ListTrails(IncludeShadowTrails=False)`",
        "non-paginated\n  `GetEventSelectors` outcomes",
        "submit no more than 20 ARNs",
        "collection account separate from actual trail ownership",
        "It is not a new persisted\n  generic resource relationship",
        "mark the affected account coverage incomplete",
        "accepted 5E bucket identity and snapshot",
        "does not add a\n  second unconditional `DescribeKey` producer",
        "Do not register `LOG-002` through `LOG-004`",
    ):
        assert required_5f_contract in active_plan

    assert "complete collection-account trail coverage set (not a persisted relationship)" in matrix
    assert "5F preflight complete; implementation unstarted / `EXPAND`" in matrix
    assert '"cloudtrail-evidence"' not in runtime
    assert 'collector_name = "cloudtrail_evidence"' not in runtime
