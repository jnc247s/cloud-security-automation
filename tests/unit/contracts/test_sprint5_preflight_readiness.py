"""Guard the approved Sprint 5 preflight contracts and repository boundary."""

import re
from pathlib import Path

from app.assessment.controls import build_default_control_catalog
from app.assessment.relationships import RelationshipType

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


def test_matrix_defines_common_provenance_failure_and_relationship_contracts() -> None:
    matrix = _read(MATRIX_PATH)

    for required_text in (
        "preallocated scan ID",
        "AWS account",
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


def test_required_relationship_vocabulary_is_controlled_and_documented() -> None:
    relationship_types = {item.value for item in RelationshipType}
    adr = _read(RELATIONSHIP_ADR_PATH)

    assert relationship_types == REQUIRED_RELATIONSHIP_TYPES
    for relationship_type in REQUIRED_RELATIONSHIP_TYPES:
        assert f"`{relationship_type}`" in adr
    for required_text in (
        "relationship_id",
        "observation_id",
        "source endpoint",
        "target endpoint",
        "collection time",
        "AWS API",
        "evidence",
        "schema version",
    ):
        assert required_text in adr


def test_preflight_does_not_enable_planned_controls_or_start_sprint_5() -> None:
    executable_ids = {contract.control_id for contract in build_default_control_catalog().controls}
    roadmap = _read(ROADMAP_PATH)
    active_plan = _read(ACTIVE_PLAN_PATH)

    assert executable_ids == EXECUTABLE_CONTROL_IDS
    assert "| Sprint 5 | AWS Evidence Expansion | **NEXT** |" in roadmap
    assert "| Sprint 6 | Production Security Controls | **PLANNED** |" in roadmap
    assert "No sprint is currently `IN PROGRESS`" in roadmap
    assert "Status: **NEXT**" in active_plan
    assert "Sprint 5 has not begun" in active_plan
