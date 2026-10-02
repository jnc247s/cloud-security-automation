"""Approved opt-in GOV-001 metadata, preserving every earlier release definition."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.cloudtrail_destination_control import build_destination_catalog
from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.execution import ExecutionContract
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.governance_evidence import GOVERNANCE_FAMILIES, GOVERNANCE_SOURCES
from app.schemas.finding import ControlCategory, Severity


def governance_contract():
    return ControlContract(
        technical=TechnicalControlContract(
            control_id="GOV-001",
            title="Required ownership or context tags are missing",
            category=ControlCategory.GOVERNANCE,
            resource_type="governed_resource",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Presence of exact required keys with nonblank string values "
            "on governed resources.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="tags",
                    description="Complete same-scan family discovery, authoritative identity "
                    "and exact tag source; preserved case and whitespace.",
                ),
            ),
            pass_logic="Complete tags contain every exact required key with a nonblank string "
            "value; aws: keys are ineligible.",
            fail_logic="Complete tags lack one or more required keys or contain unusable "
            "required values.",
            not_applicable_logic="Observed resource is outside the profile's governed set, "
            "or complete discovery proves an empty governed population.",
            insufficient_evidence_behavior="Unavailable, incomplete, ambiguous or malformed "
            "required discovery, identity or tag evidence is insufficient, never PASS.",
            severity=Severity.MEDIUM,
            impact="Missing ownership or environment context impedes accountable inventory "
            "management and security triage.",
            remediation_guidance="An authorized operator should identify the accountable owner "
            "and environment, then apply approved tags through a separately authorized process.",
            profile_parameters=("enabled_controls", "required_tags", "governed_resource_types"),
            limitations=(
                "Evaluator 1.0.0; read-only configuration assessment, no AWS calls or writes.",
                "Presence and usable values do not prove ownership truth, authorization, "
                "CMDB consistency or compliance.",
                "Only the 11 canonical initial taggable resource families are supported; "
                "unknown types are not silently governed.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.10.0",
                target_kind="resources",
                target_selection="governance_tags_v1",
                account_service="iam",
                resource_families=GOVERNANCE_FAMILIES,
                validation_strategy="governance_tags_v1",
                required_sources=GOVERNANCE_SOURCES,
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id="GOV-001",
                framework_id="nist-csf",
                framework_version="2.0+subset.12",
                reference_id="ID.AM-02",
                mapping_rationale="Ownership and environment tag configuration contributes "
                "inventory context for managed systems and services; it does not establish "
                "the complete inventory outcome, ownership truth or compliance.",
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 10, 1, tzinfo=UTC),
            ),
        ),
    )


def build_governance_catalog():
    previous = build_destination_catalog()
    control = governance_contract()
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_12.json",
        manifest_path=data / "nist_csf_2_0_subset_12_manifest.json",
        mappings=control.framework_mappings,
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.13.0",
        controls=tuple(sorted((*previous.controls, control), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
