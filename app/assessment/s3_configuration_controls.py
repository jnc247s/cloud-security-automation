"""Approved opt-in S3-001/003 contracts; prior releases remain immutable."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.execution import ExecutionContract, ResourceFamily
from app.assessment.flow_log_control import build_flow_log_catalog
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.s3_configuration_evidence import S3_CONFIGURATION_IDS, S3_SOURCES
from app.schemas.finding import ControlCategory, Severity


def s3_configuration_contract(control_id):
    if control_id not in S3_CONFIGURATION_IDS:
        raise ValueError("unsupported S3 configuration control")
    bpa = control_id == "S3-001"
    strategy = "s3_bpa_v1" if bpa else "s3_transport_v1"
    return ControlContract(
        technical=TechnicalControlContract(
            control_id=control_id,
            title="Required Block Public Access configuration missing"
            if bpa
            else "Secure transport not enforced",
            category=ControlCategory.STORAGE,
            resource_type="s3_bucket",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Evaluate combined account/bucket protection."
            if bpa
            else "Prove explicit denial of insecure bucket and object requests.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration",
                    description=(
                        "Complete discovery, authoritative home Region "
                        "and exact retained configuration sources."
                    ),
                ),
            ),
            pass_logic="All four flags are true at either applicable level."
            if bpa
            else (
                "Supported universal Deny covers all S3 actions for bucket and objects "
                "under insecure transport."
            ),
            fail_logic="At least one flag is false at both levels."
            if bpa
            else "Policy is confirmed absent or complete policy contains only Allow statements.",
            not_applicable_logic="Complete bucket discovery is empty.",
            insufficient_evidence_behavior=(
                "Missing identity/coverage or undecidable configuration is INSUFFICIENT_EVIDENCE."
            ),
            severity=Severity.HIGH if bpa else Severity.MEDIUM,
            impact="Missing public-access safeguards can permit unintended sharing."
            if bpa
            else "Missing enforced secure transport can permit unencrypted requests.",
            remediation_guidance=(
                "An authorized operator must review legitimate public workloads "
                "and dependencies before changing settings."
            )
            if bpa
            else (
                "An authorized operator must review clients and AWS-service dependencies "
                "before changing the bucket policy."
            ),
            profile_parameters=("enabled_controls",),
            limitations=(
                "Evaluation version 1.0.0; retained configuration only, "
                "not full effective access or compliance.",
                "No AWS writes. Unknown evidence never becomes a clean result.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.5.0",
                target_kind="resources",
                target_selection="all_observed_v1",
                account_service="s3",
                resource_families=(ResourceFamily(service="s3", resource_type="s3_bucket"),),
                validation_strategy=strategy,
                required_sources=S3_SOURCES[strategy],
                required_relationships=(),
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id=control_id,
                framework_id="nist-csf",
                framework_version="2.0+subset.7",
                reference_id="PR.AA-05" if bpa else "PR.DS-02",
                mapping_rationale=(
                    "Public-access safeguards contribute access-policy enforcement "
                    "evidence, not complete least privilege or separation of duties."
                )
                if bpa
                else (
                    "HTTPS-denial configuration contributes data-in-transit protection evidence, "
                    "not complete confidentiality, integrity or availability."
                ),
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 29, tzinfo=UTC),
            ),
        ),
    )


def build_s3_configuration_catalog():
    previous = build_flow_log_catalog()
    controls = tuple(s3_configuration_contract(key) for key in S3_CONFIGURATION_IDS)
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_7.json",
        manifest_path=data / "nist_csf_2_0_subset_7_manifest.json",
        mappings=tuple(m for c in controls for m in c.framework_mappings),
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.8.0",
        controls=tuple(sorted((*previous.controls, *controls), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
