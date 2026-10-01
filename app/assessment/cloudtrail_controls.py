"""Approved opt-in 6F.1 metadata; old catalogs and LOG-001 remain unchanged."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.cloudtrail_evidence import CLOUDTRAIL_SOURCES
from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.execution import ExecutionContract, ResourceFamily
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.s3_sensitive_kms_control import build_sensitive_kms_catalog
from app.schemas.finding import ControlCategory, Severity


def cloudtrail_contract(control_id):
    if control_id not in {"LOG-002", "LOG-003"}:
        raise ValueError("unsupported CloudTrail control")
    coverage = control_id == "LOG-002"
    strategy = "cloudtrail_management_coverage_v1" if coverage else "cloudtrail_integrity_v1"
    return ControlContract(
        technical=TechnicalControlContract(
            control_id=control_id,
            title="Required multi-Region management-event coverage is missing"
            if coverage
            else "CloudTrail log-file integrity validation is disabled",
            category=ControlCategory.LOGGING,
            resource_type="aws_account" if coverage else "cloudtrail_trail",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Complete account trail coverage of management read/write events."
            if coverage
            else "Explicit log-file-validation setting for each admitted trail.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration",
                    description="Complete discovery/admission, exact owner/home Region, "
                    "configuration, "
                    "logging status and complete event selectors."
                    if coverage
                    else "Complete discovery/admission, exact trail identity and explicit "
                    "integrity boolean.",
                ),
            ),
            pass_logic="At least one actively logging multi-Region trail proves both management "
            "read and write coverage under the bounded selector table."
            if coverage
            else "Exact trail configuration explicitly enables log-file validation.",
            fail_logic="Complete population contains no qualifying trail, including "
            "empty discovery."
            if coverage
            else "Exact trail configuration explicitly disables log-file validation.",
            not_applicable_logic="Never for a normal AWS account."
            if coverage
            else "Complete empty admitted trail discovery; never inferred from failed enumeration.",
            insufficient_evidence_behavior="Missing/incomplete required source or malformed "
            "fact is "
            "insufficient, even with a qualifying sibling; otherwise unknown selector coverage "
            "is insufficient when no trail qualifies."
            if coverage
            else "Incomplete required discovery/identity/configuration or unavailable "
            "boolean is insufficient.",
            severity=Severity.HIGH if coverage else Severity.MEDIUM,
            impact="Management-event gaps reduce visibility for investigations and "
            "audit reconstruction."
            if coverage
            else "Disabled validation removes digest-generation support for integrity checks.",
            remediation_guidance="An authorized operator should review management read/write "
            "coverage on an active multi-Region trail, including costs and delivery "
            "dependencies before changes."
            if coverage
            else "An authorized operator should review enabling log-file validation and "
            "a separate digest-verification process; this does not retroactively validate "
            "older logs.",
            profile_parameters=("enabled_controls",),
            limitations=(
                "Evaluator 1.0.0; retained configuration only, no AWS writes or remediation.",
                "No delivery, retention, alerting, data-event or organization-wide coverage proof."
                if coverage
                else "The enabled flag does not prove digest verification or delivery.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.8.0",
                target_kind="global_account" if coverage else "resources",
                target_selection="all_observed_v1",
                account_service="cloudtrail",
                resource_families=()
                if coverage
                else (ResourceFamily(service="cloudtrail", resource_type="cloudtrail_trail"),),
                validation_strategy=strategy,
                required_sources=CLOUDTRAIL_SOURCES[strategy],
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id=control_id,
                framework_id="nist-csf",
                framework_version="2.0+subset.10",
                reference_id="PR.PS-04" if coverage else "PR.DS-01",
                mapping_rationale="Management-log generation coverage contributes "
                "monitoring context, "
                "not continuous monitoring or compliance."
                if coverage
                else "Integrity-check configuration for stored logs contributes "
                "data-at-rest context, "
                "not verified integrity or full data protection.",
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 10, 1, tzinfo=UTC),
            ),
        ),
    )


def build_cloudtrail_catalog():
    previous = build_sensitive_kms_catalog()
    controls = tuple(cloudtrail_contract(control_id) for control_id in ("LOG-002", "LOG-003"))
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_10.json",
        manifest_path=data / "nist_csf_2_0_subset_10_manifest.json",
        mappings=tuple(mapping for control in controls for mapping in control.framework_mappings),
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.11.0",
        controls=tuple(sorted((*previous.controls, *controls), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
