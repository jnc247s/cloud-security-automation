"""Approved opt-in S3-002 metadata; preceding releases remain immutable."""

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
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.s3_configuration_controls import build_s3_configuration_catalog
from app.assessment.s3_exposure_evidence import EXPOSURE_SOURCES
from app.schemas.finding import ControlCategory, Severity


def exposure_contract():
    return ControlContract(
        technical=TechnicalControlContract(
            control_id="S3-002",
            title="Unapproved public/external bucket exposure",
            category=ControlCategory.STORAGE,
            resource_type="s3_bucket",
            assessment_type=AssessmentType.AUTOMATED,
            measure=(
                "Evaluate direct policy and effective ACL channels against exact bucket approvals."
            ),
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration",
                    description=(
                        "Same-scan discovery, home Region, policy/status, ACL, BPA "
                        "and immutable approvals."
                    ),
                ),
            ),
            pass_logic="Both channels prove no exposure or explicitly approved exposure.",
            fail_logic=(
                "Either channel independently proves unapproved exposure, "
                "even when another is unknown."
            ),
            not_applicable_logic="Complete bucket discovery is empty.",
            insufficient_evidence_behavior=(
                "Unknown without a confirmed violation is INSUFFICIENT_EVIDENCE; "
                "disappearance invalidates the bucket."
            ),
            severity=Severity.HIGH,
            impact=(
                "Unapproved public or cross-account grants can expose bucket data or permissions."
            ),
            remediation_guidance=(
                "An authorized operator must review workload dependencies and legitimate sharing "
                "before changing grants or safeguards. No automated AWS writes."
            ),
            profile_parameters=("enabled_controls", "s3_exposure_approvals"),
            limitations=(
                "Evaluator 1.0.0 covers general-purpose bucket policy/ACL configuration, "
                "not all effective access paths.",
                "No object/access-point ACL enumeration, effective IAM/SCP/RCP evaluation "
                "or compliance claim. Analyzer is supplementary only.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.6.0",
                target_kind="resources",
                target_selection="all_observed_v1",
                account_service="s3",
                resource_families=(ResourceFamily(service="s3", resource_type="s3_bucket"),),
                validation_strategy="s3_exposure_v1",
                required_sources=EXPOSURE_SOURCES,
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id="S3-002",
                framework_id="nist-csf",
                framework_version="2.0+subset.8",
                reference_id="PR.AA-05",
                mapping_rationale=(
                    "Direct exposure configuration contributes access-policy enforcement "
                    "evidence, not complete least privilege, actual access or compliance."
                ),
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 29, tzinfo=UTC),
            ),
        ),
    )


def build_exposure_catalog():
    previous = build_s3_configuration_catalog()
    control = exposure_contract()
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_8.json",
        manifest_path=data / "nist_csf_2_0_subset_8_manifest.json",
        mappings=control.framework_mappings,
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.9.0",
        controls=tuple(sorted((*previous.controls, control), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
