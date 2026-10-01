"""Approved opt-in S3-004 metadata; existing catalog releases are unchanged."""

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
from app.assessment.s3_exposure_control import build_exposure_catalog
from app.assessment.s3_sensitive_kms_evidence import SENSITIVE_KMS_SOURCES
from app.schemas.finding import ControlCategory, Severity


def sensitive_kms_contract():
    return ControlContract(
        technical=TechnicalControlContract(
            control_id="S3-004",
            title="KMS default encryption for sensitive buckets",
            category=ControlCategory.STORAGE,
            resource_type="s3_bucket",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Classify buckets using exact versioned policy, then evaluate default KMS.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration",
                    description=(
                        "Same-scan discovery, home Region, classifier inputs, encryption defaults "
                        "and exact referenced DescribeKey/ENCRYPTED_WITH proof when applicable."
                    ),
                ),
            ),
            pass_logic="Sensitive bucket requires KMS and has supported default SSE-KMS/DSSE-KMS.",
            fail_logic="Sensitive bucket requires KMS but complete defaults do not provide it.",
            not_applicable_logic=(
                "Complete empty discovery, proven non-sensitive bucket, or classified sensitive "
                "bucket with the explicit KMS requirement disabled."
            ),
            insufficient_evidence_behavior=(
                "Unknown classification or missing, ambiguous, unsupported or unresolved required "
                "evidence is INSUFFICIENT_EVIDENCE; disappearance invalidates applicability."
            ),
            severity=Severity.HIGH,
            impact="Sensitive new objects may not receive the required default KMS encryption.",
            remediation_guidance=(
                "An authorized operator must review workload compatibility and key access before "
                "changing encryption. No automated writes or object re-encryption."
            ),
            profile_parameters=(
                "enabled_controls",
                "sensitive_bucket_classifier",
                "restricted_data_requires_kms",
            ),
            limitations=(
                "Evaluator 1.0.0 accepts AWS-managed and customer-managed KMS.",
                "Default configuration only: not existing objects, upload-policy enforcement, "
                "key permissions, key availability, rotation or a compliance claim.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.7.0",
                target_kind="resources",
                target_selection="all_observed_v1",
                account_service="s3",
                resource_families=(ResourceFamily(service="s3", resource_type="s3_bucket"),),
                validation_strategy="s3_sensitive_kms_v1",
                required_sources=SENSITIVE_KMS_SOURCES,
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id="S3-004",
                framework_id="nist-csf",
                framework_version="2.0+subset.9",
                reference_id="PR.DS-01",
                mapping_rationale=(
                    "Sensitive-bucket default KMS configuration contributes data-at-rest "
                    "protection evidence, not complete object protection or compliance."
                ),
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 30, tzinfo=UTC),
            ),
        ),
    )


def build_sensitive_kms_catalog():
    previous = build_exposure_catalog()
    control = sensitive_kms_contract()
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_9.json",
        manifest_path=data / "nist_csf_2_0_subset_9_manifest.json",
        mappings=control.framework_mappings,
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.10.0",
        controls=tuple(sorted((*previous.controls, control), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
