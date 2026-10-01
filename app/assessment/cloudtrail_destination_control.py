"""Approved opt-in LOG-004 metadata, with one closed same-invocation dependency."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.cloudtrail_controls import build_cloudtrail_catalog
from app.assessment.cloudtrail_evidence import CONFIGURATION, DISCOVERY, IDENTITY
from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.execution import ExecutionContract, ResourceFamily
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.relationships import RelationshipType
from app.schemas.finding import ControlCategory, Severity


def destination_contract():
    return ControlContract(
        technical=TechnicalControlContract(
            control_id="LOG-004",
            title="CloudTrail log storage has unapproved public/external exposure",
            category=ControlCategory.LOGGING,
            resource_type="cloudtrail_trail",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Exact trail destination's validated canonical S3-002 result.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration.s3_bucket_name",
                    description="Complete CloudTrail/S3 collectors, exact discovery/identity/"
                    "configuration, "
                    "one resolved GetTrail-provenance destination and validated same-scan S3-002.",
                ),
            ),
            pass_logic="Complete exact destination relationship and canonical S3-002 PASS.",
            fail_logic="Complete exact destination relationship and canonical S3-002 FAIL.",
            not_applicable_logic="Complete empty admitted trail discovery account fallback; "
            "never for a trail.",
            insufficient_evidence_behavior="Missing/incomplete/ambiguous destination or "
            "required evidence, "
            "disabled/absent/nondecisive S3-002 dependency is insufficient.",
            severity=Severity.HIGH,
            impact="Unapproved destination exposure can disclose sensitive security logs.",
            remediation_guidance="An authorized operator should review exact destination "
            "bucket policy/ACL "
            "and legitimate delivery dependencies before separately approved restrictions.",
            profile_parameters=("enabled_controls", "s3_exposure_approvals"),
            limitations=(
                "Evaluator 1.0.0; no AWS calls, writes, historical result lookup or "
                "duplicate exposure evaluation.",
                "S3-002 access-point/object-ACL/effective-IAM limits apply; no delivery, "
                "retention, "
                "digest verification or KMS proof.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.9.0",
                target_kind="resources",
                target_selection="all_observed_v1",
                account_service="cloudtrail",
                resource_families=(
                    ResourceFamily(service="cloudtrail", resource_type="cloudtrail_trail"),
                ),
                validation_strategy="cloudtrail_destination_exposure_v1",
                required_sources=(DISCOVERY, IDENTITY, CONFIGURATION),
                required_relationships=(RelationshipType.DELIVERS_TO_BUCKET,),
                assessment_dependencies=("S3-002",),
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id="LOG-004",
                framework_id="nist-csf",
                framework_version="2.0+subset.11",
                reference_id="PR.AA-05",
                mapping_rationale="Destination access-policy context contributes to "
                "access-permission "
                "review, not complete least privilege or compliance.",
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 10, 1, tzinfo=UTC),
            ),
        ),
    )


def build_destination_catalog():
    previous = build_cloudtrail_catalog()
    control = destination_contract()
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_11.json",
        manifest_path=data / "nist_csf_2_0_subset_11_manifest.json",
        mappings=control.framework_mappings,
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.12.0",
        controls=tuple(sorted((*previous.controls, control), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
