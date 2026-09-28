"""Approved opt-in IAM-004 contract; previous catalog identities remain unchanged."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.execution import ExecutionContract
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.iam_controls import build_iam_control_catalog
from app.assessment.iam_policy_evidence import POLICY_DISCOVERY, POLICY_FAMILIES
from app.schemas.finding import ControlCategory, Severity


def iam_policy_contract():
    return ControlContract(
        technical=TechnicalControlContract(
            control_id="IAM-004",
            title="IAM policy grants explicit full administrative access",
            category=ControlCategory.IDENTITY,
            resource_type="iam_managed_policy_version",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Literal unrestricted Allow pattern in a complete permissions-policy document.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="iam.permissions-policy.document",
                    description="Complete enumeration, same-scan owner/usage/default-version "
                    "relationships, decoded document, snapshot identity, digest and provenance.",
                ),
            ),
            pass_logic="Complete document has no exact Allow, Action *, Resource * statement.",
            fail_logic="A complete statement has exact Effect Allow, Action * and Resource * "
            "(string or list member). Conditions do not erase this syntactic match.",
            insufficient_evidence_behavior="Missing, malformed or inconsistent required "
            "enumeration, identity, edges, version or document yields INSUFFICIENT_EVIDENCE.",
            not_applicable_logic="Documents outside v1 permissions-policy scope are excluded; "
            "empty in-scope enumeration yields an account NOT_APPLICABLE result.",
            severity=Severity.HIGH,
            impact="Literal unrestricted Allow statements can permit broad access as grants. "
            "A boundary grants nothing; conditions and other policies can constrain access. This "
            "pattern does not establish effective administrator access or compromise.",
            remediation_guidance="An authorized operator reviews usage and conditions, replaces "
            "unnecessary wildcards with narrowly scoped permissions through an approved change, "
            "and test workload dependencies. No automatic remediation is performed.",
            profile_parameters=("enabled_controls",),
            limitations=(
                "Evaluation version 1.0.0; syntax only, not effective authorization.",
                "Service wildcards, NotAction and NotResource do not substitute for literal *.",
                "Boundary-only documents remain in scope without being grants; trust policies "
                "and other resource-policy families are outside v1 scope.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.2.0",
                target_kind="resources",
                target_selection="iam_policy_documents_v1",
                account_service="iam",
                resource_families=POLICY_FAMILIES,
                validation_strategy="iam_policy_document_v1",
                required_sources=POLICY_DISCOVERY,
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id="IAM-004",
                framework_id="nist-csf",
                framework_version="2.0+subset.3",
                reference_id="PR.AA-05",
                mapping_rationale="Literal unrestricted-policy review contributes least-privilege "
                "permissions-policy evidence. It does not establish effective authorization, "
                "complete authorization management, separation of duties, or compliance.",
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 27, 23, 31, 30, tzinfo=UTC),
            ),
        ),
    )


def build_iam_policy_catalog():
    previous = build_iam_control_catalog()
    control = iam_policy_contract()
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_3.json",
        manifest_path=data / "nist_csf_2_0_subset_3_manifest.json",
        mappings=control.framework_mappings,
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.4.0",
        controls=tuple(sorted((*previous.controls, control), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
