"""Approved 6B.1 contracts; catalog 0.2.1 and its framework bytes remain untouched."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
    build_default_control_catalog,
)
from app.assessment.execution import ExecutionContract, RequiredSource, ResourceFamily
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.iam_key_evidence import KEY_ENUMERATION, USER_DISCOVERY, USER_IDENTITY
from app.assessment.relationships import RelationshipType
from app.schemas.finding import ControlCategory, Severity

IAM_CONTROL_IDS = ("IAM-002", "IAM-003", "IAM-005", "IAM-006")
ACCOUNT_SUMMARY = RequiredSource(
    collector="iam.account-summary",
    evidence_kind="iam.account-summary",
    source_api="iam:GetAccountSummary",
    subject="global_account",
    contract_version="1.0.0",
    completeness_fields=("complete",),
)


def iam_execution(control_id: str) -> ExecutionContract:
    if control_id not in IAM_CONTROL_IDS:
        raise ValueError("unsupported IAM control")
    if control_id in {"IAM-002", "IAM-003"}:
        return ExecutionContract(
            schema_version="1.1.0",
            target_kind="resources",
            target_selection="all_observed_v1",
            account_service="iam",
            resource_families=(ResourceFamily(service="iam", resource_type="iam_user"),),
            validation_strategy=(
                "iam_active_key_age_v1" if control_id == "IAM-002" else "iam_active_key_usage_v1"
            ),
            required_sources=(USER_DISCOVERY, USER_IDENTITY, KEY_ENUMERATION),
            required_relationships=(RelationshipType.HAS_ACCESS_KEY,),
        )
    return ExecutionContract(
        schema_version="1.0.0",
        target_kind="global_account",
        target_selection="all_observed_v1",
        account_service="iam",
        validation_strategy="all_required_sources_complete_v1",
        required_sources=(ACCOUNT_SUMMARY,),
    )


# Policy metadata is independent of the executable truth tables and framework outcome metadata.
_METADATA = {
    "IAM-002": (
        "Active IAM access key exceeds maximum age",
        Severity.MEDIUM,
        "stale_key_days",
        "All active keys are no older than the configured threshold at observation time.",
        "At least one active key is older than the configured threshold at observation time.",
        "An active long-lived credential beyond the organization's allowed age can extend "
        "exposure if compromised; age alone does not prove compromise.",
        "Prefer temporary role credentials. Where a long-term key is still necessary, review "
        "consumers and rotate it through an approved change before retiring the old key.",
        "Comparing active-key age with explicit organization policy contributes "
        "credential-lifecycle evidence; it does not prove safe credential distribution "
        "or complete identity management.",
    ),
    "IAM-003": (
        "Active IAM access key unused beyond allowed period",
        Severity.MEDIUM,
        "max_unused_access_key_days",
        "Every active key was used within the threshold, or has no recorded use and its age "
        "is within the threshold.",
        "An active key was last used before the threshold boundary, or has no recorded use "
        "and its age exceeds the threshold.",
        "An active credential without recent recorded use can retain unnecessary access and "
        "exposure; last-use evidence does not establish business need.",
        "Confirm ownership, consumers, and business need. Through an approved change, deactivate "
        "an unnecessary key, verify dependencies, and retire it; prefer temporary credentials "
        "for remaining workloads.",
        "Assessing active credentials against a last-use policy contributes credential-lifecycle "
        "review evidence; recorded use does not establish authorization or business necessity.",
    ),
    "IAM-005": (
        "Root account access key exists",
        Severity.HIGH,
        None,
        "The complete account summary reports account_access_keys_present as false.",
        "The complete account summary reports account_access_keys_present as true.",
        "A root access key exposes highly privileged programmatic credentials; presence does "
        "not prove exposure or use.",
        "Investigate dependencies and replace root-key use with appropriately scoped temporary "
        "access. Have an authorized operator remove root access keys through a controlled "
        "change. Do not create root keys for testing.",
        "Root access-key presence contributes evidence about management of privileged credentials; "
        "it does not establish management of every identity or root credential type.",
    ),
    "IAM-006": (
        "Root account MFA is not enabled",
        Severity.HIGH,
        None,
        "The complete account summary reports account_mfa_enabled as true.",
        "The complete account summary reports account_mfa_enabled as false.",
        "Missing root MFA removes a second sign-in factor where root sign-in credentials exist, "
        "increasing account-takeover exposure.",
        "Have an authorized operator review root access and enable MFA where root sign-in "
        "credentials are retained. For centrally managed member accounts with root credentials "
        "removed, verify that posture; do not recreate credentials merely to satisfy this "
        "presence-only control.",
        "Root MFA presence contributes root-authentication context; it does not establish "
        "hardware-only MFA, device health, or authentication coverage for all users and services.",
    ),
}


def iam_contract(control_id: str) -> ControlContract:
    title, severity, parameter, pass_logic, fail_logic, impact, guidance, rationale = _METADATA[
        control_id
    ]
    is_key = parameter is not None
    facts = (
        (
            ("iam.users.discovery", "Complete global IAM user enumeration."),
            ("iam.user.access-keys", "Complete same-scan user/key enumeration and resolved edges."),
            (
                "iam.access-key",
                "Authoritative key identity, status, creation and observation times.",
            ),
        )
        if is_key
        else (("iam.account-summary", "Complete global summary with strict boolean flags."),)
    )
    if control_id == "IAM-003":
        facts += (
            ("iam.access-key.last-used", "Successful lookup with recorded or no-recorded use."),
        )
    technical = TechnicalControlContract(
        control_id=control_id,
        title=title,
        category=ControlCategory.IDENTITY,
        resource_type="iam_user" if is_key else "aws_account",
        assessment_type=AssessmentType.AUTOMATED,
        measure=title,
        required_evidence=tuple(EvidenceRequirement(fact_path=p, description=d) for p, d in facts),
        pass_logic=pass_logic,
        fail_logic=fail_logic,
        insufficient_evidence_behavior="Required evidence unavailable, malformed, incomplete, "
        "or inconsistent yields INSUFFICIENT_EVIDENCE, never PASS.",
        not_applicable_logic="No active access keys after complete enumeration; no users after "
        "complete discovery."
        if is_key
        else "Never for a normal account assessment.",
        severity=severity,
        impact=impact,
        remediation_guidance=guidance,
        profile_parameters=("enabled_controls", parameter) if parameter else ("enabled_controls",),
        limitations=(
            "Evaluation version 1.0.0; only canonical retained facts, not effective authorization.",
            "Key creation does not prove secret rotation; last-use records can lag and no recorded "
            "use is not proof of never-used credentials."
            if is_key
            else "Summary flags do not prove compromise, device health, hardware-only MFA, or "
            "centralized root-access posture.",
        ),
        execution_contract=iam_execution(control_id),
    )
    mapping = ControlFrameworkMapping(
        control_id=control_id,
        framework_id="nist-csf",
        framework_version="2.0+subset.2",
        reference_id="PR.AA-03" if control_id == "IAM-006" else "PR.AA-01",
        mapping_rationale=rationale,
        mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
        mapping_source_version="2.0",
        verified_at=datetime(2026, 9, 27, 22, 54, 24, tzinfo=UTC),
    )
    return ControlContract(technical=technical, framework_mappings=(mapping,))


def build_iam_control_catalog() -> ControlCatalog:
    legacy = build_default_control_catalog()
    controls = tuple(iam_contract(control_id) for control_id in IAM_CONTROL_IDS)
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_2.json",
        manifest_path=data / "nist_csf_2_0_subset_2_manifest.json",
        mappings=tuple(mapping for control in controls for mapping in control.framework_mappings),
    )
    return ControlCatalog(
        catalog_id=legacy.catalog_id,
        version="0.3.0",
        controls=tuple(sorted((*legacy.controls, *controls), key=lambda item: item.control_id)),
        framework_catalogs=(*legacy.framework_catalogs, framework),
    )
