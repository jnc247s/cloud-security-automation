"""Approved opt-in EC2/EBS contracts, retaining all earlier release bytes."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.ec2_evidence import EC2_CONTROL_IDS
from app.assessment.execution import ExecutionContract, RequiredSource, ResourceFamily
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.iam_policy_control import build_iam_policy_catalog
from app.schemas.finding import ControlCategory, Severity


def ec2_execution(control_id):
    if control_id not in EC2_CONTROL_IDS:
        raise ValueError("unsupported EC2 control")
    setting = control_id == "EC2-004"
    volume = control_id == "EC2-003"
    collector = "ec2.ebs-defaults" if setting else ("ec2.volumes" if volume else "ec2.instances")
    kind = (
        "ec2.ebs-encryption-default"
        if setting
        else ("ec2.volumes.discovery" if volume else "ec2.instances.discovery")
    )
    api = (
        "ec2:GetEbsEncryptionByDefault"
        if setting
        else ("ec2:DescribeVolumes" if volume else "ec2:DescribeInstances")
    )
    sources = (
        RequiredSource(
            collector=collector,
            evidence_kind=kind,
            source_api=api,
            subject="regional_account",
            contract_version="1.0.0",
            completeness_fields=("complete",),
        ),
    )
    if not setting:
        sources += (
            RequiredSource(
                collector=collector,
                evidence_kind="ec2.volume" if volume else "ec2.instance",
                source_api=api,
                subject="target",
                contract_version="1.0.0",
                completion="admitted_resource_v1",
            ),
        )
    return ExecutionContract(
        schema_version="1.0.0",
        target_kind="regional_account" if setting else "resources",
        target_selection="all_observed_v1",
        account_service="ec2",
        resource_families=()
        if setting
        else (
            ResourceFamily(service="ec2", resource_type="ebs_volume" if volume else "ec2_instance"),
        ),
        validation_strategy="all_required_sources_complete_v1",
        required_sources=sources,
    )


_METADATA = {
    "EC2-001": (
        "EC2 instance does not require IMDSv2",
        ControlCategory.IDENTITY,
        Severity.HIGH,
        "metadata_options",
        "Applied metadata options enable the endpoint and require tokens.",
        "Applied metadata options enable the endpoint with optional tokens.",
        "Applied metadata options explicitly disable the endpoint, or complete discovery is empty.",
        (
            "Optional metadata tokens lack the IMDSv2-only safeguard; this does not prove "
            "credential theft."
        ),
        (
            "Check application compatibility before an authorized operator requires IMDSv2 "
            "through an approved change."
        ),
        "PR.PS-01",
        (
            "Metadata configuration contributes secure configuration-management evidence, "
            "not complete configuration management."
        ),
    ),
    "EC2-002": (
        "EC2 instance has an unapproved public IPv4 address",
        ControlCategory.NETWORK,
        Severity.MEDIUM,
        "public_ipv4_addresses",
        "No public IPv4 is assigned, or the stable resource UUID is explicitly approved.",
        "Public IPv4 is assigned and the stable resource UUID is not approved.",
        "Complete instance discovery is empty.",
        (
            "Unapproved public IPv4 assignment increases potential exposure, not proof of "
            "reachability."
        ),
        (
            "Review business need and network dependencies before an authorized operator "
            "removes public addressing or approves the exact resource identity."
        ),
        "PR.IR-01",
        (
            "Public-address policy contributes network-exposure context, not end-to-end "
            "access protection."
        ),
    ),
    "EC2-003": (
        "EBS volume is not encrypted",
        ControlCategory.STORAGE,
        Severity.MEDIUM,
        "encrypted",
        "Volume encryption is explicitly true.",
        "Volume encryption is explicitly false.",
        "Complete volume discovery is empty.",
        "Unencrypted volume data lacks the EBS encryption safeguard.",
        (
            "Plan and test an authorized encrypted replacement or migration with backups; "
            "this is not an in-place conversion."
        ),
        "PR.DS-01",
        (
            "Volume encryption contributes data-at-rest evidence, not full confidentiality, "
            "integrity and availability."
        ),
    ),
    "EC2-004": (
        "EBS encryption by default is disabled",
        ControlCategory.STORAGE,
        Severity.MEDIUM,
        "ebs_encryption_by_default",
        "The Regional setting is explicitly true.",
        "The Regional setting is explicitly false.",
        "Never for the requested supported Region.",
        "A disabled Regional default can allow new unencrypted volumes.",
        (
            "Review workloads and key access before an authorized operator enables the "
            "Regional default; existing volumes are unaffected."
        ),
        "PR.DS-01",
        (
            "Regional default configuration contributes protection context for future "
            "volumes, not proof of existing-volume encryption."
        ),
    ),
}


def ec2_contract(control_id):
    (
        title,
        category,
        severity,
        fact,
        passing,
        failing,
        na,
        impact,
        guidance,
        reference,
        rationale,
    ) = _METADATA[control_id]
    execution = ec2_execution(control_id)
    return ControlContract(
        technical=TechnicalControlContract(
            control_id=control_id,
            title=title,
            category=category,
            resource_type="aws_account"
            if control_id == "EC2-004"
            else execution.resource_families[0].resource_type,
            assessment_type=AssessmentType.AUTOMATED,
            measure=title,
            required_evidence=(
                EvidenceRequirement(
                    fact_path=fact,
                    description=(
                        "Complete same-scan, Regional source and identity-bound normalized facts."
                    ),
                ),
            ),
            pass_logic=passing,
            fail_logic=failing,
            not_applicable_logic=na,
            insufficient_evidence_behavior=(
                "Missing, malformed, pending or inconsistent required evidence yields "
                "INSUFFICIENT_EVIDENCE."
            ),
            severity=severity,
            impact=impact,
            remediation_guidance=guidance,
            profile_parameters=("enabled_controls", "public_ec2_exceptions")
            if control_id == "EC2-002"
            else ("enabled_controls",),
            limitations=(
                (
                    "Evaluation version 1.0.0; retained configuration only, not effective "
                    "access or compromise."
                ),
                (
                    "KMS key policy, optional KMS context and contextual topology do not "
                    "determine this result."
                ),
            ),
            execution_contract=execution,
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id=control_id,
                framework_id="nist-csf",
                framework_version="2.0+subset.4",
                reference_id=reference,
                mapping_rationale=rationale,
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 28, tzinfo=UTC),
            ),
        ),
    )


def build_ec2_catalog():
    previous = build_iam_policy_catalog()
    controls = tuple(ec2_contract(c) for c in EC2_CONTROL_IDS)
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_4.json",
        manifest_path=data / "nist_csf_2_0_subset_4_manifest.json",
        mappings=tuple(m for c in controls for m in c.framework_mappings),
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.5.0",
        controls=tuple(sorted((*previous.controls, *controls), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
