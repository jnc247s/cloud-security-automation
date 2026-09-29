"""Approved 6D.1 catalog; all earlier releases remain byte-identical."""

from datetime import UTC, datetime
from pathlib import Path

from app.assessment.controls import (
    AssessmentType,
    ControlCatalog,
    ControlContract,
    EvidenceRequirement,
    TechnicalControlContract,
)
from app.assessment.ec2_controls import build_ec2_catalog
from app.assessment.execution import ExecutionContract, ResourceFamily
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.relationships import RelationshipType
from app.assessment.security_group_evidence import NETWORK_CONTROL_IDS, NETWORK_SOURCES
from app.schemas.finding import ControlCategory, Severity


def network_execution():
    return ExecutionContract(
        schema_version="1.3.0",
        target_kind="resources",
        target_selection="all_observed_v1",
        account_service="ec2",
        resource_families=(ResourceFamily(service="ec2", resource_type="security_group"),),
        validation_strategy="security_group_v1",
        required_sources=NETWORK_SOURCES,
        required_relationships=(RelationshipType.IN_VPC,),
    )


_METADATA = {
    "NET-003": (
        "Security group permits unrestricted all-protocol public ingress",
        Severity.HIGH,
        "No all-protocol public IPv4/IPv6 ingress permission exists.",
        "An all-protocol public IPv4/IPv6 ingress permission exists.",
        "Complete discovery contains no security groups.",
        "All-protocol public ingress increases potential exposure.",
        "Review workload dependencies before an authorized change restricts public access.",
    ),
    "NET-004": (
        "Security group exposes a high-risk port publicly",
        Severity.HIGH,
        "No public permission covers a configured high-risk TCP port.",
        "A public permission covers a configured high-risk TCP port.",
        "Complete discovery is empty or explicit reviewed high-risk port policy is empty.",
        "Public access to configured high-risk TCP ports increases potential exposure.",
        "Review workload dependencies before an authorized change restricts public access.",
    ),
    "NET-005": (
        "Default VPC security group permits traffic",
        Severity.MEDIUM,
        "The default group has no ingress or egress permissions.",
        "The default group has any ingress or egress permission.",
        "The group is not default, or complete discovery is empty.",
        "Permissive default groups can allow unintended traffic.",
        "Review workload dependencies before an authorized change removes default-group "
        "ingress and egress rules.",
    ),
}


def network_contract(control_id):
    title, severity, passing, failing, na, impact, guidance = _METADATA[control_id]
    return ControlContract(
        technical=TechnicalControlContract(
            control_id=control_id,
            title=title,
            category=ControlCategory.NETWORK,
            resource_type="security_group",
            assessment_type=AssessmentType.AUTOMATED,
            measure=title,
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration",
                    description="Complete source-bound group facts and same-scan VPC relationship.",
                ),
            ),
            pass_logic=passing,
            fail_logic=failing,
            not_applicable_logic=na,
            insufficient_evidence_behavior=(
                "Missing, malformed or incomplete required evidence is INSUFFICIENT_EVIDENCE."
            ),
            severity=severity,
            impact=impact,
            remediation_guidance=guidance,
            profile_parameters=("enabled_controls", "high_risk_public_tcp_ports")
            if control_id == "NET-004"
            else ("enabled_controls",),
            limitations=(
                "Evaluation version 1.0.0; configuration only, not proof of reachability.",
                "No attachment check or remediation execution.",
            ),
            execution_contract=network_execution(),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id=control_id,
                framework_id="nist-csf",
                framework_version="2.0+subset.5",
                reference_id="PR.IR-01",
                mapping_rationale=(
                    "Security-group restrictions contribute network-access protection evidence, "
                    "not reachability, attachment or full compliance."
                ),
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 28, tzinfo=UTC),
            ),
        ),
    )


def build_network_catalog():
    previous = build_ec2_catalog()
    controls = tuple(network_contract(c) for c in NETWORK_CONTROL_IDS)
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_5.json",
        manifest_path=data / "nist_csf_2_0_subset_5_manifest.json",
        mappings=tuple(m for c in controls for m in c.framework_mappings),
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.6.0",
        controls=tuple(
            sorted(
                (*previous.controls, *controls),
                key=lambda c: c.control_id,
            )
        ),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
