"""Approved NET-006 metadata and opt-in catalog; previous releases stay immutable."""

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
from app.assessment.flow_log_evidence import FLOW_SOURCES
from app.assessment.frameworks import ControlFrameworkMapping, load_framework_catalog
from app.assessment.security_group_controls import build_network_catalog
from app.schemas.finding import ControlCategory, Severity


def flow_log_contract():
    return ControlContract(
        technical=TechnicalControlContract(
            control_id="NET-006",
            title="Required VPC Flow Logs are missing",
            category=ControlCategory.NETWORK,
            resource_type="vpc",
            assessment_type=AssessmentType.AUTOMATED,
            measure="Required environments have active VPC-scoped Flow Logs with accepted traffic.",
            required_evidence=(
                EvidenceRequirement(
                    fact_path="configuration",
                    description=(
                        "Complete VPC tags, Flow Log population, source facts and exact edges."
                    ),
                ),
            ),
            pass_logic="An applicable VPC has an ACTIVE VPC-scoped log with accepted traffic type.",
            fail_logic="Complete applicable VPC evidence contains no qualifying Flow Log.",
            not_applicable_logic=(
                "Complete VPC population is empty or usable Environment is outside policy."
            ),
            insufficient_evidence_behavior=(
                "Missing, malformed or incomplete required evidence is INSUFFICIENT_EVIDENCE."
            ),
            severity=Severity.MEDIUM,
            impact="Missing VPC Flow Log configuration reduces network-activity visibility.",
            remediation_guidance=(
                "An authorized operator should review dependencies and costs before enabling "
                "VPC Flow Logs."
            ),
            profile_parameters=(
                "enabled_controls",
                "vpc_flow_log_required_environments",
                "acceptable_vpc_flow_log_traffic_types",
            ),
            limitations=(
                "Evaluation version 1.0.0; configuration only, not delivery, retention "
                "or monitoring assurance.",
                "Subnet/interface logs do not satisfy VPC coverage. No AWS writes.",
            ),
            execution_contract=ExecutionContract(
                schema_version="1.4.0",
                target_kind="resources",
                target_selection="all_observed_v1",
                account_service="ec2",
                resource_families=(ResourceFamily(service="ec2", resource_type="vpc"),),
                validation_strategy="vpc_flow_logs_v1",
                required_sources=FLOW_SOURCES,
                # Exact zero-or-more membership is enforced by this bounded strategy.
                required_relationships=(),
            ),
        ),
        framework_mappings=(
            ControlFrameworkMapping(
                control_id="NET-006",
                framework_id="nist-csf",
                framework_version="2.0+subset.6",
                reference_id="PR.PS-04",
                mapping_rationale=(
                    "VPC Flow Log configuration contributes log-generation evidence only; "
                    "it does not establish delivery, retention or continuous monitoring."
                ),
                mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
                mapping_source_version="2.0",
                verified_at=datetime(2026, 9, 28, tzinfo=UTC),
            ),
        ),
    )


def build_flow_log_catalog():
    previous = build_network_catalog()
    control = flow_log_contract()
    data = Path(__file__).parent / "data"
    framework = load_framework_catalog(
        data_path=data / "nist_csf_2_0_subset_6.json",
        manifest_path=data / "nist_csf_2_0_subset_6_manifest.json",
        mappings=control.framework_mappings,
    )
    return ControlCatalog(
        catalog_id=previous.catalog_id,
        version="0.7.0",
        controls=tuple(sorted((*previous.controls, control), key=lambda c: c.control_id)),
        framework_catalogs=(*previous.framework_catalogs, framework),
    )
