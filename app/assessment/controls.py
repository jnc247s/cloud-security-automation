"""Versioned technical control contracts and external framework mappings.

Technical evaluation policy is deliberately modeled separately from framework metadata.
NIST mappings explain which external outcomes a control can contribute evidence toward; they
must never decide whether the technical control passes or fails.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.assessment.frameworks import (
    ControlFrameworkMapping,
    FrameworkCatalog,
    load_nist_csf_2_0_catalog,
)
from app.assessment.profiles import AssessmentProfile
from app.schemas.finding import ControlCategory, Severity

CONTROL_CATALOG_ID = "aws-cloud-security-controls"
CONTROL_CATALOG_VERSION = "0.2.1"
NIST_CSF_2_0_SOURCE = "https://doi.org/10.6028/NIST.CSWP.29"
_MAPPING_VERIFIED_AT = datetime(2026, 9, 3, tzinfo=UTC)


class AssessmentType(StrEnum):
    """Supported ways in which a control can produce a technical assessment."""

    AUTOMATED = "automated"


class EvidenceRequirement(BaseModel):
    """One normalized fact that an automated control needs to make a decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fact_path: str = Field(min_length=1)
    description: str = Field(min_length=1)

    @field_validator("fact_path", "description")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Reject evidence definitions that contain only whitespace."""

        if not value.strip():
            raise ValueError("evidence requirement values must not be blank")
        return value


class TechnicalControlContract(BaseModel):
    """Immutable, framework-independent policy contract for one technical control."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    control_id: str = Field(pattern=r"^[A-Z0-9]+-\d{3}$")
    title: str = Field(min_length=1)
    category: ControlCategory
    resource_type: str = Field(min_length=1)
    assessment_type: AssessmentType
    measure: str = Field(min_length=1)
    required_evidence: tuple[EvidenceRequirement, ...] = Field(min_length=1)
    pass_logic: str = Field(min_length=1)
    fail_logic: str = Field(min_length=1)
    insufficient_evidence_behavior: str = Field(min_length=1)
    not_applicable_logic: str = Field(min_length=1)
    severity: Severity
    impact: str = Field(min_length=1)
    remediation_guidance: str = Field(min_length=1)
    profile_parameters: tuple[str, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = ()

    @field_validator(
        "title",
        "resource_type",
        "measure",
        "pass_logic",
        "fail_logic",
        "insufficient_evidence_behavior",
        "not_applicable_logic",
        "impact",
        "remediation_guidance",
    )
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Require substantive human-readable control metadata."""

        if not value.strip():
            raise ValueError("technical control values must not be blank")
        return value

    @field_validator("profile_parameters", "limitations")
    @classmethod
    def reject_blank_tuple_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Reject blank policy names and lifecycle notes."""

        if any(not value.strip() for value in values):
            raise ValueError("technical control tuple values must not be blank")
        return values

    @model_validator(mode="after")
    def reject_duplicate_contract_entries(self) -> Self:
        """Keep evidence and profile dependencies unambiguous."""

        fact_paths = [requirement.fact_path for requirement in self.required_evidence]
        if len(fact_paths) != len(set(fact_paths)):
            raise ValueError(f"duplicate evidence requirement for {self.control_id}")
        if len(self.profile_parameters) != len(set(self.profile_parameters)):
            raise ValueError(f"duplicate profile parameter for {self.control_id}")
        unknown_profile_parameters = set(self.profile_parameters) - set(
            AssessmentProfile.model_fields
        )
        if unknown_profile_parameters:
            unknown = ", ".join(sorted(unknown_profile_parameters))
            raise ValueError(f"unknown assessment profile parameter: {unknown}")
        return self


class ControlContract(BaseModel):
    """Compose technical assessment policy with auditable external-framework mappings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technical: TechnicalControlContract
    framework_mappings: tuple[ControlFrameworkMapping, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_mapping_ownership(self) -> Self:
        """Require unique mappings that belong to this technical control."""

        identities: set[tuple[str, str, str, str]] = set()
        for mapping in self.framework_mappings:
            if mapping.control_id != self.technical.control_id:
                raise ValueError(
                    f"mapping for {mapping.control_id} cannot belong to {self.technical.control_id}"
                )
            if mapping.identity in identities:
                raise ValueError(
                    f"duplicate framework mapping for {self.technical.control_id}: "
                    f"{mapping.reference_id}"
                )
            identities.add(mapping.identity)
        return self

    @property
    def control_id(self) -> str:
        """Return the stable internal control identifier."""

        return self.technical.control_id


class ControlCatalog(BaseModel):
    """A versioned set of controls with validated framework mapping coverage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    catalog_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    controls: tuple[ControlContract, ...] = Field(min_length=1)
    framework_catalogs: tuple[FrameworkCatalog, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_catalog(self) -> Self:
        """Reject duplicate controls and incomplete or orphaned mapping coverage."""

        control_ids: set[str] = set()
        contract_mapping_identities: set[tuple[str, str, str, str]] = set()
        for control in self.controls:
            if control.control_id in control_ids:
                raise ValueError(f"duplicate technical control: {control.control_id}")
            control_ids.add(control.control_id)
            for mapping in control.framework_mappings:
                if mapping.identity in contract_mapping_identities:
                    raise ValueError(
                        "duplicate mapping across control contracts: "
                        f"{mapping.control_id} -> {mapping.reference_id}"
                    )
                contract_mapping_identities.add(mapping.identity)

        framework_keys: set[tuple[str, str]] = set()
        framework_mapping_identities: set[tuple[str, str, str, str]] = set()
        for framework_catalog in self.framework_catalogs:
            framework_key = (
                framework_catalog.framework.framework_id,
                framework_catalog.framework.version,
            )
            if framework_key in framework_keys:
                raise ValueError(
                    f"duplicate framework catalog: {framework_key[0]} {framework_key[1]}"
                )
            framework_keys.add(framework_key)

            for mapping in framework_catalog.mappings:
                if mapping.control_id not in control_ids:
                    raise ValueError(
                        f"framework mapping references unknown control: {mapping.control_id}"
                    )
                if mapping.identity in framework_mapping_identities:
                    raise ValueError(
                        "duplicate mapping across framework catalogs: "
                        f"{mapping.control_id} -> {mapping.reference_id}"
                    )
                framework_mapping_identities.add(mapping.identity)

        if contract_mapping_identities != framework_mapping_identities:
            missing_from_frameworks = contract_mapping_identities - framework_mapping_identities
            missing_from_controls = framework_mapping_identities - contract_mapping_identities
            details: list[str] = []
            if missing_from_frameworks:
                details.append("contract mappings absent from framework catalogs")
            if missing_from_controls:
                details.append("framework mappings absent from control contracts")
            raise ValueError("incomplete framework mapping coverage: " + "; ".join(details))

        return self

    def get(self, control_id: str) -> ControlContract:
        """Return one version-bound control contract."""

        for control in self.controls:
            if control.control_id == control_id:
                return control
        raise KeyError(f"unknown control in catalog {self.catalog_id} {self.version}: {control_id}")


TECHNICAL_CONTROL_CONTRACTS: tuple[TechnicalControlContract, ...] = (
    TechnicalControlContract(
        control_id="IAM-001",
        title="IAM User Without MFA",
        category=ControlCategory.IDENTITY,
        resource_type="iam_user",
        assessment_type=AssessmentType.AUTOMATED,
        measure="Whether each inventoried IAM user has at least one assigned MFA device.",
        required_evidence=(
            EvidenceRequirement(
                fact_path="configuration.mfa_devices",
                description="The normalized list of MFA devices assigned to the IAM user.",
            ),
            EvidenceRequirement(
                fact_path="configuration.mfa_devices[].SerialNumber",
                description="A non-empty device identifier for every returned MFA device.",
            ),
        ),
        pass_logic="The MFA-device fact is valid and contains at least one device.",
        fail_logic="The MFA-device fact is a valid empty list.",
        insufficient_evidence_behavior=(
            "Return INSUFFICIENT_EVIDENCE when the MFA-device fact is absent, is not a list, "
            "or contains malformed entries; never infer PASS."
        ),
        not_applicable_logic="No IAM user resources are present in the assessed inventory.",
        severity=Severity.MEDIUM,
        impact=(
            "A password-authenticated IAM user without MFA is more exposed to account "
            "takeover when a credential is compromised."
        ),
        remediation_guidance=(
            "Enroll the IAM user in MFA, migrate workforce access to IAM Identity Center "
            "where appropriate, or remove the user if it is no longer required."
        ),
        profile_parameters=("enabled_controls",),
    ),
    TechnicalControlContract(
        control_id="LOG-001",
        title="CloudTrail Missing",
        category=ControlCategory.LOGGING,
        resource_type="aws_account",
        assessment_type=AssessmentType.AUTOMATED,
        measure="Whether the account inventory contains at least one actively logging trail.",
        required_evidence=(
            EvidenceRequirement(
                fact_path="snapshot.resources[cloudtrail_trail]",
                description=(
                    "A completed inventory of CloudTrail trail resources for the account."
                ),
            ),
            EvidenceRequirement(
                fact_path="configuration.is_logging",
                description="The normalized active-logging status for every returned trail.",
            ),
        ),
        pass_logic="At least one returned CloudTrail trail has is_logging set to true.",
        fail_logic="No trails exist, or every returned trail has is_logging set to false.",
        insufficient_evidence_behavior=(
            "Return INSUFFICIENT_EVIDENCE when trail inventory completeness is unknown or a "
            "returned trail lacks a valid boolean logging status; never infer PASS."
        ),
        not_applicable_logic="This account-level control is always applicable.",
        severity=Severity.HIGH,
        impact=(
            "Without an actively logging CloudTrail trail, security investigations and audit "
            "reconstruction can have material visibility gaps."
        ),
        remediation_guidance=(
            "Configure and continuously monitor an actively logging CloudTrail trail; prefer "
            "a multi-Region trail that includes global service events."
        ),
        profile_parameters=("enabled_controls",),
        limitations=(
            "This Sprint 2 control measures active logging only; required multi-Region and "
            "management-event coverage belongs to the canonical LOG-002 control.",
        ),
    ),
    TechnicalControlContract(
        control_id="NET-001",
        title="Public SSH Access",
        category=ControlCategory.NETWORK,
        resource_type="security_group",
        assessment_type=AssessmentType.AUTOMATED,
        measure=(
            "Whether an EC2 security group permits TCP port 22 through an IPv4 or IPv6 "
            "Internet-wide ingress range."
        ),
        required_evidence=(
            EvidenceRequirement(
                fact_path="configuration.ingress_rules",
                description=(
                    "Normalized protocols, port ranges, and IPv4/IPv6 CIDRs for every ingress "
                    "permission."
                ),
            ),
        ),
        pass_logic="No valid ingress permission exposes port 22 to 0.0.0.0/0 or ::/0.",
        fail_logic="At least one ingress permission exposes port 22 to 0.0.0.0/0 or ::/0.",
        insufficient_evidence_behavior=(
            "Return INSUFFICIENT_EVIDENCE when ingress rules or any decision-relevant "
            "protocol, port, or CIDR fact is absent or malformed; never infer PASS."
        ),
        not_applicable_logic="No EC2 security group resources are present in the inventory.",
        severity=Severity.HIGH,
        impact=(
            "Internet-exposed SSH can permit brute-force attempts and unauthorized "
            "administrative access."
        ),
        remediation_guidance=(
            "Restrict administrative access to approved management networks or use controlled "
            "remote-management mechanisms."
        ),
        profile_parameters=("enabled_controls",),
    ),
    TechnicalControlContract(
        control_id="NET-002",
        title="Public RDP Access",
        category=ControlCategory.NETWORK,
        resource_type="security_group",
        assessment_type=AssessmentType.AUTOMATED,
        measure=(
            "Whether an EC2 security group permits TCP port 3389 through an IPv4 or IPv6 "
            "Internet-wide ingress range."
        ),
        required_evidence=(
            EvidenceRequirement(
                fact_path="configuration.ingress_rules",
                description=(
                    "Normalized protocols, port ranges, and IPv4/IPv6 CIDRs for every ingress "
                    "permission."
                ),
            ),
        ),
        pass_logic="No valid ingress permission exposes port 3389 to 0.0.0.0/0 or ::/0.",
        fail_logic="At least one ingress permission exposes port 3389 to 0.0.0.0/0 or ::/0.",
        insufficient_evidence_behavior=(
            "Return INSUFFICIENT_EVIDENCE when ingress rules or any decision-relevant "
            "protocol, port, or CIDR fact is absent or malformed; never infer PASS."
        ),
        not_applicable_logic="No EC2 security group resources are present in the inventory.",
        severity=Severity.HIGH,
        impact=(
            "Internet-exposed RDP can permit brute-force attempts and unauthorized interactive "
            "access."
        ),
        remediation_guidance=(
            "Restrict RDP access to approved management networks or use a controlled "
            "remote-management service."
        ),
        profile_parameters=("enabled_controls",),
    ),
    TechnicalControlContract(
        control_id="S3-900",
        title="Missing Bucket Encryption",
        category=ControlCategory.STORAGE,
        resource_type="s3_bucket",
        assessment_type=AssessmentType.AUTOMATED,
        measure="Whether a bucket exposes a valid explicit default-encryption configuration.",
        required_evidence=(
            EvidenceRequirement(
                fact_path="configuration.default_encryption",
                description="The normalized S3 bucket default-encryption configuration.",
            ),
            EvidenceRequirement(
                fact_path=(
                    "configuration.default_encryption.Rules[]."
                    "ApplyServerSideEncryptionByDefault.SSEAlgorithm"
                ),
                description="A supported server-side encryption algorithm in every rule.",
            ),
        ),
        pass_logic=(
            "The default-encryption fact is a mapping with a non-empty Rules list and every "
            "rule names a supported SSEAlgorithm."
        ),
        fail_logic="The default-encryption fact is explicitly null.",
        insufficient_evidence_behavior=(
            "Return INSUFFICIENT_EVIDENCE when the default-encryption fact is absent or "
            "malformed; never infer PASS."
        ),
        not_applicable_logic="No S3 bucket resources are present in the inventory.",
        severity=Severity.MEDIUM,
        impact=(
            "Without an explicit default encryption configuration, the bucket cannot "
            "demonstrate the intended encryption policy from its collected configuration."
        ),
        remediation_guidance=(
            "Configure default server-side encryption that meets the organization's "
            "key-management requirements."
        ),
        profile_parameters=("enabled_controls",),
        limitations=(
            "Legacy Sprint 2 prototype semantics: this non-core control measures explicit "
            "bucket default-encryption configuration. Sprint 2.1 migrated it from S3-002 to "
            "S3-900 before persistence existed, leaving canonical S3-002 reserved for "
            "unapproved public/external bucket exposure.",
        ),
    ),
)


CONTROL_FRAMEWORK_MAPPINGS: tuple[ControlFrameworkMapping, ...] = (
    ControlFrameworkMapping(
        control_id="IAM-001",
        framework_id="nist-csf",
        framework_version="2.0",
        reference_id="PR.AA-03",
        mapping_rationale=(
            "IAM-user MFA evidence contributes to the outcome that users are authenticated. "
            "It does not establish the full outcome for every user, service, and device."
        ),
        mapping_source=NIST_CSF_2_0_SOURCE,
        mapping_source_version="2.0",
        verified_at=_MAPPING_VERIFIED_AT,
    ),
    ControlFrameworkMapping(
        control_id="LOG-001",
        framework_id="nist-csf",
        framework_version="2.0",
        reference_id="PR.PS-04",
        mapping_rationale=(
            "An actively logging CloudTrail trail contributes evidence that log records are "
            "generated and available for monitoring. It does not establish complete log "
            "coverage, retention, or monitoring."
        ),
        mapping_source=NIST_CSF_2_0_SOURCE,
        mapping_source_version="2.0",
        verified_at=_MAPPING_VERIFIED_AT,
    ),
    ControlFrameworkMapping(
        control_id="NET-001",
        framework_id="nist-csf",
        framework_version="2.0",
        reference_id="PR.IR-01",
        mapping_rationale=(
            "Testing Internet-wide SSH exposure contributes evidence about protection from "
            "unauthorized logical network access. It does not establish every protection in "
            "the subcategory."
        ),
        mapping_source=NIST_CSF_2_0_SOURCE,
        mapping_source_version="2.0",
        verified_at=_MAPPING_VERIFIED_AT,
    ),
    ControlFrameworkMapping(
        control_id="NET-002",
        framework_id="nist-csf",
        framework_version="2.0",
        reference_id="PR.IR-01",
        mapping_rationale=(
            "Testing Internet-wide RDP exposure contributes evidence about protection from "
            "unauthorized logical network access. It does not establish every protection in "
            "the subcategory."
        ),
        mapping_source=NIST_CSF_2_0_SOURCE,
        mapping_source_version="2.0",
        verified_at=_MAPPING_VERIFIED_AT,
    ),
    ControlFrameworkMapping(
        control_id="S3-900",
        framework_id="nist-csf",
        framework_version="2.0",
        reference_id="PR.DS-01",
        mapping_rationale=(
            "An explicit S3 default-encryption configuration contributes evidence about "
            "data-at-rest protection. It does not establish the full confidentiality, "
            "integrity, and availability outcome or KMS-policy compliance."
        ),
        mapping_source=NIST_CSF_2_0_SOURCE,
        mapping_source_version="2.0",
        verified_at=_MAPPING_VERIFIED_AT,
    ),
)


def build_default_control_catalog() -> ControlCatalog:
    """Build the reviewed Sprint 2.1 catalog and validate all NIST mapping references."""

    mappings_by_control: dict[str, list[ControlFrameworkMapping]] = {}
    for mapping in CONTROL_FRAMEWORK_MAPPINGS:
        mappings_by_control.setdefault(mapping.control_id, []).append(mapping)

    controls = tuple(
        ControlContract(
            technical=technical,
            framework_mappings=tuple(mappings_by_control.get(technical.control_id, ())),
        )
        for technical in TECHNICAL_CONTROL_CONTRACTS
    )
    framework_catalog = load_nist_csf_2_0_catalog(mappings=CONTROL_FRAMEWORK_MAPPINGS)
    return ControlCatalog(
        catalog_id=CONTROL_CATALOG_ID,
        version=CONTROL_CATALOG_VERSION,
        controls=controls,
        framework_catalogs=(framework_catalog,),
    )
