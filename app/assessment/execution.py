"""Version-bound assessment targets and complete-source requirements, without rule logic."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.assessment.relationships import RelationshipType
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope


class ResourceFamily(BaseModel):
    """An exact service/type pair; no ambiguous service-independent type matching."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    service: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    resource_type: str = Field(pattern=r"^[a-z][a-z0-9_]*$")


class RequiredSource(BaseModel):
    """A mandatory source and its normalized completeness attestations."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    collector: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    evidence_kind: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    source_api: str = Field(pattern=r"^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*$")
    subject: Literal["target", "global_account", "regional_account"]
    contract_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    # The source's schema defines these top-level booleans. PRESENT alone is never proof.
    completeness_fields: tuple[Literal["complete", "admission_complete"], ...] = ()
    completion: Literal["payload_flags_v1", "admitted_resource_v1"] = "payload_flags_v1"
    expected_absence_is_complete: bool = False

    @model_validator(mode="after")
    def unique_fields(self) -> Self:
        if self.completion == "payload_flags_v1" and not self.completeness_fields:
            raise ValueError("flag-based sources require completeness fields")
        if self.completion == "admitted_resource_v1" and (
            self.subject != "target"
            or self.completeness_fields
            or self.expected_absence_is_complete
        ):
            raise ValueError("admitted-resource proof requires an exact present resource subject")
        if len(set(self.completeness_fields)) != len(self.completeness_fields):
            raise ValueError("duplicate source completeness field")
        return self


class ExecutionContract(BaseModel):
    """The only 6A strategy requires every declared source and edge to be complete."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    schema_version: Literal["1.0.0", "1.1.0", "1.2.0", "1.3.0"]
    target_kind: Literal["global_account", "regional_account", "resources"]
    target_selection: Literal["all_observed_v1", "iam_policy_documents_v1"]
    account_service: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    resource_families: tuple[ResourceFamily, ...] = ()
    validation_strategy: Literal[
        "all_required_sources_complete_v1",
        "iam_active_key_age_v1",
        "iam_active_key_usage_v1",
        "iam_policy_document_v1",
        "security_group_v1",
    ]
    required_sources: tuple[RequiredSource, ...] = Field(min_length=1)
    required_relationships: tuple[RelationshipType, ...] = ()

    @model_validator(mode="after")
    def unambiguous_contract(self) -> Self:
        if self.schema_version == "1.3.0":
            from app.assessment.security_group_evidence import NETWORK_SOURCES

            if (
                self.validation_strategy != "security_group_v1"
                or self.target_kind != "resources"
                or self.account_service != "ec2"
                or self.resource_families
                != (ResourceFamily(service="ec2", resource_type="security_group"),)
                or self.required_sources != NETWORK_SOURCES
                or self.required_relationships != (RelationshipType.IN_VPC,)
            ):
                raise ValueError("execution schema 1.3 is restricted to security-group proofs")
        if self.schema_version != "1.2.0" and self.target_selection != "all_observed_v1":
            raise ValueError("legacy execution schemas require legacy target selection")
        if self.schema_version == "1.2.0":
            from app.assessment.iam_policy_evidence import POLICY_DISCOVERY, POLICY_FAMILIES

            if (
                self.validation_strategy != "iam_policy_document_v1"
                or self.target_selection != "iam_policy_documents_v1"
                or self.target_kind != "resources"
                or self.account_service != "iam"
                or self.resource_families != POLICY_FAMILIES
                or self.required_sources != POLICY_DISCOVERY
                or self.required_relationships
            ):
                raise ValueError("execution schema 1.2 is restricted to IAM policy proofs")
        if self.schema_version == "1.0.0" and self.validation_strategy != (
            "all_required_sources_complete_v1"
        ):
            raise ValueError("legacy execution schema does not support IAM key proofs")
        if self.schema_version == "1.1.0" and (
            self.validation_strategy not in {"iam_active_key_age_v1", "iam_active_key_usage_v1"}
            or self.target_kind != "resources"
            or self.account_service != "iam"
            or self.resource_families != (ResourceFamily(service="iam", resource_type="iam_user"),)
            or self.required_relationships != (RelationshipType.HAS_ACCESS_KEY,)
        ):
            raise ValueError("execution schema 1.1 is restricted to IAM user/key proofs")
        families = [(item.service, item.resource_type) for item in self.resource_families]
        if len(set(families)) != len(families):
            raise ValueError("duplicate resource family")
        if (self.target_kind == "resources") != bool(families):
            raise ValueError("only resource targets require resource families")
        if any(item.resource_type == "aws_account" for item in self.resource_families):
            raise ValueError("account targets must use an explicit account target kind")
        if self.target_kind == "regional_account" and self.account_service != "ec2":
            raise ValueError("only EC2 Regional account settings are supported")
        if self.target_kind != "resources" and self.required_relationships:
            raise ValueError("assessment-only account targets cannot be graph endpoints")
        if self.target_kind != "resources" and any(
            source.completion == "admitted_resource_v1" for source in self.required_sources
        ):
            raise ValueError("account settings require source completeness flags")
        keys = [
            (s.collector, s.evidence_kind, s.source_api, s.subject) for s in self.required_sources
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate required source")
        if len(set(self.required_relationships)) != len(self.required_relationships):
            raise ValueError("duplicate required relationship")
        if self.target_kind == "resources" and not any(
            source.subject != "target" for source in self.required_sources
        ):
            raise ValueError("resource enumeration requires account-scoped coverage evidence")
        return self


def account_target(snapshot: InventorySnapshot, contract: ExecutionContract) -> NormalizedResource:
    """Assessment-only target; never add this to collector inventory or the evidence graph."""

    regional = contract.target_kind == "regional_account"
    return NormalizedResource(
        account_id=snapshot.account_id,
        service=contract.account_service,
        resource_type="aws_account",
        aws_resource_id=snapshot.account_id,
        name=snapshot.account_id,
        scope=ResourceScope.REGIONAL if regional else ResourceScope.GLOBAL,
        region=snapshot.requested_region if regional else None,
    )


def assessment_targets(
    snapshot: InventorySnapshot,
    contract: ExecutionContract,
) -> tuple[NormalizedResource, ...]:
    """Pure canonical enumeration shared by engine and persistence; retain actual identities."""

    if contract.target_kind != "resources":
        return (account_target(snapshot, contract),)
    if contract.target_selection == "iam_policy_documents_v1":
        from app.assessment.iam_policy_evidence import policy_targets

        return policy_targets(snapshot)
    families = {(item.service, item.resource_type) for item in contract.resource_families}
    resources = tuple(
        sorted(
            (r for r in snapshot.resources if (r.service, r.resource_type) in families),
            key=lambda r: r.identity,
        )
    )
    if len({r.identity for r in resources}) != len(resources):
        raise ValueError("duplicate assessment target in inventory")
    return resources


def validate_execution_targets(
    snapshot: InventorySnapshot,
    contract: ExecutionContract,
    candidates: tuple[AssessmentCandidate, ...],
) -> None:
    """No omitted/extra targets, and no collector failure can erase observed targets."""

    targets = assessment_targets(snapshot, contract)
    actual = [item.identity[1:] for item in candidates]
    if not targets:
        if len(candidates) != 1 or candidates[0].result not in {
            AssessmentResult.NOT_APPLICABLE,
            AssessmentResult.INSUFFICIENT_EVIDENCE,
        }:
            raise ValueError("empty target set requires an explicit N/A or insufficient result")
        targets = (account_target(snapshot, contract),)
    if len(actual) != len(set(actual)) or set(actual) != {item.identity for item in targets}:
        raise ValueError("assessment target matrix differs from the execution contract")
