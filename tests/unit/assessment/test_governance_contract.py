"""Closed release contract and explicit immutable policy, independent of framework metadata."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.assessment.execution import ExecutionContract
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE
from app.rules.registry import resolve_catalog
from app.schemas.finding import ControlCategory, Severity
from tests.governance_fixtures import governance_profile


def test_documented_initial_policy_is_exact_and_loadable():
    from app.assessment.deployment_policy import load_deployment_policy
    from app.config import Settings

    path = (
        Path(__file__).resolve().parents[3]
        / "docs/controls/examples/sprint-6g-initial-profile.json"
    )
    policy = load_deployment_policy(
        Settings(
            _env_file=None,
            app_env="test",
            auth_mode="development",
            assessment_profile_file=str(path),
            assessment_profile_version="1.0.0",
        )
    )
    assert policy.profile == governance_profile(profile_id="sprint-6g-initial", version="1.0.0")
    assert policy.catalog.version == "0.13.0"
    assert (
        policy.profile.content_checksum
        == "90a65ea73748f02742bc7cde8684264b8999d8a562ce87729478138db6caf9a5"
    )
    assert DEFAULT_ASSESSMENT_PROFILE.enabled_controls == (
        "IAM-001",
        "LOG-001",
        "NET-001",
        "NET-002",
        "S3-900",
    )


def test_approved_metadata_and_selector_vocabulary():
    from app.assessment.extended_profiles import GOVERNED_RESOURCE_TYPES

    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.13.0")
    control = catalog.get("GOV-001")
    assert registry.get("GOV-001").contract == control.technical
    assert control.technical.category is ControlCategory.GOVERNANCE
    assert control.technical.severity is Severity.MEDIUM
    assert {
        f.resource_type for f in control.technical.execution_contract.resource_families
    } == GOVERNED_RESOURCE_TYPES
    assert control.framework_mappings[0].reference_id == "ID.AM-02"
    assert control.framework_mappings[0].framework_version == "2.0+subset.12"
    reference = next(
        r for r in catalog.framework_catalogs[-1].references if r.reference_id == "ID.AM-02"
    )
    assert (
        reference.description
        == "Inventories of software, services, and systems managed by the organization "
        "are maintained"
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"required_tags": ()},
        {"required_tags": (" ",)},
        {"governed_resource_types": ()},
        {"governed_resource_types": None},
        {"governed_resource_types": ("iam_group",)},
        {"governed_resource_types": ("S3_bucket",)},
    ],
)
def test_explicit_policy_rejects_missing_blank_or_unknown_inputs(updates):
    catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.13.0")
    with pytest.raises(ValueError):
        catalog.validate_profile_inputs(governance_profile(**updates))


def test_legacy_profile_cannot_implicitly_enable_governance():
    catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.13.0")
    with pytest.raises(ValueError, match="exact explicit extended"):
        catalog.validate_profile_inputs(
            DEFAULT_ASSESSMENT_PROFILE.model_copy(update={"enabled_controls": ("GOV-001",)})
        )


def test_only_new_governance_target_selector_requires_explicit_profile():
    from app.assessment.execution import assessment_targets
    from tests.governance_fixtures import governance_bundle

    bundle = governance_bundle(empty_family="s3_bucket")
    profile = governance_profile(governed_resource_types=("s3_bucket",))
    execution = bundle["catalog"].get("GOV-001").technical.execution_contract
    assert execution.target_selection == "governance_tags_v1"
    with pytest.raises(ValueError, match="exact explicit"):
        assessment_targets(bundle["snapshot"], execution)
    targets = assessment_targets(bundle["snapshot"], execution, profile=profile)
    assert len(targets) == 11 and sum(t.resource_type == "aws_account" for t in targets) == 1
    previous, _ = resolve_catalog("aws-cloud-security-controls", "0.12.0")
    for control in previous.controls:
        contract = control.technical.execution_contract
        if contract is not None:
            assert assessment_targets(bundle["snapshot"], contract) == assessment_targets(
                bundle["snapshot"], contract, profile=profile
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "1.9.0"),
        ("target_selection", "all_observed_v1"),
        ("target_selection", "iam_policy_documents_v1"),
        ("account_service", "ec2"),
        ("validation_strategy", "all_required_sources_complete_v1"),
        ("resource_families", ()),
        ("required_sources", ()),
        ("assessment_dependencies", ("S3-002",)),
    ],
)
def test_execution_contract_cannot_be_relaxed(field, value):
    catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.13.0")
    document = catalog.get("GOV-001").technical.execution_contract.model_dump()
    document[field] = value
    with pytest.raises(ValidationError):
        ExecutionContract.model_validate(document)
