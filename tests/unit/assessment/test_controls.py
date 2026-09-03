"""Tests for versioned technical controls and external framework mappings."""

import pytest
from pydantic import ValidationError

from app.assessment.controls import (
    CONTROL_CATALOG_ID,
    CONTROL_CATALOG_VERSION,
    CONTROL_FRAMEWORK_MAPPINGS,
    TECHNICAL_CONTROL_CONTRACTS,
    ControlCatalog,
    ControlContract,
    TechnicalControlContract,
    build_default_control_catalog,
)
from app.assessment.frameworks import ControlFrameworkMapping

EXPECTED_REFERENCES = {
    "IAM-001": "PR.AA-03",
    "LOG-001": "PR.PS-04",
    "NET-001": "PR.IR-01",
    "NET-002": "PR.IR-01",
    "S3-900": "PR.DS-01",
}


def test_default_catalog_covers_every_existing_control() -> None:
    catalog = build_default_control_catalog()

    assert catalog.catalog_id == CONTROL_CATALOG_ID
    assert catalog.version == CONTROL_CATALOG_VERSION
    assert tuple(control.control_id for control in catalog.controls) == tuple(
        sorted(EXPECTED_REFERENCES)
    )

    for control in catalog.controls:
        technical = control.technical
        assert technical.measure
        assert technical.required_evidence
        assert technical.pass_logic
        assert technical.fail_logic
        assert technical.insufficient_evidence_behavior
        assert technical.not_applicable_logic
        assert technical.remediation_guidance
        assert technical.profile_parameters
        assert {mapping.reference_id for mapping in control.framework_mappings} == {
            EXPECTED_REFERENCES[control.control_id]
        }


def test_technical_contracts_remain_valid_without_framework_metadata() -> None:
    """Technical policy can be loaded without treating a NIST mapping as evaluation input."""

    for contract in TECHNICAL_CONTROL_CONTRACTS:
        payload = contract.model_dump()

        assert "framework_mappings" not in payload
        assert TechnicalControlContract.model_validate(payload) == contract


def test_technical_contract_rejects_unknown_profile_parameter() -> None:
    payload = TECHNICAL_CONTROL_CONTRACTS[0].model_dump()
    payload["profile_parameters"] = ("misspelled_policy",)

    with pytest.raises(ValidationError, match="unknown assessment profile parameter"):
        TechnicalControlContract.model_validate(payload)


def test_control_contract_rejects_missing_framework_mapping() -> None:
    with pytest.raises(ValidationError):
        ControlContract(
            technical=TECHNICAL_CONTROL_CONTRACTS[0],
            framework_mappings=(),
        )


def test_control_contract_rejects_mapping_owned_by_another_control() -> None:
    mapping = CONTROL_FRAMEWORK_MAPPINGS[0].model_copy(update={"control_id": "IAM-999"})

    with pytest.raises(ValidationError, match="cannot belong"):
        ControlContract(
            technical=TECHNICAL_CONTROL_CONTRACTS[0],
            framework_mappings=(mapping,),
        )


def test_default_mappings_have_explicit_provenance() -> None:
    for mapping in CONTROL_FRAMEWORK_MAPPINGS:
        assert mapping.mapping_source == "https://doi.org/10.6028/NIST.CSWP.29"
        assert mapping.mapping_source_version == "2.0"
        assert mapping.mapping_rationale
        assert mapping.verified_at.tzinfo is not None


def test_catalog_rejects_duplicate_controls() -> None:
    catalog = build_default_control_catalog()

    with pytest.raises(ValidationError, match="duplicate technical control"):
        ControlCatalog(
            catalog_id=catalog.catalog_id,
            version=catalog.version,
            controls=(catalog.controls[0], catalog.controls[0]),
            framework_catalogs=catalog.framework_catalogs,
        )


def test_catalog_rejects_mapping_not_bound_to_framework_catalog() -> None:
    catalog = build_default_control_catalog()
    original = catalog.controls[0]
    extra_mapping = ControlFrameworkMapping(
        control_id=original.control_id,
        framework_id="nist-csf",
        framework_version="2.0",
        reference_id="PR.DS-01",
        mapping_rationale="Additional mapping used to test catalog-level coverage validation.",
        mapping_source="https://doi.org/10.6028/NIST.CSWP.29",
        mapping_source_version="2.0",
        verified_at=original.framework_mappings[0].verified_at,
    )
    modified_control = ControlContract(
        technical=original.technical,
        framework_mappings=(*original.framework_mappings, extra_mapping),
    )

    with pytest.raises(ValidationError, match="incomplete framework mapping coverage"):
        ControlCatalog(
            catalog_id=catalog.catalog_id,
            version=catalog.version,
            controls=(modified_control, *catalog.controls[1:]),
            framework_catalogs=catalog.framework_catalogs,
        )


def test_catalog_version_is_required_and_semantic() -> None:
    catalog = build_default_control_catalog()

    with pytest.raises(ValidationError):
        ControlCatalog(
            catalog_id=catalog.catalog_id,
            version="2.1",
            controls=catalog.controls,
            framework_catalogs=catalog.framework_catalogs,
        )


def test_s3_900_records_the_completed_versioned_migration() -> None:
    technical = build_default_control_catalog().get("S3-900").technical

    assert any("migrated it from S3-002" in limitation for limitation in technical.limitations)
    assert any("canonical S3-002" in limitation for limitation in technical.limitations)
