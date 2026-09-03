"""Tests for versioned framework data and mapping provenance."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.assessment.frameworks import (
    NIST_CSF_2_0_DATA_PATH,
    NIST_CSF_2_0_MANIFEST_PATH,
    ControlFrameworkMapping,
    Framework,
    FrameworkCatalog,
    FrameworkDataIntegrityError,
    FrameworkReference,
    FrameworkReferenceLevel,
    FrameworkSourceManifest,
    load_framework_catalog,
    load_nist_csf_2_0_catalog,
)


def make_framework(**overrides: object) -> Framework:
    """Build a representative framework identity."""

    values: dict[str, object] = {
        "framework_id": "nist-csf",
        "name": "NIST Cybersecurity Framework",
        "version": "2.0",
        "source": "https://doi.org/10.6028/NIST.CSWP.29",
    }
    values.update(overrides)
    return Framework.model_validate(values)


def make_manifest(**overrides: object) -> FrameworkSourceManifest:
    """Build representative immutable source provenance."""

    values: dict[str, object] = {
        "source": "https://doi.org/10.6028/NIST.CSWP.29",
        "version": "2.0",
        "retrieved_at": datetime(2026, 9, 3, tzinfo=UTC),
        "sha256": "0" * 64,
    }
    values.update(overrides)
    return FrameworkSourceManifest.model_validate(values)


def make_reference(**overrides: object) -> FrameworkReference:
    """Build a representative Subcategory reference."""

    values: dict[str, object] = {
        "framework_id": "nist-csf",
        "framework_version": "2.0",
        "reference_id": "PR.AA-03",
        "level": FrameworkReferenceLevel.SUBCATEGORY,
        "title": "Authentication",
        "description": "Users, services, and hardware are authenticated",
        "parent_reference_id": "PR.AA",
    }
    values.update(overrides)
    return FrameworkReference.model_validate(values)


def make_mapping(**overrides: object) -> ControlFrameworkMapping:
    """Build a fully traceable internal-control mapping."""

    values: dict[str, object] = {
        "control_id": "IAM-001",
        "framework_id": "nist-csf",
        "framework_version": "2.0",
        "reference_id": "PR.AA-03",
        "mapping_rationale": (
            "Requiring MFA provides additional evidence that a user is authenticated."
        ),
        "mapping_source": "NIST CSF 2.0 Implementation Examples",
        "mapping_source_version": "2.0",
        "verified_at": datetime(2026, 9, 3, tzinfo=UTC),
    }
    values.update(overrides)
    return ControlFrameworkMapping.model_validate(values)


def test_framework_requires_an_explicit_version() -> None:
    """Mappings cannot silently float to an unspecified framework release."""

    with pytest.raises(ValidationError, match="at least 1 character"):
        make_framework(version="")


def test_reference_validates_level_specific_identifier_and_parent() -> None:
    """Subcategory identifiers must name their immediate Category parent."""

    reference = make_reference()

    assert reference.level is FrameworkReferenceLevel.SUBCATEGORY
    assert reference.parent_reference_id == "PR.AA"

    with pytest.raises(ValidationError, match="name their Category parent"):
        make_reference(parent_reference_id="PR.DS")


def test_catalog_validates_complete_parent_chain() -> None:
    """A syntactically valid child cannot reference a missing catalog parent."""

    with pytest.raises(ValidationError, match="has an unknown parent"):
        FrameworkCatalog(
            framework=make_framework(),
            references=(make_reference(),),
            source_manifest=make_manifest(),
        )


def test_catalog_rejects_duplicate_references() -> None:
    """Reference IDs are unique within one framework version."""

    catalog = load_nist_csf_2_0_catalog()

    with pytest.raises(ValidationError, match="duplicate framework reference: PR"):
        FrameworkCatalog(
            framework=catalog.framework,
            references=(*catalog.references, catalog.get_reference("PR")),
            source_manifest=catalog.source_manifest,
        )


def test_catalog_rejects_cross_version_references() -> None:
    """A reference from another framework release cannot enter this catalog."""

    catalog = load_nist_csf_2_0_catalog()
    changed_reference = catalog.get_reference("PR.AA-03").model_copy(
        update={"framework_version": "1.1"}
    )
    references = tuple(
        changed_reference if item.reference_id == "PR.AA-03" else item
        for item in catalog.references
    )

    with pytest.raises(ValidationError, match="wrong framework version"):
        FrameworkCatalog(
            framework=catalog.framework,
            references=references,
            source_manifest=catalog.source_manifest,
        )


def test_mapping_requires_complete_and_timestamped_provenance() -> None:
    """A rationale, versioned source, and aware verification time are mandatory."""

    with pytest.raises(ValidationError, match="must not be blank"):
        make_mapping(mapping_rationale="   ")

    with pytest.raises(ValidationError, match="must include a timezone"):
        make_mapping(verified_at=datetime(2026, 9, 3))


def test_catalog_rejects_duplicate_control_mappings() -> None:
    """The same control-to-outcome assertion may not be recorded twice."""

    mapping = make_mapping()

    with pytest.raises(ValidationError, match="duplicate control mapping"):
        load_nist_csf_2_0_catalog(mappings=(mapping, mapping))


def test_catalog_rejects_unknown_mapping_reference() -> None:
    """Mappings must resolve to a reviewed Subcategory in the catalog."""

    with pytest.raises(ValidationError, match="unknown reference: PR.AA-99"):
        load_nist_csf_2_0_catalog(mappings=(make_mapping(reference_id="PR.AA-99"),))


def test_bundled_nist_subset_has_correct_three_level_hierarchy() -> None:
    """The reviewed CSF subset preserves Function, Category, and Subcategory structure."""

    catalog = load_nist_csf_2_0_catalog(mappings=(make_mapping(),))

    assert catalog.framework.framework_id == "nist-csf"
    assert catalog.framework.version == "2.0"
    assert len(catalog.references) == 9
    assert catalog.get_reference("PR").level is FrameworkReferenceLevel.FUNCTION
    assert catalog.get_reference("PR.AA").parent_reference_id == "PR"
    assert catalog.get_reference("PR.AA-03").parent_reference_id == "PR.AA"
    assert catalog.mappings[0].reference_id == "PR.AA-03"


def test_manifest_is_immutable_and_requires_a_valid_digest() -> None:
    """Reviewed source identity cannot be mutated and hashes must be SHA-256 shaped."""

    manifest = make_manifest()

    with pytest.raises(ValidationError, match="Instance is frozen"):
        manifest.version = "2.1"

    with pytest.raises(ValidationError, match="String should match pattern"):
        make_manifest(sha256="not-a-digest")


def test_loader_rejects_framework_data_changed_without_manifest_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Upstream or local changes cannot silently replace the reviewed framework artifact."""

    original_read_bytes = Path.read_bytes

    def read_changed_data(path: Path) -> bytes:
        data = original_read_bytes(path)
        return data + b"\n" if path == NIST_CSF_2_0_DATA_PATH else data

    monkeypatch.setattr(Path, "read_bytes", read_changed_data)

    with pytest.raises(FrameworkDataIntegrityError, match="checksum mismatch"):
        load_framework_catalog(
            data_path=NIST_CSF_2_0_DATA_PATH,
            manifest_path=NIST_CSF_2_0_MANIFEST_PATH,
        )
