"""Versioned cybersecurity-framework references and mapping provenance.

This module intentionally contains no assessment logic. Framework mappings describe how an
internal technical control supports an external outcome; they never determine PASS or FAIL.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_DATA_DIRECTORY = Path(__file__).with_name("data")
NIST_CSF_2_0_DATA_PATH = _DATA_DIRECTORY / "nist_csf_2_0_core_subset.json"
NIST_CSF_2_0_MANIFEST_PATH = _DATA_DIRECTORY / "nist_csf_2_0_source_manifest.json"


class FrameworkReferenceLevel(StrEnum):
    """Supported levels in the NIST CSF Core hierarchy."""

    FUNCTION = "function"
    CATEGORY = "category"
    SUBCATEGORY = "subcategory"


class Framework(BaseModel):
    """Identity and provenance for one version of an external framework."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    framework_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source: str = Field(min_length=1)

    @field_validator("name", "version", "source")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Reject provenance values that contain only whitespace."""

        if not value.strip():
            raise ValueError("framework values must not be blank")
        return value


class FrameworkReference(BaseModel):
    """A version-bound Function, Category, or Subcategory in a framework hierarchy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    framework_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    framework_version: str = Field(min_length=1)
    reference_id: str = Field(pattern=r"^[A-Z]{2}(?:\.[A-Z]{2}(?:-\d{2})?)?$")
    level: FrameworkReferenceLevel
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    parent_reference_id: str | None = Field(
        default=None,
        pattern=r"^[A-Z]{2}(?:\.[A-Z]{2})?$",
    )

    @field_validator("framework_version", "title", "description")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Reject descriptive fields that contain only whitespace."""

        if not value.strip():
            raise ValueError("framework reference values must not be blank")
        return value

    @model_validator(mode="after")
    def validate_identifier_shape(self) -> Self:
        """Keep identifiers and immediate parents consistent with the declared level."""

        reference_id = self.reference_id
        if self.level is FrameworkReferenceLevel.FUNCTION:
            if "." in reference_id or self.parent_reference_id is not None:
                raise ValueError("function references must use XX and have no parent")
            return self

        if self.level is FrameworkReferenceLevel.CATEGORY:
            expected_parent = reference_id.split(".", maxsplit=1)[0]
            if (
                reference_id.count(".") != 1
                or "-" in reference_id
                or self.parent_reference_id != expected_parent
            ):
                raise ValueError(
                    "category references must use XX.YY and name their Function parent"
                )
            return self

        expected_parent = reference_id.rsplit("-", maxsplit=1)[0]
        if "-" not in reference_id or self.parent_reference_id != expected_parent:
            raise ValueError(
                "subcategory references must use XX.YY-NN and name their Category parent"
            )
        return self


class ControlFrameworkMapping(BaseModel):
    """Auditable relation between an internal control and a framework outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    control_id: str = Field(pattern=r"^[A-Z0-9]+-\d{3}$")
    framework_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    framework_version: str = Field(min_length=1)
    reference_id: str = Field(pattern=r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")
    mapping_rationale: str = Field(min_length=1)
    mapping_source: str = Field(min_length=1)
    mapping_source_version: str = Field(min_length=1)
    verified_at: datetime

    @field_validator(
        "framework_version",
        "mapping_rationale",
        "mapping_source",
        "mapping_source_version",
    )
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Require substantive, explicit provenance metadata."""

        if not value.strip():
            raise ValueError("mapping provenance values must not be blank")
        return value

    @field_validator("verified_at")
    @classmethod
    def require_aware_verification_time(cls, value: datetime) -> datetime:
        """Make provenance timestamps unambiguous across deployments."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verified_at must include a timezone")
        return value

    @property
    def identity(self) -> tuple[str, str, str, str]:
        """Return the stable key used to prevent duplicate mappings."""

        return (
            self.control_id,
            self.framework_id,
            self.framework_version,
            self.reference_id,
        )


class FrameworkSourceManifest(BaseModel):
    """Integrity metadata for the local framework source artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1)
    version: str = Field(min_length=1)
    retrieved_at: datetime
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("source", "version")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        """Reject empty source identity metadata."""

        if not value.strip():
            raise ValueError("source manifest values must not be blank")
        return value

    @field_validator("retrieved_at")
    @classmethod
    def require_aware_retrieval_time(cls, value: datetime) -> datetime:
        """Make the source retrieval instant unambiguous."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retrieved_at must include a timezone")
        return value


class FrameworkCatalog(BaseModel):
    """Validated, immutable framework hierarchy and its control mappings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: Framework
    references: tuple[FrameworkReference, ...] = Field(min_length=1)
    source_manifest: FrameworkSourceManifest
    mappings: tuple[ControlFrameworkMapping, ...] = ()

    @model_validator(mode="after")
    def validate_catalog(self) -> Self:
        """Validate version binding, hierarchy links, and mapping uniqueness."""

        if self.source_manifest.source != self.framework.source:
            raise ValueError("source manifest does not match the framework source")
        if self.source_manifest.version != self.framework.version:
            raise ValueError("source manifest does not match the framework version")

        references_by_id: dict[str, FrameworkReference] = {}
        for reference in self.references:
            if reference.framework_id != self.framework.framework_id:
                raise ValueError("framework reference has the wrong framework_id")
            if reference.framework_version != self.framework.version:
                raise ValueError("framework reference has the wrong framework version")
            if reference.reference_id in references_by_id:
                raise ValueError(f"duplicate framework reference: {reference.reference_id}")
            references_by_id[reference.reference_id] = reference

        for reference in self.references:
            if reference.parent_reference_id is None:
                continue
            parent = references_by_id.get(reference.parent_reference_id)
            if parent is None:
                raise ValueError(
                    f"framework reference {reference.reference_id} has an unknown parent"
                )
            expected_parent_level = (
                FrameworkReferenceLevel.FUNCTION
                if reference.level is FrameworkReferenceLevel.CATEGORY
                else FrameworkReferenceLevel.CATEGORY
            )
            if parent.level is not expected_parent_level:
                raise ValueError(
                    f"framework reference {reference.reference_id} has a parent at the wrong level"
                )

        mapping_identities: set[tuple[str, str, str, str]] = set()
        for mapping in self.mappings:
            if mapping.framework_id != self.framework.framework_id:
                raise ValueError("control mapping has the wrong framework_id")
            if mapping.framework_version != self.framework.version:
                raise ValueError("control mapping has the wrong framework version")
            reference = references_by_id.get(mapping.reference_id)
            if reference is None:
                raise ValueError(
                    f"control mapping has an unknown reference: {mapping.reference_id}"
                )
            if reference.level is not FrameworkReferenceLevel.SUBCATEGORY:
                raise ValueError("controls must map to framework Subcategories")
            if mapping.identity in mapping_identities:
                raise ValueError(
                    f"duplicate control mapping: {mapping.control_id} -> {mapping.reference_id}"
                )
            mapping_identities.add(mapping.identity)

        return self

    def get_reference(self, reference_id: str) -> FrameworkReference:
        """Return one validated reference or raise a descriptive lookup error."""

        for reference in self.references:
            if reference.reference_id == reference_id:
                return reference
        raise KeyError(
            f"unknown {self.framework.framework_id} {self.framework.version} reference: "
            f"{reference_id}"
        )


class FrameworkDataIntegrityError(ValueError):
    """Raised when bundled framework data no longer matches its reviewed manifest."""


class _FrameworkData(BaseModel):
    """Private validation envelope for the bundled JSON document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: Framework
    references: tuple[FrameworkReference, ...]


def load_framework_catalog(
    *,
    data_path: Path = NIST_CSF_2_0_DATA_PATH,
    manifest_path: Path = NIST_CSF_2_0_MANIFEST_PATH,
    mappings: Iterable[ControlFrameworkMapping] = (),
) -> FrameworkCatalog:
    """Load framework data only after verifying its reviewed SHA-256 digest."""

    data_bytes = data_path.read_bytes()
    manifest = FrameworkSourceManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    )
    actual_sha256 = hashlib.sha256(data_bytes).hexdigest()
    if not hmac.compare_digest(actual_sha256, manifest.sha256):
        raise FrameworkDataIntegrityError(
            f"framework data checksum mismatch for {data_path.name}: "
            f"expected {manifest.sha256}, got {actual_sha256}"
        )

    document: dict[str, Any] = json.loads(data_bytes)
    data = _FrameworkData.model_validate(document)
    return FrameworkCatalog(
        framework=data.framework,
        references=data.references,
        source_manifest=manifest,
        mappings=tuple(mappings),
    )


def load_nist_csf_2_0_catalog(
    *, mappings: Iterable[ControlFrameworkMapping] = ()
) -> FrameworkCatalog:
    """Load the reviewed NIST CSF 2.0 subset bundled with the application."""

    return load_framework_catalog(mappings=mappings)
