"""Idempotent, caller-transaction-owned persistence for immutable assessment inputs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.assessment.controls import (
    ControlCatalog as ControlCatalogContract,
)
from app.assessment.controls import TechnicalControlContract
from app.assessment.frameworks import (
    ControlFrameworkMapping as FrameworkMappingContract,
)
from app.assessment.frameworks import FrameworkCatalog
from app.assessment.profiles import AssessmentProfile
from app.assessment.provenance import control_catalog_sha256
from app.database.base import Base
from app.database.integrity import canonical_json_sha256
from app.models.control import (
    Control,
    ControlCatalog,
    ControlFrameworkMapping,
    ControlVersion,
    Framework,
    FrameworkReference,
)
from app.models.profile import PersistedAssessmentProfile


class VersionContentConflictError(ValueError):
    """An existing immutable version has different content or incomplete stored data."""


class CatalogPersistenceError(RuntimeError):
    """The database cannot safely persist or retrieve a versioned catalog record."""


def ensure_assessment_profile(
    session: Session,
    profile: AssessmentProfile,
) -> PersistedAssessmentProfile:
    """Persist a complete profile version without committing the caller's transaction.

    Existing versions are verified, never updated. On error the caller remains
    responsible for rolling back its transaction.
    """

    validated = AssessmentProfile.model_validate(profile.model_dump(mode="python"))
    content = _profile_content(validated)
    checksum = canonical_json_sha256(content)
    label = f"assessment profile {validated.profile_id} {validated.version}"
    with session.no_autoflush:
        record, _ = _ensure_row(
            session,
            PersistedAssessmentProfile,
            keys={"profile_id": validated.profile_id, "version": validated.version},
            content={
                **{
                    key: value
                    for key, value in content.items()
                    if key not in {"profile_id", "version"}
                },
                "content_checksum": checksum,
            },
            label=label,
        )
    return record


def load_assessment_profile(
    session: Session,
    *,
    profile_id: str,
    version: str,
    expected_checksum: str,
) -> AssessmentProfile:
    """Load and validate the exact immutable profile referenced by a scan."""

    with session.no_autoflush:
        record = session.scalar(
            select(PersistedAssessmentProfile).where(
                PersistedAssessmentProfile.profile_id == profile_id,
                PersistedAssessmentProfile.version == version,
            )
        )
    if record is None:
        raise CatalogPersistenceError("persisted assessment profile could not be loaded")
    if not isinstance(record.content_checksum, str):
        raise CatalogPersistenceError("persisted assessment profile content is invalid")

    try:
        profile = AssessmentProfile(
            profile_id=record.profile_id,
            version=record.version,
            enabled_controls=_stored_profile_values(record.enabled_controls),
            required_tags=_stored_profile_values(record.required_tags),
            stale_key_days=record.stale_key_days,
            approved_management_cidrs=_stored_profile_values(record.approved_management_cidrs),
            public_ec2_exceptions=_stored_profile_values(record.public_ec2_exceptions),
            restricted_data_requires_kms=record.restricted_data_requires_kms,
            content_checksum=record.content_checksum,
        )
    except (TypeError, ValidationError) as error:
        raise CatalogPersistenceError("persisted assessment profile content is invalid") from error
    if profile.content_checksum != expected_checksum:
        raise VersionContentConflictError(
            "persisted assessment profile does not match scan provenance"
        )
    return profile


def ensure_control_catalog(
    session: Session,
    catalog: ControlCatalogContract,
) -> tuple[ControlCatalog, dict[str, ControlVersion]]:
    """Persist exact technical and framework inputs, retaining all older versions.

    PostgreSQL and SQLite inserts use their unique-key conflict handling, then
    verify the winning row. No helper commits or rolls back the caller's work.
    """

    validated = ControlCatalogContract.model_validate(catalog.model_dump(mode="python"))
    label = f"control catalog {validated.catalog_id} {validated.version}"
    _verify_mapping_definitions(validated, label)
    with session.no_autoflush:
        record, inserted = _ensure_row(
            session,
            ControlCatalog,
            keys={"catalog_key": validated.catalog_id, "version": validated.version},
            content={"content_checksum": control_catalog_sha256(validated)},
            label=label,
        )
        expected_keys = {contract.control_id for contract in validated.controls}
        if not inserted:
            stored_keys = set(
                session.scalars(
                    select(Control.control_key)
                    .join(ControlVersion, ControlVersion.control_id == Control.control_id)
                    .where(ControlVersion.catalog_id == record.catalog_id)
                )
            )
            _verify_members(stored_keys, expected_keys, label)

        references: dict[tuple[str, str, str], FrameworkReference] = {}
        for framework_catalog in sorted(
            validated.framework_catalogs,
            key=lambda item: (item.framework.framework_id, item.framework.version),
        ):
            references.update(_ensure_framework(session, framework_catalog))

        versions: dict[str, ControlVersion] = {}
        for contract in sorted(validated.controls, key=lambda item: item.control_id):
            control, _ = _ensure_row(
                session,
                Control,
                keys={"control_key": contract.control_id},
                content={},
                label=f"control {contract.control_id}",
            )
            technical = _technical_content(contract.technical)
            version, version_inserted = _ensure_row(
                session,
                ControlVersion,
                keys={"catalog_id": record.catalog_id, "control_id": control.control_id},
                content={
                    **{key: value for key, value in technical.items() if key != "control_id"},
                    "definition_checksum": canonical_json_sha256(technical),
                },
                label=f"{label}, control {contract.control_id}",
            )
            mappings = tuple(sorted(contract.framework_mappings, key=lambda item: item.identity))
            expected_reference_ids = {
                references[
                    (item.framework_id, item.framework_version, item.reference_id)
                ].framework_reference_id
                for item in mappings
            }
            if not version_inserted:
                stored_reference_ids = set(
                    session.scalars(
                        select(ControlFrameworkMapping.framework_reference_id).where(
                            ControlFrameworkMapping.control_version_id == version.control_version_id
                        )
                    )
                )
                _verify_members(
                    stored_reference_ids,
                    expected_reference_ids,
                    f"{label}, mappings for {contract.control_id}",
                )
            for mapping in mappings:
                reference = references[
                    (mapping.framework_id, mapping.framework_version, mapping.reference_id)
                ]
                _ensure_row(
                    session,
                    ControlFrameworkMapping,
                    keys={
                        "control_version_id": version.control_version_id,
                        "framework_reference_id": reference.framework_reference_id,
                    },
                    content={
                        "mapping_rationale": mapping.mapping_rationale,
                        "mapping_source": mapping.mapping_source,
                        "mapping_source_version": mapping.mapping_source_version,
                        "verified_at": mapping.verified_at.astimezone(UTC),
                        "mapping_checksum": canonical_json_sha256(_mapping_content(mapping)),
                    },
                    label=f"{label}, mapping {mapping.control_id} to {mapping.reference_id}",
                )
            versions[contract.control_id] = version
    return record, versions


def _ensure_framework(
    session: Session,
    catalog: FrameworkCatalog,
) -> dict[tuple[str, str, str], FrameworkReference]:
    framework = catalog.framework
    manifest = catalog.source_manifest
    label = f"framework {framework.framework_id} {framework.version}"
    record, inserted = _ensure_row(
        session,
        Framework,
        keys={"framework_key": framework.framework_id, "version": framework.version},
        content={
            "name": framework.name,
            "source": framework.source,
            "source_retrieved_at": manifest.retrieved_at.astimezone(UTC),
            "source_checksum": manifest.sha256,
        },
        label=label,
    )
    if not inserted:
        stored_keys = set(
            session.scalars(
                select(FrameworkReference.reference_key).where(
                    FrameworkReference.framework_id == record.framework_id
                )
            )
        )
        _verify_members(stored_keys, {item.reference_id for item in catalog.references}, label)

    references_by_key: dict[str, FrameworkReference] = {}
    level_order = {"function": 0, "category": 1, "subcategory": 2}
    for reference in sorted(
        catalog.references,
        key=lambda item: (level_order[item.level.value], item.reference_id),
    ):
        parent_id = (
            references_by_key[reference.parent_reference_id].framework_reference_id
            if reference.parent_reference_id is not None
            else None
        )
        persisted, _ = _ensure_row(
            session,
            FrameworkReference,
            keys={"framework_id": record.framework_id, "reference_key": reference.reference_id},
            content={
                "level": reference.level,
                "title": reference.title,
                "description": reference.description,
                "parent_reference_id": parent_id,
            },
            label=f"{label}, reference {reference.reference_id}",
        )
        references_by_key[reference.reference_id] = persisted
    return {
        (framework.framework_id, framework.version, key): value
        for key, value in references_by_key.items()
    }


def _ensure_row[ModelT: Base](
    session: Session,
    model: type[ModelT],
    *,
    keys: dict[str, Any],
    content: dict[str, Any],
    label: str,
) -> tuple[ModelT, bool]:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgresql_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:
        raise CatalogPersistenceError(f"catalog persistence does not support {dialect}")

    primary_key = next(iter(model.__table__.primary_key.columns))
    statement = (
        insert(model.__table__)
        .values(**keys, **content)
        .on_conflict_do_nothing(index_elements=list(keys))
        .returning(primary_key)
    )
    inserted = session.execute(statement).first() is not None
    record = session.scalar(
        select(model).filter_by(**keys).execution_options(populate_existing=True)
    )
    if record is None:
        raise CatalogPersistenceError(f"could not retrieve {label} after conflict-safe insertion")
    for name, expected in content.items():
        actual = getattr(record, name)
        if isinstance(expected, datetime):
            actual = _utc_datetime(actual)
            expected = _utc_datetime(expected)
        if actual != expected:
            raise VersionContentConflictError(f"{label} already exists with different {name}")
    return record, inserted


def _verify_members(actual: set[Any], expected: set[Any], label: str) -> None:
    if actual != expected:
        raise VersionContentConflictError(f"{label} already exists with different members")


def _verify_mapping_definitions(catalog: ControlCatalogContract, label: str) -> None:
    definitions = {
        mapping.identity: _mapping_content(mapping)
        for contract in catalog.controls
        for mapping in contract.framework_mappings
    }
    for framework_catalog in catalog.framework_catalogs:
        for mapping in framework_catalog.mappings:
            if definitions[mapping.identity] != _mapping_content(mapping):
                raise VersionContentConflictError(
                    f"{label} contains inconsistent mapping definitions"
                )


def _utc_datetime(value: datetime) -> datetime:
    """Restore SQLite's timezone-less UTC round trip before comparing instants."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _profile_content(profile: AssessmentProfile) -> dict[str, Any]:
    content = profile.model_dump(mode="json", exclude={"content_checksum"})
    for key in (
        "enabled_controls",
        "required_tags",
        "approved_management_cidrs",
        "public_ec2_exceptions",
    ):
        content[key] = sorted(content[key])
    return content


def _stored_profile_values(value: Any) -> tuple[Any, ...]:
    """Restore JSON arrays without coercing invalid stored scalar content."""

    if not isinstance(value, list | tuple):
        raise TypeError("stored profile policy collection is not an array")
    return tuple(value)


def _technical_content(control: TechnicalControlContract) -> dict[str, Any]:
    content = control.model_dump(mode="json")
    content["required_evidence"] = sorted(
        content["required_evidence"], key=lambda item: item["fact_path"]
    )
    content["profile_parameters"] = sorted(content["profile_parameters"])
    content["limitations"] = sorted(content["limitations"])
    return content


def _mapping_content(mapping: FrameworkMappingContract) -> dict[str, Any]:
    content = mapping.model_dump(mode="json")
    content["verified_at"] = mapping.verified_at.astimezone(UTC).isoformat()
    return content
