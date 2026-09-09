"""Tests for complete, immutable, conflict-safe catalog persistence."""

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import create_engine, delete, event, func, select, update
from sqlalchemy.orm import Session, sessionmaker

import app.models  # noqa: F401
from app.assessment.controls import ControlCatalog as ControlCatalogContract
from app.assessment.controls import build_default_control_catalog
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
from app.assessment.provenance import control_catalog_sha256
from app.database.base import Base
from app.database.catalogs import (
    CatalogPersistenceError,
    VersionContentConflictError,
    ensure_assessment_profile,
    ensure_control_catalog,
    load_assessment_profile,
)
from app.models.control import (
    Control,
    ControlCatalog,
    ControlFrameworkMapping,
    ControlVersion,
    Framework,
    FrameworkReference,
)
from app.models.profile import PersistedAssessmentProfile


@pytest.fixture
def catalog_sessions(tmp_path: Path) -> Generator[sessionmaker[Session], None, None]:
    engine = create_engine(
        f"sqlite+pysqlite:///{(tmp_path / 'catalogs.sqlite').as_posix()}",
        connect_args={"timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, expire_on_commit=False)
    finally:
        engine.dispose()


def _profile(**updates: object) -> AssessmentProfile:
    content = DEFAULT_ASSESSMENT_PROFILE.model_dump(mode="python")
    content.update(updates)
    content["content_checksum"] = None
    return AssessmentProfile.model_validate(content)


def _catalog(*, version: str | None = None, title: str | None = None) -> ControlCatalogContract:
    content = build_default_control_catalog().model_dump(mode="python")
    if version is not None:
        content["version"] = version
    if title is not None:
        content["controls"][0]["technical"]["title"] = title
    return ControlCatalogContract.model_validate(content)


def _count(session: Session, model: type[Base]) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_profile_preserves_all_policy_and_is_idempotent(catalog_sessions) -> None:
    profile = _profile(
        required_tags=("Owner", "Environment", "DataClassification"),
        stale_key_days=45,
        approved_management_cidrs=("10.0.0.0/8", "192.168.0.0/16"),
        public_ec2_exceptions=("i-00000000000000002", "i-00000000000000001"),
        restricted_data_requires_kms=False,
    )
    reordered = profile.model_copy(update={"required_tags": tuple(reversed(profile.required_tags))})
    with catalog_sessions.begin() as session:
        first = ensure_assessment_profile(session, profile)
        second = ensure_assessment_profile(session, reordered)
        assert first.profile_version_id == second.profile_version_id
        assert first.profile_id == profile.profile_id
        assert first.version == profile.version
        assert first.content_checksum == profile.content_checksum
        assert first.enabled_controls == sorted(profile.enabled_controls)
        assert first.required_tags == sorted(profile.required_tags)
        assert first.stale_key_days == 45
        assert first.approved_management_cidrs == sorted(profile.approved_management_cidrs)
        assert first.public_ec2_exceptions == sorted(profile.public_ec2_exceptions)
        assert first.restricted_data_requires_kms is False
        assert _count(session, PersistedAssessmentProfile) == 1


def test_profile_rejects_changed_content_under_same_version(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
    with catalog_sessions.begin() as session:
        with pytest.raises(VersionContentConflictError, match="assessment profile"):
            ensure_assessment_profile(session, _profile(stale_key_days=30))
        assert _count(session, PersistedAssessmentProfile) == 1


def test_new_profile_versions_coexist(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        first = ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
        second = ensure_assessment_profile(session, _profile(version="2.0.0", stale_key_days=30))
        assert first.profile_version_id != second.profile_version_id
        assert first.stale_key_days == 90
        assert second.stale_key_days == 30
        assert _count(session, PersistedAssessmentProfile) == 2


def test_profile_loader_restores_and_verifies_exact_persisted_content(catalog_sessions) -> None:
    profile = _profile(
        version="1.1.0",
        required_tags=("DataClassification",),
        stale_key_days=120,
    )
    with catalog_sessions.begin() as session:
        ensure_assessment_profile(session, profile)
    with catalog_sessions() as session:
        loaded = load_assessment_profile(
            session,
            profile_id=profile.profile_id,
            version=profile.version,
            expected_checksum=profile.calculate_content_checksum(),
        )

    assert loaded == profile


def test_profile_loader_rejects_scan_checksum_mismatch(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
    with catalog_sessions() as session:
        with pytest.raises(VersionContentConflictError, match="scan provenance"):
            load_assessment_profile(
                session,
                profile_id=DEFAULT_ASSESSMENT_PROFILE.profile_id,
                version=DEFAULT_ASSESSMENT_PROFILE.version,
                expected_checksum="0" * 64,
            )


def test_profile_loader_rejects_corrupt_stored_content(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        record = ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
        profile_version_id = record.profile_version_id
    with catalog_sessions.begin() as session:
        session.execute(
            update(PersistedAssessmentProfile)
            .where(PersistedAssessmentProfile.profile_version_id == profile_version_id)
            .values(stale_key_days=12)
        )
    with catalog_sessions() as session:
        with pytest.raises(CatalogPersistenceError, match="content is invalid"):
            load_assessment_profile(
                session,
                profile_id=DEFAULT_ASSESSMENT_PROFILE.profile_id,
                version=DEFAULT_ASSESSMENT_PROFILE.version,
                expected_checksum=DEFAULT_ASSESSMENT_PROFILE.calculate_content_checksum(),
            )


def test_catalog_persists_technical_contracts_frameworks_and_provenance(catalog_sessions) -> None:
    catalog = build_default_control_catalog()
    with catalog_sessions.begin() as session:
        first, versions = ensure_control_catalog(session, catalog)
        second, repeated_versions = ensure_control_catalog(session, catalog)
        assert first.catalog_id == second.catalog_id
        assert first.content_checksum == control_catalog_sha256(catalog)
        assert set(versions) == {contract.control_id for contract in catalog.controls}
        assert {key: value.control_version_id for key, value in versions.items()} == {
            key: value.control_version_id for key, value in repeated_versions.items()
        }
        assert _count(session, Control) == len(catalog.controls)
        assert _count(session, ControlVersion) == len(catalog.controls)
        assert _count(session, ControlCatalog) == 1
        assert _count(session, Framework) == len(catalog.framework_catalogs)
        assert _count(session, FrameworkReference) == sum(
            len(item.references) for item in catalog.framework_catalogs
        )
        assert _count(session, ControlFrameworkMapping) == sum(
            len(item.framework_mappings) for item in catalog.controls
        )
        for contract in catalog.controls:
            stored = versions[contract.control_id]
            technical = contract.technical.model_dump(mode="json")
            for field in (
                "title",
                "category",
                "resource_type",
                "assessment_type",
                "measure",
                "pass_logic",
                "fail_logic",
                "insufficient_evidence_behavior",
                "not_applicable_logic",
                "severity",
                "impact",
                "remediation_guidance",
            ):
                assert getattr(stored, field) == technical[field]
            assert stored.required_evidence == sorted(
                technical["required_evidence"], key=lambda item: item["fact_path"]
            )
            assert stored.profile_parameters == sorted(technical["profile_parameters"])
            assert stored.limitations == sorted(technical["limitations"])
            assert len(stored.definition_checksum) == 64

        source = catalog.framework_catalogs[0]
        framework = session.scalar(select(Framework))
        assert framework is not None
        assert framework.framework_key == source.framework.framework_id
        assert framework.source == source.framework.source
        assert framework.source_checksum == source.source_manifest.sha256
        assert framework.source_retrieved_at.replace(tzinfo=UTC) == (
            source.source_manifest.retrieved_at.astimezone(UTC)
        )
        reference = session.scalar(
            select(FrameworkReference).where(FrameworkReference.reference_key == "PR.AA-03")
        )
        assert reference is not None
        parent = session.get(FrameworkReference, reference.parent_reference_id)
        assert parent is not None
        assert parent.reference_key == "PR.AA"
        mapping = versions["IAM-001"].framework_mappings[0]
        expected_mapping = catalog.get("IAM-001").framework_mappings[0]
        assert mapping.mapping_rationale == expected_mapping.mapping_rationale
        assert mapping.mapping_source == expected_mapping.mapping_source
        assert mapping.mapping_source_version == expected_mapping.mapping_source_version
        assert mapping.verified_at.replace(tzinfo=UTC) == expected_mapping.verified_at.astimezone(
            UTC
        )
        assert len(mapping.mapping_checksum) == 64


def test_catalog_rejects_changed_content_under_same_version(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        ensure_control_catalog(session, build_default_control_catalog())
    with catalog_sessions.begin() as session:
        with pytest.raises(VersionContentConflictError, match="control catalog"):
            ensure_control_catalog(session, _catalog(title="Changed technical contract"))
        assert _count(session, ControlCatalog) == 1


def test_new_catalog_versions_preserve_old_definitions_and_share_stable_controls(
    catalog_sessions,
) -> None:
    with catalog_sessions.begin() as session:
        first, old_versions = ensure_control_catalog(session, build_default_control_catalog())
        second, new_versions = ensure_control_catalog(
            session, _catalog(version="0.2.2", title="Revised control title")
        )
        assert first.catalog_id != second.catalog_id
        assert _count(session, Control) == 5
        assert _count(session, ControlVersion) == 10
        assert _count(session, Framework) == 1
        assert _count(session, ControlFrameworkMapping) == 10
        changed_key = build_default_control_catalog().controls[0].control_id
        assert old_versions[changed_key].control_id == new_versions[changed_key].control_id
        assert (
            old_versions[changed_key].control_version_id
            != new_versions[changed_key].control_version_id
        )
        assert old_versions[changed_key].title != "Revised control title"
        assert new_versions[changed_key].title == "Revised control title"


def test_framework_version_cannot_silently_replace_reference_content(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        ensure_control_catalog(session, build_default_control_catalog())
    content = _catalog(version="0.2.2").model_dump(mode="python")
    content["framework_catalogs"][0]["references"][0]["description"] = "Changed source text"
    changed = ControlCatalogContract.model_validate(content)
    with catalog_sessions() as session:
        with pytest.raises(VersionContentConflictError, match="reference"):
            ensure_control_catalog(session, changed)
        session.rollback()
    with catalog_sessions() as session:
        assert _count(session, ControlCatalog) == 1


def test_new_framework_versions_coexist_with_historical_mappings(catalog_sessions) -> None:
    original = build_default_control_catalog()
    content = original.model_dump(mode="python")
    content["version"] = "0.2.2"
    for contract in content["controls"]:
        for mapping in contract["framework_mappings"]:
            mapping["framework_version"] = "2.1"
    for framework_catalog in content["framework_catalogs"]:
        framework_catalog["framework"]["version"] = "2.1"
        framework_catalog["source_manifest"]["version"] = "2.1"
        framework_catalog["source_manifest"]["sha256"] = "b" * 64
        for reference in framework_catalog["references"]:
            reference["framework_version"] = "2.1"
        for mapping in framework_catalog["mappings"]:
            mapping["framework_version"] = "2.1"
    revised = ControlCatalogContract.model_validate(content)
    with catalog_sessions.begin() as session:
        _, old_versions = ensure_control_catalog(session, original)
        _, new_versions = ensure_control_catalog(session, revised)
        assert _count(session, Framework) == 2
        assert _count(session, FrameworkReference) == 2 * len(
            original.framework_catalogs[0].references
        )
        old_reference = old_versions["IAM-001"].framework_mappings[0].framework_reference
        new_reference = new_versions["IAM-001"].framework_mappings[0].framework_reference
        assert old_reference.framework.version == "2.0"
        assert new_reference.framework.version == "2.1"
        assert old_reference.framework_reference_id != new_reference.framework_reference_id


def test_inconsistent_duplicate_mapping_metadata_is_rejected_before_writes(
    catalog_sessions,
) -> None:
    content = build_default_control_catalog().model_dump(mode="python")
    content["framework_catalogs"][0]["mappings"][0]["mapping_rationale"] = "Different rationale"
    catalog = ControlCatalogContract.model_validate(content)
    with catalog_sessions.begin() as session:
        with pytest.raises(VersionContentConflictError, match="inconsistent mapping"):
            ensure_control_catalog(session, catalog)
        assert _count(session, ControlCatalog) == 0


def test_existing_profile_fields_are_verified_not_only_its_checksum(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        record = ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
        profile_id = record.profile_version_id
    with catalog_sessions.begin() as session:
        session.execute(
            update(PersistedAssessmentProfile)
            .where(PersistedAssessmentProfile.profile_version_id == profile_id)
            .values(stale_key_days=12)
        )
    with catalog_sessions.begin() as session:
        with pytest.raises(VersionContentConflictError, match="stale_key_days"):
            ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)


def test_existing_catalog_cannot_hide_missing_mapping_rows(catalog_sessions) -> None:
    with catalog_sessions.begin() as session:
        ensure_control_catalog(session, build_default_control_catalog())
        mapping_id = session.scalar(select(ControlFrameworkMapping.mapping_id).limit(1))
        session.execute(
            delete(ControlFrameworkMapping).where(ControlFrameworkMapping.mapping_id == mapping_id)
        )
    with catalog_sessions.begin() as session:
        with pytest.raises(VersionContentConflictError, match="different members"):
            ensure_control_catalog(session, build_default_control_catalog())


def test_helpers_leave_commit_and_rollback_to_the_caller(catalog_sessions) -> None:
    with catalog_sessions() as session:
        ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
        ensure_control_catalog(session, build_default_control_catalog())
        session.rollback()
    with catalog_sessions() as session:
        assert _count(session, PersistedAssessmentProfile) == 0
        assert _count(session, ControlCatalog) == 0
        assert _count(session, Control) == 0


def test_concurrent_identical_seeding_returns_the_same_records(catalog_sessions) -> None:
    barrier = Barrier(2)

    def seed() -> tuple[UUID, UUID, dict[str, UUID]]:
        barrier.wait(timeout=10)
        with catalog_sessions.begin() as session:
            profile = ensure_assessment_profile(session, DEFAULT_ASSESSMENT_PROFILE)
            catalog, versions = ensure_control_catalog(session, build_default_control_catalog())
            return (
                profile.profile_version_id,
                catalog.catalog_id,
                {key: value.control_version_id for key, value in versions.items()},
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first, second = tuple(executor.map(lambda _index: seed(), range(2)))
    assert first == second
    with catalog_sessions() as session:
        assert _count(session, PersistedAssessmentProfile) == 1
        assert _count(session, ControlCatalog) == 1
        assert _count(session, ControlVersion) == 5


def test_concurrent_conflicting_profiles_raise_a_version_conflict_not_integrity_error(
    catalog_sessions,
) -> None:
    barrier = Barrier(2)

    def seed(stale_days: int) -> str:
        barrier.wait(timeout=10)
        try:
            with catalog_sessions.begin() as session:
                ensure_assessment_profile(session, _profile(stale_key_days=stale_days))
        except VersionContentConflictError:
            return "conflict"
        return "inserted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(seed, (30, 60)))
    assert sorted(outcomes) == ["conflict", "inserted"]
    with catalog_sessions() as session:
        assert _count(session, PersistedAssessmentProfile) == 1


def test_equivalent_mapping_timezone_offsets_do_not_change_catalog_identity(
    catalog_sessions,
) -> None:
    content = build_default_control_catalog().model_dump(mode="python")
    instant = datetime.fromisoformat("2026-09-02T19:00:00-05:00")
    for contract in content["controls"]:
        for mapping in contract["framework_mappings"]:
            mapping["verified_at"] = instant
    for framework_catalog in content["framework_catalogs"]:
        for mapping in framework_catalog["mappings"]:
            mapping["verified_at"] = instant
    equivalent = ControlCatalogContract.model_validate(content)
    with catalog_sessions.begin() as session:
        first, _ = ensure_control_catalog(session, build_default_control_catalog())
        second, _ = ensure_control_catalog(session, equivalent)
        assert first.catalog_id == second.catalog_id
