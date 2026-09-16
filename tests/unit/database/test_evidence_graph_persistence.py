"""End-to-end persistence coverage for the immutable evidence graph."""

from datetime import UTC, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.evidence_graph import EvidenceGraphPersistenceError, load_evidence_graph
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models.evidence_graph import (
    ResourceRelationshipObservation,
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
)
from app.models.scan import ScanScopeManifest
from tests.unit.database.conftest import db_session as db_session
from tests.unit.database.conftest import migrated_engine as migrated_engine
from tests.unit.database.factories import graph_scan_bundle, scan_bundle


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_scan_persistence_round_trips_the_exact_evidence_graph(db_session: Session) -> None:
    bundle = graph_scan_bundle()
    expected = bundle["snapshot"].evidence_graph
    assert expected is not None

    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    reconstructed = load_evidence_graph(db_session, scan.scan_id)
    manifest = db_session.scalars(select(ScanScopeManifest)).one()

    assert reconstructed == expected
    assert manifest.source_manifest_schema_version == expected.source_manifest_schema_version
    assert manifest.source_manifest_checksum == expected.source_manifest_sha256
    assert _count(db_session, ScanSourceContract) == 1
    assert _count(db_session, SourceEvidenceArtifact) == 1
    assert _count(db_session, SourceEvidenceOutcome) == 1
    assert _count(db_session, ResourceRelationshipObservation) == 1


def test_cross_scan_relationship_history_and_complete_disappearance_are_retained(
    db_session: Session,
) -> None:
    first = graph_scan_bundle()
    second = graph_scan_bundle(
        observed_at=first["snapshot"].collected_at + timedelta(days=1),
    )
    disappeared = graph_scan_bundle(
        observed_at=first["snapshot"].collected_at + timedelta(days=2),
        include_relationship=False,
    )
    for bundle in (first, second, disappeared):
        persist_scan_result(db_session, **bundle)
        db_session.commit()

    first_graph = load_evidence_graph(db_session, first["snapshot"].scan_id)
    second_graph = load_evidence_graph(db_session, second["snapshot"].scan_id)
    disappeared_graph = load_evidence_graph(db_session, disappeared["snapshot"].scan_id)
    assert first_graph is not None
    assert second_graph is not None
    assert disappeared_graph is not None

    first_edge = first_graph.relationships[0]
    second_edge = second_graph.relationships[0]
    assert first_edge.relationship_id == second_edge.relationship_id
    assert first_edge.observation_id != second_edge.observation_id
    assert disappeared_graph.relationships == ()
    assert _count(db_session, ResourceRelationshipObservation) == 2
    assert _count(db_session, SourceEvidenceOutcome) == 3


def test_graph_retry_is_idempotent_and_conflicting_retry_is_rejected(
    db_session: Session,
) -> None:
    bundle = graph_scan_bundle()
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()

    assert persist_scan_result(db_session, **bundle).scan_id == scan.scan_id
    db_session.commit()
    assert _count(db_session, ResourceRelationshipObservation) == 1
    assert _count(db_session, SourceEvidenceOutcome) == 1

    conflict = graph_scan_bundle(
        scan_id=bundle["snapshot"].scan_id,
        observed_at=bundle["snapshot"].collected_at,
        include_relationship=False,
    )
    with pytest.raises(ScanPersistenceError, match="different content"):
        persist_scan_result(db_session, **conflict)
    db_session.rollback()
    assert load_evidence_graph(db_session, scan.scan_id) == bundle["snapshot"].evidence_graph


def test_offset_equivalent_graph_retry_is_idempotent(db_session: Session) -> None:
    western = timezone(timedelta(hours=-5))
    first = graph_scan_bundle(
        observed_at=graph_scan_bundle()["snapshot"].collected_at.astimezone(western)
    )
    retry = graph_scan_bundle(
        observed_at=first["snapshot"].collected_at.astimezone(UTC),
        scan_id=first["snapshot"].scan_id,
    )
    retry["started_at"] = first["started_at"]
    retry["completed_at"] = first["completed_at"]

    scan = persist_scan_result(db_session, **first)
    db_session.commit()

    assert persist_scan_result(db_session, **retry).scan_id == scan.scan_id
    db_session.commit()
    assert load_evidence_graph(db_session, scan.scan_id) is not None
    assert _count(db_session, SourceEvidenceOutcome) == 1


def test_caller_rollback_removes_every_evidence_graph_row(db_session: Session) -> None:
    with pytest.raises(RuntimeError), db_session.begin():
        persist_scan_result(db_session, **graph_scan_bundle())
        raise RuntimeError("simulated caller rollback")

    for model in (
        ScanSourceContract,
        SourceEvidenceArtifact,
        SourceEvidenceOutcome,
        ResourceRelationshipObservation,
    ):
        assert _count(db_session, model) == 0


def test_graphless_legacy_scan_does_not_fabricate_graph_records(db_session: Session) -> None:
    bundle = scan_bundle()
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    manifest = db_session.scalars(select(ScanScopeManifest)).one()

    assert load_evidence_graph(db_session, scan.scan_id) is None
    assert manifest.source_manifest_schema_version is None
    assert manifest.source_manifest_checksum is None
    for model in (
        ScanSourceContract,
        SourceEvidenceArtifact,
        SourceEvidenceOutcome,
        ResourceRelationshipObservation,
    ):
        assert _count(db_session, model) == 0


@pytest.mark.parametrize(
    ("field", "tampered_value", "error_match"),
    [
        ("source_manifest_schema_version", "9.9.9", "schema version"),
        ("source_manifest_checksum", "0" * 64, "checksum"),
    ],
)
def test_graph_load_revalidates_the_persisted_source_manifest(
    db_session: Session,
    field: str,
    tampered_value: str,
    error_match: str,
) -> None:
    bundle = graph_scan_bundle()
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    manifest = db_session.scalars(
        select(ScanScopeManifest).where(ScanScopeManifest.scan_id == scan.scan_id)
    ).one()
    setattr(manifest, field, tampered_value)

    # The database layer is append-only. Suppress autoflush here to simulate a
    # corrupt historical row and prove the read boundary rejects it as well.
    with (
        db_session.no_autoflush,
        pytest.raises(
            EvidenceGraphPersistenceError,
            match=error_match,
        ),
    ):
        load_evidence_graph(db_session, scan.scan_id)
    db_session.rollback()
