"""Deterministic operation counts for the generic Sprint 5 graph paths, without timing."""

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import NAMESPACE_URL, uuid5

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.evidence_graph import EvidenceGraph, validate_graph_resources
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipResolution,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import SourceEvidenceOutcome
from app.collectors.base import CollectionContext, RelationshipReference
from app.database.evidence_graph import load_evidence_graph
from app.database.persistence import persist_scan_result
from app.models.evidence_graph import ResourceRelationshipObservation
from app.schemas.resource import NormalizedResource, ResourceScope
from app.services.inventory_service import _resolve_relationships
from tests.unit.database.conftest import db_session as db_session
from tests.unit.database.conftest import migrated_engine as migrated_engine
from tests.unit.database.factories import scaled_graph_scan_bundle

SIZES = (16, 32)


@contextmanager
def _count_field_reads(model: type, field: str) -> Iterator[Counter]:
    """Observe actual model reads; leave validation, lookup, and persistence untouched."""

    counts = Counter()
    original = model.__getattribute__

    def counted(instance, name):
        if name == field:
            counts[field] += 1
        return original(instance, name)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(model, "__getattribute__", counted)
        yield counts


def _bundle(size: int):
    return scaled_graph_scan_bundle(
        size, scan_id=uuid5(NAMESPACE_URL, f"https://example.test/closure/{size}")
    )


def _assert_linear(counts: list[int]) -> None:
    assert counts[0] > 0, "the operation counter must observe production work"
    assert counts[1] <= counts[0] * 2.25, (
        f"doubling resources/sources/relationships exceeded linear lookup work: {counts}"
    )


def test_target_resolution_work_scales_linearly() -> None:
    resource_reads = []
    source_reads = []
    for size in SIZES:
        snapshot = _bundle(size)["snapshot"]
        graph = snapshot.evidence_graph
        references = []
        expected = {}
        for edge in graph.relationships:
            references.append(
                RelationshipReference(
                    relationship_type=edge.relationship_type,
                    source=edge.source,
                    target=UnresolvedRelationshipTarget.for_aws_reference(
                        service=edge.target.service,
                        resource_type=edge.target.resource_type,
                        aws_resource_id=edge.target.aws_resource_id,
                        scope=edge.target.scope,
                        region=edge.target.region,
                    ),
                    provenance=edge.provenance,
                )
            )
            expected[edge.source.stable_resource_id] = edge.target
            # Missing canonical targets also exercise the source-outcome fallback lookup.
            references.append(
                RelationshipReference(
                    relationship_type=RelationshipType.USES_VOLUME,
                    source=edge.source,
                    target=RelationshipEndpoint.for_aws_resource(
                        aws_account_id=snapshot.account_id,
                        service="ec2",
                        resource_type="ebs_volume",
                        aws_resource_id=f"vol-{edge.source.aws_resource_id}",
                        scope=ResourceScope.REGIONAL,
                        region=snapshot.requested_region,
                        observed_in_scan_id=None,
                    ),
                    provenance=edge.provenance,
                    target_evidence_kind="closure.missing-volume",
                )
            )
        with (
            _count_field_reads(NormalizedResource, "identity") as resource_count,
            _count_field_reads(SourceEvidenceOutcome, "evidence_kind") as source_count,
        ):
            resolved = _resolve_relationships(
                context=CollectionContext(
                    scan_id=snapshot.scan_id,
                    collection_account_id=snapshot.account_id,
                    region=snapshot.requested_region,
                    collected_at=snapshot.collected_at,
                ),
                resources=snapshot.resources,
                collector_outcomes=snapshot.collector_outcomes,
                source_contracts=graph.source_contracts,
                source_outcomes=graph.source_outcomes,
                references=tuple(references),
            )
        assert len(resolved) == size * 2
        for edge in resolved:
            if edge.relationship_type is RelationshipType.ATTACHED_TO_SECURITY_GROUP:
                assert edge.resolution is RelationshipResolution.RESOLVED
                assert edge.target == expected[edge.source.stable_resource_id]
            else:
                assert edge.resolution is RelationshipResolution.TARGET_NOT_COLLECTED
                assert edge.target.resource_snapshot_id is None
        resource_reads.append(resource_count["identity"])
        source_reads.append(source_count["evidence_kind"])
    _assert_linear(resource_reads)
    _assert_linear(source_reads)


@pytest.mark.parametrize("boundary", ["graph", "resource-binding"])
def test_relationship_provenance_validation_work_scales_linearly(boundary: str) -> None:
    reads = []
    for size in SIZES:
        snapshot = _bundle(size)["snapshot"]
        graph = snapshot.evidence_graph
        serialized = graph.model_dump_json()
        with _count_field_reads(SourceEvidenceOutcome, "collector") as counts:
            if boundary == "graph":
                reconstructed = EvidenceGraph.model_validate_json(serialized)
            else:
                validate_graph_resources(
                    graph=graph,
                    resources=snapshot.resources,
                    requested_region=snapshot.requested_region,
                )
        if boundary == "graph":
            assert reconstructed == graph
        reads.append(counts["collector"])
    _assert_linear(reads)


def test_persisted_relationship_provenance_lookup_work_scales_linearly(
    db_session: Session,
) -> None:
    reads = []
    for size in SIZES:
        bundle = _bundle(size)
        graph = bundle["snapshot"].evidence_graph
        with _count_field_reads(SourceEvidenceOutcome, "collector") as counts:
            scan = persist_scan_result(db_session, **bundle)
            db_session.commit()
        reads.append(counts["collector"])
        assert load_evidence_graph(db_session, scan.scan_id) == graph
        rows = db_session.scalars(
            select(ResourceRelationshipObservation).where(
                ResourceRelationshipObservation.scan_id == graph.scan_id
            )
        ).all()
        expected = {
            outcome.evidence_reference: outcome.source_outcome_id
            for outcome in graph.source_outcomes
        }
        assert len(rows) == size
        assert {row.observation_id for row in rows} == {
            edge.observation_id for edge in graph.relationships
        }
        assert all(row.source_outcome_id == expected[row.evidence_reference] for row in rows)
    _assert_linear(reads)
