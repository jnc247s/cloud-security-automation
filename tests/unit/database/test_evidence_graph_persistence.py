"""End-to-end persistence coverage for the immutable evidence graph."""

from datetime import UTC, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assessment.evidence_graph import EvidenceCardinality, EvidenceGraph
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceSourceState,
)
from app.collectors.base import CollectionContext, build_source_observation
from app.database.evidence_graph import EvidenceGraphPersistenceError, load_evidence_graph
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models.evidence_graph import (
    ResourceRelationshipObservation,
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
)
from app.models.scan import ScanScopeManifest
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.resource import ResourceScope
from tests.unit.database.conftest import db_session as db_session
from tests.unit.database.conftest import migrated_engine as migrated_engine
from tests.unit.database.factories import graph_scan_bundle, scan_bundle


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def _network_graph_bundle() -> dict[str, object]:
    """Extend the generic graph fixture with the exact empty 5B network manifest."""

    bundle = graph_scan_bundle()
    snapshot = bundle["snapshot"]
    graph = snapshot.evidence_graph
    assert graph is not None
    context = CollectionContext(
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        region=snapshot.requested_region,
        collected_at=snapshot.collected_at,
    )
    observations = tuple(
        build_source_observation(
            context=context,
            contract_key=evidence_kind,
            contract_version="1.0.0",
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=AccountEvidenceSubject(
                aws_account_id=snapshot.account_id,
                scope=ResourceScope.REGIONAL,
                region=snapshot.requested_region,
            ),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=collector_version,
            source_api=source_api,
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference=(
                f"normalized://aws/ec2/{snapshot.requested_region}/{segment}/discovery"
            ),
            evidence_schema=evidence_kind,
            evidence_schema_version="1.0.0",
            normalized_payload={
                "account_id": snapshot.account_id,
                "region": snapshot.requested_region,
                "resource_ids": [],
                "resource_count": 0,
                "discarded_item_count": 0,
                "admission_complete": True,
                "unadmitted_resources": [],
                "complete": True,
                "failure_category": None,
            },
            state=EvidenceSourceState.PRESENT,
        )
        for evidence_kind, collector, collector_version, source_api, segment in (
            (
                "ec2.security-groups.discovery",
                "ec2.security-groups",
                "2.0.0",
                "ec2:DescribeSecurityGroups",
                "security-groups",
            ),
            (
                "ec2.vpcs.discovery",
                "ec2.vpcs",
                "1.0.0",
                "ec2:DescribeVpcs",
                "vpcs",
            ),
            (
                "ec2.subnets.discovery",
                "ec2.subnets",
                "1.0.0",
                "ec2:DescribeSubnets",
                "subnets",
            ),
            (
                "ec2.flow-logs.discovery",
                "ec2.flow-logs",
                "1.0.0",
                "ec2:DescribeFlowLogs",
                "flow-logs",
            ),
        )
    )
    extended_graph = EvidenceGraph(
        scan_id=graph.scan_id,
        collection_account_id=graph.collection_account_id,
        collected_at=graph.collected_at,
        source_contracts=(
            *graph.source_contracts,
            *(item.contract for item in observations),
        ),
        artifacts=(*graph.artifacts, *(item.artifact for item in observations)),
        source_outcomes=(
            *graph.source_outcomes,
            *(item.outcome for item in observations),
        ),
        relationships=graph.relationships,
    )
    collector_outcome = CollectorOutcome(
        collector_name="vpc_network_evidence",
        status=CollectionStatus.SUCCEEDED,
    )
    extended_snapshot = InventorySnapshot.model_validate(
        {
            **snapshot.model_dump(mode="python"),
            "collector_outcomes": (*snapshot.collector_outcomes, collector_outcome),
            "evidence_graph": extended_graph,
        }
    )
    scope = bundle["scope"]
    extended_scope = ScanScopeManifestInput.model_validate(
        {
            **scope.model_dump(mode="python"),
            "requested_collectors": (
                *scope.requested_collectors,
                collector_outcome.collector_name,
            ),
            "collector_outcomes": (*scope.collector_outcomes, collector_outcome),
            "resource_types": (
                *scope.resource_types,
                "vpc",
                "subnet",
                "vpc_flow_log",
            ),
        }
    )
    bundle.update(
        snapshot=extended_snapshot,
        scope=extended_scope,
        assessments=RuleEngine(build_default_registry()).assess(
            extended_snapshot,
            bundle["profile"],
        ),
    )
    return bundle


def _replace_graph(bundle: dict[str, object], graph: EvidenceGraph) -> None:
    snapshot = bundle["snapshot"]
    replacement = InventorySnapshot.model_validate(
        {**snapshot.model_dump(mode="python"), "evidence_graph": graph}
    )
    bundle["snapshot"] = replacement
    bundle["assessments"] = RuleEngine(build_default_registry()).assess(
        replacement,
        bundle["profile"],
    )


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


@pytest.mark.parametrize(
    "removed_kinds",
    [
        frozenset({"ec2.subnets.discovery"}),
        frozenset(
            {
                "ec2.vpcs.discovery",
                "ec2.subnets.discovery",
                "ec2.flow-logs.discovery",
            }
        ),
    ],
)
def test_write_rejects_an_incomplete_5b_discovery_manifest(
    db_session: Session,
    removed_kinds: frozenset[str],
) -> None:
    bundle = _network_graph_bundle()
    graph = bundle["snapshot"].evidence_graph
    assert graph is not None
    removed_outcome_ids = {
        contract.source_outcome_id
        for contract in graph.source_contracts
        if contract.evidence_kind in removed_kinds
    }
    removed_references = {
        outcome.evidence_reference
        for outcome in graph.source_outcomes
        if outcome.source_outcome_id in removed_outcome_ids
    }
    incomplete_graph = EvidenceGraph(
        scan_id=graph.scan_id,
        collection_account_id=graph.collection_account_id,
        collected_at=graph.collected_at,
        source_contracts=tuple(
            item
            for item in graph.source_contracts
            if item.source_outcome_id not in removed_outcome_ids
        ),
        artifacts=tuple(
            item for item in graph.artifacts if item.evidence_reference not in removed_references
        ),
        source_outcomes=tuple(
            item
            for item in graph.source_outcomes
            if item.source_outcome_id not in removed_outcome_ids
        ),
        relationships=graph.relationships,
    )
    _replace_graph(bundle, incomplete_graph)

    with pytest.raises(
        ScanPersistenceError,
        match="evidence graph cannot reconstruct collector coverage",
    ):
        persist_scan_result(db_session, **bundle)


def test_write_rejects_graph_sources_omitted_from_collector_scope(
    db_session: Session,
) -> None:
    bundle = _network_graph_bundle()
    snapshot = bundle["snapshot"]
    scope = bundle["scope"]
    retained_outcomes = tuple(
        item
        for item in snapshot.collector_outcomes
        if item.collector_name != "vpc_network_evidence"
    )
    replacement_snapshot = InventorySnapshot.model_validate(
        {
            **snapshot.model_dump(mode="python"),
            "collector_outcomes": retained_outcomes,
        }
    )
    replacement_scope = ScanScopeManifestInput.model_validate(
        {
            **scope.model_dump(mode="python"),
            "requested_collectors": tuple(
                item for item in scope.requested_collectors if item != "vpc_network_evidence"
            ),
            "collector_outcomes": retained_outcomes,
        }
    )
    bundle.update(
        snapshot=replacement_snapshot,
        scope=replacement_scope,
        assessments=RuleEngine(build_default_registry()).assess(
            replacement_snapshot,
            bundle["profile"],
        ),
    )

    with pytest.raises(
        ScanPersistenceError,
        match="graph source outcomes require matching requested collectors",
    ):
        persist_scan_result(db_session, **bundle)


@pytest.mark.parametrize(
    ("remove_requested", "remove_outcome", "expected_message"),
    (
        (True, False, "persisted collector scope is inconsistent"),
        (False, True, "persisted collector scope is inconsistent"),
        (True, True, "graph source outcomes have no collector coverage"),
    ),
)
def test_graph_load_rejects_source_collector_omitted_from_persisted_scope(
    db_session: Session,
    *,
    remove_requested: bool,
    remove_outcome: bool,
    expected_message: str,
) -> None:
    bundle = _network_graph_bundle()
    scan = persist_scan_result(db_session, **bundle)
    db_session.commit()
    manifest = db_session.scalars(
        select(ScanScopeManifest).where(ScanScopeManifest.scan_id == scan.scan_id)
    ).one()
    if remove_requested:
        manifest.requested_collectors = [
            item for item in manifest.requested_collectors if item != "vpc_network_evidence"
        ]
    if remove_outcome:
        manifest.collector_outcomes = {
            key: value
            for key, value in manifest.collector_outcomes.items()
            if key != "vpc_network_evidence"
        }

    with (
        db_session.no_autoflush,
        pytest.raises(
            EvidenceGraphPersistenceError,
            match=expected_message,
        ),
    ):
        load_evidence_graph(db_session, scan.scan_id)
    db_session.rollback()


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
