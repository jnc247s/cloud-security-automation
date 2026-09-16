"""Query-service coverage for source outcomes and resource relationships."""

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.source_outcomes import EvidenceCollectionPhase, EvidenceSourceState
from app.database.persistence import persist_scan_result
from app.models.evidence_graph import SourceEvidenceArtifact
from app.services.errors import EntityNotFoundError
from app.services.evidence_graph_service import EvidenceGraphService
from tests.unit.database.conftest import db_session as db_session
from tests.unit.database.conftest import migrated_engine as migrated_engine
from tests.unit.database.factories import graph_scan_bundle


def _persist_graphs(db_session: Session) -> tuple[dict, dict]:
    first = graph_scan_bundle()
    second = graph_scan_bundle(
        observed_at=first["snapshot"].collected_at + timedelta(days=1),
    )
    for bundle in (first, second):
        persist_scan_result(db_session, **bundle)
        db_session.commit()
    return first, second


def test_relationship_service_filters_pages_and_returns_detail(db_session: Session) -> None:
    first, second = _persist_graphs(db_session)
    first_relationship = first["snapshot"].evidence_graph.relationships[0]
    second_relationship = second["snapshot"].evidence_graph.relationships[0]
    service = EvidenceGraphService(db_session)

    page = service.list_relationships(
        collection_account_id=first["snapshot"].account_id,
        relationship_type=RelationshipType.ATTACHED_TO_SECURITY_GROUP,
        resolution=RelationshipResolution.RESOLVED,
        source_resource_id=first_relationship.source.stable_resource_id,
        target_resource_id=first_relationship.target.stable_resource_id,
        limit=1,
        offset=1,
    )
    detail = service.get_relationship(first_relationship.observation_id)

    assert page.total == 2
    assert page.limit == 1
    assert page.offset == 1
    assert page.items == (service.get_relationship(second_relationship.observation_id),)
    assert detail.observation_id == first_relationship.observation_id
    assert detail.relationship_id == first_relationship.relationship_id
    assert (
        detail.source_outcome_id
        == first["snapshot"].evidence_graph.source_outcomes[0].source_outcome_id
    )
    assert detail.provenance.evidence_reference.startswith("normalized://")
    assert service.list_relationships(scan_id=uuid4()).total == 0


def test_source_outcome_service_filters_pages_and_embeds_sanitized_artifact(
    db_session: Session,
) -> None:
    first, second = _persist_graphs(db_session)
    first_outcome = first["snapshot"].evidence_graph.source_outcomes[0]
    service = EvidenceGraphService(db_session)

    page = service.list_source_outcomes(
        collection_account_id=first["snapshot"].account_id,
        contract_key="ec2.instance-security-groups",
        collector="SecurityGroupCollector",
        phase=EvidenceCollectionPhase.DISCOVERY,
        evidence_kind="ec2.instance-security-groups",
        state=EvidenceSourceState.PRESENT,
        limit=1,
        offset=0,
    )
    detail = service.get_source_outcome(first_outcome.source_outcome_id)

    assert page.total == 2
    assert page.items[0].scan_id == first["snapshot"].scan_id
    assert detail.source_outcome_id == first_outcome.source_outcome_id
    assert detail.artifact.evidence_sha256 == first_outcome.evidence_sha256
    assert detail.artifact.normalized_payload == {
        "instance_id": "i-evidence-graph",
        "security_group_ids": ["sg-history"],
    }
    assert service.list_source_outcomes(scan_id=uuid4()).total == 0
    assert second["snapshot"].scan_id != first["snapshot"].scan_id


def test_source_outcome_detail_revalidates_persisted_artifact_integrity(
    db_session: Session,
) -> None:
    first, _ = _persist_graphs(db_session)
    graph = first["snapshot"].evidence_graph
    outcome = graph.source_outcomes[0]
    artifact = db_session.get(SourceEvidenceArtifact, graph.artifacts[0].artifact_id)
    assert artifact is not None
    artifact.evidence_sha256 = "0" * 64

    with db_session.no_autoflush:
        with pytest.raises(ValidationError, match="does not match normalized payload"):
            EvidenceGraphService(db_session).get_source_outcome(outcome.source_outcome_id)
    db_session.rollback()


@pytest.mark.parametrize(
    ("method", "entity"),
    [
        ("get_relationship", "relationship observation"),
        ("get_source_outcome", "source evidence outcome"),
    ],
)
def test_evidence_graph_detail_queries_use_consistent_not_found_errors(
    db_session: Session,
    method: str,
    entity: str,
) -> None:
    with pytest.raises(EntityNotFoundError, match=entity):
        getattr(EvidenceGraphService(db_session), method)(uuid4())
