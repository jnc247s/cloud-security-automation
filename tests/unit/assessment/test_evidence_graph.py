"""Tests for the Sprint 5 normalized evidence-graph boundary."""

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.assessment.evidence_graph import (
    EvidenceCardinality,
    EvidenceGraph,
    ResourceOwnerMode,
    ScanSourceContract,
    SourceEvidenceArtifact,
    calculate_evidence_sha256,
)
from app.assessment.identities import inventory_sha256
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipProvenance,
    RelationshipResolution,
    RelationshipType,
    ResourceRelationship,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope

SCAN_ID = UUID("3a5b4b52-91ce-4fd7-a1d4-d7b76b70c8b6")
OTHER_SCAN_ID = UUID("41c276ee-85e0-435b-8fde-4cf930842567")
ACCOUNT_ID = "123456789012"
COLLECTED_AT = datetime(2026, 9, 15, 15, 30, tzinfo=UTC)
REGION = "us-east-1"


def _resource(
    *,
    account_id: str = ACCOUNT_ID,
    resource_type: str = "ec2_instance",
    aws_resource_id: str = "i-0123456789abcdef0",
    region: str = REGION,
) -> NormalizedResource:
    return NormalizedResource(
        account_id=account_id,
        service="ec2",
        resource_type=resource_type,
        aws_resource_id=aws_resource_id,
        scope=ResourceScope.REGIONAL,
        region=region,
        configuration={"state": "running"},
    )


def _endpoint(resource: NormalizedResource, *, scan_id: UUID = SCAN_ID) -> RelationshipEndpoint:
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
        observed_in_scan_id=scan_id,
    )


def _artifact(
    *,
    scan_id: UUID = SCAN_ID,
    account_id: str = ACCOUNT_ID,
    reference: str = "normalized://ec2/us-east-1/instances",
    collected_at: datetime = COLLECTED_AT,
    payload: dict[str, object] | None = None,
) -> SourceEvidenceArtifact:
    return SourceEvidenceArtifact.for_payload(
        scan_id=scan_id,
        collection_account_id=account_id,
        evidence_reference=reference,
        evidence_schema="ec2.instances",
        evidence_schema_version="1.0.0",
        collected_at=collected_at,
        normalized_payload=payload or {"instance_ids": ["i-0123456789abcdef0"]},
    )


def _contract(
    *,
    scan_id: UUID = SCAN_ID,
    account_id: str = ACCOUNT_ID,
    region: str = REGION,
    owner_mode: ResourceOwnerMode = ResourceOwnerMode.COLLECTION_ACCOUNT,
    identity_authoritative: bool = True,
    allows_supplemental_region: bool = False,
) -> ScanSourceContract:
    return ScanSourceContract.for_scan(
        contract_key="ec2.instances",
        contract_version="1.0.0",
        scan_id=scan_id,
        collection_account_id=account_id,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=account_id,
            scope=ResourceScope.REGIONAL,
            region=region,
        ),
        evidence_kind="ec2.instances",
        collector="Ec2InstanceCollector",
        collector_version="1.0.0",
        source_api="ec2:DescribeInstances",
        cardinality=EvidenceCardinality.COLLECTION,
        owner_mode=owner_mode,
        identity_authoritative=identity_authoritative,
        allows_supplemental_region=allows_supplemental_region,
    )


def _outcome(
    contract: ScanSourceContract,
    artifact: SourceEvidenceArtifact,
    *,
    state: EvidenceSourceState = EvidenceSourceState.PRESENT,
    failure_category: EvidenceFailureCategory | None = None,
) -> SourceEvidenceOutcome:
    return SourceEvidenceOutcome.for_observation(
        scan_id=contract.scan_id,
        collection_account_id=contract.collection_account_id,
        phase=contract.phase,
        subject=contract.subject,
        evidence_kind=contract.evidence_kind,
        state=state,
        failure_category=failure_category,
        collector=contract.collector,
        collector_version=contract.collector_version,
        source_api=contract.source_api,
        collected_at=artifact.collected_at,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )


def _resource_contract(
    resource: NormalizedResource,
    *,
    allows_supplemental_region: bool = False,
    owner_mode: ResourceOwnerMode = ResourceOwnerMode.COLLECTION_ACCOUNT,
) -> ScanSourceContract:
    return ScanSourceContract.for_scan(
        contract_key="ec2.instance-details",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=ResourceEvidenceSubject.for_aws_resource(
            scan_id=SCAN_ID,
            aws_account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            aws_resource_id=resource.aws_resource_id,
            scope=resource.scope,
            region=resource.region,
        ),
        evidence_kind="ec2.instance-details",
        collector="Ec2InstanceCollector",
        collector_version="1.0.0",
        source_api="ec2:DescribeInstances",
        cardinality=EvidenceCardinality.SINGLE,
        owner_mode=owner_mode,
        identity_authoritative=True,
        allows_supplemental_region=allows_supplemental_region,
    )


def _relationship(
    source: NormalizedResource,
    target: NormalizedResource,
    artifact: SourceEvidenceArtifact,
) -> ResourceRelationship:
    return ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.USES_VOLUME,
        source=_endpoint(source),
        target=_endpoint(target),
        resolution=RelationshipResolution.RESOLVED,
        provenance=RelationshipProvenance(
            collector="Ec2InstanceCollector",
            collector_version="1.0.0",
            source_api="ec2:DescribeInstances",
            evidence_reference=artifact.evidence_reference,
            collected_at=COLLECTED_AT,
        ),
    )


def _valid_parts() -> tuple[
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
    ResourceRelationship,
    tuple[NormalizedResource, ...],
]:
    source = _resource()
    target = _resource(resource_type="ebs_volume", aws_resource_id="vol-0123456789abcdef0")
    artifact = _artifact()
    contract = _contract()
    outcome = _outcome(contract, artifact)
    relationship = _relationship(source, target, artifact)
    return contract, artifact, outcome, relationship, (source, target)


def _graph(
    *,
    source_contracts: tuple[ScanSourceContract, ...] | None = None,
    artifacts: tuple[SourceEvidenceArtifact, ...] | None = None,
    source_outcomes: tuple[SourceEvidenceOutcome, ...] | None = None,
    relationships: tuple[ResourceRelationship, ...] | None = None,
) -> EvidenceGraph:
    contract, artifact, outcome, relationship, _ = _valid_parts()
    return EvidenceGraph(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        collected_at=COLLECTED_AT,
        source_contracts=source_contracts if source_contracts is not None else (contract,),
        artifacts=artifacts if artifacts is not None else (artifact,),
        source_outcomes=source_outcomes if source_outcomes is not None else (outcome,),
        relationships=relationships if relationships is not None else (relationship,),
    )


def _inventory(
    *,
    graph: EvidenceGraph | None,
    resources: tuple[NormalizedResource, ...] | None = None,
    requested_region: str = REGION,
) -> InventorySnapshot:
    if resources is None:
        *_, resources = _valid_parts()
    return InventorySnapshot(
        scan_id=SCAN_ID,
        account_id=ACCOUNT_ID,
        requested_region=requested_region,
        collected_at=COLLECTED_AT,
        collector_outcomes=(
            CollectorOutcome(
                collector_name="ec2_instances",
                status=CollectionStatus.SUCCEEDED,
            ),
        ),
        resources=resources,
        evidence_graph=graph,
    )


def test_graph_round_trip_is_canonical_and_deeply_immutable() -> None:
    contract, artifact, outcome, relationship, _ = _valid_parts()
    graph = _graph(
        source_contracts=(contract, contract),
        artifacts=(artifact, artifact),
        source_outcomes=(outcome, outcome),
        relationships=(relationship, relationship),
    )

    assert len(graph.source_contracts) == 1
    assert len(graph.artifacts) == 1
    assert len(graph.source_outcomes) == 1
    assert len(graph.relationships) == 1
    assert len(graph.source_manifest_sha256) == 64
    assert EvidenceGraph.model_validate_json(graph.model_dump_json()) == graph

    with pytest.raises(TypeError, match="immutable"):
        artifact.normalized_payload["new"] = True
    with pytest.raises(TypeError):
        artifact.normalized_payload["instance_ids"][0] = "i-forged"


def test_artifact_identity_and_digest_are_deterministic_and_content_bound() -> None:
    first = _artifact(payload={"b": [2, 1], "a": {"enabled": True}})
    reordered = _artifact(payload={"a": {"enabled": True}, "b": [2, 1]})
    changed = _artifact(payload={"a": {"enabled": False}, "b": [2, 1]})

    assert first.artifact_id == reordered.artifact_id == changed.artifact_id
    assert first.evidence_sha256 == reordered.evidence_sha256
    assert first.evidence_sha256 != changed.evidence_sha256
    assert calculate_evidence_sha256(first.normalized_payload) == first.evidence_sha256

    forged = first.model_dump(mode="python")
    forged["evidence_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="does not match normalized payload"):
        SourceEvidenceArtifact.model_validate(forged)


@pytest.mark.parametrize(
    "payload",
    [
        ["not-an-object"],
        {"value": float("nan")},
        {"nested": {"session_token": "must-not-persist"}},
        {"nested": {"SessionToken": "must-not-persist"}},
        {"nested": {"SecretAccessKey": "must-not-persist"}},
        {"nested": {"AWS-Access-Key-ID": "must-not-persist"}},
        {"nested": {"authorization.token": "must-not-persist"}},
    ],
)
def test_artifact_rejects_non_object_non_finite_or_sensitive_payload(payload: object) -> None:
    with pytest.raises((TypeError, ValidationError, ValueError)):
        _artifact(payload=payload)  # type: ignore[arg-type]


def test_artifact_allows_non_secret_access_key_metadata() -> None:
    artifact = _artifact(
        payload={
            "access_key_last_used": "2026-09-15T00:00:00Z",
            "access_key_status": "Inactive",
        }
    )

    assert artifact.normalized_payload["access_key_status"] == "Inactive"


def test_source_contract_is_bound_to_the_declared_outcome_identity() -> None:
    contract = _contract()
    artifact = _artifact()
    outcome = _outcome(contract, artifact)

    assert contract.matches_outcome(outcome)

    values = contract.model_dump(mode="python")
    values["source_outcome_id"] = UUID("3bf10c83-5160-56d0-b7cf-f4a827718767")
    with pytest.raises(ValidationError, match="does not match the declared source contract"):
        ScanSourceContract.model_validate(values)

    with pytest.raises(ValidationError, match="owner_mode does not match"):
        _contract(
            owner_mode=ResourceOwnerMode.EXTERNAL_ACCOUNT,
            identity_authoritative=False,
        )


@pytest.mark.parametrize("missing", ["contract", "outcome", "artifact"])
def test_graph_requires_complete_declarations_outcomes_and_artifacts(missing: str) -> None:
    contract, artifact, outcome, relationship, _ = _valid_parts()
    kwargs = {
        "source_contracts": () if missing == "contract" else (contract,),
        "artifacts": () if missing == "artifact" else (artifact,),
        "source_outcomes": () if missing == "outcome" else (outcome,),
        "relationships": () if missing != "artifact" else (relationship,),
    }

    with pytest.raises(ValidationError):
        _graph(**kwargs)


def test_graph_rejects_conflicting_duplicate_contract_outcome_and_artifact() -> None:
    contract, artifact, outcome, _, _ = _valid_parts()
    conflicting_contract = ScanSourceContract.model_validate(
        {**contract.model_dump(mode="python"), "cardinality": EvidenceCardinality.SINGLE}
    )
    conflicting_outcome = _outcome(
        contract,
        artifact,
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )
    conflicting_artifact = SourceEvidenceArtifact.model_validate(
        {
            **artifact.model_dump(mode="python"),
            "evidence_schema_version": "1.0.1",
        }
    )

    with pytest.raises(ValidationError, match="conflicting duplicate source contract"):
        _graph(source_contracts=(contract, conflicting_contract))
    with pytest.raises(ValidationError, match="conflicting duplicate source outcome"):
        _graph(source_outcomes=(outcome, conflicting_outcome))
    with pytest.raises(ValidationError, match="conflicting duplicate source artifact"):
        _graph(artifacts=(artifact, conflicting_artifact))


def test_graph_binds_scan_account_time_digest_and_relationship_provenance() -> None:
    contract, artifact, outcome, relationship, _ = _valid_parts()

    with pytest.raises(ValidationError, match="graph scan"):
        EvidenceGraph(
            scan_id=OTHER_SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=(contract,),
            artifacts=(artifact,),
            source_outcomes=(outcome,),
            relationships=(relationship,),
        )

    other_time_artifact = _artifact(collected_at=COLLECTED_AT + timedelta(seconds=1))
    with pytest.raises(ValidationError, match="graph collection time"):
        _graph(artifacts=(other_time_artifact,))

    mismatched_outcome = SourceEvidenceOutcome.model_validate(
        {**outcome.model_dump(mode="python"), "evidence_sha256": "0" * 64}
    )
    with pytest.raises(ValidationError, match="digest does not match"):
        _graph(source_outcomes=(mismatched_outcome,))

    unavailable = _outcome(
        contract,
        artifact,
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )
    with pytest.raises(ValidationError, match="relationships require PRESENT"):
        _graph(source_outcomes=(unavailable,))


def test_inventory_graph_requires_exact_top_level_relationship_endpoints() -> None:
    graph = _graph()
    *_, resources = _valid_parts()

    snapshot = _inventory(graph=graph, resources=resources)
    assert snapshot.evidence_graph == graph

    with pytest.raises(ValidationError, match="exact top-level resource snapshot"):
        _inventory(graph=graph, resources=(resources[0],))


def test_inventory_rejects_graph_for_another_scan_account_or_time() -> None:
    graph = _graph()
    mismatched = graph.model_copy(update={"scan_id": OTHER_SCAN_ID})
    with pytest.raises(ValidationError):
        _inventory(graph=mismatched)

    mismatched = graph.model_copy(update={"collection_account_id": "999900001111"})
    with pytest.raises(ValidationError, match="collection account"):
        _inventory(graph=mismatched)

    mismatched = graph.model_copy(update={"collected_at": COLLECTED_AT + timedelta(seconds=1)})
    with pytest.raises(ValidationError, match="collection time"):
        _inventory(graph=mismatched)


@pytest.mark.parametrize("resource_type", ["ec2_instance", "ebs_volume"])
def test_discovery_graph_rejects_known_top_level_resource_with_wrong_scope(
    resource_type: str,
) -> None:
    wrong_scope = NormalizedResource(
        account_id=ACCOUNT_ID,
        service="ec2",
        resource_type=resource_type,
        aws_resource_id=f"wrong-scope-{resource_type}",
        scope=ResourceScope.GLOBAL,
        region=None,
        configuration={"state": "available"},
    )
    contract = _contract()
    artifact = _artifact()
    graph = _graph(
        source_contracts=(contract,),
        artifacts=(artifact,),
        source_outcomes=(_outcome(contract, artifact),),
        relationships=(),
    )

    with pytest.raises(ValidationError, match="top-level resources must use regional scope"):
        _inventory(graph=graph, resources=(wrong_scope,))


def test_regional_discovery_source_must_match_inventory_invocation_region() -> None:
    contract = _contract(region="us-west-2")
    artifact = _artifact()
    graph = _graph(
        source_contracts=(contract,),
        artifacts=(artifact,),
        source_outcomes=(_outcome(contract, artifact),),
        relationships=(),
    )

    with pytest.raises(ValidationError, match="inventory invocation Region"):
        _inventory(graph=graph, requested_region="us-east-1")

    with pytest.raises(ValidationError, match="cannot authorize supplemental Regions"):
        _contract(allows_supplemental_region=True)


def test_graph_enabled_hash_is_deterministic_and_legacy_hash_is_unchanged() -> None:
    legacy = _inventory(graph=None)
    graph_enabled = _inventory(graph=_graph())
    legacy_document = {
        "scan_id": str(legacy.scan_id),
        "account_id": legacy.account_id,
        "requested_region": legacy.requested_region,
        "collected_at": legacy.collected_at.astimezone(UTC).isoformat(),
        "collector_outcomes": {"ec2_instances": "SUCCEEDED"},
        "resources": [
            resource.model_dump(mode="json", exclude={"raw_configuration"})
            for resource in sorted(legacy.resources, key=lambda item: item.identity)
        ],
    }
    expected_legacy = hashlib.sha256(
        json.dumps(
            legacy_document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()

    assert inventory_sha256(legacy) == expected_legacy
    assert "evidence_graph" not in json.loads(legacy.model_dump_json())
    assert inventory_sha256(graph_enabled) != expected_legacy
    assert inventory_sha256(graph_enabled) == inventory_sha256(
        InventorySnapshot.model_validate_json(graph_enabled.model_dump_json())
    )


def test_graph_hash_normalizes_offset_equivalent_provenance_timestamps() -> None:
    graph = _graph()
    western = timezone(timedelta(hours=-5))
    values = graph.model_dump(mode="python")
    values["collected_at"] = graph.collected_at.astimezone(western)
    for document, artifact in zip(values["artifacts"], graph.artifacts, strict=True):
        document["collected_at"] = artifact.collected_at.astimezone(western)
    for document, outcome in zip(values["source_outcomes"], graph.source_outcomes, strict=True):
        document["collected_at"] = outcome.collected_at.astimezone(western)
    for document, relationship in zip(values["relationships"], graph.relationships, strict=True):
        document["provenance"]["collected_at"] = relationship.provenance.collected_at.astimezone(
            western
        )
    offset_graph = EvidenceGraph.model_validate(values)

    assert graph.canonical_document() == offset_graph.canonical_document()
    assert inventory_sha256(_inventory(graph=graph)) == inventory_sha256(
        _inventory(graph=offset_graph)
    )


def test_supplemental_region_requires_explicit_source_contract_permission() -> None:
    west_source = _resource(region="us-west-2")
    artifact = _artifact()
    contract = _resource_contract(west_source)
    outcome = _outcome(contract, artifact)
    graph = _graph(
        source_contracts=(contract,),
        artifacts=(artifact,),
        source_outcomes=(outcome,),
        relationships=(),
    )

    with pytest.raises(ValidationError, match="supplemental-Region"):
        _inventory(graph=graph, resources=(west_source,))

    permitted = _resource_contract(west_source, allows_supplemental_region=True)
    permitted_outcome = _outcome(permitted, artifact)
    permitted_graph = _graph(
        source_contracts=(permitted,),
        artifacts=(artifact,),
        source_outcomes=(permitted_outcome,),
        relationships=(),
    )
    assert (
        _inventory(
            graph=permitted_graph,
            resources=(west_source,),
        ).resource_count
        == 1
    )


def test_external_owner_requires_exact_resource_proof_and_resolved_relationship() -> None:
    finding = NormalizedResource(
        account_id=ACCOUNT_ID,
        service="access-analyzer",
        resource_type="access_analyzer_finding",
        aws_resource_id="finding-123",
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )
    external_bucket = NormalizedResource(
        account_id="999900001111",
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="external-bucket",
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )
    artifact = _artifact(
        reference="normalized://access-analyzer/us-east-1/finding-123",
        payload={"finding_id": "finding-123", "resource_owner": "999900001111"},
    )
    external_subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=SCAN_ID,
        aws_account_id=external_bucket.account_id,
        service=external_bucket.service,
        resource_type=external_bucket.resource_type,
        aws_resource_id=external_bucket.aws_resource_id,
        scope=external_bucket.scope,
        region=external_bucket.region,
    )
    contract = ScanSourceContract.for_scan(
        contract_key="access-analyzer.external-resource",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=external_subject,
        evidence_kind="access-analyzer.external-resource",
        collector="AccessAnalyzerCollector",
        collector_version="1.0.0",
        source_api="access-analyzer:ListFindings",
        cardinality=EvidenceCardinality.SINGLE,
        owner_mode=ResourceOwnerMode.EXTERNAL_ACCOUNT,
        identity_authoritative=True,
    )
    outcome = _outcome(contract, artifact)
    relationship = ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.REFERENCES_RESOURCE,
        source=_endpoint(finding),
        target=_endpoint(external_bucket),
        resolution=RelationshipResolution.RESOLVED,
        provenance=RelationshipProvenance(
            collector=contract.collector,
            collector_version=contract.collector_version,
            source_api=contract.source_api,
            evidence_reference=artifact.evidence_reference,
            collected_at=COLLECTED_AT,
        ),
    )

    without_edge = _graph(
        source_contracts=(contract,),
        artifacts=(artifact,),
        source_outcomes=(outcome,),
        relationships=(),
    )
    with pytest.raises(ValidationError, match="exact resolved relationship"):
        _inventory(graph=without_edge, resources=(finding, external_bucket))

    complete = _graph(
        source_contracts=(contract,),
        artifacts=(artifact,),
        source_outcomes=(outcome,),
        relationships=(relationship,),
    )
    assert _inventory(graph=complete, resources=(finding, external_bucket)).resource_count == 2
