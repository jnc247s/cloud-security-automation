"""Application service for collecting a normalized AWS resource inventory."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import (
    EvidenceGraph,
    ScanSourceContract,
    SourceEvidenceArtifact,
)
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipResolution,
    ResourceRelationship,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.aws.client import AWSClientProvider
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceError,
    CollectorResult,
    RelationshipReference,
    ResourceCollector,
    graph_collection_status_for,
)
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.ec2 import EC2EbsCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.iam_account import IAMAccountEvidenceCollector
from app.collectors.network import VPCNetworkCollector
from app.collectors.s3 import S3BucketCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.resource import NormalizedResource


def build_default_collectors(
    client_provider: AWSClientProvider,
) -> tuple[ResourceCollector, ...]:
    """Build the accepted inventory collectors without making an AWS API call."""

    return (
        EC2EbsCollector(client_provider),
        SecurityGroupCollector(client_provider),
        VPCNetworkCollector(client_provider),
        S3BucketCollector(client_provider),
        IAMAccountEvidenceCollector(client_provider),
        IAMUserCollector(client_provider),
        CloudTrailCollector(client_provider),
    )


class InventoryService:
    """Run resource collectors and return a deterministic in-memory snapshot."""

    def __init__(
        self,
        client_provider: AWSClientProvider,
        collectors: Sequence[ResourceCollector] | None = None,
    ) -> None:
        self.client_provider = client_provider
        self.collectors = tuple(
            collectors if collectors is not None else build_default_collectors(client_provider)
        )

    def collect(self, *, scan_id: UUID | None = None) -> InventorySnapshot:
        """Collect facts under an ID allocated before any identity or evidence API call."""

        if scan_id is not None and not isinstance(scan_id, UUID):
            raise TypeError("scan_id must be a UUID")
        authoritative_scan_id = scan_id if scan_id is not None else uuid4()
        collected_at = datetime.now(UTC)
        account_id = self.client_provider.account_id
        context = CollectionContext(
            scan_id=authoritative_scan_id,
            collection_account_id=account_id,
            region=self.client_provider.region_name,
            collected_at=collected_at,
        )
        collected_results: list[tuple[str, CollectorResult]] = []

        for collector in self.collectors:
            result = self._collect_from(collector, context)
            collected_results.append((collector.collector_name, result))

        prepared_results = _prune_unadmitted_external_resources(
            context=context,
            collected_results=tuple(collected_results),
        )
        resources = [resource for _, result in prepared_results for resource in result.resources]
        outcomes = [
            CollectorOutcome(
                collector_name=collector_name,
                status=result.status,
            )
            for collector_name, result in prepared_results
        ]
        graph_results = [result for _, result in prepared_results if result.source_contracts]

        resources.sort(key=lambda resource: resource.identity)
        evidence_graph = _build_evidence_graph(
            context=context,
            resources=tuple(resources),
            collector_outcomes=tuple(outcomes),
            graph_results=tuple(graph_results),
        )
        return InventorySnapshot(
            scan_id=authoritative_scan_id,
            account_id=account_id,
            requested_region=self.client_provider.region_name,
            collected_at=collected_at,
            collector_outcomes=tuple(outcomes),
            resources=tuple(resources),
            evidence_graph=evidence_graph,
        )

    @staticmethod
    def _collect_from(
        collector: ResourceCollector,
        context: CollectionContext,
    ) -> CollectorResult:
        try:
            result = collector.collect_with_context(context)
        except (BotoCoreError, ClientError):
            if collector.produces_evidence_graph:
                raise
            return CollectorResult(status=CollectionStatus.FAILED)
        except CollectorEvidenceError:
            if collector.produces_evidence_graph:
                raise
            return CollectorResult(status=CollectionStatus.PARTIAL)
        if collector.produces_evidence_graph:
            if not result.source_contracts:
                raise ValueError("graph-aware collector omitted its declared-source manifest")
            if result.status is not graph_collection_status_for(
                collector_name=collector.collector_name,
                outcomes=result.source_outcomes,
                artifacts=result.artifacts,
            ):
                raise ValueError("graph-aware collector rollup disagrees with source outcomes")
        elif any(
            (
                result.source_contracts,
                result.artifacts,
                result.source_outcomes,
                result.relationships,
            )
        ):
            raise ValueError("legacy collector emitted an undeclared evidence graph fragment")
        return result


def _prune_unadmitted_external_resources(
    *,
    context: CollectionContext,
    collected_results: tuple[tuple[str, CollectorResult], ...],
) -> tuple[tuple[str, CollectorResult], ...]:
    """Retain exceptional owners only when the accepted resolved-edge proof exists.

    An owner observation that cannot be admitted as a top-level resource is removed from the graph
    projection. Its complete discovery artifact records a digest-bound admission gap so the
    resulting partial collector rollup is reconstructable without falsifying AWS source state.
    """

    graph_results = tuple(result for _, result in collected_results if result.source_contracts)
    if not graph_results:
        return collected_results

    resources = tuple(resource for _, result in collected_results for resource in result.resources)
    collector_outcomes = tuple(
        CollectorOutcome(collector_name=name, status=result.status)
        for name, result in collected_results
    )
    source_contracts = tuple(
        contract for result in graph_results for contract in result.source_contracts
    )
    source_outcomes = tuple(
        outcome for result in graph_results for outcome in result.source_outcomes
    )
    references = tuple(reference for result in graph_results for reference in result.relationships)
    candidate_relationships = _resolve_relationships(
        context=context,
        resources=resources,
        collector_outcomes=collector_outcomes,
        source_contracts=source_contracts,
        source_outcomes=source_outcomes,
        references=references,
    )
    authoritative_identities = _authoritative_resource_identities(
        source_contracts=source_contracts,
        source_outcomes=source_outcomes,
    )
    resolved_endpoint_identities: set[tuple[str, str, str, str, str, str]] = set()
    for relationship in candidate_relationships:
        if relationship.resolution is not RelationshipResolution.RESOLVED:
            continue
        if not isinstance(relationship.target, RelationshipEndpoint):  # pragma: no cover
            raise ValueError("resolved relationship target must have a stable identity")
        resolved_endpoint_identities.add(_endpoint_identity(relationship.source))
        resolved_endpoint_identities.add(_endpoint_identity(relationship.target))
    unadmitted_identities = {
        resource.identity
        for resource in resources
        if resource.account_id not in {context.collection_account_id, "aws"}
        and (
            resource.identity not in resolved_endpoint_identities
            or resource.identity not in authoritative_identities
        )
    }
    if not unadmitted_identities:
        return collected_results

    prepared: list[tuple[str, CollectorResult]] = []
    for collector_name, result in collected_results:
        removed_identities = {
            resource.identity
            for resource in result.resources
            if resource.identity in unadmitted_identities
        }
        if not removed_identities:
            prepared.append((collector_name, result))
            continue

        outcomes_by_id = {outcome.source_outcome_id: outcome for outcome in result.source_outcomes}
        removed_outcome_ids = {
            contract.source_outcome_id
            for contract in result.source_contracts
            if isinstance(contract.subject, ResourceEvidenceSubject)
            and _subject_identity(contract.subject) in removed_identities
        }
        removed_references = {
            outcome.evidence_reference
            for outcome in result.source_outcomes
            if outcome.source_outcome_id in removed_outcome_ids
        }
        removed_by_source: dict[tuple[str, str], set[tuple[str, str, str, str, str, str]]] = {}
        for contract in result.source_contracts:
            if contract.source_outcome_id not in removed_outcome_ids:
                continue
            outcome = outcomes_by_id.get(contract.source_outcome_id)
            if outcome is None:  # pragma: no cover - collector graph validation owns this
                raise ValueError("unadmitted resource contract has no source outcome")
            removed_by_source.setdefault((outcome.collector, outcome.source_api), set()).add(
                _subject_identity(contract.subject)
            )

        retained_outcomes = tuple(
            outcome
            for outcome in result.source_outcomes
            if outcome.source_outcome_id not in removed_outcome_ids
        )
        retained_artifacts = tuple(
            artifact
            for artifact in result.artifacts
            if artifact.evidence_reference not in removed_references
        )
        retained_artifacts, retained_outcomes = _record_unadmitted_discovery_resources(
            artifacts=retained_artifacts,
            source_outcomes=retained_outcomes,
            removed_by_source=removed_by_source,
        )
        status = graph_collection_status_for(
            collector_name=collector_name,
            outcomes=retained_outcomes,
            artifacts=retained_artifacts,
        )
        prepared.append(
            (
                collector_name,
                CollectorResult(
                    resources=tuple(
                        resource
                        for resource in result.resources
                        if resource.identity not in removed_identities
                    ),
                    status=status,
                    source_contracts=tuple(
                        contract
                        for contract in result.source_contracts
                        if contract.source_outcome_id not in removed_outcome_ids
                    ),
                    artifacts=retained_artifacts,
                    source_outcomes=retained_outcomes,
                    relationships=tuple(
                        reference
                        for reference in result.relationships
                        if _endpoint_identity(reference.source) not in removed_identities
                        and reference.provenance.evidence_reference not in removed_references
                        and not (
                            isinstance(reference.target, RelationshipEndpoint)
                            and _endpoint_identity(reference.target) in removed_identities
                        )
                    ),
                ),
            )
        )
    for collector_name, result in prepared:
        if result.source_contracts and result.status is not graph_collection_status_for(
            collector_name=collector_name,
            outcomes=result.source_outcomes,
            artifacts=result.artifacts,
        ):
            raise ValueError(
                f"graph-aware collector {collector_name} rollup disagrees with source outcomes"
            )
    return tuple(prepared)


def _record_unadmitted_discovery_resources(
    *,
    artifacts: tuple[SourceEvidenceArtifact, ...],
    source_outcomes: tuple[SourceEvidenceOutcome, ...],
    removed_by_source: dict[tuple[str, str], set[tuple[str, str, str, str, str, str]]],
) -> tuple[tuple[SourceEvidenceArtifact, ...], tuple[SourceEvidenceOutcome, ...]]:
    """Bind admission pruning to the corresponding discovery artifacts and outcomes."""

    artifacts_by_reference = {artifact.evidence_reference: artifact for artifact in artifacts}
    replacement_artifacts: dict[str, SourceEvidenceArtifact] = {}
    replacement_outcomes: dict[UUID, SourceEvidenceOutcome] = {}

    for source_key, identities in removed_by_source.items():
        discoveries = [
            outcome
            for outcome in source_outcomes
            if outcome.phase is EvidenceCollectionPhase.DISCOVERY
            and (outcome.collector, outcome.source_api) == source_key
        ]
        if len(discoveries) != 1:
            raise ValueError("unadmitted resources require exactly one matching discovery source")
        discovery = discoveries[0]
        artifact = artifacts_by_reference.get(discovery.evidence_reference)
        if artifact is None:  # pragma: no cover - collector graph validation owns this
            raise ValueError("unadmitted resource discovery has no source artifact")

        serialized = artifact.model_dump(mode="json")
        normalized_payload = serialized["normalized_payload"]
        if not isinstance(normalized_payload, dict):  # pragma: no cover - model invariant
            raise TypeError("discovery evidence payload must be an object")
        discarded_item_count = normalized_payload.get("discarded_item_count")
        if not isinstance(discarded_item_count, int) or isinstance(discarded_item_count, bool):
            raise TypeError("discovery discarded_item_count must be an integer")

        unadmitted_resources = [
            {
                "account_id": identity[0],
                "service": identity[1],
                "resource_type": identity[2],
                "scope": identity[3],
                "region": identity[4],
                "resource_id": identity[5],
            }
            for identity in sorted(identities)
        ]

        normalized_payload.update(
            {
                "admission_complete": False,
                "unadmitted_resources": unadmitted_resources,
            }
        )
        replacement_artifact = SourceEvidenceArtifact.for_payload(
            scan_id=artifact.scan_id,
            collection_account_id=artifact.collection_account_id,
            evidence_reference=artifact.evidence_reference,
            evidence_schema=artifact.evidence_schema,
            evidence_schema_version=artifact.evidence_schema_version,
            collected_at=artifact.collected_at,
            normalized_payload=normalized_payload,
        )
        replacement_artifacts[artifact.evidence_reference] = replacement_artifact
        replacement_outcomes[discovery.source_outcome_id] = SourceEvidenceOutcome.for_observation(
            scan_id=discovery.scan_id,
            collection_account_id=discovery.collection_account_id,
            phase=discovery.phase,
            subject=discovery.subject,
            evidence_kind=discovery.evidence_kind,
            state=discovery.state,
            failure_category=discovery.failure_category,
            collector=discovery.collector,
            collector_version=discovery.collector_version,
            source_api=discovery.source_api,
            collected_at=discovery.collected_at,
            evidence_reference=replacement_artifact.evidence_reference,
            evidence_sha256=replacement_artifact.evidence_sha256,
        )

    return (
        tuple(
            replacement_artifacts.get(artifact.evidence_reference, artifact)
            for artifact in artifacts
        ),
        tuple(
            replacement_outcomes.get(outcome.source_outcome_id, outcome)
            for outcome in source_outcomes
        ),
    )


def _endpoint_identity(
    endpoint: RelationshipEndpoint,
) -> tuple[str, str, str, str, str, str]:
    return (
        endpoint.aws_account_id,
        endpoint.service,
        endpoint.resource_type,
        endpoint.scope.value,
        endpoint.region or "global",
        endpoint.aws_resource_id,
    )


def _subject_identity(
    subject: ResourceEvidenceSubject,
) -> tuple[str, str, str, str, str, str]:
    return (
        subject.aws_account_id,
        subject.service,
        subject.resource_type,
        subject.scope.value,
        subject.region or "global",
        subject.aws_resource_id,
    )


def _build_evidence_graph(
    *,
    context: CollectionContext,
    resources: tuple[NormalizedResource, ...],
    collector_outcomes: tuple[CollectorOutcome, ...],
    graph_results: tuple[CollectorResult, ...],
) -> EvidenceGraph | None:
    """Compose graph-aware collector fragments and resolve exact observed targets."""

    if not graph_results:
        return None
    source_contracts = tuple(
        contract for result in graph_results for contract in result.source_contracts
    )
    artifacts = tuple(artifact for result in graph_results for artifact in result.artifacts)
    source_outcomes = tuple(
        outcome for result in graph_results for outcome in result.source_outcomes
    )
    references = tuple(
        relationship for result in graph_results for relationship in result.relationships
    )
    relationships = _resolve_relationships(
        context=context,
        resources=resources,
        collector_outcomes=collector_outcomes,
        source_contracts=source_contracts,
        source_outcomes=source_outcomes,
        references=references,
    )
    return EvidenceGraph(
        scan_id=context.scan_id,
        collection_account_id=context.collection_account_id,
        collected_at=context.collected_at,
        source_contracts=source_contracts,
        artifacts=artifacts,
        source_outcomes=source_outcomes,
        relationships=relationships,
    )


def _resolve_relationships(
    *,
    context: CollectionContext,
    resources: tuple[NormalizedResource, ...],
    collector_outcomes: tuple[CollectorOutcome, ...],
    source_contracts: tuple[ScanSourceContract, ...],
    source_outcomes: tuple[SourceEvidenceOutcome, ...],
    references: tuple[RelationshipReference, ...],
) -> tuple[ResourceRelationship, ...]:
    """Resolve only exact same-scan targets; retain every other reference explicitly."""

    resource_identities = {resource.identity for resource in resources}
    authoritative_identities = _authoritative_resource_identities(
        source_contracts=source_contracts,
        source_outcomes=source_outcomes,
    )
    rollups = {outcome.collector_name: outcome.status for outcome in collector_outcomes}
    relationships: list[ResourceRelationship] = []
    for reference in references:
        if isinstance(reference.target, UnresolvedRelationshipTarget):
            target = _refine_unresolved_target(
                context=context,
                target=reference.target,
                resources=resources,
                authoritative_identities=authoritative_identities,
            )
            if target is not None:
                relationships.append(
                    ResourceRelationship.for_observation(
                        scan_id=context.scan_id,
                        collection_account_id=context.collection_account_id,
                        relationship_type=reference.relationship_type,
                        source=reference.source,
                        target=target,
                        resolution=RelationshipResolution.RESOLVED,
                        provenance=reference.provenance,
                    )
                )
                continue
            relationships.append(
                ResourceRelationship.for_observation(
                    scan_id=context.scan_id,
                    collection_account_id=context.collection_account_id,
                    relationship_type=reference.relationship_type,
                    source=reference.source,
                    target=reference.target,
                    resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
                    provenance=reference.provenance,
                )
            )
            continue
        target_identity = (
            reference.target.aws_account_id,
            reference.target.service,
            reference.target.resource_type,
            reference.target.scope.value,
            reference.target.region or "global",
            reference.target.aws_resource_id,
        )
        target = reference.target
        if target_identity in resource_identities:
            target = RelationshipEndpoint.for_aws_resource(
                aws_account_id=target.aws_account_id,
                service=target.service,
                resource_type=target.resource_type,
                aws_resource_id=target.aws_resource_id,
                scope=target.scope,
                region=target.region,
                observed_in_scan_id=context.scan_id,
            )
            resolution = RelationshipResolution.RESOLVED
        else:
            resolution = _unresolved_target_reason(
                reference=reference,
                source_outcomes=source_outcomes,
                collector_rollups=rollups,
            )
        relationships.append(
            ResourceRelationship.for_observation(
                scan_id=context.scan_id,
                collection_account_id=context.collection_account_id,
                relationship_type=reference.relationship_type,
                source=reference.source,
                target=target,
                resolution=resolution,
                provenance=reference.provenance,
            )
        )
    return tuple(relationships)


def _authoritative_resource_identities(
    *,
    source_contracts: tuple[ScanSourceContract, ...],
    source_outcomes: tuple[SourceEvidenceOutcome, ...],
) -> frozenset[tuple[str, str, str, str, str, str]]:
    """Return resource identities backed by matching PRESENT authoritative evidence."""

    outcomes = {outcome.source_outcome_id: outcome for outcome in source_outcomes}
    identities: set[tuple[str, str, str, str, str, str]] = set()
    for contract in source_contracts:
        outcome = outcomes.get(contract.source_outcome_id)
        subject = contract.subject
        if (
            outcome is None
            or outcome.state is not EvidenceSourceState.PRESENT
            or not contract.identity_authoritative
            or not contract.matches_outcome(outcome)
            or not isinstance(subject, ResourceEvidenceSubject)
        ):
            continue
        identities.add(
            (
                subject.aws_account_id,
                subject.service,
                subject.resource_type,
                subject.scope.value,
                subject.region or "global",
                subject.aws_resource_id,
            )
        )
    return frozenset(identities)


def _refine_unresolved_target(
    *,
    context: CollectionContext,
    target: UnresolvedRelationshipTarget,
    resources: tuple[NormalizedResource, ...],
    authoritative_identities: frozenset[tuple[str, str, str, str, str, str]],
) -> RelationshipEndpoint | None:
    """Resolve a partial reference only from one exact authoritative same-scan candidate."""

    candidates: dict[tuple[str, str, str, str, str, str], NormalizedResource] = {}
    for resource in resources:
        if resource.identity not in authoritative_identities:
            continue
        if (
            resource.service != target.service
            or resource.resource_type != target.resource_type
            or resource.aws_resource_id != target.aws_resource_id
        ):
            continue
        if target.aws_account_id is not None and resource.account_id != target.aws_account_id:
            continue
        if target.scope is not None and resource.scope is not target.scope:
            continue
        if target.region is not None and resource.region != target.region:
            continue
        candidates[resource.identity] = resource
    if len(candidates) != 1:
        return None
    resource = next(iter(candidates.values()))
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
        observed_in_scan_id=context.scan_id,
    )


def _unresolved_target_reason(
    *,
    reference: RelationshipReference,
    source_outcomes: tuple[SourceEvidenceOutcome, ...],
    collector_rollups: dict[str, CollectionStatus],
) -> RelationshipResolution:
    if reference.target_evidence_kind is not None:
        matching = tuple(
            outcome
            for outcome in source_outcomes
            if outcome.evidence_kind == reference.target_evidence_kind
        )
        if any(
            outcome.state in {EvidenceSourceState.PRESENT, EvidenceSourceState.EXPECTED_ABSENCE}
            for outcome in matching
        ):
            return RelationshipResolution.TARGET_NOT_COLLECTED
        if any(
            outcome.failure_category is EvidenceFailureCategory.ACCESS_DENIED
            for outcome in matching
        ):
            return RelationshipResolution.TARGET_ACCESS_DENIED
        if matching:
            return RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE
    if reference.target_collector_name is None:
        return RelationshipResolution.TARGET_NOT_COLLECTED
    if reference.target_collector_name not in collector_rollups:
        return RelationshipResolution.TARGET_NOT_COLLECTED
    if collector_rollups.get(reference.target_collector_name) is CollectionStatus.SUCCEEDED:
        return RelationshipResolution.TARGET_NOT_COLLECTED
    return RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE
