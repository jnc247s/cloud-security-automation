"""Application service for collecting a normalized AWS resource inventory."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceGraph
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipResolution,
    ResourceRelationship,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    EvidenceFailureCategory,
    EvidenceSourceState,
    SourceEvidenceOutcome,
)
from app.aws.client import AWSClientProvider
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceError,
    CollectorResult,
    RelationshipReference,
    ResourceCollector,
    collection_status_for,
)
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.ec2 import EC2EbsCollector
from app.collectors.iam import IAMUserCollector
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
        S3BucketCollector(client_provider),
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
        resources: list[NormalizedResource] = []
        outcomes: list[CollectorOutcome] = []
        graph_results: list[CollectorResult] = []

        for collector in self.collectors:
            result = self._collect_from(collector, context)
            resources.extend(result.resources)
            outcomes.append(
                CollectorOutcome(
                    collector_name=collector.collector_name,
                    status=result.status,
                )
            )
            if result.source_contracts:
                graph_results.append(result)

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
            if result.status is not collection_status_for(result.source_outcomes):
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
    source_outcomes: tuple[SourceEvidenceOutcome, ...],
    references: tuple[RelationshipReference, ...],
) -> tuple[ResourceRelationship, ...]:
    """Resolve only exact same-scan targets; retain every other reference explicitly."""

    resource_identities = {resource.identity for resource in resources}
    rollups = {outcome.collector_name: outcome.status for outcome in collector_outcomes}
    relationships: list[ResourceRelationship] = []
    for reference in references:
        if isinstance(reference.target, UnresolvedRelationshipTarget):
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
