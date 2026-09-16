"""Same-scan refinement of incomplete network relationship targets."""

from datetime import UTC, datetime
from uuid import UUID

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipResolution,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceSourceState,
    ResourceEvidenceSubject,
)
from app.collectors.base import (
    CollectionContext,
    RelationshipReference,
    SourceObservation,
    build_source_observation,
)
from app.schemas.inventory import CollectionStatus, CollectorOutcome
from app.schemas.resource import NormalizedResource, ResourceScope
from app.services.inventory_service import _resolve_relationships

SCAN_ID = UUID("cb9f6e31-5508-4bd8-b7e1-a2c216316c78")
COLLECTION_ACCOUNT_ID = "123456789012"
EXTERNAL_ACCOUNT_ID = "210987654321"
REGION = "us-east-1"
COLLECTED_AT = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def _resource(
    *,
    account_id: str,
    resource_type: str,
    aws_resource_id: str,
) -> NormalizedResource:
    return NormalizedResource(
        account_id=account_id,
        service="ec2",
        resource_type=resource_type,
        aws_resource_id=aws_resource_id,
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )


def _observation(
    context: CollectionContext,
    resource: NormalizedResource,
    *,
    collector: str,
    source_api: str,
    identity_authoritative: bool = True,
) -> SourceObservation:
    return build_source_observation(
        context=context,
        contract_key=f"test.{resource.resource_type}",
        contract_version="1.0.0",
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=ResourceEvidenceSubject.for_aws_resource(
            scan_id=context.scan_id,
            aws_account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            aws_resource_id=resource.aws_resource_id,
            scope=resource.scope,
            region=resource.region,
        ),
        evidence_kind=f"test.{resource.resource_type}",
        collector=collector,
        collector_version="1.0.0",
        source_api=source_api,
        cardinality=EvidenceCardinality.SINGLE,
        evidence_reference=(
            f"normalized://test/{resource.resource_type}/"
            f"{resource.account_id}/{resource.aws_resource_id}"
        ),
        evidence_schema=f"test.{resource.resource_type}",
        evidence_schema_version="1.0.0",
        normalized_payload={"resource_id": resource.aws_resource_id},
        state=EvidenceSourceState.PRESENT,
        identity_authoritative=identity_authoritative,
    )


def _fixture() -> tuple[
    CollectionContext,
    NormalizedResource,
    SourceObservation,
    RelationshipReference,
]:
    context = CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=COLLECTION_ACCOUNT_ID,
        region=REGION,
        collected_at=COLLECTED_AT,
    )
    source = _resource(
        account_id=COLLECTION_ACCOUNT_ID,
        resource_type="ec2_instance",
        aws_resource_id="i-network-source",
    )
    source_observation = _observation(
        context,
        source,
        collector="test.instances",
        source_api="ec2:DescribeInstances",
    )
    reference = RelationshipReference(
        relationship_type=RelationshipType.ATTACHED_TO_SECURITY_GROUP,
        source=RelationshipEndpoint.for_aws_resource(
            aws_account_id=source.account_id,
            service=source.service,
            resource_type=source.resource_type,
            aws_resource_id=source.aws_resource_id,
            scope=source.scope,
            region=source.region,
            observed_in_scan_id=context.scan_id,
        ),
        target=UnresolvedRelationshipTarget.for_aws_reference(
            service="ec2",
            resource_type="security_group",
            aws_resource_id="sg-refined",
            scope=ResourceScope.REGIONAL,
            region=REGION,
        ),
        provenance=source_observation.provenance,
        target_collector_name="security_groups",
        target_evidence_kind="ec2.security-group",
    )
    return context, source, source_observation, reference


def _resolve(
    *,
    targets: tuple[NormalizedResource, ...],
    target_observations: tuple[SourceObservation, ...],
):
    context, source, source_observation, reference = _fixture()
    observations = (source_observation, *target_observations)
    return _resolve_relationships(
        context=context,
        resources=(source, *targets),
        collector_outcomes=(
            CollectorOutcome(
                collector_name="security_groups",
                status=CollectionStatus.SUCCEEDED,
            ),
        ),
        source_contracts=tuple(item.contract for item in observations),
        source_outcomes=tuple(item.outcome for item in observations),
        references=(reference,),
    )[0]


def test_refines_partial_target_from_one_same_account_authoritative_observation() -> None:
    context, _, _, _ = _fixture()
    target = _resource(
        account_id=COLLECTION_ACCOUNT_ID,
        resource_type="security_group",
        aws_resource_id="sg-refined",
    )

    relationship = _resolve(
        targets=(target,),
        target_observations=(
            _observation(
                context,
                target,
                collector="test.security-groups",
                source_api="ec2:DescribeSecurityGroups",
            ),
        ),
    )

    assert relationship.resolution is RelationshipResolution.RESOLVED
    assert isinstance(relationship.target, RelationshipEndpoint)
    assert relationship.target.aws_account_id == COLLECTION_ACCOUNT_ID
    assert relationship.target.resource_snapshot_id is not None


def test_refines_partial_target_from_one_external_owner_authoritative_observation() -> None:
    context, _, _, _ = _fixture()
    target = _resource(
        account_id=EXTERNAL_ACCOUNT_ID,
        resource_type="security_group",
        aws_resource_id="sg-refined",
    )

    relationship = _resolve(
        targets=(target,),
        target_observations=(
            _observation(
                context,
                target,
                collector="test.security-groups",
                source_api="ec2:DescribeSecurityGroups",
            ),
        ),
    )

    assert relationship.resolution is RelationshipResolution.RESOLVED
    assert isinstance(relationship.target, RelationshipEndpoint)
    assert relationship.target.aws_account_id == EXTERNAL_ACCOUNT_ID
    assert relationship.target.resource_snapshot_id is not None


def test_matching_resource_without_authoritative_proof_remains_identity_incomplete() -> None:
    context, _, _, _ = _fixture()
    target = _resource(
        account_id=COLLECTION_ACCOUNT_ID,
        resource_type="security_group",
        aws_resource_id="sg-refined",
    )

    relationship = _resolve(
        targets=(target,),
        target_observations=(
            _observation(
                context,
                target,
                collector="test.security-groups",
                source_api="ec2:DescribeSecurityGroups",
                identity_authoritative=False,
            ),
        ),
    )

    assert relationship.resolution is RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
    assert isinstance(relationship.target, UnresolvedRelationshipTarget)
    assert relationship.target.aws_account_id is None
    assert relationship.target.resource_snapshot_id is None


def test_multiple_authoritative_owner_matches_remain_identity_incomplete() -> None:
    context, _, _, _ = _fixture()
    same_account_target = _resource(
        account_id=COLLECTION_ACCOUNT_ID,
        resource_type="security_group",
        aws_resource_id="sg-refined",
    )
    external_target = _resource(
        account_id=EXTERNAL_ACCOUNT_ID,
        resource_type="security_group",
        aws_resource_id="sg-refined",
    )

    relationship = _resolve(
        targets=(same_account_target, external_target),
        target_observations=(
            _observation(
                context,
                same_account_target,
                collector="test.security-groups",
                source_api="ec2:DescribeSecurityGroups",
            ),
            _observation(
                context,
                external_target,
                collector="test.security-groups",
                source_api="ec2:DescribeSecurityGroups",
            ),
        ),
    )

    assert relationship.resolution is RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
    assert isinstance(relationship.target, UnresolvedRelationshipTarget)
    assert relationship.target.aws_account_id is None
    assert relationship.target.resource_snapshot_id is None
