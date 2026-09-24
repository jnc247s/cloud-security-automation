"""Deterministic, AWS-free scan-result fixtures."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.assessment.controls import build_default_control_catalog
from app.assessment.evidence_graph import (
    EvidenceCardinality,
    EvidenceGraph,
    ResourceOwnerMode,
    ScanSourceContract,
    SourceEvidenceArtifact,
)
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
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
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.collectors.base import CollectionContext, build_source_observation
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.resource import NormalizedResource, ResourceScope


def scan_bundle(
    *,
    public_ssh: bool | None = True,
    malformed: bool = False,
    observed_at: datetime = datetime(2026, 9, 3, 12, tzinfo=UTC),
    scan_id: UUID | None = None,
    region: str = "us-east-1",
    collection_status: CollectionStatus = CollectionStatus.SUCCEEDED,
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    profile_values = DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"})
    profile_values.update(profile_id="test-network", enabled_controls=("NET-001",))
    profile = AssessmentProfile.model_validate(profile_values)
    catalog = build_default_control_catalog()
    configuration: dict[str, Any] = {"ingress_rules": [], "egress_rules": []}
    if public_ssh:
        configuration["ingress_rules"] = [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "ipv4_ranges": [{"cidr": "0.0.0.0/0"}],
                "ipv6_ranges": [],
                "prefix_lists": [],
                "referenced_security_groups": [],
            }
        ]
    if malformed:
        configuration = {}
    resources = (
        ()
        if public_ssh is None
        else (
            NormalizedResource(
                account_id="123456789012",
                service="ec2",
                resource_type="security_group",
                aws_resource_id="sg-history",
                name="history-test",
                scope=ResourceScope.REGIONAL,
                region=region,
                tags=tags or {},
                configuration=configuration,
                raw_configuration={"not_persisted": "raw collector details"},
            ),
        )
    )
    outcomes = (CollectorOutcome(collector_name="security_groups", status=collection_status),)
    snapshot = InventorySnapshot(
        scan_id=scan_id or uuid4(),
        account_id="123456789012",
        requested_region=region,
        collected_at=observed_at,
        collector_outcomes=outcomes,
        resources=resources,
    )
    scope = ScanScopeManifestInput(
        aws_account_id=snapshot.account_id,
        requested_regions=(region,),
        successful_regions=(region,) if collection_status is CollectionStatus.SUCCEEDED else (),
        requested_services=("ec2",),
        requested_collectors=("security_groups",),
        collector_outcomes=outcomes,
        resource_types=("security_group",),
        enabled_controls=profile.enabled_controls,
        assessment_profile_id=profile.profile_id,
        assessment_profile_version=profile.version,
        assessment_profile_checksum=profile.calculate_content_checksum(),
        control_catalog_id=catalog.catalog_id,
        control_catalog_version=catalog.version,
    )
    return {
        "snapshot": snapshot,
        "scope": scope,
        "profile": profile,
        "catalog": catalog,
        "assessments": RuleEngine(build_default_registry()).assess(snapshot, profile),
        "started_at": observed_at - timedelta(minutes=1),
        "completed_at": observed_at + timedelta(minutes=1),
        "scanner_version": "test-build",
    }


def graph_scan_bundle(
    *,
    observed_at: datetime = datetime(2026, 9, 15, 12, tzinfo=UTC),
    scan_id: UUID | None = None,
    include_relationship: bool = True,
) -> dict[str, Any]:
    """Return one deterministic graph-enabled scan without contacting AWS."""

    bundle = scan_bundle(
        public_ssh=True,
        observed_at=observed_at,
        scan_id=scan_id,
    )
    snapshot = bundle["snapshot"]
    security_group = snapshot.resources[0]
    instance = NormalizedResource(
        account_id=snapshot.account_id,
        service="ec2",
        resource_type="ec2_instance",
        aws_resource_id="i-evidence-graph",
        name="evidence-graph-instance",
        scope=ResourceScope.REGIONAL,
        region=snapshot.requested_region,
        configuration={"state": "running"},
    )
    evidence_reference = f"normalized://scan/{snapshot.scan_id}/ec2/instances/i-evidence-graph"
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        evidence_reference=evidence_reference,
        evidence_schema="ec2.instance-security-groups",
        evidence_schema_version="1.0.0",
        collected_at=snapshot.collected_at,
        normalized_payload={
            "instance_id": instance.aws_resource_id,
            "security_group_ids": (
                [security_group.aws_resource_id] if include_relationship else []
            ),
        },
    )
    subject = AccountEvidenceSubject(
        aws_account_id=snapshot.account_id,
        scope=ResourceScope.REGIONAL,
        region=snapshot.requested_region,
    )
    source_contract = ScanSourceContract.for_scan(
        contract_key="ec2.instance-security-groups",
        contract_version="1.0.0",
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=subject,
        evidence_kind="ec2.instance-security-groups",
        collector="SecurityGroupCollector",
        collector_version="1.0.0",
        source_api="ec2:DescribeInstances",
        cardinality=EvidenceCardinality.COLLECTION,
        identity_authoritative=True,
    )
    outcome = SourceEvidenceOutcome.for_observation(
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        phase=source_contract.phase,
        subject=source_contract.subject,
        evidence_kind=source_contract.evidence_kind,
        state=EvidenceSourceState.PRESENT,
        failure_category=None,
        collector=source_contract.collector,
        collector_version=source_contract.collector_version,
        source_api=source_contract.source_api,
        collected_at=snapshot.collected_at,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )
    relationships: tuple[ResourceRelationship, ...] = ()
    if include_relationship:
        relationships = (
            ResourceRelationship.for_observation(
                scan_id=snapshot.scan_id,
                collection_account_id=snapshot.account_id,
                relationship_type=RelationshipType.ATTACHED_TO_SECURITY_GROUP,
                source=_endpoint(snapshot.scan_id, instance),
                target=_endpoint(snapshot.scan_id, security_group),
                resolution=RelationshipResolution.RESOLVED,
                provenance=RelationshipProvenance(
                    collector=source_contract.collector,
                    collector_version=source_contract.collector_version,
                    source_api=source_contract.source_api,
                    evidence_reference=artifact.evidence_reference,
                    collected_at=snapshot.collected_at,
                ),
            ),
        )
    evidence_graph = EvidenceGraph(
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        collected_at=snapshot.collected_at,
        source_contracts=(source_contract,),
        artifacts=(artifact,),
        source_outcomes=(outcome,),
        relationships=relationships,
    )
    graph_snapshot = InventorySnapshot.model_validate(
        {
            **snapshot.model_dump(mode="python"),
            "resources": (security_group, instance),
            "evidence_graph": evidence_graph,
        }
    )
    scope = bundle["scope"].model_copy(
        update={"resource_types": ("ec2_instance", "security_group")}
    )
    bundle.update(
        snapshot=graph_snapshot,
        scope=scope,
        assessments=RuleEngine(build_default_registry()).assess(
            graph_snapshot,
            bundle["profile"],
        ),
    )
    return bundle


def _endpoint(scan_id: UUID, resource: NormalizedResource) -> RelationshipEndpoint:
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
        observed_in_scan_id=scan_id,
    )


def scaled_graph_scan_bundle(size: int, *, scan_id: UUID) -> dict[str, Any]:
    """Build a real, persistable generic graph with independent instance/group pairs."""

    bundle = scan_bundle(scan_id=scan_id)
    original = bundle["snapshot"]
    context = CollectionContext(
        scan_id=scan_id,
        collection_account_id=original.account_id,
        region=original.requested_region,
        collected_at=original.collected_at,
    )
    resources = []
    observations = []
    relationships = []
    for index in range(size):
        instance = NormalizedResource(
            account_id=original.account_id,
            service="ec2",
            resource_type="ec2_instance",
            aws_resource_id=f"i-closure-{index:04d}",
            scope=ResourceScope.REGIONAL,
            region=original.requested_region,
            configuration={"state": "running"},
        )
        group = NormalizedResource(
            **{
                **original.resources[0].model_dump(),
                "aws_resource_id": f"sg-closure-{index:04d}",
            }
        )
        resources.extend((instance, group))
        for resource in (instance, group):
            observation = build_source_observation(
                context=context,
                contract_key=f"closure.{resource.resource_type}",
                contract_version="1.0.0",
                phase=EvidenceCollectionPhase.ENRICHMENT,
                subject=ResourceEvidenceSubject.for_aws_resource(
                    scan_id=scan_id,
                    aws_account_id=resource.account_id,
                    service=resource.service,
                    resource_type=resource.resource_type,
                    aws_resource_id=resource.aws_resource_id,
                    scope=resource.scope,
                    region=resource.region,
                ),
                evidence_kind=f"closure.{resource.resource_type}",
                collector="ClosureFixtureCollector",
                collector_version="1.0.0",
                source_api="ec2:DescribeInstances"
                if resource is instance
                else "ec2:DescribeSecurityGroups",
                cardinality=EvidenceCardinality.SINGLE,
                evidence_reference=f"normalized://closure/{resource.aws_resource_id}",
                evidence_schema="closure.resource",
                evidence_schema_version="1.0.0",
                normalized_payload={"resource_id": resource.aws_resource_id},
                state=EvidenceSourceState.PRESENT,
                identity_authoritative=True,
            )
            observations.append(observation)
        relationships.append(
            ResourceRelationship.for_observation(
                scan_id=scan_id,
                collection_account_id=original.account_id,
                relationship_type=RelationshipType.ATTACHED_TO_SECURITY_GROUP,
                source=_endpoint(scan_id, instance),
                target=_endpoint(scan_id, group),
                resolution=RelationshipResolution.RESOLVED,
                provenance=observations[-2].provenance,
            )
        )
    graph = EvidenceGraph(
        scan_id=scan_id,
        collection_account_id=original.account_id,
        collected_at=original.collected_at,
        source_contracts=tuple(item.contract for item in observations),
        artifacts=tuple(item.artifact for item in observations),
        source_outcomes=tuple(item.outcome for item in observations),
        relationships=tuple(relationships),
    )
    snapshot = InventorySnapshot(
        **{
            **original.model_dump(),
            "resources": tuple(resources),
            "evidence_graph": graph,
        }
    )
    bundle.update(
        snapshot=snapshot,
        scope=bundle["scope"].model_copy(
            update={"resource_types": ("ec2_instance", "security_group")}
        ),
        assessments=RuleEngine(build_default_registry()).assess(snapshot, bundle["profile"]),
    )
    return bundle


def exceptional_owner_graph_scan_bundle(
    scenario: str,
    *,
    observed_at: datetime = datetime(2026, 9, 15, 12, tzinfo=UTC),
) -> dict[str, Any]:
    """Return a valid graph bundle for a security-sensitive owner/scope admission path."""

    bundle = graph_scan_bundle(observed_at=observed_at)
    snapshot = bundle["snapshot"]
    graph = snapshot.evidence_graph
    assert graph is not None

    extra_resources: tuple[NormalizedResource, ...]
    extra_relationships: tuple[ResourceRelationship, ...] = ()
    if scenario == "aws-managed":
        subject_resource = NormalizedResource(
            account_id="aws",
            service="iam",
            resource_type="iam_aws_managed_policy",
            aws_resource_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
            scope=ResourceScope.GLOBAL,
            region=None,
            configuration={"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        )
        extra_resources = (subject_resource,)
        owner_mode = ResourceOwnerMode.AWS_MANAGED
        collector_name = "iam_policies"
        collector = "IamPolicyCollector"
        source_api = "iam:GetPolicy"
        evidence_kind = "iam.managed-policy"
        evidence_payload = {"policy_arn": subject_resource.aws_resource_id}
    elif scenario == "external-owner":
        finding = NormalizedResource(
            account_id=snapshot.account_id,
            service="access-analyzer",
            resource_type="access_analyzer_finding",
            aws_resource_id="finding-external-bucket",
            scope=ResourceScope.REGIONAL,
            region=snapshot.requested_region,
            configuration={"status": "ACTIVE"},
        )
        subject_resource = NormalizedResource(
            account_id="210987654321",
            service="s3",
            resource_type="s3_bucket",
            aws_resource_id="external-evidence-bucket",
            scope=ResourceScope.REGIONAL,
            region=snapshot.requested_region,
            configuration={"owner_account_id": "210987654321"},
        )
        extra_resources = (finding, subject_resource)
        owner_mode = ResourceOwnerMode.EXTERNAL_ACCOUNT
        collector_name = "access_analyzer"
        collector = "AccessAnalyzerCollector"
        source_api = "access-analyzer:GetFinding"
        evidence_kind = "access-analyzer.external-resource"
        evidence_payload = {
            "finding_id": finding.aws_resource_id,
            "resource_owner": subject_resource.account_id,
        }
    elif scenario == "supplemental-region":
        subject_resource = NormalizedResource(
            account_id=snapshot.account_id,
            service="ec2",
            resource_type="ec2_instance",
            aws_resource_id="i-supplemental-region",
            scope=ResourceScope.REGIONAL,
            region="us-west-2",
            configuration={"state": "running"},
        )
        extra_resources = (subject_resource,)
        owner_mode = ResourceOwnerMode.COLLECTION_ACCOUNT
        collector_name = "supplemental_instances"
        collector = "SupplementalInstanceCollector"
        source_api = "ec2:DescribeInstances"
        evidence_kind = "ec2.supplemental-instance"
        evidence_payload = {"instance_id": subject_resource.aws_resource_id}
    else:  # pragma: no cover - tests use the closed scenarios above
        raise ValueError("unknown exceptional owner graph scenario")

    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        evidence_reference=f"normalized://scan/{snapshot.scan_id}/{scenario}",
        evidence_schema=evidence_kind,
        evidence_schema_version="1.0.0",
        collected_at=snapshot.collected_at,
        normalized_payload=evidence_payload,
    )
    subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=snapshot.scan_id,
        aws_account_id=subject_resource.account_id,
        service=subject_resource.service,
        resource_type=subject_resource.resource_type,
        aws_resource_id=subject_resource.aws_resource_id,
        scope=subject_resource.scope,
        region=subject_resource.region,
    )
    contract = ScanSourceContract.for_scan(
        contract_key=evidence_kind,
        contract_version="1.0.0",
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=subject,
        evidence_kind=evidence_kind,
        collector=collector,
        collector_version="1.0.0",
        source_api=source_api,
        cardinality=EvidenceCardinality.SINGLE,
        owner_mode=owner_mode,
        identity_authoritative=True,
        allows_supplemental_region=scenario == "supplemental-region",
    )
    outcome = SourceEvidenceOutcome.for_observation(
        scan_id=snapshot.scan_id,
        collection_account_id=snapshot.account_id,
        phase=contract.phase,
        subject=contract.subject,
        evidence_kind=contract.evidence_kind,
        state=EvidenceSourceState.PRESENT,
        failure_category=None,
        collector=contract.collector,
        collector_version=contract.collector_version,
        source_api=contract.source_api,
        collected_at=snapshot.collected_at,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )
    if scenario == "external-owner":
        finding = extra_resources[0]
        extra_relationships = (
            ResourceRelationship.for_observation(
                scan_id=snapshot.scan_id,
                collection_account_id=snapshot.account_id,
                relationship_type=RelationshipType.REFERENCES_RESOURCE,
                source=_endpoint(snapshot.scan_id, finding),
                target=_endpoint(snapshot.scan_id, subject_resource),
                resolution=RelationshipResolution.RESOLVED,
                provenance=RelationshipProvenance(
                    collector=contract.collector,
                    collector_version=contract.collector_version,
                    source_api=contract.source_api,
                    evidence_reference=artifact.evidence_reference,
                    collected_at=snapshot.collected_at,
                ),
            ),
        )

    extended_graph = EvidenceGraph(
        scan_id=graph.scan_id,
        collection_account_id=graph.collection_account_id,
        collected_at=graph.collected_at,
        source_contracts=(*graph.source_contracts, contract),
        artifacts=(*graph.artifacts, artifact),
        source_outcomes=(*graph.source_outcomes, outcome),
        relationships=(*graph.relationships, *extra_relationships),
    )
    collector_outcomes = (
        *snapshot.collector_outcomes,
        CollectorOutcome(collector_name=collector_name, status=CollectionStatus.SUCCEEDED),
    )
    extended_snapshot = InventorySnapshot.model_validate(
        {
            **snapshot.model_dump(mode="python"),
            "collector_outcomes": collector_outcomes,
            "resources": (*snapshot.resources, *extra_resources),
            "evidence_graph": extended_graph,
        }
    )
    scope_values = bundle["scope"].model_dump(mode="python")
    scope_values.update(
        requested_services=tuple(
            sorted(
                {*bundle["scope"].requested_services, *(item.service for item in extra_resources)}
            )
        ),
        requested_collectors=tuple(sorted({*bundle["scope"].requested_collectors, collector_name})),
        collector_outcomes=collector_outcomes,
        resource_types=tuple(
            sorted(
                {*bundle["scope"].resource_types, *(item.resource_type for item in extra_resources)}
            )
        ),
    )
    extended_scope = ScanScopeManifestInput.model_validate(scope_values)
    bundle.update(
        snapshot=extended_snapshot,
        scope=extended_scope,
        assessments=RuleEngine(build_default_registry()).assess(
            extended_snapshot,
            bundle["profile"],
        ),
    )
    return bundle
