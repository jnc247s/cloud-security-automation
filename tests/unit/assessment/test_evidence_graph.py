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
    reconstruct_s3_bucket_region_evidence,
)
from app.assessment.identities import inventory_sha256
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipProvenance,
    RelationshipResolution,
    RelationshipType,
    ResourceRelationship,
    UnresolvedRelationshipTarget,
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


def _access_analyzer_contract(
    *,
    region: str,
    allows_supplemental_region: bool,
) -> ScanSourceContract:
    return ScanSourceContract.for_scan(
        contract_key="access-analyzer.analyzers.discovery",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=ACCOUNT_ID,
            scope=ResourceScope.REGIONAL,
            region=region,
        ),
        evidence_kind="access-analyzer.analyzers.discovery",
        collector="access-analyzer.analyzers",
        collector_version="1.0.0",
        source_api="access-analyzer:ListAnalyzers",
        cardinality=EvidenceCardinality.COLLECTION,
        allows_supplemental_region=allows_supplemental_region,
    )


def _access_analyzer_artifact(region: str) -> SourceEvidenceArtifact:
    return SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference=f"normalized://access-analyzer/{region}/analyzers",
        evidence_schema="access-analyzer.analyzers.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={"region": region},
    )


def _s3_bucket(*, region: str) -> NormalizedResource:
    return NormalizedResource(
        account_id=ACCOUNT_ID,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=f"bucket-{region}",
        scope=ResourceScope.REGIONAL,
        region=region,
    )


def _empty_s3_discovery() -> tuple[
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
]:
    subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    contract = ScanSourceContract.for_scan(
        contract_key="s3.buckets.discovery",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=subject,
        evidence_kind="s3.buckets.discovery",
        collector="s3.buckets",
        collector_version="1.0.0",
        source_api="s3:ListAllMyBuckets",
        cardinality=EvidenceCardinality.COLLECTION,
    )
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/empty-buckets",
        evidence_schema="s3.buckets.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "buckets": [],
            "bucket_names": [],
            "resource_count": 0,
            "discarded_item_count": 0,
            "complete": True,
            "failure_category": None,
        },
    )
    return contract, artifact, _outcome(contract, artifact)


def _s3_account_public_access_block() -> tuple[
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
]:
    subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    contract = ScanSourceContract.for_scan(
        contract_key="s3.account-public-access-block",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=subject,
        evidence_kind="s3.account-public-access-block",
        collector="s3.account-public-access-block",
        collector_version="1.0.0",
        source_api="s3:GetAccountPublicAccessBlock",
        cardinality=EvidenceCardinality.SINGLE,
    )
    block = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/public-access-block",
        evidence_schema="s3.account-public-access-block",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "configured": True,
            "public_access_block": block,
            "complete": True,
            "expected_absence": False,
            "failure_category": None,
        },
    )
    return contract, artifact, _outcome(contract, artifact)


def _legacy_encryption_projection(value: dict[str, object]) -> dict[str, object]:
    rules: list[dict[str, object]] = []
    for normalized_rule in value["rules"]:
        if not isinstance(normalized_rule, dict):  # pragma: no cover - fixture invariant
            raise TypeError("fixture encryption rule must be a mapping")
        legacy_rule: dict[str, object] = {}
        algorithm = normalized_rule["sse_algorithm"]
        reference = normalized_rule["kms_key_reference"]
        if algorithm is not None:
            defaults = {"SSEAlgorithm": algorithm}
            if reference is not None:
                defaults["KMSMasterKeyID"] = reference
            legacy_rule["ApplyServerSideEncryptionByDefault"] = defaults
        if normalized_rule["bucket_key_enabled"] is not None:
            legacy_rule["BucketKeyEnabled"] = normalized_rule["bucket_key_enabled"]
        blocked_types = normalized_rule["blocked_encryption_types"]
        if blocked_types:
            legacy_rule["BlockedEncryptionTypes"] = {"EncryptionType": blocked_types}
        rules.append(legacy_rule)
    return {"Rules": rules}


def _complete_s3_manifest_parts(
    *,
    bucket_names: tuple[str, ...] = (),
    region: str = REGION,
    encryption_values: dict[str, dict[str, object]] | None = None,
) -> tuple[
    tuple[ScanSourceContract, ...],
    tuple[SourceEvidenceArtifact, ...],
    tuple[SourceEvidenceOutcome, ...],
]:
    """Build the exact live-reachable S3 source family used by graph contract tests."""

    account_subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    discovery_contract = ScanSourceContract.for_scan(
        contract_key="s3.buckets.discovery",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=account_subject,
        evidence_kind="s3.buckets.discovery",
        collector="s3.buckets",
        collector_version="1.0.0",
        source_api="s3:ListAllMyBuckets",
        cardinality=EvidenceCardinality.COLLECTION,
    )
    discovery_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/complete-buckets",
        evidence_schema="s3.buckets.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "buckets": [
                {
                    "bucket_name": bucket_name,
                    "bucket_arn": f"arn:aws:s3:::{bucket_name}",
                    "creation_date": None,
                    "list_bucket_region": region,
                }
                for bucket_name in sorted(bucket_names)
            ],
            "bucket_names": sorted(bucket_names),
            "resource_count": len(bucket_names),
            "discarded_item_count": 0,
            "complete": True,
            "failure_category": None,
        },
    )
    contracts = [discovery_contract]
    artifacts = [discovery_artifact]
    outcomes = [_outcome(discovery_contract, discovery_artifact)]
    account_contract, account_artifact, account_outcome = _s3_account_public_access_block()
    contracts.append(account_contract)
    artifacts.append(account_artifact)
    outcomes.append(account_outcome)

    default_encryption: dict[str, object] = {
        "rules": [
            {
                "sse_algorithm": "AES256",
                "kms_key_reference": None,
                "kms_reference_explicit": False,
                "key_management": "S3_MANAGED",
                "bucket_key_enabled": None,
                "blocked_encryption_types": [],
            }
        ]
    }
    source_definitions: dict[
        str,
        tuple[str, EvidenceSourceState, object, object],
    ] = {
        "s3.bucket-acl": (
            "s3:GetBucketAcl",
            EvidenceSourceState.PRESENT,
            {"owner": {"id": "owner-id", "display_name": None}, "grants": []},
            None,
        ),
        "s3.bucket-ownership-controls": (
            "s3:GetBucketOwnershipControls",
            EvidenceSourceState.EXPECTED_ABSENCE,
            None,
            None,
        ),
        "s3.bucket-policy": (
            "s3:GetBucketPolicy",
            EvidenceSourceState.EXPECTED_ABSENCE,
            None,
            None,
        ),
        "s3.bucket-policy-status": (
            "s3:GetBucketPolicyStatus",
            EvidenceSourceState.EXPECTED_ABSENCE,
            {"policy_present": False, "is_public": False},
            None,
        ),
        "s3.bucket-public-access-block": (
            "s3:GetBucketPublicAccessBlock",
            EvidenceSourceState.EXPECTED_ABSENCE,
            {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            None,
        ),
        "s3.bucket-tags": (
            "s3:GetBucketTagging",
            EvidenceSourceState.EXPECTED_ABSENCE,
            [],
            None,
        ),
        "s3.bucket-versioning": (
            "s3:GetBucketVersioning",
            EvidenceSourceState.EXPECTED_ABSENCE,
            {"status": None, "mfa_delete": None},
            None,
        ),
    }
    for bucket_name in sorted(bucket_names):
        subject = ResourceEvidenceSubject.for_aws_resource(
            scan_id=SCAN_ID,
            aws_account_id=ACCOUNT_ID,
            service="s3",
            resource_type="s3_bucket",
            aws_resource_id=bucket_name,
            scope=ResourceScope.REGIONAL,
            region=region,
        )
        location_contract = ScanSourceContract.for_scan(
            contract_key="s3.bucket-location",
            contract_version="1.0.0",
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=subject,
            evidence_kind="s3.bucket-location",
            collector="s3.bucket-location",
            collector_version="1.0.0",
            source_api="s3:GetBucketLocation",
            cardinality=EvidenceCardinality.SINGLE,
            identity_authoritative=True,
        )
        location_artifact = SourceEvidenceArtifact.for_payload(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            evidence_reference=f"normalized://s3/{bucket_name}/location",
            evidence_schema="s3.bucket-location",
            evidence_schema_version="1.0.0",
            collected_at=COLLECTED_AT,
            normalized_payload={
                "account_id": ACCOUNT_ID,
                "bucket_name": bucket_name,
                "bucket_arn": f"arn:aws:s3:::{bucket_name}",
                "list_bucket_region": region,
                "legacy_bucket_region": region,
                "location_constraint": None if region == "us-east-1" else region,
                "bucket_region": region,
                "resource_not_found": False,
                "complete": True,
                "failure_category": None,
            },
        )
        contracts.append(location_contract)
        artifacts.append(location_artifact)
        outcomes.append(_outcome(location_contract, location_artifact))

        encryption = (encryption_values or {}).get(bucket_name, default_encryption)
        definitions = {
            **source_definitions,
            "s3.bucket-encryption": (
                "s3:GetEncryptionConfiguration",
                EvidenceSourceState.PRESENT,
                encryption,
                _legacy_encryption_projection(encryption),
            ),
        }
        for evidence_kind, (source_api, state, value, legacy_projection) in definitions.items():
            contract = ScanSourceContract.for_scan(
                contract_key=evidence_kind,
                contract_version="1.0.0",
                scan_id=SCAN_ID,
                collection_account_id=ACCOUNT_ID,
                phase=EvidenceCollectionPhase.ENRICHMENT,
                subject=subject,
                evidence_kind=evidence_kind,
                collector=evidence_kind,
                collector_version="1.0.0",
                source_api=source_api,
                cardinality=EvidenceCardinality.SINGLE,
            )
            artifact = SourceEvidenceArtifact.for_payload(
                scan_id=SCAN_ID,
                collection_account_id=ACCOUNT_ID,
                evidence_reference=f"normalized://s3/{bucket_name}/{evidence_kind}",
                evidence_schema=evidence_kind,
                evidence_schema_version="1.0.0",
                collected_at=COLLECTED_AT,
                normalized_payload={
                    "account_id": ACCOUNT_ID,
                    "bucket_name": bucket_name,
                    "bucket_arn": f"arn:aws:s3:::{bucket_name}",
                    "bucket_region": region,
                    "value": value,
                    "legacy_projection": legacy_projection,
                    "complete": True,
                    "expected_absence": state is EvidenceSourceState.EXPECTED_ABSENCE,
                    "failure_category": None,
                },
            )
            contracts.append(contract)
            artifacts.append(artifact)
            outcomes.append(_outcome(contract, artifact, state=state))
    return tuple(contracts), tuple(artifacts), tuple(outcomes)


def _failed_s3_location(
    bucket: NormalizedResource,
) -> tuple[ScanSourceContract, SourceEvidenceArtifact, SourceEvidenceOutcome]:
    digest = hashlib.sha256(bucket.aws_resource_id.encode()).hexdigest()
    evidence_kind = f"s3.bucket-location.{digest}"
    subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    contract = ScanSourceContract.for_scan(
        contract_key=evidence_kind,
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=subject,
        evidence_kind=evidence_kind,
        collector="s3.bucket-location",
        collector_version="1.0.0",
        source_api="s3:GetBucketLocation",
        cardinality=EvidenceCardinality.SINGLE,
    )
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference=f"normalized://s3/{bucket.aws_resource_id}/location",
        evidence_schema="s3.bucket-location",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "bucket_name": bucket.aws_resource_id,
            "bucket_arn": f"arn:aws:s3:::{bucket.aws_resource_id}",
            "list_bucket_region": bucket.region,
            "legacy_bucket_region": bucket.region,
            "location_constraint": None,
            "bucket_region": None,
            "resource_not_found": False,
            "complete": False,
            "failure_category": "ACCESS_DENIED",
        },
    )
    outcome = _outcome(
        contract,
        artifact,
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )
    return contract, artifact, outcome


def _s3_kms_graph_parts(
    *,
    bucket_names: tuple[str, ...] = ("bucket-a", "bucket-b"),
    lookup_present: bool = True,
    kms_references: tuple[str, ...] = ("alias/example",),
) -> tuple[
    tuple[ScanSourceContract, ...],
    tuple[SourceEvidenceArtifact, ...],
    tuple[SourceEvidenceOutcome, ...],
    tuple[ResourceRelationship, ...],
]:
    encryption_value = {
        "rules": [
            {
                "sse_algorithm": "aws:kms",
                "kms_key_reference": kms_reference,
                "kms_reference_explicit": True,
                "key_management": "EXPLICIT_KMS_REFERENCE",
                "bucket_key_enabled": None,
                "blocked_encryption_types": [],
            }
            for kms_reference in sorted(kms_references)
        ]
    }
    base_contracts, base_artifacts, base_outcomes = _complete_s3_manifest_parts(
        bucket_names=bucket_names,
        encryption_values={bucket_name: encryption_value for bucket_name in bucket_names},
    )
    contracts = list(base_contracts)
    artifacts = list(base_artifacts)
    outcomes = list(base_outcomes)
    encryption_parts: list[
        tuple[ResourceEvidenceSubject, SourceEvidenceArtifact, SourceEvidenceOutcome]
    ] = []
    if not lookup_present and len(kms_references) != 1:
        raise ValueError("the failed-lookup fixture supports one reference")
    artifacts_by_reference = {item.evidence_reference: item for item in artifacts}
    for outcome in outcomes:
        if outcome.collector != "s3.bucket-encryption":
            continue
        if not isinstance(outcome.subject, ResourceEvidenceSubject):  # pragma: no cover
            raise TypeError("fixture encryption source must have a resource subject")
        encryption_parts.append(
            (
                outcome.subject,
                artifacts_by_reference[outcome.evidence_reference],
                outcome,
            )
        )

    key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/key-123"
    if lookup_present:
        kms_subject = ResourceEvidenceSubject.for_aws_resource(
            scan_id=SCAN_ID,
            aws_account_id=ACCOUNT_ID,
            service="kms",
            resource_type="kms_key",
            aws_resource_id=key_arn,
            scope=ResourceScope.REGIONAL,
            region=REGION,
        )
    else:
        kms_subject = encryption_parts[0][0]
    for kms_reference in kms_references:
        kms_kind = "kms.key." + hashlib.sha256(f"{REGION}\0{kms_reference}".encode()).hexdigest()
        kms_contract = ScanSourceContract.for_scan(
            contract_key=kms_kind,
            contract_version="1.0.0",
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=kms_subject,
            evidence_kind=kms_kind,
            collector="kms.keys",
            collector_version="1.0.0",
            source_api="kms:DescribeKey",
            cardinality=EvidenceCardinality.SINGLE,
            identity_authoritative=lookup_present,
        )
        kms_artifact = SourceEvidenceArtifact.for_payload(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            evidence_reference=f"normalized://kms/{REGION}/{kms_kind}",
            evidence_schema="kms.key",
            evidence_schema_version="1.0.0",
            collected_at=COLLECTED_AT,
            normalized_payload={
                "region": REGION,
                "supplied_reference": kms_reference,
                "source_bucket_names": sorted(bucket_names),
                "key": (
                    {
                        "aws_account_id": ACCOUNT_ID,
                        "region": REGION,
                        "key_id": "key-123",
                        "arn": key_arn,
                        "key_manager": "CUSTOMER",
                        "enabled": None,
                        "multi_region": None,
                        "creation_date": None,
                        "key_state": None,
                        "origin": None,
                        "key_usage": None,
                        "key_spec": None,
                    }
                    if lookup_present
                    else None
                ),
                "complete": lookup_present,
                "failure_category": None if lookup_present else "ACCESS_DENIED",
            },
        )
        kms_outcome = _outcome(
            kms_contract,
            kms_artifact,
            state=(
                EvidenceSourceState.PRESENT if lookup_present else EvidenceSourceState.UNAVAILABLE
            ),
            failure_category=(None if lookup_present else EvidenceFailureCategory.ACCESS_DENIED),
        )
        contracts.append(kms_contract)
        artifacts.append(kms_artifact)
        outcomes.append(kms_outcome)

    relationships: list[ResourceRelationship] = []
    for bucket_subject, encryption_artifact, encryption_outcome in encryption_parts:
        source = RelationshipEndpoint.for_aws_resource(
            aws_account_id=bucket_subject.aws_account_id,
            service=bucket_subject.service,
            resource_type=bucket_subject.resource_type,
            aws_resource_id=bucket_subject.aws_resource_id,
            scope=bucket_subject.scope,
            region=bucket_subject.region,
            observed_in_scan_id=SCAN_ID,
        )
        if lookup_present:
            target: RelationshipEndpoint | UnresolvedRelationshipTarget = (
                RelationshipEndpoint.for_aws_resource(
                    aws_account_id=ACCOUNT_ID,
                    service="kms",
                    resource_type="kms_key",
                    aws_resource_id=key_arn,
                    scope=ResourceScope.REGIONAL,
                    region=REGION,
                    observed_in_scan_id=SCAN_ID,
                )
            )
            resolution = RelationshipResolution.RESOLVED
        else:
            target = UnresolvedRelationshipTarget.for_aws_reference(
                service="kms",
                resource_type="kms_key",
                aws_resource_id=kms_references[0],
                scope=ResourceScope.REGIONAL,
                region=REGION,
            )
            resolution = RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
        relationships.append(
            ResourceRelationship.for_observation(
                scan_id=SCAN_ID,
                collection_account_id=ACCOUNT_ID,
                relationship_type=RelationshipType.ENCRYPTED_WITH,
                source=source,
                target=target,
                resolution=resolution,
                provenance=RelationshipProvenance(
                    collector=encryption_outcome.collector,
                    collector_version=encryption_outcome.collector_version,
                    source_api=encryption_outcome.source_api,
                    evidence_reference=encryption_artifact.evidence_reference,
                    collected_at=COLLECTED_AT,
                ),
            )
        )
    return tuple(contracts), tuple(artifacts), tuple(outcomes), tuple(relationships)


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


def _rebind_graph_artifact(
    *,
    artifacts: tuple[SourceEvidenceArtifact, ...],
    outcomes: tuple[SourceEvidenceOutcome, ...],
    evidence_kind: str,
    payload: dict[str, object],
) -> tuple[tuple[SourceEvidenceArtifact, ...], tuple[SourceEvidenceOutcome, ...]]:
    outcome = next(item for item in outcomes if item.evidence_kind == evidence_kind)
    artifact = next(
        item for item in artifacts if item.evidence_reference == outcome.evidence_reference
    )
    rebound_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=artifact.scan_id,
        collection_account_id=artifact.collection_account_id,
        evidence_reference=artifact.evidence_reference,
        evidence_schema=artifact.evidence_schema,
        evidence_schema_version=artifact.evidence_schema_version,
        collected_at=artifact.collected_at,
        normalized_payload=payload,
    )
    rebound_outcome = outcome.model_copy(
        update={"evidence_sha256": rebound_artifact.evidence_sha256}
    )
    return (
        tuple(rebound_artifact if item is artifact else item for item in artifacts),
        tuple(rebound_outcome if item is outcome else item for item in outcomes),
    )


def _rebind_graph_source(
    *,
    artifacts: tuple[SourceEvidenceArtifact, ...],
    outcomes: tuple[SourceEvidenceOutcome, ...],
    evidence_kind: str,
    payload: dict[str, object],
    state: EvidenceSourceState,
    failure_category: EvidenceFailureCategory | None = None,
) -> tuple[tuple[SourceEvidenceArtifact, ...], tuple[SourceEvidenceOutcome, ...]]:
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind=evidence_kind,
        payload=payload,
    )
    rebound = next(item for item in rebound_outcomes if item.evidence_kind == evidence_kind)
    restated = rebound.model_copy(
        update={
            "state": state,
            "failure_category": failure_category,
        }
    )
    return (
        rebound_artifacts,
        tuple(restated if item is rebound else item for item in rebound_outcomes),
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


def _cloudtrail_source(
    *,
    evidence_kind: str,
    collector: str,
    source_api: str,
    subject: AccountEvidenceSubject | ResourceEvidenceSubject,
    payload: dict[str, object],
    index: int,
    identity_authoritative: bool = False,
) -> tuple[ScanSourceContract, SourceEvidenceArtifact, SourceEvidenceOutcome]:
    phase = (
        EvidenceCollectionPhase.DISCOVERY
        if isinstance(subject, AccountEvidenceSubject)
        else EvidenceCollectionPhase.ENRICHMENT
    )
    contract = ScanSourceContract.for_scan(
        contract_key=evidence_kind,
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=phase,
        subject=subject,
        evidence_kind=evidence_kind,
        collector=collector,
        collector_version="1.0.0",
        source_api=source_api,
        cardinality=(
            EvidenceCardinality.COLLECTION
            if phase is EvidenceCollectionPhase.DISCOVERY
            else EvidenceCardinality.SINGLE
        ),
        owner_mode=(
            ResourceOwnerMode.EXTERNAL_ACCOUNT
            if isinstance(subject, ResourceEvidenceSubject) and subject.aws_account_id != ACCOUNT_ID
            else ResourceOwnerMode.COLLECTION_ACCOUNT
        ),
        identity_authoritative=identity_authoritative,
    )
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference=f"normalized://cloudtrail/source/{index}",
        evidence_schema=evidence_kind,
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload=payload,
    )
    return contract, artifact, _outcome(contract, artifact)


def _cloudtrail_graph_parts(
    *,
    owner_account_id: str = ACCOUNT_ID,
    home_region: str = "us-west-2",
    invocation_region: str = REGION,
    destination_region: str | None = None,
    kms_key_resource_id: str = "12345678-1234-1234-1234-123456789012",
    with_destinations: bool = False,
) -> tuple[
    EvidenceGraph,
    NormalizedResource,
    tuple[ScanSourceContract, ...],
    tuple[SourceEvidenceArtifact, ...],
    tuple[SourceEvidenceOutcome, ...],
]:
    trail_name = "audit-trail"
    trail_arn = f"arn:aws:cloudtrail:{home_region}:{owner_account_id}:trail/{trail_name}"
    account_subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    trail_subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=SCAN_ID,
        aws_account_id=owner_account_id,
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=trail_arn,
        scope=ResourceScope.REGIONAL,
        region=home_region,
    )
    s3_bucket_name = "audit-logs" if with_destinations else None
    kms_region = destination_region or home_region
    kms_key_id = (
        f"arn:aws:kms:{kms_region}:{ACCOUNT_ID}:key/{kms_key_resource_id}"
        if with_destinations
        else None
    )
    configuration: dict[str, object] = {
        "name": trail_name,
        "s3_bucket_name": s3_bucket_name,
        "s3_key_prefix": None,
        "include_global_service_events": True,
        "is_multi_region_trail": True,
        "log_file_validation_enabled": True,
        "cloudwatch_logs_log_group_arn": None,
        "cloudwatch_logs_role_arn": None,
        "kms_key_id": kms_key_id,
        "is_organization_trail": owner_account_id != ACCOUNT_ID,
    }
    status: dict[str, object] = {
        "is_logging": True,
        "status": {"IsLogging": True},
    }
    selectors: dict[str, object] = {
        "selector_form": "BASIC",
        "basic_selectors": [
            {
                "raw_presence": {
                    "include_management_events": False,
                    "read_write_type": False,
                    "exclude_management_event_sources": False,
                    "data_resources": False,
                },
                "include_management_events": True,
                "read_write_type": "All",
                "exclude_management_event_sources": [],
                "data_resources": [],
            }
        ],
        "advanced_selectors": [],
    }
    definitions = (
        (
            "cloudtrail.trails.discovery",
            "cloudtrail.trails",
            "cloudtrail:ListTrails",
            account_subject,
            {
                "collection_account_id": ACCOUNT_ID,
                "invocation_region": invocation_region,
                "trail_arns": [trail_arn],
                "trail_count": 1,
                "discarded_item_count": 0,
                "admission_complete": True,
                "unadmitted_resources": [],
                "complete": True,
                "failure_category": None,
            },
            False,
        ),
        (
            "cloudtrail.trail.identity",
            "cloudtrail.trails",
            "cloudtrail:ListTrails",
            trail_subject,
            {
                "collection_account_id": ACCOUNT_ID,
                "owner_account_id": owner_account_id,
                "partition": "aws",
                "trail_arn": trail_arn,
                "name": trail_name,
                "home_region": home_region,
                "complete": True,
                "failure_category": None,
            },
            True,
        ),
        (
            "cloudtrail.trail.configuration",
            "cloudtrail.trail-configuration",
            "cloudtrail:GetTrail",
            trail_subject,
            {
                "trail_arn": trail_arn,
                "home_region": home_region,
                "value": configuration,
                "complete": True,
                "failure_category": None,
            },
            False,
        ),
        (
            "cloudtrail.trail.status",
            "cloudtrail.trail-status",
            "cloudtrail:GetTrailStatus",
            trail_subject,
            {
                "trail_arn": trail_arn,
                "home_region": home_region,
                "value": status,
                "complete": True,
                "failure_category": None,
            },
            False,
        ),
        (
            "cloudtrail.trail.event-selectors",
            "cloudtrail.trail-event-selectors",
            "cloudtrail:GetEventSelectors",
            trail_subject,
            {
                "trail_arn": trail_arn,
                "home_region": home_region,
                "value": selectors,
                "complete": True,
                "failure_category": None,
            },
            False,
        ),
        (
            "cloudtrail.trail.tags",
            "cloudtrail.trail-tags",
            "cloudtrail:ListTags",
            trail_subject,
            {
                "trail_arn": trail_arn,
                "home_region": home_region,
                "value": [{"key": "Environment", "value": "test"}],
                "complete": True,
                "failure_category": None,
            },
            False,
        ),
    )
    built = tuple(
        _cloudtrail_source(
            evidence_kind=evidence_kind,
            collector=collector,
            source_api=source_api,
            subject=subject,
            payload=payload,
            index=index,
            identity_authoritative=authoritative,
        )
        for index, (
            evidence_kind,
            collector,
            source_api,
            subject,
            payload,
            authoritative,
        ) in enumerate(definitions)
    )
    contracts = tuple(item[0] for item in built)
    artifacts = tuple(item[1] for item in built)
    outcomes = tuple(item[2] for item in built)
    resource = NormalizedResource(
        account_id=owner_account_id,
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=trail_arn,
        arn=trail_arn,
        name=trail_name,
        scope=ResourceScope.REGIONAL,
        region=home_region,
        tags={"Environment": "test"},
        configuration={
            "home_region": home_region,
            **{key: configuration[key] for key in configuration if key != "name"},
            "is_logging": True,
            "status": status["status"],
            "event_selectors": selectors,
            "source_states": {
                "identity": "PRESENT",
                "configuration": "PRESENT",
                "status": "PRESENT",
                "event_selectors": "PRESENT",
                "tags": "PRESENT",
            },
        },
        raw_configuration={
            "summary": {
                "TrailARN": trail_arn,
                "Name": trail_name,
                "HomeRegion": home_region,
            },
            "trail": configuration,
            "status": status["status"],
            "event_selectors": selectors,
        },
    )
    relationships: list[ResourceRelationship] = []
    provenance = RelationshipProvenance(
        collector="cloudtrail.trail-configuration",
        collector_version="1.0.0",
        source_api="cloudtrail:GetTrail",
        evidence_reference=artifacts[2].evidence_reference,
        collected_at=COLLECTED_AT,
    )
    if s3_bucket_name is not None:
        relationships.append(
            ResourceRelationship.for_observation(
                scan_id=SCAN_ID,
                collection_account_id=ACCOUNT_ID,
                relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
                source=_endpoint(resource),
                target=UnresolvedRelationshipTarget.for_aws_reference(
                    service="s3",
                    resource_type="s3_bucket",
                    aws_resource_id=s3_bucket_name,
                    scope=ResourceScope.REGIONAL,
                ),
                resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
                provenance=provenance,
            )
        )
    if kms_key_id is not None:
        relationships.append(
            ResourceRelationship.for_observation(
                scan_id=SCAN_ID,
                collection_account_id=ACCOUNT_ID,
                relationship_type=RelationshipType.ENCRYPTED_WITH,
                source=_endpoint(resource),
                target=RelationshipEndpoint.for_aws_resource(
                    aws_account_id=ACCOUNT_ID,
                    service="kms",
                    resource_type="kms_key",
                    aws_resource_id=kms_key_id,
                    scope=ResourceScope.REGIONAL,
                    region=kms_region,
                    observed_in_scan_id=None,
                ),
                resolution=RelationshipResolution.TARGET_NOT_COLLECTED,
                provenance=provenance,
            )
        )
    graph = EvidenceGraph(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        collected_at=COLLECTED_AT,
        source_contracts=contracts,
        artifacts=artifacts,
        source_outcomes=outcomes,
        relationships=tuple(relationships),
    )
    return graph, resource, contracts, artifacts, outcomes


def _cloudtrail_kms_relationship_with_resolution(
    graph: EvidenceGraph,
    resolution: RelationshipResolution,
) -> ResourceRelationship:
    relationship = next(
        item
        for item in graph.relationships
        if item.relationship_type is RelationshipType.ENCRYPTED_WITH
    )
    target = relationship.target
    if not isinstance(target, RelationshipEndpoint):  # pragma: no cover - fixture invariant
        raise TypeError("CloudTrail KMS fixture target must have a stable identity")
    rebound_target = RelationshipEndpoint.for_aws_resource(
        aws_account_id=target.aws_account_id,
        service=target.service,
        resource_type=target.resource_type,
        aws_resource_id=target.aws_resource_id,
        scope=target.scope,
        region=target.region,
        observed_in_scan_id=(SCAN_ID if resolution is RelationshipResolution.RESOLVED else None),
    )
    return ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.ENCRYPTED_WITH,
        source=relationship.source,
        target=rebound_target,
        resolution=resolution,
        provenance=relationship.provenance,
    )


def _replace_cloudtrail_kms_relationship(
    graph: EvidenceGraph,
    replacement: ResourceRelationship,
) -> tuple[ResourceRelationship, ...]:
    return tuple(
        replacement
        if item.relationship_type is RelationshipType.ENCRYPTED_WITH
        and item.source.service == "cloudtrail"
        else item
        for item in graph.relationships
    )


def test_cloudtrail_manifest_replays_resource_and_proof_bound_home_region() -> None:
    graph, resource, *_ = _cloudtrail_graph_parts()

    snapshot = _inventory(graph=graph, resources=(resource,), requested_region=REGION)

    assert snapshot.resource_count == 1


def test_cloudtrail_manifest_preserves_cross_region_destination_key_identity() -> None:
    graph, resource, *_ = _cloudtrail_graph_parts(
        home_region="eu-west-1",
        destination_region="eu-central-1",
        with_destinations=True,
    )

    snapshot = _inventory(graph=graph, resources=(resource,), requested_region=REGION)

    kms_relationship = next(
        relationship
        for relationship in snapshot.evidence_graph.relationships
        if relationship.relationship_type is RelationshipType.ENCRYPTED_WITH
    )
    assert kms_relationship.target.region == "eu-central-1"


def test_cloudtrail_manifest_binds_destination_relationships_to_configuration() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(with_destinations=True)

    with pytest.raises(ValidationError, match="relationship observation is duplicated"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(*graph.relationships, graph.relationships[0]),
        )


def test_cloudtrail_kms_replay_rejects_unproved_resolution_substitution() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(with_destinations=True)
    substituted = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE,
    )

    with pytest.raises(ValidationError, match="KMS relationship resolution"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=_replace_cloudtrail_kms_relationship(graph, substituted),
        )


def test_cloudtrail_kms_replay_resolves_exact_key_collected_through_alias() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(
        destination_region=REGION,
        kms_key_resource_id="key-123",
        with_destinations=True,
    )
    s3_contracts, s3_artifacts, s3_outcomes, s3_relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        kms_references=("alias/example",),
    )
    resolved = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.RESOLVED,
    )
    kms_outcome = next(
        outcome
        for outcome in s3_outcomes
        if outcome.collector == "kms.keys" and outcome.state is EvidenceSourceState.PRESENT
    )
    assert isinstance(kms_outcome.subject, ResourceEvidenceSubject)
    assert resolved.target.resource_snapshot_id == kms_outcome.subject.resource_snapshot_id

    combined = EvidenceGraph(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        collected_at=COLLECTED_AT,
        source_contracts=(*contracts, *s3_contracts),
        artifacts=(*artifacts, *s3_artifacts),
        source_outcomes=(*outcomes, *s3_outcomes),
        relationships=(
            *_replace_cloudtrail_kms_relationship(graph, resolved),
            *s3_relationships,
        ),
    )
    assert (
        next(
            item
            for item in combined.relationships
            if item.source.service == "cloudtrail"
            and item.relationship_type is RelationshipType.ENCRYPTED_WITH
        ).resolution
        is RelationshipResolution.RESOLVED
    )

    substituted = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_NOT_COLLECTED,
    )
    with pytest.raises(ValidationError, match="KMS relationship resolution"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=(*contracts, *s3_contracts),
            artifacts=(*artifacts, *s3_artifacts),
            source_outcomes=(*outcomes, *s3_outcomes),
            relationships=(
                *_replace_cloudtrail_kms_relationship(graph, substituted),
                *s3_relationships,
            ),
        )


def test_cloudtrail_kms_replay_rejects_orphan_describe_key_evidence() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(
        destination_region=REGION,
        kms_key_resource_id="key-123",
        with_destinations=True,
    )
    s3_contracts, s3_artifacts, s3_outcomes, _ = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        kms_references=("alias/example",),
    )
    kms_outcome = next(item for item in s3_outcomes if item.collector == "kms.keys")
    kms_contract = next(
        item for item in s3_contracts if item.source_outcome_id == kms_outcome.source_outcome_id
    )
    kms_artifact = next(
        item for item in s3_artifacts if item.evidence_reference == kms_outcome.evidence_reference
    )
    resolved = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.RESOLVED,
    )

    with pytest.raises(ValidationError, match="valid S3 collection manifest"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=(*contracts, kms_contract),
            artifacts=(*artifacts, kms_artifact),
            source_outcomes=(*outcomes, kms_outcome),
            relationships=_replace_cloudtrail_kms_relationship(graph, resolved),
        )


def test_cloudtrail_kms_replay_uses_exact_access_denied_outcome() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(
        destination_region=REGION,
        kms_key_resource_id="key-123",
        with_destinations=True,
    )
    kms_arn = next(
        item.target.aws_resource_id
        for item in graph.relationships
        if item.relationship_type is RelationshipType.ENCRYPTED_WITH
    )
    s3_contracts, s3_artifacts, s3_outcomes, s3_relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        lookup_present=False,
        kms_references=(kms_arn,),
    )
    access_denied = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_ACCESS_DENIED,
    )

    EvidenceGraph(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        collected_at=COLLECTED_AT,
        source_contracts=(*contracts, *s3_contracts),
        artifacts=(*artifacts, *s3_artifacts),
        source_outcomes=(*outcomes, *s3_outcomes),
        relationships=(
            *_replace_cloudtrail_kms_relationship(graph, access_denied),
            *s3_relationships,
        ),
    )

    substituted = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_NOT_COLLECTED,
    )
    with pytest.raises(ValidationError, match="KMS relationship resolution"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=(*contracts, *s3_contracts),
            artifacts=(*artifacts, *s3_artifacts),
            source_outcomes=(*outcomes, *s3_outcomes),
            relationships=(
                *_replace_cloudtrail_kms_relationship(graph, substituted),
                *s3_relationships,
            ),
        )


def test_cloudtrail_kms_replay_uses_not_collected_for_complete_s3_rollup() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(
        destination_region=REGION,
        kms_key_resource_id="key-123",
        with_destinations=True,
    )
    s3_contracts, s3_artifacts, s3_outcomes = _complete_s3_manifest_parts(
        bucket_names=("bucket-a",),
    )

    EvidenceGraph(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        collected_at=COLLECTED_AT,
        source_contracts=(*contracts, *s3_contracts),
        artifacts=(*artifacts, *s3_artifacts),
        source_outcomes=(*outcomes, *s3_outcomes),
        relationships=graph.relationships,
    )

    substituted = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE,
    )
    with pytest.raises(ValidationError, match="KMS relationship resolution"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=(*contracts, *s3_contracts),
            artifacts=(*artifacts, *s3_artifacts),
            source_outcomes=(*outcomes, *s3_outcomes),
            relationships=_replace_cloudtrail_kms_relationship(graph, substituted),
        )


def test_cloudtrail_kms_replay_uses_incomplete_s3_rollup_without_exact_outcome() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(
        destination_region=REGION,
        kms_key_resource_id="key-123",
        with_destinations=True,
    )
    s3_contracts, s3_artifacts, s3_outcomes, s3_relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        lookup_present=False,
        kms_references=("alias/unrelated",),
    )
    incomplete = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE,
    )

    EvidenceGraph(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        collected_at=COLLECTED_AT,
        source_contracts=(*contracts, *s3_contracts),
        artifacts=(*artifacts, *s3_artifacts),
        source_outcomes=(*outcomes, *s3_outcomes),
        relationships=(
            *_replace_cloudtrail_kms_relationship(graph, incomplete),
            *s3_relationships,
        ),
    )

    substituted = _cloudtrail_kms_relationship_with_resolution(
        graph,
        RelationshipResolution.TARGET_NOT_COLLECTED,
    )
    with pytest.raises(ValidationError, match="KMS relationship resolution"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=(*contracts, *s3_contracts),
            artifacts=(*artifacts, *s3_artifacts),
            source_outcomes=(*outcomes, *s3_outcomes),
            relationships=(
                *_replace_cloudtrail_kms_relationship(graph, substituted),
                *s3_relationships,
            ),
        )


def test_cloudtrail_manifest_rejects_omitted_destination_relationship() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(with_destinations=True)

    with pytest.raises(ValidationError, match="relationship manifest is incomplete"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=graph.relationships[1:],
        )


def test_cloudtrail_manifest_rejects_substituted_destination_target() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(with_destinations=True)
    bucket_relationship = next(
        relationship
        for relationship in graph.relationships
        if relationship.relationship_type is RelationshipType.DELIVERS_TO_BUCKET
    )
    wrong_target = ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=bucket_relationship.source,
        target=UnresolvedRelationshipTarget.for_aws_reference(
            service="s3",
            resource_type="s3_bucket",
            aws_resource_id="substituted-bucket",
            scope=ResourceScope.REGIONAL,
        ),
        resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
        provenance=bucket_relationship.provenance,
    )

    with pytest.raises(ValidationError, match="bucket relationship target is invalid"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=tuple(
                wrong_target if relationship is bucket_relationship else relationship
                for relationship in graph.relationships
            ),
        )


def test_cloudtrail_manifest_rejects_substituted_destination_provenance() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(with_destinations=True)
    bucket_relationship = next(
        relationship
        for relationship in graph.relationships
        if relationship.relationship_type is RelationshipType.DELIVERS_TO_BUCKET
    )
    wrong_provenance = bucket_relationship.model_copy(
        update={
            "provenance": RelationshipProvenance(
                collector="cloudtrail.trail-status",
                collector_version="1.0.0",
                source_api="cloudtrail:GetTrailStatus",
                evidence_reference=artifacts[3].evidence_reference,
                collected_at=COLLECTED_AT,
            )
        }
    )

    with pytest.raises(ValidationError, match="relationship provenance is invalid"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=tuple(
                wrong_provenance if relationship is bucket_relationship else relationship
                for relationship in graph.relationships
            ),
        )


@pytest.mark.parametrize(
    "tampered_field",
    ("tags", "configuration", "source_states", "raw_configuration"),
)
def test_cloudtrail_resource_replay_rejects_projection_tampering(
    tampered_field: str,
) -> None:
    graph, resource, *_ = _cloudtrail_graph_parts()
    if tampered_field == "tags":
        tampered = resource.model_copy(update={"tags": {"Environment": "tampered"}})
    elif tampered_field == "configuration":
        configuration = dict(resource.configuration)
        configuration["is_logging"] = False
        tampered = resource.model_copy(update={"configuration": configuration})
    elif tampered_field == "source_states":
        configuration = dict(resource.configuration)
        source_states = dict(configuration["source_states"])
        source_states["tags"] = "UNAVAILABLE"
        configuration["source_states"] = source_states
        tampered = resource.model_copy(update={"configuration": configuration})
    else:
        raw_configuration = dict(resource.raw_configuration)
        raw_configuration["summary"] = {
            "TrailARN": resource.aws_resource_id,
            "Name": "substituted-name",
            "HomeRegion": resource.region,
        }
        tampered = resource.model_copy(update={"raw_configuration": raw_configuration})

    with pytest.raises(ValidationError, match="canonical resource contradicts"):
        _inventory(graph=graph, resources=(tampered,), requested_region=REGION)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("name", "other-trail", "configuration name"),
        (
            "kms_key_id",
            "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "KMS key identity",
        ),
        (
            "cloudwatch_logs_log_group_arn",
            "arn:aws:logs:us-west-2:123456789012:log-group:audit",
            "CloudWatch delivery",
        ),
    ),
)
def test_cloudtrail_manifest_rejects_redigested_configuration_tampering(
    field: str,
    value: object,
    message: str,
) -> None:
    _, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts()
    payload = artifacts[2].model_dump(mode="json")["normalized_payload"]
    payload["value"][field] = value
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="cloudtrail.trail.configuration",
        payload=payload,
    )

    with pytest.raises(ValidationError, match=message):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_cloudtrail_manifest_rejects_redigested_unsafe_tag_key() -> None:
    _, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts()
    payload = artifacts[5].model_dump(mode="json")["normalized_payload"]
    payload["value"] = [{"key": "Environment\nInjected", "value": "test"}]
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="cloudtrail.trail.tags",
        payload=payload,
    )

    with pytest.raises(ValidationError, match="tag evidence is malformed"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_cloudtrail_manifest_binds_discovery_invocation_region_to_scan() -> None:
    graph, resource, *_ = _cloudtrail_graph_parts(invocation_region="eu-west-1")

    with pytest.raises(ValidationError, match="invocation Region"):
        _inventory(graph=graph, resources=(resource,), requested_region=REGION)


def test_cloudtrail_external_enrichment_requires_paired_identity() -> None:
    graph, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(
        owner_account_id="210987654321"
    )
    identity = outcomes[1]

    with pytest.raises(ValidationError, match="manifest is incomplete"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=tuple(
                item for item in contracts if item.source_outcome_id != identity.source_outcome_id
            ),
            artifacts=tuple(
                item for item in artifacts if item.evidence_reference != identity.evidence_reference
            ),
            source_outcomes=tuple(item for item in outcomes if item is not identity),
            relationships=graph.relationships,
        )


def test_cloudtrail_external_enrichment_rejects_nonpresent_identity() -> None:
    _, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(owner_account_id="210987654321")
    payload = artifacts[1].model_dump(mode="json")["normalized_payload"]
    payload["complete"] = False
    payload["failure_category"] = "ACCESS_DENIED"
    rebound_artifacts, rebound_outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="cloudtrail.trail.identity",
        payload=payload,
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )

    with pytest.raises(ValidationError, match="PRESENT authoritative identity"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_cloudtrail_external_enrichment_rejects_mismatched_identity() -> None:
    _, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(owner_account_id="210987654321")
    payload = artifacts[1].model_dump(mode="json")["normalized_payload"]
    payload["owner_account_id"] = "999999999999"
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="cloudtrail.trail.identity",
        payload=payload,
    )

    with pytest.raises(ValidationError, match="identity evidence is malformed"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_cloudtrail_external_owner_replay_requires_organization_context() -> None:
    _, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts(owner_account_id="210987654321")
    payload = artifacts[2].model_dump(mode="json")["normalized_payload"]
    payload["value"]["is_organization_trail"] = False
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="cloudtrail.trail.configuration",
        payload=payload,
    )

    with pytest.raises(ValidationError, match="requires organization context"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_cloudtrail_selector_defaults_are_digest_bound() -> None:
    _, _, contracts, artifacts, outcomes = _cloudtrail_graph_parts()
    payload = artifacts[4].model_dump(mode="json")["normalized_payload"]
    payload["value"]["basic_selectors"][0]["read_write_type"] = "ReadOnly"
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="cloudtrail.trail.event-selectors",
        payload=payload,
    )

    with pytest.raises(ValidationError, match="default provenance"):
        EvidenceGraph(
            scan_id=SCAN_ID,
            collection_account_id=ACCOUNT_ID,
            collected_at=COLLECTED_AT,
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
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


def test_relationship_provenance_index_does_not_hide_multiple_matching_sources() -> None:
    contract, artifact, outcome, _, _ = _valid_parts()
    second_contract = ScanSourceContract.for_scan(
        **{
            **contract.model_dump(exclude={"source_outcome_id", "schema_version"}),
            "subject": contract.subject,
            "contract_key": "ec2.other-instances",
            "evidence_kind": "ec2.other-instances",
        }
    )
    second_outcome = _outcome(second_contract, artifact)
    assert second_outcome.source_outcome_id != outcome.source_outcome_id
    # Both declarations may cite this artifact, but an edge must identify exactly one.
    with pytest.raises(ValidationError, match="exactly one declared source outcome"):
        _graph(
            source_contracts=(contract, second_contract),
            source_outcomes=(outcome, second_outcome),
        )


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

    with pytest.raises(ValidationError, match="only controlled Access Analyzer"):
        _contract(allows_supplemental_region=True)


def test_access_analyzer_supplemental_discovery_requires_exact_s3_region_proof() -> None:
    east_contract = _access_analyzer_contract(
        region="us-east-1",
        allows_supplemental_region=False,
    )
    west_contract = _access_analyzer_contract(
        region="us-west-2",
        allows_supplemental_region=True,
    )
    east_artifact = _access_analyzer_artifact("us-east-1")
    west_artifact = _access_analyzer_artifact("us-west-2")
    graph = _graph(
        source_contracts=(east_contract, west_contract),
        artifacts=(east_artifact, west_artifact),
        source_outcomes=(
            _outcome(east_contract, east_artifact),
            _outcome(west_contract, west_artifact),
        ),
        relationships=(),
    )

    assert east_contract.source_outcome_id != west_contract.source_outcome_id
    with pytest.raises(ValidationError, match="same-scan S3 bucket Region"):
        _inventory(graph=graph, resources=())

    snapshot = _inventory(graph=graph, resources=(_s3_bucket(region="us-west-2"),))
    assert snapshot.resource_count == 1


def test_access_analyzer_requested_region_cannot_claim_supplemental_permission() -> None:
    contract = _access_analyzer_contract(
        region="us-east-1",
        allows_supplemental_region=True,
    )
    artifact = _access_analyzer_artifact("us-east-1")
    graph = _graph(
        source_contracts=(contract,),
        artifacts=(artifact,),
        source_outcomes=(_outcome(contract, artifact),),
        relationships=(),
    )

    with pytest.raises(ValidationError, match="cannot claim supplemental-Region"):
        _inventory(graph=graph, resources=())


def test_access_analyzer_regional_coverage_requires_requested_region() -> None:
    west_contract = _access_analyzer_contract(
        region="us-west-2",
        allows_supplemental_region=True,
    )
    west_artifact = _access_analyzer_artifact("us-west-2")
    graph = _graph(
        source_contracts=(west_contract,),
        artifacts=(west_artifact,),
        source_outcomes=(_outcome(west_contract, west_artifact),),
        relationships=(),
    )

    with pytest.raises(ValidationError, match="Regional coverage must exactly match"):
        _inventory(graph=graph, resources=(_s3_bucket(region="us-west-2"),))


def test_access_analyzer_regional_coverage_requires_every_bucket_region() -> None:
    east_contract = _access_analyzer_contract(
        region="us-east-1",
        allows_supplemental_region=False,
    )
    east_artifact = _access_analyzer_artifact("us-east-1")
    graph = _graph(
        source_contracts=(east_contract,),
        artifacts=(east_artifact,),
        source_outcomes=(_outcome(east_contract, east_artifact),),
        relationships=(),
    )

    with pytest.raises(ValidationError, match="Regional coverage must exactly match"):
        _inventory(graph=graph, resources=(_s3_bucket(region="us-west-2"),))


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

    s3_contracts, s3_artifacts, s3_outcomes = _complete_s3_manifest_parts()
    graph_with_5e_manifest = _graph(
        source_contracts=(contract, *s3_contracts),
        artifacts=(artifact, *s3_artifacts),
        source_outcomes=(outcome, *s3_outcomes),
        relationships=(relationship,),
    )
    assert (
        _inventory(
            graph=graph_with_5e_manifest,
            resources=(finding, external_bucket),
        ).resource_count
        == 2
    )


def test_kms_resource_requires_describe_key_proof_and_s3_encryption_edge() -> None:
    bucket = _s3_bucket(region=REGION)
    key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/key-123"
    kms_key = NormalizedResource(
        account_id=ACCOUNT_ID,
        service="kms",
        resource_type="kms_key",
        aws_resource_id=key_arn,
        arn=key_arn,
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )
    kms_subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=SCAN_ID,
        aws_account_id=ACCOUNT_ID,
        service="kms",
        resource_type="kms_key",
        aws_resource_id=key_arn,
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )
    kms_kind = "kms.key." + hashlib.sha256(f"{REGION}\0alias/example".encode()).hexdigest()
    kms_contract = ScanSourceContract.for_scan(
        contract_key=kms_kind,
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=kms_subject,
        evidence_kind=kms_kind,
        collector="kms.keys",
        collector_version="1.0.0",
        source_api="kms:DescribeKey",
        cardinality=EvidenceCardinality.SINGLE,
        identity_authoritative=True,
    )
    kms_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://kms/us-east-1/key/key-123",
        evidence_schema="kms.key",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "region": REGION,
            "supplied_reference": "alias/example",
            "source_bucket_names": [bucket.aws_resource_id],
            "key": {
                "aws_account_id": ACCOUNT_ID,
                "region": REGION,
                "key_id": "key-123",
                "arn": key_arn,
                "key_manager": "CUSTOMER",
            },
            "complete": True,
            "failure_category": None,
        },
    )
    kms_outcome = _outcome(kms_contract, kms_artifact)

    bucket_subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=SCAN_ID,
        aws_account_id=ACCOUNT_ID,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=bucket.aws_resource_id,
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )
    encryption_contract = ScanSourceContract.for_scan(
        contract_key="s3.bucket-encryption",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=bucket_subject,
        evidence_kind="s3.bucket-encryption",
        collector="s3.bucket-encryption",
        collector_version="1.0.0",
        source_api="s3:GetEncryptionConfiguration",
        cardinality=EvidenceCardinality.SINGLE,
    )
    encryption_artifact = _artifact(
        reference="normalized://s3/bucket/encryption",
        payload={"kms_reference": "alias/example"},
    )
    encryption_outcome = _outcome(encryption_contract, encryption_artifact)
    relationship = ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.ENCRYPTED_WITH,
        source=_endpoint(bucket),
        target=_endpoint(kms_key),
        resolution=RelationshipResolution.RESOLVED,
        provenance=RelationshipProvenance(
            collector=encryption_contract.collector,
            collector_version=encryption_contract.collector_version,
            source_api=encryption_contract.source_api,
            evidence_reference=encryption_artifact.evidence_reference,
            collected_at=COLLECTED_AT,
        ),
    )
    graph_without_edge = _graph(
        source_contracts=(kms_contract, encryption_contract),
        artifacts=(kms_artifact, encryption_artifact),
        source_outcomes=(kms_outcome, encryption_outcome),
        relationships=(),
    )
    with pytest.raises(ValidationError, match="S3 encryption relationship"):
        _inventory(graph=graph_without_edge, resources=(bucket, kms_key))

    complete = _graph(
        source_contracts=(kms_contract, encryption_contract),
        artifacts=(kms_artifact, encryption_artifact),
        source_outcomes=(kms_outcome, encryption_outcome),
        relationships=(relationship,),
    )
    assert _inventory(graph=complete, resources=(bucket, kms_key)).resource_count == 2

    unrelated_bucket = NormalizedResource(
        account_id=ACCOUNT_ID,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="unrelated-bucket",
        scope=ResourceScope.REGIONAL,
        region=REGION,
    )
    wrong_source = ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.ENCRYPTED_WITH,
        source=_endpoint(unrelated_bucket),
        target=_endpoint(kms_key),
        resolution=RelationshipResolution.RESOLVED,
        provenance=relationship.provenance,
    )
    wrong_source_graph = _graph(
        source_contracts=(kms_contract, encryption_contract),
        artifacts=(kms_artifact, encryption_artifact),
        source_outcomes=(kms_outcome, encryption_outcome),
        relationships=(wrong_source,),
    )
    with pytest.raises(ValidationError, match="S3 encryption relationship"):
        _inventory(
            graph=wrong_source_graph,
            resources=(bucket, unrelated_bucket, kms_key),
        )

    wrong_provenance = relationship.model_copy(
        update={
            "provenance": RelationshipProvenance(
                collector=kms_contract.collector,
                collector_version=kms_contract.collector_version,
                source_api=kms_contract.source_api,
                evidence_reference=kms_artifact.evidence_reference,
                collected_at=COLLECTED_AT,
            )
        }
    )
    wrong_graph = _graph(
        source_contracts=(kms_contract, encryption_contract),
        artifacts=(kms_artifact, encryption_artifact),
        source_outcomes=(kms_outcome, encryption_outcome),
        relationships=(wrong_provenance,),
    )
    with pytest.raises(ValidationError, match="S3 encryption relationship"):
        _inventory(graph=wrong_graph, resources=(bucket, kms_key))


def test_complete_s3_manifest_cannot_omit_account_or_per_bucket_sources() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))

    for omitted_collector in ("s3.account-public-access-block", "s3.bucket-tags"):
        omitted_outcome_ids = {
            outcome.source_outcome_id
            for outcome in outcomes
            if outcome.collector == omitted_collector
        }
        omitted_references = {
            outcome.evidence_reference
            for outcome in outcomes
            if outcome.collector == omitted_collector
        }
        with pytest.raises(ValidationError, match="S3 evidence requires|manifest is incomplete"):
            _graph(
                source_contracts=tuple(
                    item for item in contracts if item.source_outcome_id not in omitted_outcome_ids
                ),
                artifacts=tuple(
                    item for item in artifacts if item.evidence_reference not in omitted_references
                ),
                source_outcomes=tuple(
                    item for item in outcomes if item.source_outcome_id not in omitted_outcome_ids
                ),
                relationships=(),
            )


def test_s3_replay_rejects_absent_policy_with_public_status() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    status_outcome = next(
        item for item in outcomes if item.evidence_kind == "s3.bucket-policy-status"
    )
    status_artifact = next(
        item for item in artifacts if item.evidence_reference == status_outcome.evidence_reference
    )
    payload = status_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    rebound_artifacts, rebound_outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-policy-status",
        payload={
            **payload,
            "value": {"policy_present": True, "is_public": True},
            "expected_absence": False,
        },
        state=EvidenceSourceState.PRESENT,
    )

    with pytest.raises(ValidationError, match="contradictory S3 policy sources"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_s3_replay_detects_case_insensitive_unconditional_public_policy() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    document = {
        "Version": None,
        "Id": None,
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "S3:GetObject",
                "Resource": "arn:aws:s3:::bucket-a/*",
            }
        ],
    }
    digest = hashlib.sha256(
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    policy_outcome = next(item for item in outcomes if item.evidence_kind == "s3.bucket-policy")
    policy_artifact = next(
        item for item in artifacts if item.evidence_reference == policy_outcome.evidence_reference
    )
    policy_payload = policy_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(policy_payload, dict)
    artifacts, outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-policy",
        payload={
            **policy_payload,
            "value": {"document": document, "sha256": digest},
            "expected_absence": False,
        },
        state=EvidenceSourceState.PRESENT,
    )
    status_outcome = next(
        item for item in outcomes if item.evidence_kind == "s3.bucket-policy-status"
    )
    status_artifact = next(
        item for item in artifacts if item.evidence_reference == status_outcome.evidence_reference
    )
    status_payload = status_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(status_payload, dict)
    artifacts, outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-policy-status",
        payload={
            **status_payload,
            "value": {"policy_present": True, "is_public": False},
            "expected_absence": False,
        },
        state=EvidenceSourceState.PRESENT,
    )

    with pytest.raises(ValidationError, match="contradictory S3 policy sources"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(),
        )


def test_s3_replay_rejects_public_acl_with_effective_ignore_public_acls() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    acl_outcome = next(item for item in outcomes if item.evidence_kind == "s3.bucket-acl")
    acl_artifact = next(
        item for item in artifacts if item.evidence_reference == acl_outcome.evidence_reference
    )
    payload = acl_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-acl",
        payload={
            **payload,
            "value": {
                "owner": {"id": "owner-id", "display_name": None},
                "grants": [
                    {
                        "grantee": {
                            "type": "Group",
                            "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "permission": "READ",
                    }
                ],
            },
        },
    )

    with pytest.raises(ValidationError, match="contradictory S3 ACL evidence"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_s3_replay_rejects_bucket_owner_enforced_acl_mismatch() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    ownership_outcome = next(
        item for item in outcomes if item.evidence_kind == "s3.bucket-ownership-controls"
    )
    ownership_artifact = next(
        item
        for item in artifacts
        if item.evidence_reference == ownership_outcome.evidence_reference
    )
    ownership_payload = ownership_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(ownership_payload, dict)
    artifacts, outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-ownership-controls",
        payload={
            **ownership_payload,
            "value": {"rules": [{"object_ownership": "BucketOwnerEnforced"}]},
            "expected_absence": False,
        },
        state=EvidenceSourceState.PRESENT,
    )
    acl_outcome = next(item for item in outcomes if item.evidence_kind == "s3.bucket-acl")
    acl_artifact = next(
        item for item in artifacts if item.evidence_reference == acl_outcome.evidence_reference
    )
    acl_payload = acl_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(acl_payload, dict)
    artifacts, outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-acl",
        payload={
            **acl_payload,
            "value": {
                "owner": {"id": "owner-id", "display_name": None},
                "grants": [
                    {
                        "grantee": {"type": "CanonicalUser", "id": "external-owner"},
                        "permission": "FULL_CONTROL",
                    }
                ],
            },
        },
    )

    with pytest.raises(ValidationError, match="contradictory S3 ACL evidence"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(),
        )


def test_s3_replay_rejects_acl_grantee_with_conflicting_identity_fields() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    acl_outcome = next(item for item in outcomes if item.evidence_kind == "s3.bucket-acl")
    acl_artifact = next(
        item for item in artifacts if item.evidence_reference == acl_outcome.evidence_reference
    )
    payload = acl_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-acl",
        payload={
            **payload,
            "value": {
                "owner": {"id": "owner-id", "display_name": None},
                "grants": [
                    {
                        "grantee": {
                            "type": "CanonicalUser",
                            "id": "owner-id",
                            "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "permission": "FULL_CONTROL",
                    }
                ],
            },
        },
    )

    with pytest.raises(ValidationError, match="S3 per-bucket artifact value is malformed"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_s3_replay_rejects_multiple_bucket_ownership_rules() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    ownership_outcome = next(
        item for item in outcomes if item.evidence_kind == "s3.bucket-ownership-controls"
    )
    ownership_artifact = next(
        item
        for item in artifacts
        if item.evidence_reference == ownership_outcome.evidence_reference
    )
    payload = ownership_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    rebound_artifacts, rebound_outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-ownership-controls",
        payload={
            **payload,
            "value": {
                "rules": [
                    {"object_ownership": "BucketOwnerEnforced"},
                    {"object_ownership": "BucketOwnerPreferred"},
                ]
            },
            "expected_absence": False,
        },
        state=EvidenceSourceState.PRESENT,
    )

    with pytest.raises(ValidationError, match="S3 per-bucket artifact value is malformed"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_s3_replay_accepts_blocked_encryption_type_without_default() -> None:
    blocked_only = {
        "rules": [
            {
                "sse_algorithm": None,
                "kms_key_reference": None,
                "kms_reference_explicit": False,
                "key_management": None,
                "bucket_key_enabled": None,
                "blocked_encryption_types": ["SSE-C"],
            }
        ]
    }
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(
        bucket_names=("bucket-a",),
        encryption_values={"bucket-a": blocked_only},
    )

    graph = _graph(
        source_contracts=contracts,
        artifacts=artifacts,
        source_outcomes=outcomes,
        relationships=(),
    )

    assert EvidenceGraph.model_validate(graph.model_dump(mode="python")) == graph


@pytest.mark.parametrize(
    "rule_update",
    [
        {"bucket_key_enabled": True},
        {"blocked_encryption_types": ["NONE", "SSE-C"]},
    ],
)
def test_s3_replay_rejects_invalid_encryption_semantics(
    rule_update: dict[str, object],
) -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    encryption_outcome = next(
        item for item in outcomes if item.evidence_kind == "s3.bucket-encryption"
    )
    encryption_artifact = next(
        item
        for item in artifacts
        if item.evidence_reference == encryption_outcome.evidence_reference
    )
    payload = encryption_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    value = payload["value"]
    assert isinstance(value, dict)
    rules = value["rules"]
    assert isinstance(rules, list)
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-encryption",
        payload={
            **payload,
            "value": {"rules": [{**rules[0], **rule_update}]},
        },
    )

    with pytest.raises(ValidationError, match="S3 per-bucket artifact value is malformed"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_s3_replay_rejects_mfa_delete_without_versioning_status() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    versioning_outcome = next(
        item for item in outcomes if item.evidence_kind == "s3.bucket-versioning"
    )
    versioning_artifact = next(
        item
        for item in artifacts
        if item.evidence_reference == versioning_outcome.evidence_reference
    )
    payload = versioning_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    rebound_artifacts, rebound_outcomes = _rebind_graph_source(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind="s3.bucket-versioning",
        payload={
            **payload,
            "value": {"status": None, "mfa_delete": "Enabled"},
            "expected_absence": False,
        },
        state=EvidenceSourceState.PRESENT,
    )

    with pytest.raises(ValidationError, match="S3 per-bucket artifact value is malformed"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=(),
        )


def test_s3_discovery_and_location_artifacts_require_exact_live_shapes() -> None:
    contracts, artifacts, outcomes = _complete_s3_manifest_parts(bucket_names=("bucket-a",))
    discovery_outcome = next(item for item in outcomes if item.collector == "s3.buckets")
    discovery_artifact = next(
        item
        for item in artifacts
        if item.evidence_reference == discovery_outcome.evidence_reference
    )
    discovery_payload = discovery_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(discovery_payload, dict)
    location_outcome = next(item for item in outcomes if item.collector == "s3.bucket-location")
    location_artifact = next(
        item for item in artifacts if item.evidence_reference == location_outcome.evidence_reference
    )
    location_payload = location_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(location_payload, dict)

    invalid_discovery_payloads = [
        {**discovery_payload, "unknown": True},
        {
            **discovery_payload,
            "buckets": [{**discovery_payload["buckets"][0], "unknown": True}],
        },
        {
            **discovery_payload,
            "buckets": [{**discovery_payload["buckets"][0], "creation_date": "not-a-date"}],
        },
    ]
    for payload in invalid_discovery_payloads:
        rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
            artifacts=artifacts,
            outcomes=outcomes,
            evidence_kind=discovery_outcome.evidence_kind,
            payload=payload,
        )
        with pytest.raises(ValidationError, match="ListBuckets manifest is malformed"):
            _graph(
                source_contracts=contracts,
                artifacts=rebound_artifacts,
                source_outcomes=rebound_outcomes,
                relationships=(),
            )

    missing_not_found = dict(location_payload)
    missing_not_found.pop("resource_not_found")
    invalid_location_payloads = [
        {**location_payload, "unknown": True},
        missing_not_found,
        {**location_payload, "legacy_bucket_region": None},
        {**location_payload, "location_constraint": "us-east-1"},
    ]
    for payload in invalid_location_payloads:
        rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
            artifacts=artifacts,
            outcomes=outcomes,
            evidence_kind=location_outcome.evidence_kind,
            payload=payload,
        )
        with pytest.raises(
            ValidationError,
            match=(
                "bucket-location evidence is malformed|legacy identity is invalid|"
                "successful S3 bucket-location identity is invalid"
            ),
        ):
            _graph(
                source_contracts=contracts,
                artifacts=rebound_artifacts,
                source_outcomes=rebound_outcomes,
                relationships=(),
            )


def test_s3_kms_manifest_requires_each_bucket_edge_for_one_coalesced_key() -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts()
    assert len(relationships) == 2
    _graph(
        source_contracts=contracts,
        artifacts=artifacts,
        source_outcomes=outcomes,
        relationships=relationships,
    )

    with pytest.raises(ValidationError, match="relationship manifest"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=relationships[:1],
        )


def test_s3_kms_manifest_preserves_valid_aliases_coalesced_to_one_key_edge() -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        kms_references=("alias/first", "alias/second"),
    )
    assert len(relationships) == 1
    graph = _graph(
        source_contracts=contracts,
        artifacts=artifacts,
        source_outcomes=outcomes,
        relationships=(relationships[0], relationships[0]),
    )
    assert graph.relationships == relationships
    assert EvidenceGraph.model_validate(graph.model_dump(mode="python")) == graph


def test_s3_kms_manifest_rejects_key_arn_resolving_to_a_different_key() -> None:
    expected_arn = f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/key-expected"
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        kms_references=(expected_arn,),
    )

    with pytest.raises(ValidationError, match="successful DescribeKey relationship identity"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=relationships,
        )


def test_s3_kms_manifest_requires_failed_lookup_unresolved_edge() -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
        lookup_present=False,
    )
    assert len(relationships) == 1
    assert relationships[0].resolution is RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
    _graph(
        source_contracts=contracts,
        artifacts=artifacts,
        source_outcomes=outcomes,
        relationships=relationships,
    )

    with pytest.raises(ValidationError, match="relationship manifest"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(),
        )


def test_s3_kms_failed_lookup_subject_must_be_first_source_bucket() -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a", "bucket-b"),
        lookup_present=False,
    )
    kms_outcome = next(item for item in outcomes if item.collector == "kms.keys")
    kms_contract = next(
        item for item in contracts if item.source_outcome_id == kms_outcome.source_outcome_id
    )
    kms_artifact = next(
        item for item in artifacts if item.evidence_reference == kms_outcome.evidence_reference
    )
    wrong_subject = next(
        item.subject
        for item in outcomes
        if item.collector == "s3.bucket-encryption"
        and isinstance(item.subject, ResourceEvidenceSubject)
        and item.subject.aws_resource_id == "bucket-b"
    )
    wrong_contract = ScanSourceContract.for_scan(
        contract_key=kms_contract.contract_key,
        contract_version=kms_contract.contract_version,
        scan_id=kms_contract.scan_id,
        collection_account_id=kms_contract.collection_account_id,
        phase=kms_contract.phase,
        subject=wrong_subject,
        evidence_kind=kms_contract.evidence_kind,
        collector=kms_contract.collector,
        collector_version=kms_contract.collector_version,
        source_api=kms_contract.source_api,
        cardinality=kms_contract.cardinality,
    )
    wrong_outcome = _outcome(
        wrong_contract,
        kms_artifact,
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )

    with pytest.raises(ValidationError, match="canonical source bucket"):
        _graph(
            source_contracts=tuple(
                wrong_contract if item is kms_contract else item for item in contracts
            ),
            artifacts=artifacts,
            source_outcomes=tuple(
                wrong_outcome if item is kms_outcome else item for item in outcomes
            ),
            relationships=relationships,
        )


@pytest.mark.parametrize(
    "key_update",
    [
        {"enabled": True, "key_state": "Disabled"},
        {"key_state": "BOGUS"},
        {"origin": "BOGUS"},
        {"key_usage": "BOGUS"},
        {"key_spec": "BOGUS"},
        {"key_spec": "HMAC_256", "key_usage": "ENCRYPT_DECRYPT"},
    ],
)
def test_s3_kms_replay_rejects_invalid_or_contradictory_metadata(
    key_update: dict[str, object],
) -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
    )
    kms_outcome = next(item for item in outcomes if item.collector == "kms.keys")
    kms_artifact = next(
        item for item in artifacts if item.evidence_reference == kms_outcome.evidence_reference
    )
    payload = kms_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    key = payload["key"]
    assert isinstance(key, dict)
    rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
        artifacts=artifacts,
        outcomes=outcomes,
        evidence_kind=kms_outcome.evidence_kind,
        payload={**payload, "key": {**key, **key_update}},
    )

    with pytest.raises(ValidationError, match="KMS DescribeKey evidence metadata"):
        _graph(
            source_contracts=contracts,
            artifacts=rebound_artifacts,
            source_outcomes=rebound_outcomes,
            relationships=relationships,
        )


def test_kms_outer_artifact_is_exact_and_bound_to_referencing_buckets() -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
    )
    kms_outcome = next(item for item in outcomes if item.collector == "kms.keys")
    kms_artifact = next(
        item for item in artifacts if item.evidence_reference == kms_outcome.evidence_reference
    )
    payload = kms_artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    invalid_payloads = [
        {**payload, "unknown": True},
        {**payload, "complete": False},
        {**payload, "failure_category": "MALFORMED_RESPONSE"},
        {**payload, "source_bucket_names": ["other-bucket"]},
    ]

    for invalid_payload in invalid_payloads:
        rebound_artifacts, rebound_outcomes = _rebind_graph_artifact(
            artifacts=artifacts,
            outcomes=outcomes,
            evidence_kind=kms_outcome.evidence_kind,
            payload=invalid_payload,
        )
        with pytest.raises(ValidationError, match="KMS DescribeKey evidence metadata"):
            _graph(
                source_contracts=contracts,
                artifacts=rebound_artifacts,
                source_outcomes=rebound_outcomes,
                relationships=relationships,
            )


def test_s3_kms_manifest_rejects_duplicate_extra_and_mismatched_edges() -> None:
    contracts, artifacts, outcomes, relationships = _s3_kms_graph_parts(
        bucket_names=("bucket-a",),
    )
    relationship = relationships[0]
    with pytest.raises(ValidationError, match="contains duplicates"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(relationship, relationship),
        )

    extra_source = RelationshipEndpoint.for_aws_resource(
        aws_account_id=ACCOUNT_ID,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="extra-bucket",
        scope=ResourceScope.REGIONAL,
        region=REGION,
        observed_in_scan_id=SCAN_ID,
    )
    extra = ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.ENCRYPTED_WITH,
        source=extra_source,
        target=relationship.target,
        resolution=RelationshipResolution.RESOLVED,
        provenance=relationship.provenance,
    )
    with pytest.raises(ValidationError, match="relationship manifest"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(relationship, extra),
        )

    mismatched = ResourceRelationship.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        relationship_type=RelationshipType.ENCRYPTED_WITH,
        source=relationship.source,
        target=UnresolvedRelationshipTarget.for_aws_reference(
            service="kms",
            resource_type="kms_key",
            aws_resource_id="alias/wrong",
            scope=ResourceScope.REGIONAL,
            region=REGION,
        ),
        resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
        provenance=relationship.provenance,
    )
    with pytest.raises(ValidationError, match="relationship manifest"):
        _graph(
            source_contracts=contracts,
            artifacts=artifacts,
            source_outcomes=outcomes,
            relationships=(mismatched,),
        )


def test_off_region_s3_bucket_requires_exact_authoritative_location_evidence() -> None:
    bucket = _s3_bucket(region="us-west-2")
    account_subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    discovery_contract = ScanSourceContract.for_scan(
        contract_key="s3.buckets.discovery",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=account_subject,
        evidence_kind="s3.buckets.discovery",
        collector="s3.buckets",
        collector_version="1.0.0",
        source_api="s3:ListAllMyBuckets",
        cardinality=EvidenceCardinality.COLLECTION,
    )
    discovery_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/buckets",
        evidence_schema="s3.buckets.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "buckets": [
                {
                    "bucket_name": bucket.aws_resource_id,
                    "bucket_arn": f"arn:aws:s3:::{bucket.aws_resource_id}",
                    "creation_date": None,
                    "list_bucket_region": "us-west-2",
                }
            ],
            "bucket_names": [bucket.aws_resource_id],
            "resource_count": 1,
            "discarded_item_count": 0,
            "complete": True,
            "failure_category": None,
        },
    )
    discovery_outcome = _outcome(discovery_contract, discovery_artifact)
    bucket_subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=SCAN_ID,
        aws_account_id=ACCOUNT_ID,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=bucket.aws_resource_id,
        scope=ResourceScope.REGIONAL,
        region="us-west-2",
    )
    location_contract = ScanSourceContract.for_scan(
        contract_key="s3.bucket-location",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=bucket_subject,
        evidence_kind="s3.bucket-location",
        collector="s3.bucket-location",
        collector_version="1.0.0",
        source_api="s3:GetBucketLocation",
        cardinality=EvidenceCardinality.SINGLE,
        identity_authoritative=True,
    )
    location_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/bucket-us-west-2/location",
        evidence_schema="s3.bucket-location",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "bucket_name": bucket.aws_resource_id,
            "bucket_arn": f"arn:aws:s3:::{bucket.aws_resource_id}",
            "list_bucket_region": "us-west-2",
            "location_constraint": "us-west-2",
            "bucket_region": "us-west-2",
            "complete": True,
            "failure_category": None,
        },
    )
    location_outcome = _outcome(location_contract, location_artifact)
    account_contract, account_artifact, account_outcome = _s3_account_public_access_block()

    with pytest.raises(ValidationError, match="location manifest is incomplete"):
        _graph(
            source_contracts=(discovery_contract, account_contract),
            artifacts=(discovery_artifact, account_artifact),
            source_outcomes=(discovery_outcome, account_outcome),
            relationships=(),
        )

    non_authoritative_location = ScanSourceContract.for_scan(
        contract_key="s3.bucket-location",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=bucket_subject,
        evidence_kind="s3.bucket-location",
        collector="s3.bucket-location",
        collector_version="1.0.0",
        source_api="s3:GetBucketLocation",
        cardinality=EvidenceCardinality.SINGLE,
    )
    with pytest.raises(ValidationError, match="source contract manifest"):
        _graph(
            source_contracts=(
                discovery_contract,
                non_authoritative_location,
                account_contract,
            ),
            artifacts=(discovery_artifact, location_artifact, account_artifact),
            source_outcomes=(discovery_outcome, location_outcome, account_outcome),
            relationships=(),
        )

    complete_contracts, complete_artifacts, complete_outcomes = _complete_s3_manifest_parts(
        bucket_names=(bucket.aws_resource_id,),
        region="us-west-2",
    )
    complete = _graph(
        source_contracts=complete_contracts,
        artifacts=complete_artifacts,
        source_outcomes=complete_outcomes,
        relationships=(),
    )
    region_evidence = reconstruct_s3_bucket_region_evidence(
        contracts=complete.source_contracts,
        outcomes=complete.source_outcomes,
        artifacts=complete.artifacts,
    )
    assert region_evidence is not None
    assert region_evidence.complete
    assert region_evidence.region_for(bucket.aws_resource_id) == "us-west-2"


def test_legacy_s3_bucket_survives_failed_5e_location_without_expanding_analyzer() -> None:
    bucket = _s3_bucket(region="us-west-2")
    account_subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    discovery_contract = ScanSourceContract.for_scan(
        contract_key="s3.buckets.discovery",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=account_subject,
        evidence_kind="s3.buckets.discovery",
        collector="s3.buckets",
        collector_version="1.0.0",
        source_api="s3:ListAllMyBuckets",
        cardinality=EvidenceCardinality.COLLECTION,
    )
    discovery_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/legacy-location-bucket",
        evidence_schema="s3.buckets.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "buckets": [
                {
                    "bucket_name": bucket.aws_resource_id,
                    "bucket_arn": f"arn:aws:s3:::{bucket.aws_resource_id}",
                    "creation_date": None,
                    "list_bucket_region": bucket.region,
                }
            ],
            "bucket_names": [bucket.aws_resource_id],
            "resource_count": 1,
            "discarded_item_count": 0,
            "complete": True,
            "failure_category": None,
        },
    )
    discovery_outcome = _outcome(discovery_contract, discovery_artifact)
    location_contract, location_artifact, location_outcome = _failed_s3_location(bucket)
    analyzer_contract = _access_analyzer_contract(
        region=REGION,
        allows_supplemental_region=False,
    )
    analyzer_artifact = _access_analyzer_artifact(REGION)
    analyzer_outcome = _outcome(analyzer_contract, analyzer_artifact)
    account_contract, account_artifact, account_outcome = _s3_account_public_access_block()
    graph = _graph(
        source_contracts=(
            discovery_contract,
            location_contract,
            account_contract,
            analyzer_contract,
        ),
        artifacts=(
            discovery_artifact,
            location_artifact,
            account_artifact,
            analyzer_artifact,
        ),
        source_outcomes=(
            discovery_outcome,
            location_outcome,
            account_outcome,
            analyzer_outcome,
        ),
        relationships=(),
    )

    assert _inventory(graph=graph, resources=(bucket,), requested_region=REGION).resource_count == 1

    bucket_subject = ResourceEvidenceSubject.for_aws_resource(
        scan_id=SCAN_ID,
        aws_account_id=ACCOUNT_ID,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=bucket.aws_resource_id,
        scope=ResourceScope.REGIONAL,
        region=bucket.region,
    )
    tags_contract = ScanSourceContract.for_scan(
        contract_key="s3.bucket-tags",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=bucket_subject,
        evidence_kind="s3.bucket-tags",
        collector="s3.bucket-tags",
        collector_version="1.0.0",
        source_api="s3:GetBucketTagging",
        cardinality=EvidenceCardinality.SINGLE,
    )
    tags_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/legacy-location-bucket/tags",
        evidence_schema="s3.bucket-tags",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "bucket_name": bucket.aws_resource_id,
            "bucket_arn": f"arn:aws:s3:::{bucket.aws_resource_id}",
            "bucket_region": bucket.region,
            "value": [],
            "legacy_projection": None,
            "complete": True,
            "expected_absence": False,
            "failure_category": None,
        },
    )
    tags_outcome = _outcome(tags_contract, tags_artifact)
    with pytest.raises(ValidationError, match="artifact identity is inconsistent"):
        _graph(
            source_contracts=(
                discovery_contract,
                location_contract,
                account_contract,
                analyzer_contract,
                tags_contract,
            ),
            artifacts=(
                discovery_artifact,
                location_artifact,
                account_artifact,
                analyzer_artifact,
                tags_artifact,
            ),
            source_outcomes=(
                discovery_outcome,
                location_outcome,
                account_outcome,
                analyzer_outcome,
                tags_outcome,
            ),
            relationships=(),
        )
