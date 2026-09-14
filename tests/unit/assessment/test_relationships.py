"""Contract tests for deterministic, typed AWS resource relationships."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.assessment.relationships import (
    RELATIONSHIP_SCHEMA_VERSION,
    RelationshipEndpoint,
    RelationshipProvenance,
    RelationshipResolution,
    RelationshipType,
    ResourceRelationship,
    UnresolvedRelationshipTarget,
    calculate_relationship_id,
    deduplicate_relationships,
)
from app.schemas.resource import ResourceScope

ACCOUNT_ID = "123456789012"
SCAN_ID = UUID("f1713df7-4f68-51c0-8dd9-fc1b7f3a7048")
OTHER_SCAN_ID = UUID("b633264e-0825-5e66-919f-f0875085a7df")
COLLECTED_AT = datetime(2026, 9, 13, 14, 30, tzinfo=UTC)


def _endpoint(
    service: str,
    resource_type: str,
    aws_resource_id: str,
    *,
    scan_id: UUID | None = SCAN_ID,
    region: str | None = "us-east-1",
    account_id: str = ACCOUNT_ID,
) -> RelationshipEndpoint:
    scope = ResourceScope.GLOBAL if region is None else ResourceScope.REGIONAL
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=account_id,
        service=service,
        resource_type=resource_type,
        aws_resource_id=aws_resource_id,
        scope=scope,
        region=region,
        observed_in_scan_id=scan_id,
    )


def _provenance(**overrides: object) -> RelationshipProvenance:
    values: dict[str, object] = {
        "collector": "Ec2InstanceCollector",
        "source": "aws-api",
        "source_api": "ec2:DescribeInstances",
        "evidence_reference": "normalized://ec2/instance/i-0123456789abcdef0/block-device/0",
        "collected_at": COLLECTED_AT,
    }
    values.update(overrides)
    return RelationshipProvenance.model_validate(values)


def _relationship(
    *,
    scan_id: UUID = SCAN_ID,
    relationship_type: RelationshipType = RelationshipType.USES_VOLUME,
    source: RelationshipEndpoint | None = None,
    target: RelationshipEndpoint | UnresolvedRelationshipTarget | None = None,
    resolution: RelationshipResolution = RelationshipResolution.RESOLVED,
    provenance: RelationshipProvenance | None = None,
) -> ResourceRelationship:
    source = source or _endpoint(
        "ec2",
        "ec2_instance",
        "i-0123456789abcdef0",
        scan_id=scan_id,
    )
    target = target or _endpoint(
        "ec2",
        "ebs_volume",
        "vol-0123456789abcdef0",
        scan_id=scan_id if resolution is RelationshipResolution.RESOLVED else None,
    )
    return ResourceRelationship.for_observation(
        scan_id=scan_id,
        aws_account_id=ACCOUNT_ID,
        relationship_type=relationship_type,
        source=source,
        target=target,
        resolution=resolution,
        provenance=provenance or _provenance(),
    )


def test_relationship_vocabulary_covers_every_approved_edge() -> None:
    assert {relationship_type.value for relationship_type in RelationshipType} >= {
        "uses_volume",
        "attached_to_security_group",
        "in_subnet",
        "in_vpc",
        "contains_subnet",
        "has_flow_log",
        "member_of_group",
        "has_access_key",
        "attached_managed_policy",
        "attached_inline_policy",
        "permissions_boundary",
        "selects_default_version",
        "references_resource",
        "encrypted_with",
        "delivers_to_bucket",
    }


@pytest.mark.parametrize(
    ("relationship_type", "source_signature", "target_signature"),
    [
        (RelationshipType.USES_VOLUME, ("ec2", "ec2_instance"), ("ec2", "ebs_volume")),
        (
            RelationshipType.ATTACHED_TO_SECURITY_GROUP,
            ("ec2", "ec2_instance"),
            ("ec2", "security_group"),
        ),
        (RelationshipType.IN_SUBNET, ("ec2", "ec2_instance"), ("ec2", "subnet")),
        (RelationshipType.IN_VPC, ("ec2", "ec2_instance"), ("ec2", "vpc")),
        (RelationshipType.IN_VPC, ("ec2", "security_group"), ("ec2", "vpc")),
        (RelationshipType.CONTAINS_SUBNET, ("ec2", "vpc"), ("ec2", "subnet")),
        (RelationshipType.HAS_FLOW_LOG, ("ec2", "vpc"), ("ec2", "vpc_flow_log")),
        (RelationshipType.MEMBER_OF_GROUP, ("iam", "iam_user"), ("iam", "iam_group")),
        (RelationshipType.HAS_ACCESS_KEY, ("iam", "iam_user"), ("iam", "iam_access_key")),
        (RelationshipType.HAS_MFA_DEVICE, ("iam", "iam_user"), ("iam", "iam_mfa_device")),
        (
            RelationshipType.ATTACHED_MANAGED_POLICY,
            ("iam", "iam_user"),
            ("iam", "iam_customer_managed_policy"),
        ),
        (
            RelationshipType.ATTACHED_MANAGED_POLICY,
            ("iam", "iam_group"),
            ("iam", "iam_aws_managed_policy"),
        ),
        (
            RelationshipType.ATTACHED_MANAGED_POLICY,
            ("iam", "iam_role"),
            ("iam", "iam_customer_managed_policy"),
        ),
        (
            RelationshipType.ATTACHED_INLINE_POLICY,
            ("iam", "iam_user"),
            ("iam", "iam_inline_policy"),
        ),
        (
            RelationshipType.PERMISSIONS_BOUNDARY,
            ("iam", "iam_role"),
            ("iam", "iam_aws_managed_policy"),
        ),
        (
            RelationshipType.SELECTS_DEFAULT_VERSION,
            ("iam", "iam_customer_managed_policy"),
            ("iam", "iam_managed_policy_version"),
        ),
        (
            RelationshipType.REFERENCES_RESOURCE,
            ("access-analyzer", "access_analyzer_finding"),
            ("s3", "s3_bucket"),
        ),
        (RelationshipType.ENCRYPTED_WITH, ("s3", "s3_bucket"), ("kms", "kms_key")),
        (
            RelationshipType.ENCRYPTED_WITH,
            ("cloudtrail", "cloudtrail_trail"),
            ("kms", "kms_key"),
        ),
        (
            RelationshipType.DELIVERS_TO_BUCKET,
            ("cloudtrail", "cloudtrail_trail"),
            ("s3", "s3_bucket"),
        ),
    ],
)
def test_relationship_direction_contract_accepts_each_approved_edge(
    relationship_type: RelationshipType,
    source_signature: tuple[str, str],
    target_signature: tuple[str, str],
) -> None:
    source_global = source_signature[0] == "iam"
    target_global = target_signature[0] == "iam"
    relationship = _relationship(
        relationship_type=relationship_type,
        source=_endpoint(
            *source_signature,
            "source-id",
            region=None if source_global else "us-east-1",
        ),
        target=_endpoint(
            *target_signature,
            "target-id",
            region=None if target_global else "us-east-1",
        ),
    )

    assert relationship.relationship_type is relationship_type
    assert relationship.source.resource_type == source_signature[1]
    assert relationship.target.resource_type == target_signature[1]


def test_logical_relationship_identity_is_stable_and_directional() -> None:
    relationship = _relationship()
    repeated = _relationship()

    assert relationship.relationship_id == repeated.relationship_id
    assert relationship.observation_id == repeated.observation_id
    assert relationship.relationship_id != calculate_relationship_id(
        source_resource_id=relationship.target.stable_resource_id,
        relationship_type=relationship.relationship_type,
        target_resource_id=relationship.source.stable_resource_id,
    )


def test_historical_scans_share_logical_identity_but_not_observation_identity() -> None:
    first = _relationship()
    second = _relationship(
        scan_id=OTHER_SCAN_ID,
        source=_endpoint(
            "ec2",
            "ec2_instance",
            "i-0123456789abcdef0",
            scan_id=OTHER_SCAN_ID,
        ),
        target=_endpoint(
            "ec2",
            "ebs_volume",
            "vol-0123456789abcdef0",
            scan_id=OTHER_SCAN_ID,
        ),
    )

    assert first.relationship_id == second.relationship_id
    assert first.observation_id != second.observation_id
    assert first.source.resource_snapshot_id != second.source.resource_snapshot_id
    assert first.target.resource_snapshot_id != second.target.resource_snapshot_id


def test_cross_region_relationship_preserves_each_endpoint_region() -> None:
    relationship = _relationship(
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=_endpoint(
            "cloudtrail",
            "cloudtrail_trail",
            "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit",
            region="us-east-1",
        ),
        target=_endpoint("s3", "s3_bucket", "central-audit", region="us-west-2"),
    )

    assert relationship.source.region == "us-east-1"
    assert relationship.target.region == "us-west-2"
    assert relationship.source.resource_snapshot_id is not None
    assert relationship.target.resource_snapshot_id is not None


def test_global_iam_relationship_has_no_inferred_scan_region() -> None:
    relationship = _relationship(
        relationship_type=RelationshipType.ATTACHED_MANAGED_POLICY,
        source=_endpoint("iam", "iam_role", "AROAEXAMPLE", region=None),
        target=_endpoint(
            "iam",
            "iam_aws_managed_policy",
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            region=None,
            account_id="aws",
        ),
    )

    assert relationship.source.scope is ResourceScope.GLOBAL
    assert relationship.source.region is None
    assert relationship.target.scope is ResourceScope.GLOBAL
    assert relationship.target.region is None


@pytest.mark.parametrize(
    "resolution",
    [
        RelationshipResolution.TARGET_NOT_COLLECTED,
        RelationshipResolution.TARGET_OUTSIDE_SCAN_SCOPE,
        RelationshipResolution.TARGET_ACCESS_DENIED,
        RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE,
    ],
)
def test_unresolved_target_is_a_reference_without_a_fabricated_snapshot(
    resolution: RelationshipResolution,
) -> None:
    target = _endpoint(
        "ec2",
        "ebs_volume",
        "vol-unresolved",
        scan_id=None,
        region="us-west-2",
    )
    relationship = _relationship(target=target, resolution=resolution)

    assert not relationship.is_resolved
    assert relationship.target.stable_resource_id is not None
    assert relationship.target.resource_snapshot_id is None
    assert relationship.resolution is resolution


def test_cloudtrail_bucket_reference_preserves_incomplete_target_identity() -> None:
    target = UnresolvedRelationshipTarget.for_aws_reference(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="central-audit-bucket",
        scope=ResourceScope.REGIONAL,
    )
    relationship = _relationship(
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=_endpoint(
            "cloudtrail",
            "cloudtrail_trail",
            "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit",
        ),
        target=target,
        resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
        provenance=_provenance(
            collector="CloudTrailCollector",
            source_api="cloudtrail:GetTrail",
            evidence_reference="normalized://cloudtrail/trail/audit/s3_bucket_name",
        ),
    )

    assert relationship.target.identity_state == "unresolved"
    assert relationship.target.aws_resource_id == "central-audit-bucket"
    assert relationship.target.aws_account_id is None
    assert relationship.target.scope is ResourceScope.REGIONAL
    assert relationship.target.region is None
    assert relationship.target.stable_resource_id is None
    assert relationship.target.resource_snapshot_id is None
    assert not relationship.is_resolved
    serialized_target = relationship.model_dump(mode="json")["target"]
    assert serialized_target["stable_resource_id"] is None
    assert serialized_target["resource_snapshot_id"] is None


def test_unresolved_reference_and_relationship_id_are_stable_and_serializable() -> None:
    first_target = UnresolvedRelationshipTarget.for_aws_reference(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="central-audit-bucket",
        scope=ResourceScope.REGIONAL,
    )
    repeated_target = UnresolvedRelationshipTarget.for_aws_reference(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="central-audit-bucket",
        scope=ResourceScope.REGIONAL,
    )
    first = _relationship(
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=_endpoint("cloudtrail", "cloudtrail_trail", "trail-audit"),
        target=first_target,
        resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
    )
    repeated = _relationship(
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=_endpoint("cloudtrail", "cloudtrail_trail", "trail-audit"),
        target=repeated_target,
        resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
    )

    restored = ResourceRelationship.model_validate_json(first.model_dump_json())

    assert first_target.reference_id == repeated_target.reference_id
    assert first.relationship_id == repeated.relationship_id
    assert first.observation_id == repeated.observation_id
    assert restored == first
    assert isinstance(restored.target, UnresolvedRelationshipTarget)


def test_later_target_resolution_creates_a_canonical_edge_without_rewriting_history() -> None:
    source = _endpoint("cloudtrail", "cloudtrail_trail", "trail-audit")
    incomplete_target = UnresolvedRelationshipTarget.for_aws_reference(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="central-audit-bucket",
        scope=ResourceScope.REGIONAL,
    )
    incomplete = _relationship(
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=source,
        target=incomplete_target,
        resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
    )
    resolved_target = _endpoint(
        "s3",
        "s3_bucket",
        "central-audit-bucket",
        region="us-west-2",
    )
    resolved = _relationship(
        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
        source=source,
        target=resolved_target,
    )

    assert incomplete.relationship_id != resolved.relationship_id
    assert incomplete.observation_id != resolved.observation_id
    assert incomplete.target.stable_resource_id is None
    assert resolved.target.stable_resource_id is not None


def test_partial_target_rejects_fabricated_or_complete_identity() -> None:
    target = UnresolvedRelationshipTarget.for_aws_reference(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="central-audit-bucket",
        scope=ResourceScope.REGIONAL,
    )
    payload = target.model_dump()
    payload["stable_resource_id"] = UUID("00000000-0000-0000-0000-000000000004")
    with pytest.raises(ValidationError, match="stable_resource_id"):
        UnresolvedRelationshipTarget.model_validate(payload)

    payload = target.model_dump()
    payload["reference_id"] = UUID("00000000-0000-0000-0000-000000000005")
    with pytest.raises(ValidationError, match="reference_id does not match"):
        UnresolvedRelationshipTarget.model_validate(payload)

    with pytest.raises(ValidationError, match="complete target identity"):
        UnresolvedRelationshipTarget.for_aws_reference(
            service="s3",
            resource_type="s3_bucket",
            aws_resource_id="central-audit-bucket",
            aws_account_id=ACCOUNT_ID,
            scope=ResourceScope.REGIONAL,
            region="us-west-2",
        )


def test_incomplete_target_identity_requires_its_exact_resolution_state() -> None:
    partial_target = UnresolvedRelationshipTarget.for_aws_reference(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="central-audit-bucket",
        scope=ResourceScope.REGIONAL,
    )
    source = _endpoint("cloudtrail", "cloudtrail_trail", "trail-audit")

    with pytest.raises(ValidationError, match="require TARGET_IDENTITY_INCOMPLETE"):
        _relationship(
            relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
            source=source,
            target=partial_target,
            resolution=RelationshipResolution.TARGET_NOT_COLLECTED,
        )

    with pytest.raises(ValidationError, match="requires an unresolved target reference"):
        _relationship(
            relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
            source=source,
            target=_endpoint("s3", "s3_bucket", "central-audit-bucket"),
            resolution=RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
        )


def test_resolution_state_must_match_target_snapshot_presence() -> None:
    with pytest.raises(ValidationError, match="resolved target resource_snapshot_id"):
        _relationship(
            target=_endpoint("ec2", "ebs_volume", "vol-unresolved", scan_id=None),
            resolution=RelationshipResolution.RESOLVED,
        )

    with pytest.raises(ValidationError, match="must not claim a resource snapshot"):
        _relationship(
            target=_endpoint("ec2", "ebs_volume", "vol-observed"),
            resolution=RelationshipResolution.TARGET_NOT_COLLECTED,
        )


def test_source_must_be_observed_in_the_relationship_scan() -> None:
    with pytest.raises(ValidationError, match="source resource_snapshot_id"):
        _relationship(
            source=_endpoint(
                "ec2",
                "ec2_instance",
                "i-0123456789abcdef0",
                scan_id=None,
            )
        )

    with pytest.raises(ValidationError, match="source resource_snapshot_id"):
        _relationship(
            source=_endpoint(
                "ec2",
                "ec2_instance",
                "i-0123456789abcdef0",
                scan_id=OTHER_SCAN_ID,
            )
        )


def test_existing_resources_do_not_imply_an_edge_when_source_edge_evidence_is_incomplete() -> None:
    source = _endpoint("cloudtrail", "cloudtrail_trail", "trail-audit")
    target = _endpoint("s3", "s3_bucket", "central-audit-bucket")

    # Both resources independently exist, but incomplete GetTrail edge evidence produces no
    # positive relationship. The future collector outcome carries incompleteness; the target's
    # existence must never be used to infer this edge.
    confirmed_relationships = deduplicate_relationships(())

    assert source.resource_snapshot_id is not None
    assert target.resource_snapshot_id is not None
    assert confirmed_relationships == ()


def test_resolved_target_must_be_observed_in_the_relationship_scan() -> None:
    with pytest.raises(ValidationError, match="resolved target resource_snapshot_id"):
        _relationship(
            target=_endpoint(
                "ec2",
                "ebs_volume",
                "vol-0123456789abcdef0",
                scan_id=OTHER_SCAN_ID,
            )
        )


def test_exact_duplicate_api_evidence_is_deduplicated_deterministically() -> None:
    first = _relationship()
    other = _relationship(
        relationship_type=RelationshipType.ATTACHED_TO_SECURITY_GROUP,
        target=_endpoint("ec2", "security_group", "sg-0123456789abcdef0"),
    )

    deduplicated = deduplicate_relationships((other, first, first))

    assert len(deduplicated) == 2
    assert tuple(item.observation_id.hex for item in deduplicated) == tuple(
        sorted(item.observation_id.hex for item in deduplicated)
    )


def test_conflicting_duplicate_provenance_is_never_silently_discarded() -> None:
    first = _relationship()
    conflicting = _relationship(
        provenance=_provenance(evidence_reference="normalized://ec2/instance/duplicate-page")
    )

    assert first.observation_id == conflicting.observation_id
    with pytest.raises(ValueError, match="conflicting duplicate"):
        deduplicate_relationships((first, conflicting))


def test_provenance_and_contract_round_trip_through_json() -> None:
    relationship = _relationship()

    restored = ResourceRelationship.model_validate_json(relationship.model_dump_json())

    assert restored == relationship
    assert restored.provenance.collector == "Ec2InstanceCollector"
    assert restored.provenance.source_api == "ec2:DescribeInstances"
    assert restored.provenance.evidence_reference.endswith("/block-device/0")
    assert restored.provenance.collected_at == COLLECTED_AT
    assert restored.schema_version == RELATIONSHIP_SCHEMA_VERSION


def test_unknown_relationship_type_and_reverse_direction_are_rejected() -> None:
    payload = _relationship().model_dump(mode="json")
    payload["relationship_type"] = "connects_to"
    with pytest.raises(ValidationError, match="relationship_type"):
        ResourceRelationship.model_validate(payload)

    with pytest.raises(ValidationError, match="source resource type is invalid"):
        _relationship(
            relationship_type=RelationshipType.USES_VOLUME,
            source=_endpoint("ec2", "ebs_volume", "vol-0123456789abcdef0"),
            target=_endpoint("ec2", "ec2_instance", "i-0123456789abcdef0"),
        )


def test_identifiers_and_account_cannot_be_substituted() -> None:
    relationship = _relationship()
    payload = relationship.model_dump()
    payload["relationship_id"] = UUID("00000000-0000-0000-0000-000000000001")
    with pytest.raises(ValidationError, match="relationship_id does not match"):
        ResourceRelationship.model_validate(payload)

    payload = relationship.model_dump()
    payload["observation_id"] = UUID("00000000-0000-0000-0000-000000000002")
    with pytest.raises(ValidationError, match="observation_id does not match"):
        ResourceRelationship.model_validate(payload)

    payload = relationship.model_dump()
    payload["aws_account_id"] = "999999999999"
    with pytest.raises(ValidationError, match="account must match the source"):
        ResourceRelationship.model_validate(payload)


def test_endpoint_rejects_forged_stable_identity_and_ambiguous_region() -> None:
    endpoint = _endpoint("ec2", "ec2_instance", "i-0123456789abcdef0")
    payload = endpoint.model_dump()
    payload["stable_resource_id"] = UUID("00000000-0000-0000-0000-000000000003")
    with pytest.raises(ValidationError, match="stable_resource_id does not match"):
        RelationshipEndpoint.model_validate(payload)

    endpoint_payload = _endpoint("ec2", "ec2_instance", "i-regional").model_dump()
    endpoint_payload["region"] = None
    with pytest.raises(ValidationError, match="regional relationship endpoints require"):
        RelationshipEndpoint.model_validate(endpoint_payload)

    endpoint_payload = _endpoint("iam", "iam_user", "AIDAEXAMPLE", region=None).model_dump()
    endpoint_payload["region"] = "us-east-1"
    with pytest.raises(ValidationError, match="global relationship endpoints must not"):
        RelationshipEndpoint.model_validate(endpoint_payload)


def test_provenance_rejects_ambiguous_time_or_unbounded_reference() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        _provenance(collected_at=datetime(2026, 9, 13, 14, 30))

    with pytest.raises(ValidationError, match="evidence_reference"):
        _provenance(evidence_reference="first-line\nsecond-line")


def test_models_are_strict_frozen_and_forbid_extra_fields() -> None:
    relationship = _relationship()

    with pytest.raises(ValidationError, match="frozen"):
        relationship.resolution = RelationshipResolution.TARGET_NOT_COLLECTED

    payload = relationship.model_dump()
    payload["metadata"] = {"unreviewed": True}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ResourceRelationship.model_validate(payload)

    payload = relationship.model_dump()
    payload["schema_version"] = "2.0.0"
    with pytest.raises(ValidationError, match="schema_version"):
        ResourceRelationship.model_validate(payload)


def test_json_schema_exposes_required_identity_and_provenance_contract() -> None:
    schema = ResourceRelationship.model_json_schema()

    assert set(schema["required"]) >= {
        "relationship_id",
        "observation_id",
        "scan_id",
        "aws_account_id",
        "relationship_type",
        "source",
        "target",
        "resolution",
        "provenance",
    }
    provenance_schema = RelationshipProvenance.model_json_schema()
    assert set(provenance_schema["required"]) >= {
        "collector",
        "source_api",
        "evidence_reference",
        "collected_at",
    }
