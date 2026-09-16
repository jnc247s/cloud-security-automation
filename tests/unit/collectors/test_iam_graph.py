"""Focused tests for Sprint 5C graph-aware IAM evidence collection."""

import json
from datetime import UTC, datetime
from urllib.parse import quote
from uuid import UUID

import pytest

from app.assessment.models import AssessmentResult
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE
from app.assessment.relationships import RelationshipType
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceSourceState,
    ResourceEvidenceSubject,
)
from app.collectors.base import CollectionContext, CollectorEvidenceError
from app.collectors.iam import IAMUserCollector, _decode_policy_document
from app.rules.identity import IAMUserWithoutMFARule
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import ResourceScope
from app.services.inventory_service import InventoryService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

_ACCOUNT_ID = "123456789012"
_COLLECTED_AT = datetime(2026, 9, 16, 12, tzinfo=UTC)
_CREATED_AT = datetime(2024, 1, 1, tzinfo=UTC)
_SCAN_ID = UUID("00000000-0000-4000-8000-00000000005c")
_LOCAL_POLICY_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:policy/Admin"
_AWS_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def _context() -> CollectionContext:
    return CollectionContext(
        scan_id=_SCAN_ID,
        collection_account_id=_ACCOUNT_ID,
        region="us-east-1",
        collected_at=_COLLECTED_AT,
    )


def _collector(client: FakeAWSClient) -> IAMUserCollector:
    return IAMUserCollector(
        FakeClientProvider({("iam", "us-east-1"): client}, account_id=_ACCOUNT_ID)
    )


def _empty_client() -> FakeAWSClient:
    return FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": []}]),
            "list_groups": FakePaginator([{"Groups": []}]),
            "list_roles": FakePaginator([{"Roles": []}]),
            "list_policies": FakePaginator([{"Policies": []}]),
        }
    )


def test_empty_graph_declares_all_global_iam_discovery_sources() -> None:
    client = _empty_client()

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert result.resources == ()
    assert result.relationships == ()
    assert {
        (
            outcome.evidence_kind,
            outcome.collector,
            outcome.collector_version,
            outcome.source_api,
        )
        for outcome in result.source_outcomes
    } == {
        ("iam.users.discovery", "iam.users", "2.0.0", "iam:ListUsers"),
        ("iam.groups.discovery", "iam.groups", "2.0.0", "iam:ListGroups"),
        ("iam.roles.discovery", "iam.roles", "2.0.0", "iam:ListRoles"),
        (
            "iam.customer-managed-policies.discovery",
            "iam.policies",
            "2.0.0",
            "iam:ListPolicies",
        ),
    }
    assert all(outcome.state is EvidenceSourceState.PRESENT for outcome in result.source_outcomes)
    assert all(
        isinstance(outcome.subject, AccountEvidenceSubject)
        and outcome.subject.scope is ResourceScope.GLOBAL
        and outcome.subject.region is None
        for outcome in result.source_outcomes
    )


def _complete_graph_client(*, groups_error: BaseException | None = None) -> FakeAWSClient:
    user = {
        "Path": "/engineering/",
        "UserName": "alice",
        "UserId": "AIDAALICE",
        "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/engineering/alice",
        "CreateDate": _CREATED_AT,
    }
    group = {
        "Path": "/",
        "GroupName": "admins",
        "GroupId": "AGPAADMINS",
        "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:group/admins",
        "CreateDate": _CREATED_AT,
    }
    role = {
        "Path": "/",
        "RoleName": "reader",
        "RoleId": "AROAREADER",
        "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:role/reader",
        "CreateDate": _CREATED_AT,
        "MaxSessionDuration": 3600,
    }
    local_policy = {
        "PolicyName": "Admin",
        "PolicyId": "ANPALOCAL",
        "Arn": _LOCAL_POLICY_ARN,
        "Path": "/",
        "DefaultVersionId": "v1",
        "IsAttachable": True,
        "AttachmentCount": 2,
        "PermissionsBoundaryUsageCount": 1,
    }
    allow_document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    trust_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    return FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": [user]}]),
            "list_groups": FakePaginator([{"Groups": [group]}], error=groups_error),
            "list_roles": FakePaginator([{"Roles": [role]}]),
            "list_policies": FakePaginator([{"Policies": [local_policy]}]),
            "list_user_tags": FakePaginator([{"Tags": [{"Key": "Owner", "Value": "security"}]}]),
            "list_mfa_devices": FakePaginator(
                [
                    {
                        "MFADevices": [
                            {
                                "UserName": "alice",
                                "SerialNumber": f"arn:aws:iam::{_ACCOUNT_ID}:mfa/alice",
                                "EnableDate": _CREATED_AT,
                            }
                        ]
                    }
                ]
            ),
            "list_access_keys": FakePaginator(
                [
                    {
                        "AccessKeyMetadata": [
                            {
                                "UserName": "alice",
                                "AccessKeyId": "AKIAEXAMPLEONLY",
                                "Status": "Active",
                                "CreateDate": _CREATED_AT,
                            }
                        ]
                    }
                ]
            ),
            "list_attached_user_policies": FakePaginator(
                [
                    {
                        "AttachedPolicies": [
                            {"PolicyName": "Admin", "PolicyArn": _LOCAL_POLICY_ARN},
                            {
                                "PolicyName": "ReadOnlyAccess",
                                "PolicyArn": _AWS_POLICY_ARN,
                            },
                        ]
                    }
                ]
            ),
            "list_user_policies": FakePaginator([{"PolicyNames": ["Emergency"]}]),
            "get_group": FakePaginator([{"Group": group, "Users": [user]}]),
            "list_attached_group_policies": FakePaginator([{"AttachedPolicies": []}]),
            "list_group_policies": FakePaginator([{"PolicyNames": []}]),
            "list_role_tags": FakePaginator([{"Tags": [{"Key": "Owner", "Value": "platform"}]}]),
            "list_attached_role_policies": FakePaginator(
                [{"AttachedPolicies": [{"PolicyName": "Admin", "PolicyArn": _LOCAL_POLICY_ARN}]}]
            ),
            "list_role_policies": FakePaginator([{"PolicyNames": ["Emergency"]}]),
            "list_policy_tags": FakePaginator([{"Tags": [{"Key": "Owner", "Value": "security"}]}]),
        },
        responses={
            "get_access_key_last_used": [
                {
                    "UserName": "alice",
                    "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"},
                }
            ],
            "get_user": [
                {
                    "User": {
                        **user,
                        "PermissionsBoundary": {
                            "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                            "PermissionsBoundaryArn": _AWS_POLICY_ARN,
                        },
                    }
                }
            ],
            "get_user_policy": [
                {
                    "UserName": "alice",
                    "PolicyName": "Emergency",
                    "PolicyDocument": quote(json.dumps(allow_document), safe=""),
                }
            ],
            "get_role": [
                {
                    "Role": {
                        **role,
                        "AssumeRolePolicyDocument": trust_document,
                        "PermissionsBoundary": {
                            "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                            "PermissionsBoundaryArn": _LOCAL_POLICY_ARN,
                        },
                    }
                }
            ],
            "get_role_policy": [
                {
                    "RoleName": "reader",
                    "PolicyName": "Emergency",
                    "PolicyDocument": allow_document,
                }
            ],
            "get_policy": [
                {"Policy": local_policy},
                {
                    "Policy": {
                        "PolicyName": "ReadOnlyAccess",
                        "PolicyId": "ANPAAWSMANAGED",
                        "Arn": _AWS_POLICY_ARN,
                        "Path": "/",
                        "DefaultVersionId": "v5",
                        "IsAttachable": True,
                    }
                },
            ],
            "get_policy_version": [
                {
                    "PolicyVersion": {
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "CreateDate": _CREATED_AT,
                        "Document": allow_document,
                    }
                },
                {
                    "PolicyVersion": {
                        "VersionId": "v5",
                        "IsDefaultVersion": True,
                        "CreateDate": _CREATED_AT,
                        "Document": allow_document,
                    }
                },
            ],
        },
    )


@pytest.mark.parametrize(
    ("operation", "items_key", "resource_type", "evidence_kind", "wrong_arn"),
    (
        (
            "list_users",
            "Users",
            "iam_user",
            "iam.users.discovery",
            f"arn:aws:iam::{_ACCOUNT_ID}:user/engineering/bob",
        ),
        (
            "list_groups",
            "Groups",
            "iam_group",
            "iam.groups.discovery",
            f"arn:aws:iam::{_ACCOUNT_ID}:group/operators",
        ),
        (
            "list_roles",
            "Roles",
            "iam_role",
            "iam.roles.discovery",
            f"arn:aws:iam::{_ACCOUNT_ID}:role/writer",
        ),
    ),
)
def test_identity_discovery_rejects_arn_that_disagrees_with_path_and_name(
    operation: str,
    items_key: str,
    resource_type: str,
    evidence_kind: str,
    wrong_arn: str,
) -> None:
    client = _complete_graph_client()
    client._paginators[operation][0].pages[0][items_key][0]["Arn"] = wrong_arn

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert not any(resource.resource_type == resource_type for resource in result.resources)
    outcome = next(item for item in result.source_outcomes if item.evidence_kind == evidence_kind)
    assert outcome.state is EvidenceSourceState.MALFORMED
    artifact = next(item for item in result.artifacts if item.evidence_schema == evidence_kind)
    assert artifact.normalized_payload["discarded_item_count"] == 1


@pytest.mark.parametrize(("field", "invalid"), (("Path", "/wrong/"), ("PolicyName", "Other")))
def test_managed_policy_discovery_rejects_path_or_name_that_disagrees_with_arn(
    field: str,
    invalid: str,
) -> None:
    client = _complete_graph_client()
    policies = client._paginators["list_policies"][0].pages[0]["Policies"]
    policies[0] = {**policies[0], field: invalid}

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    outcome = next(
        item
        for item in result.source_outcomes
        if item.evidence_kind == "iam.customer-managed-policies.discovery"
    )
    assert outcome.state is EvidenceSourceState.MALFORMED
    artifact = next(
        item
        for item in result.artifacts
        if item.evidence_schema == "iam.customer-managed-policies.discovery"
    )
    assert artifact.normalized_payload["resource_ids"] == ()


@pytest.mark.parametrize(("field", "invalid"), (("Path", "/wrong/"), ("PolicyName", "Other")))
def test_managed_policy_metadata_rejects_path_or_name_that_disagrees_with_arn(
    field: str,
    invalid: str,
) -> None:
    client = _complete_graph_client()
    response = client._responses["get_policy"][0]
    response["Policy"] = {**response["Policy"], field: invalid}

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    outcome = next(
        item
        for item in result.source_outcomes
        if item.evidence_kind == "iam.managed-policy.metadata"
        and isinstance(item.subject, ResourceEvidenceSubject)
        and item.subject.aws_resource_id == _LOCAL_POLICY_ARN
    )
    assert outcome.state is EvidenceSourceState.MALFORMED
    policy = next(item for item in result.resources if item.aws_resource_id == _LOCAL_POLICY_ARN)
    assert policy.configuration["metadata_complete"] is False


@pytest.mark.parametrize(
    ("operation", "result_key", "evidence_kind", "source_resource_id"),
    (
        ("get_user", "User", "iam.user.profile", "AIDAALICE"),
        ("get_role", "Role", "iam.role.profile", "AROAREADER"),
    ),
)
def test_permissions_boundary_rejects_policy_arn_with_empty_final_name(
    operation: str,
    result_key: str,
    evidence_kind: str,
    source_resource_id: str,
) -> None:
    client = _complete_graph_client()
    profile = client._responses[operation][0][result_key]
    profile["PermissionsBoundary"]["PermissionsBoundaryArn"] = (
        "arn:aws:iam::aws:policy/service-role/"
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    outcome = next(item for item in result.source_outcomes if item.evidence_kind == evidence_kind)
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert not any(
        item.aws_resource_id == "arn:aws:iam::aws:policy/service-role/" for item in result.resources
    )
    assert not any(
        item.relationship_type is RelationshipType.PERMISSIONS_BOUNDARY
        and item.source.aws_resource_id == source_resource_id
        for item in result.relationships
    )


def test_collects_complete_identity_policy_graph_without_secret_material() -> None:
    result = _collector(_complete_graph_client()).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    resource_types = [resource.resource_type for resource in result.resources]
    assert resource_types.count("iam_user") == 1
    assert resource_types.count("iam_group") == 1
    assert resource_types.count("iam_role") == 1
    assert resource_types.count("iam_mfa_device") == 1
    assert resource_types.count("iam_access_key") == 1
    assert resource_types.count("iam_customer_managed_policy") == 1
    assert resource_types.count("iam_aws_managed_policy") == 1
    assert resource_types.count("iam_managed_policy_version") == 2
    assert resource_types.count("iam_inline_policy") == 2

    relationship_types = [item.relationship_type for item in result.relationships]
    assert RelationshipType.MEMBER_OF_GROUP in relationship_types
    assert RelationshipType.HAS_MFA_DEVICE in relationship_types
    assert RelationshipType.HAS_ACCESS_KEY in relationship_types
    assert relationship_types.count(RelationshipType.ATTACHED_MANAGED_POLICY) == 3
    assert relationship_types.count(RelationshipType.ATTACHED_INLINE_POLICY) == 2
    assert relationship_types.count(RelationshipType.PERMISSIONS_BOUNDARY) == 2
    assert relationship_types.count(RelationshipType.SELECTS_DEFAULT_VERSION) == 2

    inline_ids = {
        resource.aws_resource_id
        for resource in result.resources
        if resource.resource_type == "iam_inline_policy"
    }
    assert len(inline_ids) == 2
    assert all(identifier.startswith("{") for identifier in inline_ids)
    version_ids = {
        resource.aws_resource_id
        for resource in result.resources
        if resource.resource_type == "iam_managed_policy_version"
    }
    assert len(version_ids) == 2

    access_key = next(
        resource for resource in result.resources if resource.resource_type == "iam_access_key"
    )
    assert access_key.configuration["last_used_state"] == "no_recorded_use"
    assert access_key.configuration["observed_at"] == _COLLECTED_AT.isoformat()
    assert any(
        outcome.evidence_kind == "iam.access-key.last-used"
        and outcome.state is EvidenceSourceState.EXPECTED_ABSENCE
        for outcome in result.source_outcomes
    )

    role = next(resource for resource in result.resources if resource.resource_type == "iam_role")
    assert role.configuration["trust_policy_document"]["Statement"][0]["Action"] == (
        "sts:AssumeRole"
    )
    artifacts = [artifact.model_dump(mode="json") for artifact in result.artifacts]
    serialized = str(artifacts).casefold()
    assert "secretaccesskey" not in serialized
    assert "sessiontoken" not in serialized


def test_graph_requires_status_and_creation_time_without_weakening_direct_compatibility() -> None:
    user = {
        "Path": "/",
        "UserName": "alice",
        "UserId": "AIDAALICE",
        "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/alice",
        "CreateDate": _CREATED_AT,
    }
    client = FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": [user]}]),
            "list_groups": FakePaginator([{"Groups": []}]),
            "list_roles": FakePaginator([{"Roles": []}]),
            "list_policies": FakePaginator([{"Policies": []}]),
            "list_user_tags": FakePaginator([{"Tags": []}]),
            "list_mfa_devices": FakePaginator([{"MFADevices": []}]),
            "list_access_keys": FakePaginator(
                [{"AccessKeyMetadata": [{"UserName": "alice", "AccessKeyId": "AKIAINCOMPLETE"}]}]
            ),
            "list_attached_user_policies": FakePaginator([{"AttachedPolicies": []}]),
            "list_user_policies": FakePaginator([{"PolicyNames": []}]),
        },
        responses={"get_user": [{"User": user}]},
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert [resource.resource_type for resource in result.resources] == ["iam_user"]
    access_key_outcome = next(
        outcome
        for outcome in result.source_outcomes
        if outcome.evidence_kind == "iam.user.access-keys"
    )
    assert access_key_outcome.state is EvidenceSourceState.MALFORMED
    assert client.calls[0].operation_name == "get_user"


def test_complete_fixture_builds_a_valid_resolved_inventory_graph() -> None:
    client = _complete_graph_client()
    provider = FakeClientProvider(
        {("iam", "us-east-1"): client},
        account_id=_ACCOUNT_ID,
    )

    snapshot = InventoryService(
        provider,
        collectors=(IAMUserCollector(provider),),
    ).collect(scan_id=_SCAN_ID)

    assert snapshot.evidence_graph is not None
    assert snapshot.collection_status("iam_users") is CollectionStatus.SUCCEEDED
    assert len(snapshot.evidence_graph.relationships) == 12
    assert all(
        relationship.resolution.value == "RESOLVED"
        for relationship in snapshot.evidence_graph.relationships
    )


def test_cross_account_virtual_mfa_arn_is_rejected_without_false_iam_001_pass() -> None:
    client = _complete_graph_client()
    list_mfa_devices = client._paginators["list_mfa_devices"][0]
    list_mfa_devices.pages[0]["MFADevices"][0]["SerialNumber"] = (
        "arn:aws:iam::999999999999:mfa/alice"
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert not any(resource.resource_type == "iam_mfa_device" for resource in result.resources)
    mfa_outcome = next(
        outcome
        for outcome in result.source_outcomes
        if outcome.evidence_kind == "iam.user.mfa-devices"
    )
    assert mfa_outcome.state is EvidenceSourceState.MALFORMED


def test_virtual_mfa_arn_with_empty_final_name_cannot_produce_iam_001_pass() -> None:
    client = _complete_graph_client()
    client._paginators["list_mfa_devices"][0].pages[0]["MFADevices"][0]["SerialNumber"] = (
        f"arn:aws:iam::{_ACCOUNT_ID}:mfa/team/"
    )
    provider = FakeClientProvider(
        {("iam", "us-east-1"): client},
        account_id=_ACCOUNT_ID,
    )

    snapshot = InventoryService(
        provider,
        collectors=(IAMUserCollector(provider),),
    ).collect(scan_id=_SCAN_ID)

    assert snapshot.collection_status("iam_users") is CollectionStatus.PARTIAL
    assert not any(resource.resource_type == "iam_mfa_device" for resource in snapshot.resources)
    assessments = IAMUserWithoutMFARule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)
    assert len(assessments) == 1
    assert assessments[0].result is AssessmentResult.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    "document",
    (
        {"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]},
        {"Statement": [{"Effect": "Allow", "Resource": "*"}]},
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "NotAction": "iam:*",
                    "Resource": "*",
                }
            ]
        },
        {"Statement": [{"Effect": "Allow", "Action": "*"}]},
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "NotResource": "arn:aws:s3:::example",
                }
            ]
        },
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": "*",
                }
            ]
        },
    ),
)
def test_identity_policy_decoder_rejects_invalid_statement_shapes(
    document: dict[str, object],
) -> None:
    with pytest.raises(CollectorEvidenceError):
        _decode_policy_document(
            document,
            operation_name="get_policy_version",
            fact_path="PolicyVersion.Document",
        )


def test_policy_decoder_rejects_duplicate_json_keys() -> None:
    duplicate = quote(
        '{"Statement":[{"Effect":"Allow","Action":"*","Action":"iam:*","Resource":"*"}]}',
        safe="",
    )

    with pytest.raises(CollectorEvidenceError):
        _decode_policy_document(
            duplicate,
            operation_name="get_policy_version",
            fact_path="PolicyVersion.Document",
        )


@pytest.mark.parametrize("invalid_value", (object(), float("nan")))
def test_policy_decoder_rejects_non_json_or_non_finite_nested_values(
    invalid_value: object,
) -> None:
    document = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": invalid_value}},
            }
        ]
    }

    with pytest.raises(CollectorEvidenceError):
        _decode_policy_document(
            document,
            operation_name="get_policy_version",
            fact_path="PolicyVersion.Document",
        )


def test_inline_policy_response_for_a_different_owner_is_not_attributed() -> None:
    client = _complete_graph_client()
    client._responses["get_user_policy"][0]["UserName"] = "mallory"

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    outcome = next(
        item
        for item in result.source_outcomes
        if item.evidence_kind == "iam.inline-policy.document"
        and item.source_api == "iam:GetUserPolicy"
    )
    assert outcome.state is EvidenceSourceState.MALFORMED
    user_inline = next(
        resource
        for resource in result.resources
        if resource.resource_type == "iam_inline_policy"
        and resource.configuration["owner_resource_type"] == "iam_user"
    )
    assert user_inline.configuration["document_complete"] is False
    assert user_inline.configuration["document"] is None


def test_unrelated_iam_policy_failure_does_not_erase_complete_iam_001_evidence() -> None:
    client = _complete_graph_client(
        groups_error=client_error("AccessDenied", "ListGroups"),
    )
    provider = FakeClientProvider(
        {("iam", "us-east-1"): client},
        account_id=_ACCOUNT_ID,
    )
    snapshot = InventoryService(
        provider,
        collectors=(IAMUserCollector(provider),),
    ).collect(scan_id=_SCAN_ID)

    assert snapshot.collection_status("iam_users") is CollectionStatus.PARTIAL
    assessments = IAMUserWithoutMFARule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)
    assert len(assessments) == 1
    assert assessments[0].result is AssessmentResult.PASS
    assert assessments[0].aws_resource_id == "AIDAALICE"


@pytest.mark.parametrize(
    (
        "operation",
        "items_key",
        "conflict_field",
        "conflict_value",
        "resource_type",
        "parent_evidence_kind",
        "child_evidence_kind",
        "configuration_field",
    ),
    (
        (
            "list_mfa_devices",
            "MFADevices",
            "EnableDate",
            datetime(2025, 1, 1, tzinfo=UTC),
            "iam_mfa_device",
            "iam.user.mfa-devices",
            "iam.mfa-device",
            "mfa_devices",
        ),
        (
            "list_access_keys",
            "AccessKeyMetadata",
            "Status",
            "Inactive",
            "iam_access_key",
            "iam.user.access-keys",
            "iam.access-key",
            "access_keys",
        ),
    ),
)
def test_user_child_identity_conflict_cannot_be_resurrected_by_later_duplicate(
    operation: str,
    items_key: str,
    conflict_field: str,
    conflict_value: object,
    resource_type: str,
    parent_evidence_kind: str,
    child_evidence_kind: str,
    configuration_field: str,
) -> None:
    client = _complete_graph_client()
    items = client._paginators[operation][0].pages[0][items_key]
    original = dict(items[0])
    items.extend(({**original, conflict_field: conflict_value}, dict(original)))

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert not any(resource.resource_type == resource_type for resource in result.resources)
    user = next(resource for resource in result.resources if resource.resource_type == "iam_user")
    assert user.configuration[configuration_field] == []
    outcome = next(
        item for item in result.source_outcomes if item.evidence_kind == parent_evidence_kind
    )
    assert outcome.state is EvidenceSourceState.CONFLICT
    artifact = next(
        item for item in result.artifacts if item.evidence_schema == parent_evidence_kind
    )
    assert artifact.normalized_payload["discarded_item_count"] == 3
    assert not any(item.evidence_kind == child_evidence_kind for item in result.source_outcomes)


def test_group_member_identity_conflict_cannot_be_resurrected_by_later_duplicate() -> None:
    client = _complete_graph_client()
    users = client._paginators["get_group"][0].pages[0]["Users"]
    original = dict(users[0])
    users.extend(({**original, "Path": "/conflicting/"}, dict(original)))

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    group = next(resource for resource in result.resources if resource.resource_type == "iam_group")
    assert group.configuration["member_user_ids"] == []
    outcome = next(
        item for item in result.source_outcomes if item.evidence_kind == "iam.group.members"
    )
    assert outcome.state is EvidenceSourceState.CONFLICT
    artifact = next(
        item for item in result.artifacts if item.evidence_schema == "iam.group.members"
    )
    assert artifact.normalized_payload["discarded_item_count"] == 3
    assert not any(
        item.relationship_type is RelationshipType.MEMBER_OF_GROUP for item in result.relationships
    )


def test_cross_user_mfa_identity_conflict_is_quarantined_and_fails_closed() -> None:
    users = [
        {
            "Path": "/",
            "UserName": name,
            "UserId": user_id,
            "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/{name}",
            "CreateDate": _CREATED_AT,
        }
        for name, user_id in (("alice", "AIDAALICE"), ("bob", "AIDABOB"))
    ]
    shared_serial = f"arn:aws:iam::{_ACCOUNT_ID}:mfa/shared"
    client = FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": users}]),
            "list_groups": FakePaginator([{"Groups": []}]),
            "list_roles": FakePaginator([{"Roles": []}]),
            "list_policies": FakePaginator([{"Policies": []}]),
            "list_user_tags": [
                FakePaginator([{"Tags": []}]),
                FakePaginator([{"Tags": []}]),
            ],
            "list_mfa_devices": [
                FakePaginator(
                    [
                        {
                            "MFADevices": [
                                {
                                    "UserName": user["UserName"],
                                    "SerialNumber": shared_serial,
                                    "EnableDate": _CREATED_AT,
                                }
                            ]
                        }
                    ]
                )
                for user in users
            ],
            "list_access_keys": [
                FakePaginator([{"AccessKeyMetadata": []}]),
                FakePaginator([{"AccessKeyMetadata": []}]),
            ],
            "list_attached_user_policies": [
                FakePaginator([{"AttachedPolicies": []}]),
                FakePaginator([{"AttachedPolicies": []}]),
            ],
            "list_user_policies": [
                FakePaginator([{"PolicyNames": []}]),
                FakePaginator([{"PolicyNames": []}]),
            ],
        },
        responses={"get_user": [{"User": user} for user in users]},
    )
    provider = FakeClientProvider(
        {("iam", "us-east-1"): client},
        account_id=_ACCOUNT_ID,
    )

    snapshot = InventoryService(
        provider,
        collectors=(IAMUserCollector(provider),),
    ).collect(scan_id=_SCAN_ID)

    assert snapshot.collection_status("iam_users") is CollectionStatus.PARTIAL
    assert not any(resource.resource_type == "iam_mfa_device" for resource in snapshot.resources)
    assert snapshot.evidence_graph is not None
    mfa_outcomes = [
        outcome
        for outcome in snapshot.evidence_graph.source_outcomes
        if outcome.evidence_kind == "iam.user.mfa-devices"
    ]
    assert len(mfa_outcomes) == 2
    assert {outcome.state for outcome in mfa_outcomes} == {EvidenceSourceState.CONFLICT}
    assert not any(
        relationship.relationship_type is RelationshipType.HAS_MFA_DEVICE
        for relationship in snapshot.evidence_graph.relationships
    )
    assessments = IAMUserWithoutMFARule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)
    assert len(assessments) == 2
    assert {assessment.result for assessment in assessments} == {
        AssessmentResult.INSUFFICIENT_EVIDENCE
    }
