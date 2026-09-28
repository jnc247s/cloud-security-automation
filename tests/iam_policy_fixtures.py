"""Offline IAM-004 responses flow through the existing real IAM collector."""

from collections import deque
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.collectors.iam import IAMUserCollector
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.fakes import FakeClientProvider, FakePaginator
from tests.foundation_fixtures import extended_profile
from tests.iam_credentials_fixtures import OBSERVED
from tests.unit.collectors.test_iam_graph import _complete_graph_client, _empty_client


def policy_client(
    *,
    document=None,
    empty=False,
    boundary_only=False,
    group_inline=False,
    error_operation=None,
    local_version="v1",
    aws_version="v5",
):
    client = _empty_client() if empty else _complete_graph_client()
    if not empty:
        client._paginators["list_policies"][0].pages[0]["Policies"][0]["DefaultVersionId"] = (
            local_version
        )
        client._responses["get_policy"][0]["Policy"]["DefaultVersionId"] = local_version
        client._responses["get_policy_version"][0]["PolicyVersion"]["VersionId"] = local_version
        client._responses["get_policy"][1]["Policy"]["DefaultVersionId"] = aws_version
        client._responses["get_policy_version"][1]["PolicyVersion"]["VersionId"] = aws_version
    if document is not None and not empty:
        for operation in ("get_user_policy", "get_role_policy"):
            client._responses[operation][0]["PolicyDocument"] = document
        for response in client._responses["get_policy_version"]:
            response["PolicyVersion"]["Document"] = document
    if boundary_only:
        client._paginators["list_attached_user_policies"] = deque(
            [
                FakePaginator(
                    [
                        {"AttachedPolicies": []},
                    ]
                )
            ]
        )
        client._paginators["list_attached_role_policies"] = deque(
            [
                FakePaginator(
                    [
                        {"AttachedPolicies": []},
                    ]
                )
            ]
        )
    if group_inline:
        client._paginators["list_group_policies"] = deque(
            [
                FakePaginator(
                    [
                        {"PolicyNames": ["Emergency"]},
                    ]
                )
            ]
        )
        client._responses["get_group_policy"] = deque(
            [
                {
                    "GroupName": "admins",
                    "PolicyName": "Emergency",
                    "PolicyDocument": document
                    or {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}},
                }
            ]
        )
    client._responses["get_account_summary"] = deque(
        [
            {
                "SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1},
            }
        ]
    )
    if error_operation:
        from tests.fakes import client_error

        error = client_error("AccessDenied", error_operation)
        if error_operation in client._paginators:
            client._paginators[error_operation][0].error = error
        else:
            client._responses[error_operation][0] = error
    return client


def policy_profile(**updates):
    return extended_profile(enabled_controls=("IAM-004",), **updates)


def policy_snapshot(**options):
    provider = FakeClientProvider({("iam", "us-east-1"): policy_client(**options)})
    service = InventoryService(provider, collectors=(IAMUserCollector(provider),))
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = OBSERVED
        return service.collect(scan_id=uuid4())


def policy_bundle(*, profile=None, **options):
    snapshot = policy_snapshot(**options)
    profile = profile or policy_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.4.0")
    return {
        "snapshot": snapshot,
        "profile": profile,
        "catalog": catalog,
        "scope": _scope_for(
            snapshot,
            profile,
            catalog,
            requested_services=("iam",),
            requested_collectors=("iam_users",),
            resource_types=(
                "iam_user",
                "iam_group",
                "iam_role",
                "iam_customer_managed_policy",
                "iam_aws_managed_policy",
                "iam_managed_policy_version",
                "iam_inline_policy",
                "iam_access_key",
                "iam_mfa_device",
            ),
        ),
        "assessments": RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        "started_at": OBSERVED - timedelta(seconds=1),
        "completed_at": OBSERVED + timedelta(seconds=1),
        "scanner_version": "6b2-test",
    }
