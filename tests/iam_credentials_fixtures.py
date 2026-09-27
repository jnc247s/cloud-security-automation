"""Safe offline AWS responses shared by 6B.1 rules, persistence and HTTP acceptance."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from app.assessment.iam_controls import IAM_CONTROL_IDS
from app.collectors.iam import IAMUserCollector
from app.collectors.iam_account import IAMAccountEvidenceCollector
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator
from tests.foundation_fixtures import extended_profile

OBSERVED = datetime(2026, 9, 27, 12, tzinfo=UTC)
ACCOUNT = "123456789012"


def iam_client(
    *,
    age=91,
    unused=91,
    keys=True,
    users=True,
    active=True,
    root_key=1,
    root_mfa=0,
    key_error=None,
    usage_error=None,
    summary_error=None,
    discovery_error=None,
    groups_error=None,
):
    user = {
        "Path": "/",
        "UserName": "alice",
        "UserId": "AIDA6BTEST",
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice",
        "CreateDate": OBSERVED - timedelta(days=730),
    }
    usage = {
        "UserName": "alice",
        "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}
        if unused is None
        else {
            "LastUsedDate": OBSERVED - timedelta(days=unused),
            "ServiceName": "s3",
            "Region": "us-east-1",
        },
    }
    return FakeAWSClient(
        paginators={
            "list_users": FakePaginator(
                [{"Users": [user] if users else []}], error=discovery_error
            ),
            "list_groups": FakePaginator([{"Groups": []}], error=groups_error),
            "list_roles": FakePaginator([{"Roles": []}]),
            "list_policies": FakePaginator([{"Policies": []}]),
            "list_user_tags": FakePaginator([{"Tags": []}]),
            "list_mfa_devices": FakePaginator([{"MFADevices": []}]),
            "list_access_keys": FakePaginator(
                [
                    {
                        "AccessKeyMetadata": [
                            {
                                "UserName": "alice",
                                "AccessKeyId": "AKIAEXAMPLEONLY",
                                "Status": "Active" if active else "Inactive",
                                "CreateDate": OBSERVED - timedelta(days=age),
                            }
                        ]
                        if keys
                        else []
                    }
                ],
                error=key_error,
            ),
            "list_attached_user_policies": FakePaginator([{"AttachedPolicies": []}]),
            "list_user_policies": FakePaginator([{"PolicyNames": []}]),
        },
        responses={
            "get_user": [{"User": user}],
            "get_access_key_last_used": [usage_error or usage],
            "get_account_summary": [
                summary_error
                or {
                    "SummaryMap": {
                        "AccountAccessKeysPresent": root_key,
                        "AccountMFAEnabled": root_mfa,
                    }
                }
            ],
        },
    )


def iam_profile(**updates):
    values = {"enabled_controls": IAM_CONTROL_IDS, "max_unused_access_key_days": 90, **updates}
    return extended_profile(**values)


def iam_snapshot(**options):
    provider = FakeClientProvider({("iam", "us-east-1"): iam_client(**options)})
    service = InventoryService(
        provider,
        collectors=(
            IAMAccountEvidenceCollector(provider),
            IAMUserCollector(provider),
        ),
    )
    # Unit fixture clock only. HTTP acceptance uses the actual clock and real executor.
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = OBSERVED
        return service.collect(scan_id=uuid4())


def iam_bundle(*, profile=None, **options):
    snapshot = iam_snapshot(**options)
    profile = profile or iam_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.3.0")
    return {
        "snapshot": snapshot,
        "profile": profile,
        "catalog": catalog,
        "scope": _scope_for(
            snapshot,
            profile,
            catalog,
            requested_services=("iam",),
            requested_collectors=("iam_users", "iam_account_evidence"),
            resource_types=("iam_user", "iam_access_key"),
        ),
        "assessments": RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        "started_at": OBSERVED - timedelta(seconds=1),
        "completed_at": OBSERVED + timedelta(seconds=1),
        "scanner_version": "6b-test",
    }
