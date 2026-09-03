"""Small normalized-resource factories used by offline rule tests."""

from datetime import UTC, datetime
from typing import Any

from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def resource(
    *,
    service: str,
    resource_type: str,
    aws_resource_id: str,
    configuration: dict[str, Any],
    name: str | None = None,
    arn: str | None = None,
    scope: ResourceScope = ResourceScope.REGIONAL,
    region: str | None = REGION,
) -> NormalizedResource:
    """Build a normalized resource without contacting AWS."""

    return NormalizedResource(
        account_id=ACCOUNT_ID,
        service=service,
        resource_type=resource_type,
        aws_resource_id=aws_resource_id,
        arn=arn,
        name=name,
        scope=scope,
        region=region,
        configuration=configuration,
    )


def snapshot(*resources: NormalizedResource) -> InventorySnapshot:
    """Build a deterministic inventory snapshot around supplied resources."""

    return InventorySnapshot(
        account_id=ACCOUNT_ID,
        requested_region=REGION,
        collected_at=datetime(2026, 9, 2, 12, tzinfo=UTC),
        collector_outcomes=tuple(
            CollectorOutcome(collector_name=name, status=CollectionStatus.SUCCEEDED)
            for name in ("security_groups", "s3_buckets", "iam_users", "cloudtrail_trails")
        ),
        resources=resources,
    )
