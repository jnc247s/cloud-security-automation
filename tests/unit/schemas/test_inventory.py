"""Tests for in-memory inventory snapshots."""

import json
from datetime import UTC, datetime

from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope


def test_inventory_snapshot_counts_and_serializes_resources() -> None:
    """A snapshot is deterministic, JSON serializable, and non-persistent."""

    resource = NormalizedResource(
        account_id="123456789012",
        service="s3",
        resource_type="bucket",
        aws_resource_id="cloud-security-fixture",
        arn="arn:aws:s3:::cloud-security-fixture",
        name="cloud-security-fixture",
        scope=ResourceScope.REGIONAL,
        region="us-west-2",
        tags={"Environment": "test"},
        configuration={"encryption": None},
        raw_configuration={"Name": "cloud-security-fixture"},
    )
    snapshot = InventorySnapshot(
        account_id="123456789012",
        requested_region="us-east-1",
        collected_at=datetime(2026, 9, 2, 15, 0, tzinfo=UTC),
        resources=(resource,),
    )

    payload = json.loads(snapshot.model_dump_json())

    assert snapshot.resource_count == 1
    assert payload["account_id"] == "123456789012"
    assert payload["requested_region"] == "us-east-1"
    assert payload["collected_at"] == "2026-09-02T15:00:00Z"
    assert payload["resources"][0]["aws_resource_id"] == "cloud-security-fixture"
