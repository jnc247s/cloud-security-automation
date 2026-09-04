"""Tests for in-memory inventory snapshots."""

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
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
        scan_id=UUID("0b8bf2d2-cd63-5dca-af97-59f68aa27b32"),
        account_id="123456789012",
        requested_region="us-east-1",
        collected_at=datetime(2026, 9, 2, 15, 0, tzinfo=UTC),
        collector_outcomes=(
            CollectorOutcome(
                collector_name="s3_buckets",
                status=CollectionStatus.SUCCEEDED,
            ),
        ),
        resources=(resource,),
    )

    payload = json.loads(snapshot.model_dump_json())

    assert snapshot.resource_count == 1
    assert payload["account_id"] == "123456789012"
    assert payload["requested_region"] == "us-east-1"
    assert payload["collected_at"] == "2026-09-02T15:00:00Z"
    assert payload["collector_outcomes"] == [
        {"collector_name": "s3_buckets", "status": "SUCCEEDED"}
    ]
    assert payload["resources"][0]["aws_resource_id"] == "cloud-security-fixture"
    assert snapshot.collector_succeeded("s3_buckets")
    assert snapshot.collection_status("iam_users") is None


def test_inventory_snapshot_requires_an_authoritative_scan_uuid() -> None:
    values = {
        "account_id": "123456789012",
        "requested_region": "us-east-1",
        "collected_at": datetime(2026, 9, 2, 15, 0, tzinfo=UTC),
        "collector_outcomes": (),
        "resources": (),
    }

    with pytest.raises(ValidationError, match="scan_id"):
        InventorySnapshot.model_validate(values)

    with pytest.raises(ValidationError, match="scan_id"):
        InventorySnapshot.model_validate({**values, "scan_id": "not-a-scan-uuid"})

    scan_id = UUID("77f0d7c3-d67e-4e65-9bbf-783414355fdb")
    snapshot = InventorySnapshot.model_validate({**values, "scan_id": scan_id})

    assert snapshot.scan_id == scan_id
    assert json.loads(snapshot.model_dump_json())["scan_id"] == str(scan_id)


def test_inventory_snapshot_requires_unique_explicit_collection_coverage() -> None:
    outcome = CollectorOutcome(
        collector_name="s3_buckets",
        status=CollectionStatus.SUCCEEDED,
    )

    with pytest.raises(ValidationError, match="collector outcomes must be unique"):
        InventorySnapshot(
            scan_id=UUID("0b8bf2d2-cd63-5dca-af97-59f68aa27b32"),
            account_id="123456789012",
            requested_region="us-east-1",
            collected_at=datetime(2026, 9, 2, 15, 0, tzinfo=UTC),
            collector_outcomes=(outcome, outcome),
            resources=(),
        )

    with pytest.raises(ValidationError, match="timezone-aware"):
        InventorySnapshot(
            scan_id=UUID("0b8bf2d2-cd63-5dca-af97-59f68aa27b32"),
            account_id="123456789012",
            requested_region="us-east-1",
            collected_at=datetime(2026, 9, 2, 15, 0),
            collector_outcomes=(outcome,),
            resources=(),
        )
