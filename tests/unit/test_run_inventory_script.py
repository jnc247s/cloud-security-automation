"""Tests for the Sprint 1 inventory command."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

from botocore.exceptions import ProfileNotFound

from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope
from scripts import run_inventory


def test_main_prints_only_inventory_summary(monkeypatch, capsys) -> None:
    settings = SimpleNamespace(log_level="INFO")
    provider = object()
    snapshot = InventorySnapshot(
        account_id="123456789012",
        requested_region="us-east-1",
        collected_at=datetime(2026, 9, 2, 18, 30, tzinfo=UTC),
        resources=(
            NormalizedResource(
                account_id="123456789012",
                service="s3",
                resource_type="s3_bucket",
                aws_resource_id="private-inventory-bucket",
                scope=ResourceScope.REGIONAL,
                region="us-east-1",
                raw_configuration={"sensitive_detail": "must-not-be-printed"},
            ),
        ),
    )
    service = Mock()
    service.collect.return_value = snapshot
    monkeypatch.setattr(run_inventory, "get_settings", lambda: settings)
    monkeypatch.setattr(run_inventory, "configure_logging", Mock())
    provider_factory = Mock(return_value=provider)
    monkeypatch.setattr(run_inventory.Boto3ClientProvider, "from_settings", provider_factory)
    monkeypatch.setattr(run_inventory, "InventoryService", Mock(return_value=service))

    exit_code = run_inventory.main()

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert exit_code == 0
    assert payload == {
        "account_id": "123456789012",
        "requested_region": "us-east-1",
        "collected_at": "2026-09-02T18:30:00+00:00",
        "resource_count": 1,
        "resources_by_service": {"s3": 1},
    }
    assert "must-not-be-printed" not in output
    provider_factory.assert_called_once_with(settings)


def test_main_handles_invalid_profile_without_traceback(monkeypatch, caplog) -> None:
    settings = SimpleNamespace(log_level="INFO")
    monkeypatch.setattr(run_inventory, "get_settings", lambda: settings)
    monkeypatch.setattr(run_inventory, "configure_logging", Mock())
    monkeypatch.setattr(
        run_inventory.Boto3ClientProvider,
        "from_settings",
        Mock(side_effect=ProfileNotFound(profile="missing-profile")),
    )

    exit_code = run_inventory.main()

    assert exit_code == 1
    assert "Unable to resolve the configured AWS identity" in caplog.text
    assert "missing-profile" not in caplog.text
