"""Authoritative scan identity is allocated before inventory collection begins."""

from uuid import UUID

import pytest

from app.collectors.base import ResourceCollector
from app.schemas.resource import NormalizedResource
from app.services import inventory_service

SCAN_ID = UUID("77f0d7c3-d67e-4e65-9bbf-783414355fdb")


class RecordingProvider:
    region_name = "us-east-1"

    def __init__(self, events: list[str]) -> None:
        self.events = events

    @property
    def account_id(self) -> str:
        self.events.append("identity")
        return "123456789012"


class RecordingCollector(ResourceCollector):
    collector_name = "recording"

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def collect(self) -> list[NormalizedResource]:
        self.events.append("collection")
        return []


def test_scan_id_is_allocated_before_identity_or_evidence_collection(monkeypatch) -> None:
    events: list[str] = []

    def allocate_scan_id() -> UUID:
        events.append("allocated")
        return SCAN_ID

    monkeypatch.setattr(inventory_service, "uuid4", allocate_scan_id)
    service = inventory_service.InventoryService(
        RecordingProvider(events),
        collectors=(RecordingCollector(events),),
    )

    snapshot = service.collect()

    assert snapshot.scan_id == SCAN_ID
    assert events == ["allocated", "identity", "collection"]


def test_existing_scan_id_is_preserved_without_allocating_another(monkeypatch) -> None:
    events: list[str] = []

    def unexpected_allocation() -> UUID:
        raise AssertionError("A caller-supplied scan ID must remain authoritative")

    monkeypatch.setattr(inventory_service, "uuid4", unexpected_allocation)
    service = inventory_service.InventoryService(
        RecordingProvider(events),
        collectors=(RecordingCollector(events),),
    )

    snapshot = service.collect(scan_id=SCAN_ID)

    assert snapshot.scan_id == SCAN_ID
    assert events == ["identity", "collection"]


def test_identical_inventory_runs_get_distinct_scan_ids() -> None:
    service = inventory_service.InventoryService(RecordingProvider([]), collectors=())

    first = service.collect()
    second = service.collect()

    assert first.scan_id != second.scan_id
    assert first.scan_id.version == second.scan_id.version == 4
    assert first.resources == second.resources == ()


def test_invalid_scan_id_is_rejected_before_any_collection() -> None:
    events: list[str] = []
    service = inventory_service.InventoryService(
        RecordingProvider(events),
        collectors=(RecordingCollector(events),),
    )

    with pytest.raises(TypeError, match="scan_id must be a UUID"):
        service.collect(scan_id="not-a-scan-uuid")

    assert events == []
