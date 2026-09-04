"""Deterministic identifiers shared by assessment and persistence boundaries."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from uuid import UUID, uuid5

from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import ResourceScope

_ASSESSMENT_NAMESPACE = UUID("e62d55d7-baea-57d6-82cd-b8ea6c1d23d6")
_RESOURCE_NAMESPACE = UUID("32d096cd-4a27-54fb-a611-01bcf7678bb4")
_CONTROL_ASSESSMENT_NAMESPACE = UUID("d3a00eb8-f71c-59d4-a1df-c73ab9b7d85d")


def assessment_scan_id(snapshot: InventorySnapshot) -> UUID:
    """Return the scan ID allocated before technical assessment begins."""

    return snapshot.scan_id


def inventory_sha256(snapshot: InventorySnapshot) -> str:
    """Bind assessments to the exact normalized facts and collection coverage they used."""

    document = {
        "scan_id": str(snapshot.scan_id),
        "account_id": snapshot.account_id,
        "requested_region": snapshot.requested_region,
        "collected_at": snapshot.collected_at.astimezone(UTC).isoformat(),
        "collector_outcomes": {
            item.collector_name: item.status.value for item in snapshot.collector_outcomes
        },
        "resources": [
            resource.model_dump(mode="json", exclude={"raw_configuration"})
            for resource in sorted(snapshot.resources, key=lambda item: item.identity)
        ],
    }
    encoded = json.dumps(
        document, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def stable_resource_id(
    *,
    provider: str,
    aws_account_id: str,
    service: str,
    resource_type: str,
    scope: ResourceScope,
    region: str | None,
    aws_resource_id: str,
) -> UUID:
    """Identify a logical cloud resource independently of any one observed state."""

    seed = "\x1f".join(
        (
            provider,
            aws_account_id,
            service,
            resource_type,
            scope.value,
            region or "global",
            aws_resource_id,
        )
    )
    return uuid5(_RESOURCE_NAMESPACE, seed)


def resource_snapshot_id(
    *,
    scan_id: UUID,
    account_id: str,
    service: str,
    resource_type: str,
    scope: ResourceScope,
    region: str | None,
    aws_resource_id: str,
) -> UUID:
    """Identify one resource state observed by one scan."""

    seed = "\x1f".join(
        (
            str(scan_id),
            account_id,
            service,
            resource_type,
            scope.value,
            region or "global",
            aws_resource_id,
        )
    )
    return uuid5(_ASSESSMENT_NAMESPACE, seed)


def control_assessment_id(
    *,
    scan_id: UUID,
    resource_snapshot_id: UUID,
    control_id: str,
) -> UUID:
    """Identify one control result for one resource snapshot within a scan."""

    return uuid5(
        _CONTROL_ASSESSMENT_NAMESPACE,
        "\x1f".join((str(scan_id), str(resource_snapshot_id), control_id)),
    )


def finding_fingerprint(
    *,
    aws_account_id: str,
    resource_id: UUID,
    control_id: str,
    region: str | None,
) -> str:
    """Hash the stable identity used to deduplicate a recurring technical failure."""

    seed = "\x1f".join((aws_account_id, str(resource_id), control_id, region or "global")).encode(
        "utf-8"
    )
    return hashlib.sha256(seed).hexdigest()
