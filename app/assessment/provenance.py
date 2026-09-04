"""Canonical catalog provenance shared by assessment and persistence boundaries."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.assessment.controls import ControlCatalog


def _json_value(value: Any) -> Any:
    """Preserve model content while normalizing its JSON types and timestamp offsets."""

    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("catalog provenance timestamps must include a timezone")
        return value.astimezone(UTC).isoformat()
    if isinstance(value, Enum):
        return _json_value(value.value)
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _mapping_key(mapping: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        mapping["control_id"],
        mapping["framework_id"],
        mapping["framework_version"],
        mapping["reference_id"],
    )


def canonical_control_catalog_document(catalog: ControlCatalog) -> dict[str, Any]:
    """Return a fresh, fully validated, order-independent catalog provenance document.

    Rebuilding from a model dump also revalidates nested unchecked ``model_copy``
    changes. Set-like arrays are sorted, not deduplicated; all content remains
    represented. No database modules or state are needed.
    """

    from app.assessment.controls import ControlCatalog

    if not isinstance(catalog, ControlCatalog):
        raise TypeError("catalog must be a ControlCatalog")
    validated = ControlCatalog.model_validate(catalog.model_dump(mode="python"))
    document = _json_value(validated.model_dump(mode="python"))
    document["controls"].sort(key=lambda item: item["technical"]["control_id"])
    for control in document["controls"]:
        technical = control["technical"]
        technical["required_evidence"].sort(key=lambda item: item["fact_path"])
        technical["profile_parameters"].sort()
        technical["limitations"].sort()
        control["framework_mappings"].sort(key=_mapping_key)
    document["framework_catalogs"].sort(
        key=lambda item: (item["framework"]["framework_id"], item["framework"]["version"])
    )
    for framework in document["framework_catalogs"]:
        framework["references"].sort(key=lambda item: item["reference_id"])
        framework["mappings"].sort(key=_mapping_key)
    return document


def control_catalog_sha256(catalog: ControlCatalog) -> str:
    """Bind a catalog's complete canonical content to a stable SHA-256 digest."""

    encoded = json.dumps(
        canonical_control_catalog_document(catalog),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
