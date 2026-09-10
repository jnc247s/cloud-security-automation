"""Shared contracts and normalization helpers for AWS resource collectors."""

import base64
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from app.aws.client import AWSClientProvider
from app.schemas.resource import NormalizedResource


class ResourceCollector(ABC):
    """Base class for fact-only AWS resource collectors."""

    collector_name: str

    def __init__(self, client_provider: AWSClientProvider) -> None:
        self.client_provider = client_provider

    @abstractmethod
    def collect(self) -> list[NormalizedResource]:
        """Collect and normalize resources without making security decisions."""


class CollectorEvidenceError(RuntimeError):
    """Raised when an AWS response omits or malforms a required collection fact."""

    def __init__(self, operation_name: str, fact_path: str) -> None:
        self.operation_name = operation_name
        self.fact_path = fact_path
        super().__init__(f"collector evidence is incomplete at {operation_name}.{fact_path}")


def require_mapping(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> dict[str, Any]:
    """Return one AWS object or reject a malformed response without echoing it."""

    if not isinstance(value, Mapping):
        raise CollectorEvidenceError(operation_name, fact_path)
    return dict(value)


def require_list(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> list[Any]:
    """Return one AWS list while preserving a valid known-empty list."""

    if not isinstance(value, list):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_member(
    value: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> Any:
    """Return a required member, distinguishing an absent key from other values."""

    if key not in value:
        raise CollectorEvidenceError(operation_name, fact_path)
    return value[key]


def require_string(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    """Return a string value without coercing another primitive into evidence."""

    if not isinstance(value, str):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_non_empty_string(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    """Return a non-blank string without rewriting the value supplied by AWS."""

    result = require_string(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if not result.strip():
        raise CollectorEvidenceError(operation_name, fact_path)
    return result


def require_boolean(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> bool:
    """Return an actual boolean rather than accepting truthy integer evidence."""

    if not isinstance(value, bool):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_integer(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> int:
    """Return an integer while rejecting booleans and coercible strings."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_datetime(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> datetime:
    """Return a boto3 timestamp without accepting stringified substitutes."""

    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def should_skip_exact_duplicate(
    seen: dict[str, dict[str, Any]],
    identity: str,
    item: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
) -> bool:
    """Skip an exact repeated item and reject conflicting data for one stable identity."""

    candidate = dict(item)
    if identity not in seen:
        seen[identity] = candidate
        return False
    if seen[identity] != candidate:
        raise CollectorEvidenceError(operation_name, fact_path)
    return True


def iter_paginated_items(
    client: Any,
    operation_name: str,
    result_key: str,
    **paginate_options: Any,
) -> Iterator[dict[str, Any]]:
    """Yield dictionary items from every page of a boto3 paginator."""

    paginator = client.get_paginator(operation_name)
    for page_index, raw_page in enumerate(paginator.paginate(**paginate_options)):
        page = require_mapping(
            raw_page,
            operation_name=operation_name,
            fact_path=f"pages[{page_index}]",
        )
        item_path = f"pages[{page_index}].{result_key}"
        items = require_list(
            require_member(
                page,
                result_key,
                operation_name=operation_name,
                fact_path=item_path,
            ),
            operation_name=operation_name,
            fact_path=item_path,
        )
        for item_index, item in enumerate(items):
            yield require_mapping(
                item,
                operation_name=operation_name,
                fact_path=f"{item_path}[{item_index}]",
            )


def tags_to_dict(
    tags: object,
    *,
    operation_name: str,
    fact_path: str,
    allow_missing_value: bool = False,
) -> dict[str, str]:
    """Validate and normalize AWS tag entries into a stable string dictionary."""

    if isinstance(tags, str | bytes | Mapping) or not isinstance(tags, Iterable):
        raise CollectorEvidenceError(operation_name, fact_path)
    normalized_tags: dict[str, str] = {}
    for tag_index, raw_tag in enumerate(tags):
        tag_path = f"{fact_path}[{tag_index}]"
        tag = require_mapping(
            raw_tag,
            operation_name=operation_name,
            fact_path=tag_path,
        )
        key = require_non_empty_string(
            require_member(
                tag,
                "Key",
                operation_name=operation_name,
                fact_path=f"{tag_path}.Key",
            ),
            operation_name=operation_name,
            fact_path=f"{tag_path}.Key",
        )
        if "Value" not in tag:
            if not allow_missing_value:
                raise CollectorEvidenceError(operation_name, f"{tag_path}.Value")
            value = ""
        else:
            value = require_string(
                tag["Value"],
                operation_name=operation_name,
                fact_path=f"{tag_path}.Value",
            )
        if key in normalized_tags and normalized_tags[key] != value:
            raise CollectorEvidenceError(operation_name, f"{tag_path}.Key")
        normalized_tags[key] = value
    return normalized_tags


def to_json_safe(value: Any) -> Any:
    """Recursively convert common boto3 response values to JSON-safe values."""

    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Mapping):
        return {str(key): to_json_safe(item) for key, item in value.items()}
    if isinstance(value, Iterable):
        return [to_json_safe(item) for item in value]
    return str(value)
