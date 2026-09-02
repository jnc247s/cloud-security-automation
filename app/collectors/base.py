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


def iter_paginated_items(
    client: Any,
    operation_name: str,
    result_key: str,
    **paginate_options: Any,
) -> Iterator[dict[str, Any]]:
    """Yield dictionary items from every page of a boto3 paginator."""

    paginator = client.get_paginator(operation_name)
    for page in paginator.paginate(**paginate_options):
        yield from page.get(result_key, [])


def tags_to_dict(tags: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Normalize AWS tag lists into a stable string dictionary."""

    normalized_tags: dict[str, str] = {}
    for tag in tags:
        key = tag.get("Key")
        if key is not None:
            normalized_tags[str(key)] = str(tag.get("Value", ""))
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
