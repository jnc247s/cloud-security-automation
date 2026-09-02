"""Collect AWS inventory and print a non-sensitive summary."""

import json
import logging
from collections import Counter

from botocore.exceptions import BotoCoreError, ClientError

from app.aws.client import Boto3ClientProvider
from app.config import get_settings
from app.logging.config import configure_logging
from app.services.inventory_service import InventoryCollectionError, InventoryService

LOGGER = logging.getLogger(__name__)


def main() -> int:
    """Run all Sprint 1 collectors against the configured AWS account."""

    settings = get_settings()
    configure_logging(settings.log_level)

    try:
        provider = Boto3ClientProvider.from_settings(settings)
        snapshot = InventoryService(provider).collect()
    except InventoryCollectionError as error:
        LOGGER.error("Inventory collection failed in collector '%s'.", error.collector_name)
        return 1
    except (BotoCoreError, ClientError):
        LOGGER.error("Unable to resolve the configured AWS identity.")
        return 1

    resources_by_service = Counter(resource.service for resource in snapshot.resources)
    summary = {
        "account_id": snapshot.account_id,
        "requested_region": snapshot.requested_region,
        "collected_at": snapshot.collected_at.isoformat(),
        "resource_count": snapshot.resource_count,
        "resources_by_service": dict(sorted(resources_by_service.items())),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
