"""Collect AWS inventory and print a non-sensitive summary."""

import json
import logging
from collections import Counter

from botocore.exceptions import BotoCoreError, ClientError

from app.aws.client import AWSIdentityEvidenceError, Boto3ClientProvider
from app.config import get_settings
from app.logging.config import configure_logging
from app.schemas.inventory import CollectionStatus
from app.services.inventory_service import InventoryService

LOGGER = logging.getLogger(__name__)


def main() -> int:
    """Run all Sprint 1 collectors against the configured AWS account."""

    settings = get_settings()
    configure_logging(settings.log_level)

    try:
        provider = Boto3ClientProvider.from_settings(settings)
        snapshot = InventoryService(provider).collect()
    except (AWSIdentityEvidenceError, BotoCoreError, ClientError):
        LOGGER.error("Unable to resolve the configured AWS identity.")
        return 1

    resources_by_service = Counter(resource.service for resource in snapshot.resources)
    summary = {
        "scan_id": str(snapshot.scan_id),
        "account_id": snapshot.account_id,
        "requested_region": snapshot.requested_region,
        "collected_at": snapshot.collected_at.isoformat(),
        "resource_count": snapshot.resource_count,
        "resources_by_service": dict(sorted(resources_by_service.items())),
        "collector_outcomes": {
            outcome.collector_name: outcome.status.value for outcome in snapshot.collector_outcomes
        },
    }
    print(json.dumps(summary, indent=2))
    if any(
        outcome.status is not CollectionStatus.SUCCEEDED for outcome in snapshot.collector_outcomes
    ):
        LOGGER.error("Inventory collection is incomplete; see collector_outcomes.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
