"""Run the complete AWS inventory, evaluation, and persistence workflow."""

import json
from dataclasses import asdict

from app.aws.client import Boto3ClientProvider
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.services.inventory_service import InventoryService
from app.services.scan_service import ScanService


def main() -> None:
    """Execute one persisted scan and print only aggregate scan metadata."""

    provider = Boto3ClientProvider.from_settings()
    result = ScanService(
        inventory_service=InventoryService(provider),
        rule_engine=RuleEngine(build_default_registry()),
    ).run(account_id=provider.account_id, region=provider.region_name)
    print(json.dumps(asdict(result), default=str, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
