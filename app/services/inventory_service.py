"""Application service for collecting a normalized AWS resource inventory."""

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime

from botocore.exceptions import BotoCoreError, ClientError

from app.aws.client import AWSClientProvider
from app.collectors.base import ResourceCollector
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.s3 import S3BucketCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource


class InventoryCollectionError(RuntimeError):
    """Raised when an AWS collector cannot complete its inventory operation."""

    def __init__(self, collector_name: str) -> None:
        self.collector_name = collector_name
        super().__init__(f"AWS inventory collector failed: {collector_name}")


def build_default_collectors(
    client_provider: AWSClientProvider,
) -> tuple[ResourceCollector, ...]:
    """Build the Sprint 1 collectors without making an AWS API call."""

    return (
        SecurityGroupCollector(client_provider),
        S3BucketCollector(client_provider),
        IAMUserCollector(client_provider),
        CloudTrailCollector(client_provider),
    )


class InventoryService:
    """Run resource collectors and return a deterministic in-memory snapshot."""

    def __init__(
        self,
        client_provider: AWSClientProvider,
        collectors: Sequence[ResourceCollector] | None = None,
    ) -> None:
        self.client_provider = client_provider
        self.collectors = tuple(
            collectors if collectors is not None else build_default_collectors(client_provider)
        )

    def collect(self) -> InventorySnapshot:
        """Collect inventory facts, surfacing AWS failures without partial success."""

        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []

        for collector in self.collectors:
            resources.extend(self._collect_from(collector))

        resources.sort(key=lambda resource: resource.identity)
        return InventorySnapshot(
            account_id=account_id,
            requested_region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
            resources=tuple(resources),
        )

    @staticmethod
    def _collect_from(collector: ResourceCollector) -> Iterable[NormalizedResource]:
        try:
            return collector.collect()
        except (BotoCoreError, ClientError) as error:
            raise InventoryCollectionError(collector.collector_name) from error
