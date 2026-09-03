"""Application service for collecting a normalized AWS resource inventory."""

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime

from botocore.exceptions import BotoCoreError, ClientError

from app.aws.client import AWSClientProvider
from app.collectors.base import CollectorEvidenceError, ResourceCollector
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.s3 import S3BucketCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.resource import NormalizedResource


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
        """Collect independent facts and record sanitized per-collector completeness."""

        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        outcomes: list[CollectorOutcome] = []

        for collector in self.collectors:
            collected, status = self._collect_from(collector)
            resources.extend(collected)
            outcomes.append(
                CollectorOutcome(
                    collector_name=collector.collector_name,
                    status=status,
                )
            )

        resources.sort(key=lambda resource: resource.identity)
        return InventorySnapshot(
            account_id=account_id,
            requested_region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
            collector_outcomes=tuple(outcomes),
            resources=tuple(resources),
        )

    @staticmethod
    def _collect_from(
        collector: ResourceCollector,
    ) -> tuple[Iterable[NormalizedResource], CollectionStatus]:
        try:
            return collector.collect(), CollectionStatus.SUCCEEDED
        except (BotoCoreError, ClientError):
            return (), CollectionStatus.FAILED
        except CollectorEvidenceError:
            return (), CollectionStatus.PARTIAL
