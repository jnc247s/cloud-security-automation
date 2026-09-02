"""CloudTrail trail resource collection."""

from typing import Any

from app.collectors.base import (
    ResourceCollector,
    iter_paginated_items,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope


class CloudTrailCollector(ResourceCollector):
    """Collect account trails and enrich them through their home-region clients."""

    collector_name = "cloudtrail_trails"

    def collect(self) -> list[NormalizedResource]:
        discovery_client = self.client_provider.client("cloudtrail")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        seen_trail_arns: set[str] = set()

        for trail_summary in iter_paginated_items(
            discovery_client,
            "list_trails",
            "Trails",
        ):
            trail_arn = str(trail_summary["TrailARN"])
            if trail_arn in seen_trail_arns:
                continue
            seen_trail_arns.add(trail_arn)

            home_region = str(trail_summary["HomeRegion"])
            client = self.client_provider.client("cloudtrail", region_name=home_region)
            trail = client.get_trail(Name=trail_arn)["Trail"]
            trail_status = _without_response_metadata(client.get_trail_status(Name=trail_arn))
            tags = self._get_tags(client, trail_arn)

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="cloudtrail",
                    resource_type="cloudtrail_trail",
                    aws_resource_id=trail_arn,
                    arn=trail_arn,
                    name=trail.get("Name") or trail_summary.get("Name"),
                    scope=ResourceScope.REGIONAL,
                    region=home_region,
                    tags=tags,
                    configuration={
                        "home_region": home_region,
                        "s3_bucket_name": trail.get("S3BucketName"),
                        "s3_key_prefix": trail.get("S3KeyPrefix"),
                        "include_global_service_events": trail.get("IncludeGlobalServiceEvents"),
                        "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                        "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                        "cloudwatch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                        "kms_key_id": trail.get("KmsKeyId"),
                        "is_organization_trail": trail.get("IsOrganizationTrail"),
                        "is_logging": trail_status.get("IsLogging"),
                        "status": to_json_safe(trail_status),
                    },
                    raw_configuration={
                        "summary": to_json_safe(trail_summary),
                        "trail": to_json_safe(trail),
                        "status": to_json_safe(trail_status),
                    },
                )
            )

        return resources

    @staticmethod
    def _get_tags(client: Any, trail_arn: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        for resource_tags in iter_paginated_items(
            client,
            "list_tags",
            "ResourceTagList",
            ResourceIdList=[trail_arn],
        ):
            tags.update(tags_to_dict(resource_tags.get("TagsList", [])))
        return tags


def _without_response_metadata(response: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in response.items() if key != "ResponseMetadata"}
