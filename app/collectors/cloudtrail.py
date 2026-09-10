"""CloudTrail trail resource collection."""

from typing import Any

from app.collectors.base import (
    CollectorEvidenceError,
    ResourceCollector,
    iter_paginated_items,
    require_boolean,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    should_skip_exact_duplicate,
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
        seen_trails: dict[str, dict[str, Any]] = {}

        for trail_summary in iter_paginated_items(
            discovery_client,
            "list_trails",
            "Trails",
        ):
            trail_arn = require_non_empty_string(
                require_member(
                    trail_summary,
                    "TrailARN",
                    operation_name="list_trails",
                    fact_path="Trails[].TrailARN",
                ),
                operation_name="list_trails",
                fact_path="Trails[].TrailARN",
            )
            home_region = require_non_empty_string(
                require_member(
                    trail_summary,
                    "HomeRegion",
                    operation_name="list_trails",
                    fact_path="Trails[].HomeRegion",
                ),
                operation_name="list_trails",
                fact_path="Trails[].HomeRegion",
            )
            summary_name = _optional_non_empty_string(
                trail_summary,
                "Name",
                operation_name="list_trails",
                fact_path="Trails[].Name",
            )
            if should_skip_exact_duplicate(
                seen_trails,
                trail_arn,
                trail_summary,
                operation_name="list_trails",
                fact_path="Trails[].duplicate_identity",
            ):
                continue

            client = self.client_provider.client("cloudtrail", region_name=home_region)
            get_trail_response = require_mapping(
                client.get_trail(Name=trail_arn),
                operation_name="get_trail",
                fact_path="response",
            )
            trail = require_mapping(
                require_member(
                    get_trail_response,
                    "Trail",
                    operation_name="get_trail",
                    fact_path="Trail",
                ),
                operation_name="get_trail",
                fact_path="Trail",
            )
            trail_fields = _validate_trail(trail, trail_arn, home_region)
            status_response = require_mapping(
                client.get_trail_status(Name=trail_arn),
                operation_name="get_trail_status",
                fact_path="response",
            )
            is_logging = require_boolean(
                require_member(
                    status_response,
                    "IsLogging",
                    operation_name="get_trail_status",
                    fact_path="IsLogging",
                ),
                operation_name="get_trail_status",
                fact_path="IsLogging",
            )
            trail_status = _without_response_metadata(status_response)
            tags = self._get_tags(client, trail_arn)

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="cloudtrail",
                    resource_type="cloudtrail_trail",
                    aws_resource_id=trail_arn,
                    arn=trail_arn,
                    name=trail_fields["Name"] or summary_name,
                    scope=ResourceScope.REGIONAL,
                    region=home_region,
                    tags=tags,
                    configuration={
                        "home_region": home_region,
                        "s3_bucket_name": trail_fields["S3BucketName"],
                        "s3_key_prefix": trail_fields["S3KeyPrefix"],
                        "include_global_service_events": trail_fields["IncludeGlobalServiceEvents"],
                        "is_multi_region_trail": trail_fields["IsMultiRegionTrail"],
                        "log_file_validation_enabled": trail_fields["LogFileValidationEnabled"],
                        "cloudwatch_logs_log_group_arn": trail_fields["CloudWatchLogsLogGroupArn"],
                        "kms_key_id": trail_fields["KmsKeyId"],
                        "is_organization_trail": trail_fields["IsOrganizationTrail"],
                        "is_logging": is_logging,
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
        tag_entries: list[Any] = []
        for resource_tags in iter_paginated_items(
            client,
            "list_tags",
            "ResourceTagList",
            ResourceIdList=[trail_arn],
        ):
            resource_id = require_non_empty_string(
                require_member(
                    resource_tags,
                    "ResourceId",
                    operation_name="list_tags",
                    fact_path="ResourceTagList[].ResourceId",
                ),
                operation_name="list_tags",
                fact_path="ResourceTagList[].ResourceId",
            )
            if resource_id != trail_arn:
                raise CollectorEvidenceError(
                    "list_tags",
                    "ResourceTagList[].ResourceId",
                )
            if "TagsList" not in resource_tags:
                continue
            tag_entries.extend(
                require_list(
                    resource_tags["TagsList"],
                    operation_name="list_tags",
                    fact_path="ResourceTagList[].TagsList",
                )
            )
        return tags_to_dict(
            tag_entries,
            operation_name="list_tags",
            fact_path="ResourceTagList[].TagsList",
            allow_missing_value=True,
        )


_TRAIL_STRING_FIELDS = (
    "S3BucketName",
    "S3KeyPrefix",
    "CloudWatchLogsLogGroupArn",
    "KmsKeyId",
)
_TRAIL_BOOLEAN_FIELDS = (
    "IncludeGlobalServiceEvents",
    "IsMultiRegionTrail",
    "LogFileValidationEnabled",
    "IsOrganizationTrail",
)


def _validate_trail(
    trail: dict[str, Any],
    expected_arn: str,
    expected_home_region: str,
) -> dict[str, str | bool | None]:
    """Validate the CloudTrail fields promoted into normalized configuration."""

    fields: dict[str, str | bool | None] = {
        "Name": _optional_non_empty_string(
            trail,
            "Name",
            operation_name="get_trail",
            fact_path="Trail.Name",
        )
    }
    for field_name in _TRAIL_STRING_FIELDS:
        fields[field_name] = _optional_string(
            trail,
            field_name,
            operation_name="get_trail",
            fact_path=f"Trail.{field_name}",
        )
    for field_name in _TRAIL_BOOLEAN_FIELDS:
        fields[field_name] = _optional_boolean(
            trail,
            field_name,
            operation_name="get_trail",
            fact_path=f"Trail.{field_name}",
        )

    returned_arn = _optional_non_empty_string(
        trail,
        "TrailARN",
        operation_name="get_trail",
        fact_path="Trail.TrailARN",
    )
    if returned_arn is not None and returned_arn != expected_arn:
        raise CollectorEvidenceError("get_trail", "Trail.TrailARN")

    returned_home_region = _optional_non_empty_string(
        trail,
        "HomeRegion",
        operation_name="get_trail",
        fact_path="Trail.HomeRegion",
    )
    if returned_home_region is not None and returned_home_region != expected_home_region:
        raise CollectorEvidenceError("get_trail", "Trail.HomeRegion")

    return fields


def _optional_string(
    container: dict[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container:
        return None
    return require_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_non_empty_string(
    container: dict[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container:
        return None
    return require_non_empty_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_boolean(
    container: dict[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> bool | None:
    if key not in container:
        return None
    return require_boolean(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _without_response_metadata(response: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in response.items() if key != "ResponseMetadata"}
