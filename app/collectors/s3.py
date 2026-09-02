"""S3 bucket resource collection."""

from typing import Any

from botocore.exceptions import ClientError

from app.collectors.base import (
    ResourceCollector,
    iter_paginated_items,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_MISSING_TAG_CODES = {"NoSuchTagSet"}
_MISSING_ENCRYPTION_CODES = {"ServerSideEncryptionConfigurationNotFoundError"}
_MISSING_PUBLIC_ACCESS_BLOCK_CODES = {"NoSuchPublicAccessBlockConfiguration"}


class S3BucketCollector(ResourceCollector):
    """Collect account buckets and selected configuration facts."""

    collector_name = "s3_buckets"

    def collect(self) -> list[NormalizedResource]:
        discovery_client = self.client_provider.client("s3")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []

        for bucket in iter_paginated_items(
            discovery_client,
            "list_buckets",
            "Buckets",
            PaginationConfig={"PageSize": 1000},
        ):
            bucket_name = str(bucket["Name"])
            bucket_region = self._resolve_bucket_region(
                discovery_client,
                bucket,
                account_id,
            )
            regional_client = self.client_provider.client(
                "s3",
                region_name=bucket_region,
            )
            tags = self._get_tags(regional_client, bucket_name, account_id)
            encryption = self._get_optional_configuration(
                regional_client,
                operation_name="get_bucket_encryption",
                result_key="ServerSideEncryptionConfiguration",
                missing_codes=_MISSING_ENCRYPTION_CODES,
                bucket_name=bucket_name,
                account_id=account_id,
            )
            public_access_block = self._get_optional_configuration(
                regional_client,
                operation_name="get_public_access_block",
                result_key="PublicAccessBlockConfiguration",
                missing_codes=_MISSING_PUBLIC_ACCESS_BLOCK_CODES,
                bucket_name=bucket_name,
                account_id=account_id,
            )

            configuration = {
                "creation_date": to_json_safe(bucket.get("CreationDate")),
                "bucket_region": bucket_region,
                "default_encryption": to_json_safe(encryption),
                "public_access_block": to_json_safe(public_access_block),
            }

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="s3",
                    resource_type="s3_bucket",
                    aws_resource_id=bucket_name,
                    arn=f"arn:{self.client_provider.partition}:s3:::{bucket_name}",
                    name=bucket_name,
                    scope=ResourceScope.REGIONAL,
                    region=bucket_region,
                    tags=tags,
                    configuration=configuration,
                    raw_configuration={
                        "bucket": to_json_safe(bucket),
                        "default_encryption": to_json_safe(encryption),
                        "public_access_block": to_json_safe(public_access_block),
                    },
                )
            )

        return resources

    def _resolve_bucket_region(
        self,
        client: Any,
        bucket: dict[str, Any],
        account_id: str,
    ) -> str:
        region = bucket.get("BucketRegion")
        if region:
            return str(region)

        response = client.head_bucket(
            Bucket=str(bucket["Name"]),
            ExpectedBucketOwner=account_id,
        )
        response_headers = response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        region = response.get("BucketRegion") or response_headers.get("x-amz-bucket-region")

        if not region:
            raise ValueError(f"AWS did not return a region for S3 bucket {bucket['Name']}")

        return str(region)

    @staticmethod
    def _get_tags(client: Any, bucket_name: str, account_id: str) -> dict[str, str]:
        try:
            response = client.get_bucket_tagging(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            )
        except ClientError as error:
            if _error_code(error) in _MISSING_TAG_CODES:
                return {}
            raise

        return tags_to_dict(response.get("TagSet", []))

    @staticmethod
    def _get_optional_configuration(
        client: Any,
        *,
        operation_name: str,
        result_key: str,
        missing_codes: set[str],
        bucket_name: str,
        account_id: str,
    ) -> dict[str, Any] | None:
        try:
            response = getattr(client, operation_name)(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            )
        except ClientError as error:
            if _error_code(error) in missing_codes:
                return None
            raise

        result = response.get(result_key)
        return result if isinstance(result, dict) else None


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", "Unknown"))
