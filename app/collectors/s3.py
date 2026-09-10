"""S3 bucket resource collection."""

from typing import Any

from botocore.exceptions import ClientError

from app.collectors.base import (
    CollectorEvidenceError,
    ResourceCollector,
    iter_paginated_items,
    require_boolean,
    require_datetime,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    should_skip_exact_duplicate,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_MISSING_TAG_CODES = {"NoSuchTagSet"}
_MISSING_ENCRYPTION_CODES = {"ServerSideEncryptionConfigurationNotFoundError"}
_MISSING_PUBLIC_ACCESS_BLOCK_CODES = {"NoSuchPublicAccessBlockConfiguration"}
_S3_ENCRYPTION_ALGORITHMS = {
    "AES256",
    "aws:backup",
    "aws:fsx",
    "aws:kms",
    "aws:kms:dsse",
}
_PUBLIC_ACCESS_BLOCK_FIELDS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


class S3BucketCollector(ResourceCollector):
    """Collect account buckets and selected configuration facts."""

    collector_name = "s3_buckets"

    def collect(self) -> list[NormalizedResource]:
        discovery_client = self.client_provider.client("s3")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        seen_buckets: dict[str, dict[str, Any]] = {}

        for bucket in iter_paginated_items(
            discovery_client,
            "list_buckets",
            "Buckets",
            PaginationConfig={"PageSize": 1000},
        ):
            bucket_name = require_non_empty_string(
                require_member(
                    bucket,
                    "Name",
                    operation_name="list_buckets",
                    fact_path="Buckets[].Name",
                ),
                operation_name="list_buckets",
                fact_path="Buckets[].Name",
            )
            self._validate_bucket_summary(bucket)
            if should_skip_exact_duplicate(
                seen_buckets,
                bucket_name,
                bucket,
                operation_name="list_buckets",
                fact_path="Buckets[].duplicate_identity",
            ):
                continue
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
            if encryption is not None:
                self._validate_encryption(encryption)
            public_access_block = self._get_optional_configuration(
                regional_client,
                operation_name="get_public_access_block",
                result_key="PublicAccessBlockConfiguration",
                missing_codes=_MISSING_PUBLIC_ACCESS_BLOCK_CODES,
                bucket_name=bucket_name,
                account_id=account_id,
            )
            if public_access_block is not None:
                self._validate_public_access_block(public_access_block)

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

    @staticmethod
    def _validate_bucket_summary(bucket: dict[str, Any]) -> None:
        """Validate optional discovery facts when AWS supplied them."""

        if bucket.get("CreationDate") is not None:
            require_datetime(
                bucket["CreationDate"],
                operation_name="list_buckets",
                fact_path="Buckets[].CreationDate",
            )
        if "BucketRegion" in bucket:
            require_non_empty_string(
                bucket["BucketRegion"],
                operation_name="list_buckets",
                fact_path="Buckets[].BucketRegion",
            )

    def _resolve_bucket_region(
        self,
        client: Any,
        bucket: dict[str, Any],
        account_id: str,
    ) -> str:
        if "BucketRegion" in bucket:
            return require_non_empty_string(
                bucket["BucketRegion"],
                operation_name="list_buckets",
                fact_path="Buckets[].BucketRegion",
            )

        bucket_name = require_non_empty_string(
            require_member(
                bucket,
                "Name",
                operation_name="list_buckets",
                fact_path="Buckets[].Name",
            ),
            operation_name="list_buckets",
            fact_path="Buckets[].Name",
        )
        response = require_mapping(
            client.head_bucket(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            ),
            operation_name="head_bucket",
            fact_path="response",
        )
        direct_region = None
        if "BucketRegion" in response:
            direct_region = require_non_empty_string(
                response["BucketRegion"],
                operation_name="head_bucket",
                fact_path="BucketRegion",
            )

        header_region = None
        if "ResponseMetadata" in response:
            response_metadata = require_mapping(
                response["ResponseMetadata"],
                operation_name="head_bucket",
                fact_path="ResponseMetadata",
            )
            if "HTTPHeaders" in response_metadata:
                response_headers = require_mapping(
                    response_metadata["HTTPHeaders"],
                    operation_name="head_bucket",
                    fact_path="ResponseMetadata.HTTPHeaders",
                )
                if "x-amz-bucket-region" in response_headers:
                    header_region = require_non_empty_string(
                        response_headers["x-amz-bucket-region"],
                        operation_name="head_bucket",
                        fact_path=("ResponseMetadata.HTTPHeaders.x-amz-bucket-region"),
                    )

        if direct_region and header_region and direct_region != header_region:
            raise CollectorEvidenceError("head_bucket", "BucketRegion")
        region = direct_region or header_region
        if region is None:
            raise CollectorEvidenceError("head_bucket", "BucketRegion")

        return region

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

        response = require_mapping(
            response,
            operation_name="get_bucket_tagging",
            fact_path="response",
        )
        tag_set = require_list(
            require_member(
                response,
                "TagSet",
                operation_name="get_bucket_tagging",
                fact_path="TagSet",
            ),
            operation_name="get_bucket_tagging",
            fact_path="TagSet",
        )
        return tags_to_dict(
            tag_set,
            operation_name="get_bucket_tagging",
            fact_path="TagSet",
        )

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

        response = require_mapping(
            response,
            operation_name=operation_name,
            fact_path="response",
        )
        return require_mapping(
            require_member(
                response,
                result_key,
                operation_name=operation_name,
                fact_path=result_key,
            ),
            operation_name=operation_name,
            fact_path=result_key,
        )

    @staticmethod
    def _validate_encryption(configuration: dict[str, Any]) -> None:
        rules = require_list(
            require_member(
                configuration,
                "Rules",
                operation_name="get_bucket_encryption",
                fact_path="ServerSideEncryptionConfiguration.Rules",
            ),
            operation_name="get_bucket_encryption",
            fact_path="ServerSideEncryptionConfiguration.Rules",
        )
        if not rules:
            raise CollectorEvidenceError(
                "get_bucket_encryption",
                "ServerSideEncryptionConfiguration.Rules",
            )
        for rule_index, raw_rule in enumerate(rules):
            rule_path = f"ServerSideEncryptionConfiguration.Rules[{rule_index}]"
            rule = require_mapping(
                raw_rule,
                operation_name="get_bucket_encryption",
                fact_path=rule_path,
            )
            if "ApplyServerSideEncryptionByDefault" in rule:
                defaults = require_mapping(
                    rule["ApplyServerSideEncryptionByDefault"],
                    operation_name="get_bucket_encryption",
                    fact_path=f"{rule_path}.ApplyServerSideEncryptionByDefault",
                )
                algorithm_path = f"{rule_path}.ApplyServerSideEncryptionByDefault.SSEAlgorithm"
                algorithm = require_non_empty_string(
                    require_member(
                        defaults,
                        "SSEAlgorithm",
                        operation_name="get_bucket_encryption",
                        fact_path=algorithm_path,
                    ),
                    operation_name="get_bucket_encryption",
                    fact_path=algorithm_path,
                )
                if algorithm not in _S3_ENCRYPTION_ALGORITHMS:
                    raise CollectorEvidenceError(
                        "get_bucket_encryption",
                        algorithm_path,
                    )
                if "KMSMasterKeyID" in defaults:
                    require_non_empty_string(
                        defaults["KMSMasterKeyID"],
                        operation_name="get_bucket_encryption",
                        fact_path=(
                            f"{rule_path}.ApplyServerSideEncryptionByDefault.KMSMasterKeyID"
                        ),
                    )
            if "BucketKeyEnabled" in rule:
                require_boolean(
                    rule["BucketKeyEnabled"],
                    operation_name="get_bucket_encryption",
                    fact_path=f"{rule_path}.BucketKeyEnabled",
                )

    @staticmethod
    def _validate_public_access_block(configuration: dict[str, Any]) -> None:
        for field_name in _PUBLIC_ACCESS_BLOCK_FIELDS:
            if field_name in configuration:
                require_boolean(
                    configuration[field_name],
                    operation_name="get_public_access_block",
                    fact_path=f"PublicAccessBlockConfiguration.{field_name}",
                )


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", "Unknown"))
