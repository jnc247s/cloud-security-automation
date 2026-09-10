"""IAM user resource collection."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from app.collectors.base import (
    CollectorEvidenceError,
    ResourceCollector,
    iter_paginated_items,
    require_datetime,
    require_mapping,
    require_member,
    require_non_empty_string,
    should_skip_exact_duplicate,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_ACCESS_KEY_STATUSES = {"Active", "Inactive", "Expired"}


class IAMUserCollector(ResourceCollector):
    """Collect account-global IAM users and authentication metadata facts."""

    collector_name = "iam_users"

    def collect(self) -> list[NormalizedResource]:
        client = self.client_provider.client("iam")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        seen_users: dict[str, dict[str, Any]] = {}

        for user in iter_paginated_items(client, "list_users", "Users"):
            user_name = _required_string_member(user, "UserName", "list_users", "Users[].UserName")
            user_id = _required_string_member(user, "UserId", "list_users", "Users[].UserId")
            arn = _required_string_member(user, "Arn", "list_users", "Users[].Arn")
            path = _required_string_member(user, "Path", "list_users", "Users[].Path")
            created_at = _required_datetime_member(
                user,
                "CreateDate",
                "list_users",
                "Users[].CreateDate",
            )
            password_last_used = _nullable_datetime_member(
                user,
                "PasswordLastUsed",
                "list_users",
                "Users[].PasswordLastUsed",
            )
            if should_skip_exact_duplicate(
                seen_users,
                user_id,
                user,
                operation_name="list_users",
                fact_path="Users[].UserId",
            ):
                continue

            tags = tags_to_dict(
                list(
                    iter_paginated_items(
                        client,
                        "list_user_tags",
                        "Tags",
                        UserName=user_name,
                    )
                ),
                operation_name="list_user_tags",
                fact_path="Tags",
            )
            mfa_devices = self._collect_mfa_devices(client, user_name)
            access_keys = self._collect_access_keys(client, user_name)

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="iam",
                    resource_type="iam_user",
                    aws_resource_id=user_id,
                    arn=arn,
                    name=user_name,
                    scope=ResourceScope.GLOBAL,
                    region=None,
                    tags=tags,
                    configuration={
                        "path": path,
                        "created_at": to_json_safe(created_at),
                        "password_last_used": to_json_safe(password_last_used),
                        "mfa_devices": to_json_safe(mfa_devices),
                        "access_keys": to_json_safe(access_keys),
                    },
                    raw_configuration={
                        "user": to_json_safe(user),
                        "mfa_devices": to_json_safe(mfa_devices),
                        "access_keys": to_json_safe(access_keys),
                    },
                )
            )

        return resources

    @staticmethod
    def _collect_mfa_devices(client: Any, user_name: str) -> list[dict[str, Any]]:
        mfa_devices: list[dict[str, Any]] = []
        seen_devices: dict[str, dict[str, Any]] = {}

        for device in iter_paginated_items(
            client,
            "list_mfa_devices",
            "MFADevices",
            UserName=user_name,
        ):
            device_user_name = _required_string_member(
                device,
                "UserName",
                "list_mfa_devices",
                "MFADevices[].UserName",
            )
            if device_user_name != user_name:
                raise CollectorEvidenceError("list_mfa_devices", "MFADevices[].UserName")
            serial_number = _required_string_member(
                device,
                "SerialNumber",
                "list_mfa_devices",
                "MFADevices[].SerialNumber",
            )
            _required_datetime_member(
                device,
                "EnableDate",
                "list_mfa_devices",
                "MFADevices[].EnableDate",
            )
            if should_skip_exact_duplicate(
                seen_devices,
                serial_number,
                device,
                operation_name="list_mfa_devices",
                fact_path="MFADevices[].SerialNumber",
            ):
                continue
            mfa_devices.append(device)

        return mfa_devices

    @staticmethod
    def _collect_access_keys(client: Any, user_name: str) -> list[dict[str, Any]]:
        access_keys: list[dict[str, Any]] = []
        seen_access_keys: dict[str, dict[str, Any]] = {}

        for key_metadata in iter_paginated_items(
            client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=user_name,
        ):
            access_key_id = _required_string_member(
                key_metadata,
                "AccessKeyId",
                "list_access_keys",
                "AccessKeyMetadata[].AccessKeyId",
            )
            _validate_optional_access_key_metadata(key_metadata, user_name)
            if should_skip_exact_duplicate(
                seen_access_keys,
                access_key_id,
                key_metadata,
                operation_name="list_access_keys",
                fact_path="AccessKeyMetadata[].AccessKeyId",
            ):
                continue

            raw_last_used_response = client.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_response = require_mapping(
                raw_last_used_response,
                operation_name="get_access_key_last_used",
                fact_path="response",
            )
            _validate_optional_response_user_name(last_used_response, user_name)
            last_used = _validated_last_used(last_used_response)
            access_keys.append(
                {
                    **key_metadata,
                    "LastUsed": last_used,
                }
            )

        return access_keys


def _required_string_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str:
    return require_non_empty_string(
        require_member(
            value,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _required_datetime_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> datetime:
    return require_datetime(
        require_member(
            value,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _nullable_datetime_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> datetime | None:
    if key not in value or value[key] is None:
        return None
    return require_datetime(
        value[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _validate_optional_access_key_metadata(
    key_metadata: Mapping[str, Any],
    expected_user_name: str,
) -> None:
    operation_name = "list_access_keys"
    fact_path = "AccessKeyMetadata[]"
    if "UserName" in key_metadata:
        user_name = require_non_empty_string(
            key_metadata["UserName"],
            operation_name=operation_name,
            fact_path=f"{fact_path}.UserName",
        )
        if user_name != expected_user_name:
            raise CollectorEvidenceError(operation_name, f"{fact_path}.UserName")
    if "Status" in key_metadata:
        status = require_non_empty_string(
            key_metadata["Status"],
            operation_name=operation_name,
            fact_path=f"{fact_path}.Status",
        )
        if status not in _ACCESS_KEY_STATUSES:
            raise CollectorEvidenceError(operation_name, f"{fact_path}.Status")
    if "CreateDate" in key_metadata:
        require_datetime(
            key_metadata["CreateDate"],
            operation_name=operation_name,
            fact_path=f"{fact_path}.CreateDate",
        )


def _validate_optional_response_user_name(
    response: Mapping[str, Any],
    expected_user_name: str,
) -> None:
    if "UserName" not in response:
        return
    user_name = require_non_empty_string(
        response["UserName"],
        operation_name="get_access_key_last_used",
        fact_path="UserName",
    )
    if user_name != expected_user_name:
        raise CollectorEvidenceError("get_access_key_last_used", "UserName")


def _validated_last_used(response: Mapping[str, Any]) -> dict[str, Any] | None:
    operation_name = "get_access_key_last_used"
    if "AccessKeyLastUsed" not in response:
        return None

    last_used = require_mapping(
        response["AccessKeyLastUsed"],
        operation_name=operation_name,
        fact_path="AccessKeyLastUsed",
    )
    _required_string_member(
        last_used,
        "ServiceName",
        operation_name,
        "AccessKeyLastUsed.ServiceName",
    )
    _required_string_member(
        last_used,
        "Region",
        operation_name,
        "AccessKeyLastUsed.Region",
    )
    if "LastUsedDate" in last_used:
        require_datetime(
            last_used["LastUsedDate"],
            operation_name=operation_name,
            fact_path="AccessKeyLastUsed.LastUsedDate",
        )
    return last_used
