"""IAM user resource collection."""

from typing import Any

from app.collectors.base import (
    ResourceCollector,
    iter_paginated_items,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope


class IAMUserCollector(ResourceCollector):
    """Collect account-global IAM users and authentication metadata facts."""

    collector_name = "iam_users"

    def collect(self) -> list[NormalizedResource]:
        client = self.client_provider.client("iam")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []

        for user in iter_paginated_items(client, "list_users", "Users"):
            user_name = str(user["UserName"])
            tags = tags_to_dict(
                iter_paginated_items(
                    client,
                    "list_user_tags",
                    "Tags",
                    UserName=user_name,
                )
            )
            mfa_devices = list(
                iter_paginated_items(
                    client,
                    "list_mfa_devices",
                    "MFADevices",
                    UserName=user_name,
                )
            )
            access_keys = self._collect_access_keys(client, user_name)

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="iam",
                    resource_type="iam_user",
                    aws_resource_id=str(user["UserId"]),
                    arn=str(user["Arn"]),
                    name=user_name,
                    scope=ResourceScope.GLOBAL,
                    region=None,
                    tags=tags,
                    configuration={
                        "path": user.get("Path"),
                        "created_at": to_json_safe(user.get("CreateDate")),
                        "password_last_used": to_json_safe(user.get("PasswordLastUsed")),
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
    def _collect_access_keys(client: Any, user_name: str) -> list[dict[str, Any]]:
        access_keys: list[dict[str, Any]] = []

        for key_metadata in iter_paginated_items(
            client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=user_name,
        ):
            access_key_id = str(key_metadata["AccessKeyId"])
            last_used_response = client.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used = last_used_response.get("AccessKeyLastUsed", {})
            access_keys.append(
                {
                    **key_metadata,
                    "LastUsed": last_used,
                }
            )

        return access_keys
