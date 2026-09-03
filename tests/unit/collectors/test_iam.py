"""Tests for IAM user collection."""

import json
from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError

from app.collectors.iam import IAMUserCollector
from app.schemas.resource import ResourceScope
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error


def test_collects_paginated_users_and_authentication_metadata() -> None:
    created_at = datetime(2024, 5, 6, 7, 8, tzinfo=UTC)
    key_created_at = datetime(2025, 1, 1, tzinfo=UTC)
    user_pages = FakePaginator(
        [
            {
                "Users": [
                    {
                        "Path": "/engineering/",
                        "UserName": "alice",
                        "UserId": "AIDAALICE",
                        "Arn": "arn:aws:iam::123456789012:user/engineering/alice",
                        "CreateDate": created_at,
                        "PasswordLastUsed": datetime(2025, 2, 3, tzinfo=UTC),
                    }
                ]
            },
            {
                "Users": [
                    {
                        "Path": "/",
                        "UserName": "bob",
                        "UserId": "AIDABOB",
                        "Arn": "arn:aws:iam::123456789012:user/bob",
                        "CreateDate": created_at,
                    }
                ]
            },
        ]
    )
    alice_tags = FakePaginator(
        [
            {"Tags": [{"Key": "Owner", "Value": "engineering"}]},
            {"Tags": [{"Key": "Environment", "Value": "test"}]},
        ]
    )
    bob_tags = FakePaginator([{"Tags": []}])
    alice_mfa = FakePaginator(
        [
            {
                "MFADevices": [
                    {
                        "UserName": "alice",
                        "SerialNumber": "arn:aws:iam::123456789012:mfa/alice",
                        "EnableDate": datetime(2024, 6, 1, tzinfo=UTC),
                    }
                ]
            }
        ]
    )
    bob_mfa = FakePaginator([{"MFADevices": []}])
    alice_keys = FakePaginator(
        [
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "alice",
                        "AccessKeyId": "AKIAALICE",
                        "Status": "Active",
                        "CreateDate": key_created_at,
                    }
                ]
            }
        ]
    )
    bob_keys = FakePaginator(
        [
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "bob",
                        "AccessKeyId": "AKIABOB",
                        "Status": "Inactive",
                        "CreateDate": key_created_at,
                    }
                ]
            }
        ]
    )
    client = FakeAWSClient(
        paginators={
            "list_users": user_pages,
            "list_user_tags": [alice_tags, bob_tags],
            "list_mfa_devices": [alice_mfa, bob_mfa],
            "list_access_keys": [alice_keys, bob_keys],
        },
        responses={
            "get_access_key_last_used": [
                {
                    "UserName": "alice",
                    "AccessKeyLastUsed": {
                        "LastUsedDate": datetime(2025, 3, 1, tzinfo=UTC),
                        "ServiceName": "s3",
                        "Region": "us-east-1",
                    },
                },
                {
                    "UserName": "bob",
                    "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"},
                },
            ]
        },
    )
    provider = FakeClientProvider({("iam", "us-east-1"): client})

    resources = IAMUserCollector(provider).collect()

    assert len(resources) == 2
    assert user_pages.calls == [{}]
    assert alice_tags.calls == [{"UserName": "alice"}]
    assert resources[0].scope is ResourceScope.GLOBAL
    assert resources[0].region is None
    assert resources[0].tags == {"Owner": "engineering", "Environment": "test"}
    assert resources[0].configuration["created_at"] == "2024-05-06T07:08:00+00:00"
    assert resources[0].configuration["mfa_devices"][0]["EnableDate"] == (
        "2024-06-01T00:00:00+00:00"
    )
    assert resources[0].configuration["access_keys"][0]["LastUsed"]["ServiceName"] == "s3"
    assert resources[1].configuration["password_last_used"] is None
    assert resources[1].configuration["mfa_devices"] == []
    assert resources[1].configuration["access_keys"][0]["LastUsed"] == {
        "ServiceName": "N/A",
        "Region": "N/A",
    }
    json.dumps(resources[0].model_dump(mode="json"))


def test_propagates_iam_enrichment_errors() -> None:
    error = client_error("AccessDenied", "ListMFADevices", status_code=403)
    client = FakeAWSClient(
        paginators={
            "list_users": FakePaginator(
                [
                    {
                        "Users": [
                            {
                                "Path": "/",
                                "UserName": "alice",
                                "UserId": "AIDAALICE",
                                "Arn": "arn:aws:iam::123456789012:user/alice",
                                "CreateDate": datetime(2024, 1, 1, tzinfo=UTC),
                            }
                        ]
                    }
                ]
            ),
            "list_user_tags": FakePaginator([{"Tags": []}]),
            "list_mfa_devices": FakePaginator(error=error),
        }
    )
    provider = FakeClientProvider({("iam", "us-east-1"): client})

    with pytest.raises(ClientError) as exc_info:
        IAMUserCollector(provider).collect()

    assert exc_info.value.response["Error"]["Code"] == "AccessDenied"
