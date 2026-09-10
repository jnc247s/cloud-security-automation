"""Tests for IAM user collection."""

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from app.collectors.base import CollectorEvidenceError
from app.collectors.iam import IAMUserCollector
from app.schemas.resource import ResourceScope
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

_CREATED_AT = datetime(2024, 1, 1, tzinfo=UTC)
_MISSING = object()


def _user(**overrides: object) -> dict[str, object]:
    user: dict[str, object] = {
        "Path": "/",
        "UserName": "alice",
        "UserId": "AIDAALICE",
        "Arn": "arn:aws:iam::123456789012:user/alice",
        "CreateDate": _CREATED_AT,
    }
    user.update(overrides)
    return user


def _access_key(**overrides: object) -> dict[str, object]:
    key: dict[str, object] = {
        "UserName": "alice",
        "AccessKeyId": "AKIAALICE",
        "Status": "Active",
        "CreateDate": _CREATED_AT,
    }
    key.update(overrides)
    return key


def _client_for_one_user(
    *,
    user: object | None = None,
    tag_pages: list[object] | None = None,
    mfa_pages: list[object] | None = None,
    access_key_pages: list[object] | None = None,
    last_used_responses: list[object | BaseException] | None = None,
) -> FakeAWSClient:
    return FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": [_user() if user is None else user]}]),
            "list_user_tags": FakePaginator([{"Tags": []}] if tag_pages is None else tag_pages),
            "list_mfa_devices": FakePaginator(
                [{"MFADevices": []}] if mfa_pages is None else mfa_pages
            ),
            "list_access_keys": FakePaginator(
                [{"AccessKeyMetadata": []}] if access_key_pages is None else access_key_pages
            ),
        },
        responses={"get_access_key_last_used": last_used_responses or []},
    )


def _collect(client: FakeAWSClient) -> list[Any]:
    provider = FakeClientProvider({("iam", "us-east-1"): client})
    return IAMUserCollector(provider).collect()


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


@pytest.mark.parametrize(
    ("error_code", "status_code"),
    (("AccessDenied", 403), ("Throttling", 429)),
)
def test_propagates_iam_enrichment_errors(error_code: str, status_code: int) -> None:
    error = client_error(error_code, "ListMFADevices", status_code=status_code)
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

    assert exc_info.value.response["Error"]["Code"] == error_code


def test_rejects_mfa_page_that_omits_required_result_list() -> None:
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
                                "CreateDate": _CREATED_AT,
                            }
                        ]
                    }
                ]
            ),
            "list_user_tags": FakePaginator([{"Tags": []}]),
            "list_mfa_devices": FakePaginator([{}]),
        }
    )

    with pytest.raises(CollectorEvidenceError, match="MFADevices"):
        IAMUserCollector(FakeClientProvider({("iam", "us-east-1"): client})).collect()


def test_valid_empty_user_inventory_succeeds_without_enrichment_calls() -> None:
    client = FakeAWSClient(
        paginators={"list_users": FakePaginator([{"Users": []}])},
    )

    assert _collect(client) == []
    assert client.paginator_requests == ["list_users"]


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("UserName", _MISSING),
        ("UserName", None),
        ("UserId", 123),
        ("UserId", None),
        ("Arn", ""),
        ("Arn", None),
        ("Path", _MISSING),
        ("Path", None),
        ("CreateDate", _MISSING),
        ("CreateDate", "2024-01-01"),
    ),
    ids=(
        "missing-name",
        "null-name",
        "wrong-user-id",
        "null-user-id",
        "empty-arn",
        "null-arn",
        "missing-path",
        "null-path",
        "missing-created-at",
        "wrong-created-at",
    ),
)
def test_rejects_missing_or_malformed_required_user_fields(
    field: str,
    invalid_value: object,
) -> None:
    user = _user()
    if invalid_value is _MISSING:
        user.pop(field)
    else:
        user[field] = invalid_value

    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(_client_for_one_user(user=user))

    assert exc_info.value.operation_name == "list_users"
    assert exc_info.value.fact_path == f"Users[].{field}"
    assert "None" not in exc_info.value.fact_path


def test_optional_password_last_used_accepts_explicit_null() -> None:
    resources = _collect(_client_for_one_user(user=_user(PasswordLastUsed=None)))

    assert resources[0].configuration["password_last_used"] is None


def test_rejects_malformed_optional_password_last_used() -> None:
    with pytest.raises(CollectorEvidenceError, match="PasswordLastUsed"):
        _collect(_client_for_one_user(user=_user(PasswordLastUsed="yesterday")))


def test_accepts_empty_tag_value_without_coercion() -> None:
    resources = _collect(
        _client_for_one_user(tag_pages=[{"Tags": [{"Key": "Owner", "Value": ""}]}])
    )

    assert resources[0].tags == {"Owner": ""}


@pytest.mark.parametrize(
    "tag",
    (
        {"Value": "platform"},
        {"Key": None, "Value": "platform"},
        {"Key": "Owner"},
        {"Key": "Owner", "Value": None},
        {"Key": "Owner", "Value": 7},
    ),
)
def test_rejects_malformed_paginated_user_tags(tag: dict[str, object]) -> None:
    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(_client_for_one_user(tag_pages=[{"Tags": [tag]}]))

    assert exc_info.value.operation_name == "list_user_tags"
    assert "Tags" in exc_info.value.fact_path


def test_rejects_conflicting_duplicate_tag_evidence() -> None:
    client = _client_for_one_user(
        tag_pages=[
            {"Tags": [{"Key": "Owner", "Value": "platform"}]},
            {"Tags": [{"Key": "Owner", "Value": "security"}]},
        ]
    )

    with pytest.raises(CollectorEvidenceError, match="list_user_tags"):
        _collect(client)


def _mfa_device(**overrides: object) -> dict[str, object]:
    device: dict[str, object] = {
        "UserName": "alice",
        "SerialNumber": "arn:aws:iam::123456789012:mfa/alice",
        "EnableDate": _CREATED_AT,
    }
    device.update(overrides)
    return device


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("UserName", _MISSING),
        ("UserName", "other-user"),
        ("SerialNumber", _MISSING),
        ("SerialNumber", None),
        ("SerialNumber", 42),
        ("SerialNumber", " "),
        ("EnableDate", _MISSING),
        ("EnableDate", "2024-01-01"),
    ),
)
def test_rejects_partial_or_malformed_mfa_device(
    field: str,
    invalid_value: object,
) -> None:
    device = _mfa_device()
    if invalid_value is _MISSING:
        device.pop(field)
    else:
        device[field] = invalid_value

    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(_client_for_one_user(mfa_pages=[{"MFADevices": [device]}]))

    assert exc_info.value.operation_name == "list_mfa_devices"
    assert exc_info.value.fact_path == f"MFADevices[].{field}"


def test_deduplicates_exact_mfa_device_across_pages() -> None:
    device = _mfa_device()
    resources = _collect(
        _client_for_one_user(
            mfa_pages=[{"MFADevices": [device]}, {"MFADevices": [device]}],
        )
    )

    assert resources[0].configuration["mfa_devices"] == [
        {
            "UserName": "alice",
            "SerialNumber": "arn:aws:iam::123456789012:mfa/alice",
            "EnableDate": "2024-01-01T00:00:00+00:00",
        }
    ]


def test_rejects_conflicting_duplicate_mfa_device() -> None:
    first = _mfa_device()
    second = _mfa_device(EnableDate=datetime(2024, 2, 1, tzinfo=UTC))

    with pytest.raises(CollectorEvidenceError, match="SerialNumber"):
        _collect(
            _client_for_one_user(
                mfa_pages=[{"MFADevices": [first]}, {"MFADevices": [second]}],
            )
        )


@pytest.mark.parametrize(
    "invalid_value",
    (_MISSING, None, 42, ""),
    ids=("missing", "null", "wrong-type", "empty"),
)
def test_rejects_malformed_required_access_key_id(invalid_value: object) -> None:
    key = _access_key()
    if invalid_value is _MISSING:
        key.pop("AccessKeyId")
    else:
        key["AccessKeyId"] = invalid_value

    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(_client_for_one_user(access_key_pages=[{"AccessKeyMetadata": [key]}]))

    assert exc_info.value.operation_name == "list_access_keys"
    assert exc_info.value.fact_path == "AccessKeyMetadata[].AccessKeyId"


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("UserName", None),
        ("UserName", "other-user"),
        ("Status", None),
        ("Status", "Unexpected"),
        ("CreateDate", None),
        ("CreateDate", "2024-01-01"),
    ),
)
def test_rejects_malformed_present_optional_access_key_metadata(
    field: str,
    invalid_value: object,
) -> None:
    key = _access_key(**{field: invalid_value})

    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(_client_for_one_user(access_key_pages=[{"AccessKeyMetadata": [key]}]))

    assert exc_info.value.operation_name == "list_access_keys"
    assert exc_info.value.fact_path == f"AccessKeyMetadata[].{field}"


def test_accepts_absent_optional_access_key_metadata_and_missing_last_used_result() -> None:
    resources = _collect(
        _client_for_one_user(
            access_key_pages=[{"AccessKeyMetadata": [{"AccessKeyId": "AKIAALICE"}]}],
            last_used_responses=[{}],
        )
    )

    assert resources[0].configuration["access_keys"] == [
        {"AccessKeyId": "AKIAALICE", "LastUsed": None}
    ]


def test_accepts_expired_access_key_status() -> None:
    resources = _collect(
        _client_for_one_user(
            access_key_pages=[{"AccessKeyMetadata": [_access_key(Status="Expired")]}],
            last_used_responses=[{}],
        )
    )

    assert resources[0].configuration["access_keys"][0]["Status"] == "Expired"


def test_deduplicates_exact_access_key_before_last_used_lookup() -> None:
    key = _access_key()
    client = _client_for_one_user(
        access_key_pages=[
            {"AccessKeyMetadata": [key]},
            {"AccessKeyMetadata": [key]},
        ],
        last_used_responses=[{}],
    )

    resources = _collect(client)

    assert len(resources[0].configuration["access_keys"]) == 1
    assert [call.operation_name for call in client.calls] == ["get_access_key_last_used"]


def test_rejects_conflicting_duplicate_access_key() -> None:
    client = _client_for_one_user(
        access_key_pages=[
            {"AccessKeyMetadata": [_access_key()]},
            {"AccessKeyMetadata": [_access_key(Status="Inactive")]},
        ],
        last_used_responses=[{}],
    )

    with pytest.raises(CollectorEvidenceError, match="AccessKeyId"):
        _collect(client)


@pytest.mark.parametrize(
    ("response", "expected_path"),
    (
        (None, "response"),
        ({"AccessKeyLastUsed": None}, "AccessKeyLastUsed"),
        ({"AccessKeyLastUsed": {}}, "AccessKeyLastUsed.ServiceName"),
        (
            {"AccessKeyLastUsed": {"ServiceName": None, "Region": "N/A"}},
            "AccessKeyLastUsed.ServiceName",
        ),
        (
            {"AccessKeyLastUsed": {"ServiceName": "N/A"}},
            "AccessKeyLastUsed.Region",
        ),
        (
            {"AccessKeyLastUsed": {"ServiceName": "s3", "Region": 42}},
            "AccessKeyLastUsed.Region",
        ),
        (
            {
                "AccessKeyLastUsed": {
                    "ServiceName": "s3",
                    "Region": "us-east-1",
                    "LastUsedDate": "yesterday",
                }
            },
            "AccessKeyLastUsed.LastUsedDate",
        ),
    ),
)
def test_rejects_malformed_access_key_last_used_response(
    response: object,
    expected_path: str,
) -> None:
    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(
            _client_for_one_user(
                access_key_pages=[{"AccessKeyMetadata": [_access_key()]}],
                last_used_responses=[response],
            )
        )

    assert exc_info.value.operation_name == "get_access_key_last_used"
    assert exc_info.value.fact_path == expected_path


def test_rejects_mismatched_last_used_response_user() -> None:
    with pytest.raises(CollectorEvidenceError) as exc_info:
        _collect(
            _client_for_one_user(
                access_key_pages=[{"AccessKeyMetadata": [_access_key()]}],
                last_used_responses=[{"UserName": "other-user"}],
            )
        )

    assert exc_info.value.fact_path == "UserName"


def test_deduplicates_exact_user_across_pages_before_enrichment() -> None:
    user = _user()
    client = FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": [user]}, {"Users": [user]}]),
            "list_user_tags": FakePaginator([{"Tags": []}]),
            "list_mfa_devices": FakePaginator([{"MFADevices": []}]),
            "list_access_keys": FakePaginator([{"AccessKeyMetadata": []}]),
        }
    )

    resources = _collect(client)

    assert [resource.aws_resource_id for resource in resources] == ["AIDAALICE"]
    assert client.paginator_requests == [
        "list_users",
        "list_user_tags",
        "list_mfa_devices",
        "list_access_keys",
    ]


def test_rejects_conflicting_duplicate_user_identity() -> None:
    first = _user()
    second = _user(Arn="arn:aws:iam::123456789012:user/renamed-alice")
    client = FakeAWSClient(
        paginators={
            "list_users": FakePaginator([{"Users": [first]}, {"Users": [second]}]),
            "list_user_tags": FakePaginator([{"Tags": []}]),
            "list_mfa_devices": FakePaginator([{"MFADevices": []}]),
            "list_access_keys": FakePaginator([{"AccessKeyMetadata": []}]),
        }
    )

    with pytest.raises(CollectorEvidenceError, match=r"Users\[\].UserId"):
        _collect(client)


def test_programming_error_is_not_reclassified_as_collector_evidence(monkeypatch) -> None:
    def fail_with_programming_error(_client: object, _user_name: str) -> list[dict[str, Any]]:
        raise RuntimeError("programming defect")

    monkeypatch.setattr(
        IAMUserCollector,
        "_collect_access_keys",
        staticmethod(fail_with_programming_error),
    )

    with pytest.raises(RuntimeError, match="programming defect"):
        _collect(_client_for_one_user())
