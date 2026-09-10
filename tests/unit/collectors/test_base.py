"""Evidence-completeness tests for shared collector helpers."""

from datetime import UTC, datetime

import pytest
from botocore.exceptions import PaginationError

from app.collectors.base import (
    CollectorEvidenceError,
    iter_paginated_items,
    require_boolean,
    require_datetime,
    require_integer,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    should_skip_exact_duplicate,
    tags_to_dict,
)
from tests.fakes import FakeAWSClient, FakePaginator


@pytest.mark.parametrize(
    "page",
    (
        {},
        {"Things": None},
        {"Things": "not-a-list"},
        {"Things": ["not-an-object"]},
    ),
)
def test_paginated_items_reject_missing_or_malformed_result_evidence(
    page: dict[str, object],
) -> None:
    client = FakeAWSClient(paginators={"list_things": FakePaginator([page])})

    with pytest.raises(CollectorEvidenceError, match="list_things"):
        list(iter_paginated_items(client, "list_things", "Things"))


def test_paginated_items_preserve_known_empty_result() -> None:
    client = FakeAWSClient(paginators={"list_things": FakePaginator([{"Things": []}])})

    assert list(iter_paginated_items(client, "list_things", "Things")) == []


def test_paginated_items_reject_non_mapping_page() -> None:
    client = FakeAWSClient(paginators={"list_things": FakePaginator(["sensitive-page"])})

    with pytest.raises(CollectorEvidenceError) as error_info:
        list(iter_paginated_items(client, "list_things", "Things"))

    assert error_info.value.operation_name == "list_things"
    assert error_info.value.fact_path == "pages[0]"
    assert "sensitive-page" not in str(error_info.value)


@pytest.mark.parametrize(
    ("validator", "value"),
    (
        (require_mapping, []),
        (require_list, {}),
        (require_string, 1),
        (require_non_empty_string, "  "),
        (require_boolean, 1),
        (require_integer, True),
        (require_datetime, "2026-09-09T00:00:00Z"),
        (require_datetime, datetime(2026, 9, 9)),
    ),
)
def test_required_type_validators_raise_sanitized_evidence_errors(
    validator,
    value: object,
) -> None:
    with pytest.raises(CollectorEvidenceError) as error_info:
        validator(
            value,
            operation_name="describe_things",
            fact_path="Things[].SensitiveFact",
        )

    assert error_info.value.operation_name == "describe_things"
    assert error_info.value.fact_path == "Things[].SensitiveFact"


def test_required_type_validators_preserve_valid_values() -> None:
    now = datetime(2026, 9, 9, tzinfo=UTC)

    assert require_mapping({}, operation_name="op", fact_path="map") == {}
    assert require_list([], operation_name="op", fact_path="list") == []
    assert require_string("", operation_name="op", fact_path="string") == ""
    assert require_non_empty_string(" id ", operation_name="op", fact_path="id") == " id "
    assert require_boolean(False, operation_name="op", fact_path="flag") is False
    assert require_integer(0, operation_name="op", fact_path="count") == 0
    assert require_datetime(now, operation_name="op", fact_path="time") is now


def test_required_member_distinguishes_absence_from_explicit_null() -> None:
    with pytest.raises(CollectorEvidenceError, match="response.Required"):
        require_member(
            {},
            "Required",
            operation_name="operation",
            fact_path="response.Required",
        )

    assert (
        require_member(
            {"Required": None},
            "Required",
            operation_name="operation",
            fact_path="response.Required",
        )
        is None
    )


def test_tags_validate_entries_and_preserve_valid_empty_values() -> None:
    tags = tags_to_dict(
        [
            {"Key": "Owner", "Value": "platform"},
            {"Key": "Empty", "Value": ""},
            {"Key": "Owner", "Value": "platform"},
        ],
        operation_name="list_tags",
        fact_path="Tags",
    )

    assert tags == {"Owner": "platform", "Empty": ""}
    assert tags_to_dict([], operation_name="list_tags", fact_path="Tags") == {}
    assert tags_to_dict(
        [{"Key": "OptionalValue"}],
        operation_name="list_tags",
        fact_path="Tags",
        allow_missing_value=True,
    ) == {"OptionalValue": ""}


@pytest.mark.parametrize(
    "tags",
    (
        None,
        "not-a-list",
        [None],
        [{}],
        [{"Key": None, "Value": "value"}],
        [{"Key": "", "Value": "value"}],
        [{"Key": "Owner", "Value": None}],
        [{"Key": "Owner"}],
        [
            {"Key": "Owner", "Value": "one"},
            {"Key": "Owner", "Value": "two"},
        ],
    ),
)
def test_tags_reject_malformed_or_conflicting_evidence(tags: object) -> None:
    with pytest.raises(CollectorEvidenceError, match="list_tags"):
        tags_to_dict(tags, operation_name="list_tags", fact_path="Tags")


def test_exact_duplicate_helper_skips_repeats_and_rejects_conflicts() -> None:
    seen: dict[str, dict[str, object]] = {}
    item = {"Id": "thing-1", "State": "ready"}

    assert not should_skip_exact_duplicate(
        seen,
        "thing-1",
        item,
        operation_name="list_things",
        fact_path="Things[].duplicate_identity",
    )
    assert should_skip_exact_duplicate(
        seen,
        "thing-1",
        dict(item),
        operation_name="list_things",
        fact_path="Things[].duplicate_identity",
    )
    with pytest.raises(CollectorEvidenceError, match="duplicate_identity"):
        should_skip_exact_duplicate(
            seen,
            "thing-1",
            {"Id": "thing-1", "State": "changed"},
            operation_name="list_things",
            fact_path="Things[].duplicate_identity",
        )


def test_paginated_items_preserve_botocore_pagination_failures() -> None:
    error = PaginationError(message="sensitive malformed token state")
    client = FakeAWSClient(paginators={"list_things": FakePaginator(error=error)})

    with pytest.raises(PaginationError) as error_info:
        list(iter_paginated_items(client, "list_things", "Things"))

    assert error_info.value is error
