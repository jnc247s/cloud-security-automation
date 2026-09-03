"""Evidence-completeness tests for shared collector helpers."""

import pytest

from app.collectors.base import CollectorEvidenceError, iter_paginated_items
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
