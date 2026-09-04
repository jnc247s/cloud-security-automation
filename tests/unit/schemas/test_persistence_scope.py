"""Validation of exact requested and successful scan coverage."""

import pytest
from pydantic import ValidationError

from app.schemas.inventory import CollectionStatus
from app.schemas.persistence import ScanScopeManifestInput
from tests.unit.database.factories import scan_bundle


@pytest.mark.parametrize(
    "updates",
    [
        {"requested_regions": ("us-east-1", "us-east-1")},
        {"successful_regions": ("us-west-2",)},
        {"requested_collectors": ("security_groups", "s3_buckets")},
        {"requested_services": ("",)},
    ],
)
def test_scope_rejects_ambiguous_or_impossible_coverage(updates) -> None:
    values = scan_bundle()["scope"].model_dump()
    values.update(updates)
    with pytest.raises(ValidationError):
        ScanScopeManifestInput.model_validate(values)


def test_partial_scope_is_not_complete() -> None:
    scope = scan_bundle(collection_status=CollectionStatus.PARTIAL)["scope"]
    assert not scope.is_complete
    assert scope.successful_collectors == ()
    assert scope.collector_outcome_document() == {"security_groups": "PARTIAL"}
