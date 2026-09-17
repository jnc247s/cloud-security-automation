"""Evidence-completeness tests for shared collector helpers."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest
from botocore.exceptions import PaginationError

from app.assessment.evidence_graph import SourceEvidenceArtifact
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceSourceState,
    SourceEvidenceOutcome,
)
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceError,
    graph_collection_status_for,
    graph_collection_validation_required,
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
    validate_access_analyzer_s3_region_source_status,
)
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import ResourceScope
from tests.fakes import FakeAWSClient, FakePaginator

SCAN_ID = UUID("68d059ae-a5b6-42a1-aac6-76d7e72ac2ca")
ACCOUNT_ID = "123456789012"
COLLECTED_AT = datetime(2026, 9, 16, 15, 30, tzinfo=UTC)


def _access_analyzer_source(
    *,
    region: str,
    required_regions: tuple[str, ...],
    s3_region_discovery_complete: bool,
    analyzer_arn: str | None = None,
) -> tuple[SourceEvidenceArtifact, SourceEvidenceOutcome]:
    if analyzer_arn is None:
        evidence_kind = "access-analyzer.analyzers.discovery"
        collector = "access-analyzer.analyzers"
        source_api = "access-analyzer:ListAnalyzers"
        payload: dict[str, object] = {
            "account_id": ACCOUNT_ID,
            "region": region,
            "required_regions": list(required_regions),
            "s3_region_discovery_complete": s3_region_discovery_complete,
            "analyzers": [],
            "relevant_analyzer_arns": [],
            "complete": True,
            "failure_category": None,
        }
        suffix = "analyzers"
    else:
        digest = hashlib.sha256(analyzer_arn.encode()).hexdigest()
        evidence_kind = f"access-analyzer.findings.discovery.{digest}"
        collector = "access-analyzer.findings"
        source_api = "access-analyzer:ListFindings"
        payload = {
            "account_id": ACCOUNT_ID,
            "region": region,
            "analyzer": {"arn": analyzer_arn},
            "finding_ids": [],
            "resource_arns": [],
            "complete": True,
            "failure_category": None,
        }
        suffix = f"findings/{digest}"
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference=f"normalized://access-analyzer/{region}/{suffix}",
        evidence_schema=(
            "access-analyzer.findings.discovery" if analyzer_arn is not None else evidence_kind
        ),
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload=payload,
    )
    outcome = SourceEvidenceOutcome.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=ACCOUNT_ID,
            scope=ResourceScope.REGIONAL,
            region=region,
        ),
        evidence_kind=evidence_kind,
        state=EvidenceSourceState.PRESENT,
        failure_category=None,
        collector=collector,
        collector_version="1.0.0",
        source_api=source_api,
        collected_at=COLLECTED_AT,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )
    return artifact, outcome


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


def test_5c_manifest_marker_preserves_pre_5c_iam_history_and_gates_new_scans() -> None:
    """The new account collector distinguishes exact 5C manifests from legacy IAM scans."""

    assert not graph_collection_validation_required(
        collector_name="iam_users",
        requested_collectors=("iam_users",),
        outcomes=(),
    )
    assert graph_collection_validation_required(
        collector_name="iam_users",
        requested_collectors=("iam_account_evidence", "iam_users"),
        outcomes=(),
    )
    assert graph_collection_validation_required(
        collector_name="iam_account_evidence",
        requested_collectors=("iam_account_evidence", "iam_users"),
        outcomes=(),
    )


def test_collection_context_requires_canonical_supplemental_regions() -> None:
    context = CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        region="us-east-1",
        collected_at=COLLECTED_AT,
        supplemental_regions=("eu-west-1", "us-west-2"),
        supplemental_region_source_complete=False,
    )

    assert context.supplemental_regions == ("eu-west-1", "us-west-2")
    assert not context.supplemental_region_source_complete

    for invalid in (
        ("us-west-2", "eu-west-1"),
        ("us-west-2", "us-west-2"),
        ("us-east-1",),
        ("",),
    ):
        with pytest.raises(ValueError, match="supplemental Regions"):
            CollectionContext(
                scan_id=SCAN_ID,
                collection_account_id=ACCOUNT_ID,
                region="us-east-1",
                collected_at=COLLECTED_AT,
                supplemental_regions=invalid,
            )


def test_5d_manifest_marker_preserves_pre_5d_history_and_gates_new_scans() -> None:
    artifact, outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=True,
    )
    del artifact

    assert not graph_collection_validation_required(
        collector_name="access_analyzer_evidence",
        requested_collectors=("s3_buckets",),
        outcomes=(),
    )
    assert graph_collection_validation_required(
        collector_name="access_analyzer_evidence",
        requested_collectors=("access_analyzer_evidence", "s3_buckets"),
        outcomes=(),
    )
    assert graph_collection_validation_required(
        collector_name="access_analyzer_evidence",
        requested_collectors=("s3_buckets",),
        outcomes=(outcome,),
    )


def test_access_analyzer_status_reconstructs_dynamic_regional_manifest() -> None:
    east = _access_analyzer_source(
        region="us-east-1",
        required_regions=("eu-west-1", "us-east-1"),
        s3_region_discovery_complete=True,
    )
    west = _access_analyzer_source(
        region="eu-west-1",
        required_regions=("eu-west-1", "us-east-1"),
        s3_region_discovery_complete=True,
    )

    assert (
        graph_collection_status_for(
            collector_name="access_analyzer_evidence",
            artifacts=(east[0], west[0]),
            outcomes=(east[1], west[1]),
        )
        is CollectionStatus.SUCCEEDED
    )

    with pytest.raises(ValueError, match="Regional discovery manifest is incomplete"):
        graph_collection_status_for(
            collector_name="access_analyzer_evidence",
            artifacts=(east[0],),
            outcomes=(east[1],),
        )


def test_incomplete_s3_region_source_makes_analyzer_coverage_partial() -> None:
    artifact, outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=False,
    )
    assert (
        graph_collection_status_for(
            collector_name="access_analyzer_evidence",
            artifacts=(artifact,),
            outcomes=(outcome,),
        )
        is CollectionStatus.PARTIAL
    )


@pytest.mark.parametrize("s3_status", [CollectionStatus.PARTIAL, CollectionStatus.FAILED])
def test_access_analyzer_region_source_flag_matches_outer_s3_status(
    s3_status: CollectionStatus,
) -> None:
    complete_artifact, complete_outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=True,
    )
    incomplete_artifact, incomplete_outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=False,
    )

    assert validate_access_analyzer_s3_region_source_status(
        outcomes=(complete_outcome,),
        artifacts=(complete_artifact,),
        s3_status=CollectionStatus.SUCCEEDED,
    )
    assert not validate_access_analyzer_s3_region_source_status(
        outcomes=(incomplete_outcome,),
        artifacts=(incomplete_artifact,),
        s3_status=s3_status,
    )

    with pytest.raises(ValueError, match="disagrees with S3 discovery status"):
        validate_access_analyzer_s3_region_source_status(
            outcomes=(complete_outcome,),
            artifacts=(complete_artifact,),
            s3_status=s3_status,
        )
    with pytest.raises(ValueError, match="disagrees with S3 discovery status"):
        validate_access_analyzer_s3_region_source_status(
            outcomes=(incomplete_outcome,),
            artifacts=(incomplete_artifact,),
            s3_status=CollectionStatus.SUCCEEDED,
        )


def test_access_analyzer_manifest_requires_findings_source_for_each_analyzer() -> None:
    analyzer_arn = "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account-analyzer"
    analyzer_artifact, analyzer_outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=True,
    )
    analyzer_payload = analyzer_artifact.model_dump(mode="json")["normalized_payload"]
    analyzer_payload["relevant_analyzer_arns"] = [analyzer_arn]
    analyzer_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference=analyzer_artifact.evidence_reference,
        evidence_schema=analyzer_artifact.evidence_schema,
        evidence_schema_version=analyzer_artifact.evidence_schema_version,
        collected_at=COLLECTED_AT,
        normalized_payload=analyzer_payload,
    )
    analyzer_outcome = SourceEvidenceOutcome.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=analyzer_outcome.phase,
        subject=analyzer_outcome.subject,
        evidence_kind=analyzer_outcome.evidence_kind,
        state=analyzer_outcome.state,
        failure_category=None,
        collector=analyzer_outcome.collector,
        collector_version=analyzer_outcome.collector_version,
        source_api=analyzer_outcome.source_api,
        collected_at=COLLECTED_AT,
        evidence_reference=analyzer_artifact.evidence_reference,
        evidence_sha256=analyzer_artifact.evidence_sha256,
    )
    finding_artifact, finding_outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=True,
        analyzer_arn=analyzer_arn,
    )

    with pytest.raises(ValueError, match="findings manifest is incomplete"):
        graph_collection_status_for(
            collector_name="access_analyzer_evidence",
            artifacts=(analyzer_artifact,),
            outcomes=(analyzer_outcome,),
        )

    assert (
        graph_collection_status_for(
            collector_name="access_analyzer_evidence",
            artifacts=(analyzer_artifact, finding_artifact),
            outcomes=(analyzer_outcome, finding_outcome),
        )
        is CollectionStatus.SUCCEEDED
    )
