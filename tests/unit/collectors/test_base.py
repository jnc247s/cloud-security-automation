"""Evidence-completeness tests for shared collector helpers."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest
from botocore.exceptions import PaginationError

from app.assessment.evidence_graph import (
    EvidenceCardinality,
    ScanSourceContract,
    SourceEvidenceArtifact,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
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
    source_failure,
    tags_to_dict,
    validate_access_analyzer_s3_region_source_status,
)
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import ResourceScope
from tests.fakes import FakeAWSClient, FakePaginator, client_error

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


def _s3_discovery_source(
    *,
    state: EvidenceSourceState = EvidenceSourceState.PRESENT,
    failure_category: EvidenceFailureCategory | None = None,
) -> tuple[SourceEvidenceArtifact, SourceEvidenceOutcome]:
    complete = state is EvidenceSourceState.PRESENT
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/buckets",
        evidence_schema="s3.buckets.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "buckets": [],
            "bucket_names": [],
            "resource_count": 0,
            "discarded_item_count": 0,
            "complete": complete,
            "failure_category": (failure_category.value if failure_category is not None else None),
        },
    )
    outcome = SourceEvidenceOutcome.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=ACCOUNT_ID,
            scope=ResourceScope.GLOBAL,
        ),
        evidence_kind="s3.buckets.discovery",
        state=state,
        failure_category=failure_category,
        collector="s3.buckets",
        collector_version="1.0.0",
        source_api="s3:ListAllMyBuckets",
        collected_at=COLLECTED_AT,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )
    return artifact, outcome


def _cloudtrail_discovery_source(
    *,
    unadmitted: bool,
) -> tuple[ScanSourceContract, SourceEvidenceArtifact, SourceEvidenceOutcome]:
    trail_arn = "arn:aws:cloudtrail:us-west-2:210987654321:trail/audit-trail"
    subject = AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    contract = ScanSourceContract.for_scan(
        contract_key="cloudtrail.trails.discovery",
        contract_version="1.0.0",
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=subject,
        evidence_kind="cloudtrail.trails.discovery",
        collector="cloudtrail.trails",
        collector_version="1.0.0",
        source_api="cloudtrail:ListTrails",
        cardinality=EvidenceCardinality.COLLECTION,
    )
    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://cloudtrail/trails/discovery",
        evidence_schema="cloudtrail.trails.discovery",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "collection_account_id": ACCOUNT_ID,
            "invocation_region": "us-east-1",
            "trail_arns": [trail_arn] if unadmitted else [],
            "trail_count": 1 if unadmitted else 0,
            "discarded_item_count": 0,
            "admission_complete": not unadmitted,
            "unadmitted_resources": (
                [
                    {
                        "account_id": "210987654321",
                        "service": "cloudtrail",
                        "resource_type": "cloudtrail_trail",
                        "scope": "regional",
                        "region": "us-west-2",
                        "resource_id": trail_arn,
                    }
                ]
                if unadmitted
                else []
            ),
            "complete": True,
            "failure_category": None,
        },
    )
    outcome = SourceEvidenceOutcome.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=subject,
        evidence_kind="cloudtrail.trails.discovery",
        state=EvidenceSourceState.PRESENT,
        failure_category=None,
        collector="cloudtrail.trails",
        collector_version="1.0.0",
        source_api="cloudtrail:ListTrails",
        collected_at=COLLECTED_AT,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )
    return contract, artifact, outcome


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


def test_source_failure_classifies_unsupported_operation_exception() -> None:
    state, category = source_failure(
        client_error("UnsupportedOperationException", "GetEventSelectors")
    )

    assert state is EvidenceSourceState.UNAVAILABLE
    assert category is EvidenceFailureCategory.UNSUPPORTED_OPERATION


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


def test_cloudtrail_graph_status_reconstructs_empty_dynamic_manifest() -> None:
    contract, artifact, outcome = _cloudtrail_discovery_source(unadmitted=False)

    assert (
        graph_collection_status_for(
            collector_name="cloudtrail_evidence",
            outcomes=(outcome,),
            artifacts=(artifact,),
            contracts=(contract,),
        )
        is CollectionStatus.SUCCEEDED
    )
    assert graph_collection_validation_required(
        collector_name="cloudtrail_evidence",
        requested_collectors=("cloudtrail_evidence",),
        outcomes=(),
    )


def test_cloudtrail_graph_status_retains_unadmitted_external_gap() -> None:
    contract, artifact, outcome = _cloudtrail_discovery_source(unadmitted=True)

    assert (
        graph_collection_status_for(
            collector_name="cloudtrail_evidence",
            outcomes=(outcome,),
            artifacts=(artifact,),
            contracts=(contract,),
        )
        is CollectionStatus.PARTIAL
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


def test_5e_analyzer_coverage_uses_exact_s3_discovery_not_outer_rollup() -> None:
    analyzer_artifact, analyzer_outcome = _access_analyzer_source(
        region="us-east-1",
        required_regions=("us-east-1",),
        s3_region_discovery_complete=True,
    )
    s3_artifact, s3_outcome = _s3_discovery_source()

    assert validate_access_analyzer_s3_region_source_status(
        outcomes=(analyzer_outcome, s3_outcome),
        artifacts=(analyzer_artifact, s3_artifact),
        s3_status=CollectionStatus.PARTIAL,
    )

    failed_artifact, failed_outcome = _s3_discovery_source(
        state=EvidenceSourceState.UNAVAILABLE,
        failure_category=EvidenceFailureCategory.ACCESS_DENIED,
    )
    with pytest.raises(ValueError, match="disagrees with S3 discovery status"):
        validate_access_analyzer_s3_region_source_status(
            outcomes=(analyzer_outcome, failed_outcome),
            artifacts=(analyzer_artifact, failed_artifact),
            s3_status=CollectionStatus.SUCCEEDED,
        )


def test_s3_account_public_access_block_subject_must_match_collection_account() -> None:
    discovery_artifact, discovery_outcome = _s3_discovery_source()
    account_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        evidence_reference="normalized://s3/account/public-access-block",
        evidence_schema="s3.account-public-access-block",
        evidence_schema_version="1.0.0",
        collected_at=COLLECTED_AT,
        normalized_payload={
            "account_id": ACCOUNT_ID,
            "configured": True,
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "complete": True,
            "expected_absence": False,
            "failure_category": None,
        },
    )
    account_outcome = SourceEvidenceOutcome.for_observation(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=ACCOUNT_ID,
            scope=ResourceScope.GLOBAL,
        ),
        evidence_kind="s3.account-public-access-block",
        state=EvidenceSourceState.PRESENT,
        failure_category=None,
        collector="s3.account-public-access-block",
        collector_version="1.0.0",
        source_api="s3:GetAccountPublicAccessBlock",
        collected_at=COLLECTED_AT,
        evidence_reference=account_artifact.evidence_reference,
        evidence_sha256=account_artifact.evidence_sha256,
    )
    tampered = account_outcome.model_copy(
        update={
            "subject": AccountEvidenceSubject(
                aws_account_id="210987654321",
                scope=ResourceScope.GLOBAL,
            )
        }
    )

    with pytest.raises(ValueError, match="S3 source contract manifest"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=(discovery_outcome, tampered),
            artifacts=(discovery_artifact, account_artifact),
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
