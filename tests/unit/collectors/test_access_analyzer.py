"""Unit coverage for Sprint 5D fact-only IAM Access Analyzer evidence."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.assessment.source_outcomes import (
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.collectors.access_analyzer import AccessAnalyzerCollector, _finding_resource_id
from app.collectors.base import CollectionContext, graph_collection_status_for
from app.schemas.inventory import CollectionStatus
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

ACCOUNT_ID = "123456789012"
REGION = "us-west-2"
SUPPLEMENTAL_REGION = "us-east-1"
SCAN_ID = UUID("74959769-c887-4d9a-a95f-f58edfc39b5d")
COLLECTED_AT = datetime(2026, 9, 16, 16, 30, tzinfo=UTC)
OBSERVED_AT = datetime(2026, 9, 16, 16, 0, tzinfo=UTC)


def _context(
    *,
    supplemental_regions: tuple[str, ...] = (),
    region_source_complete: bool = True,
) -> CollectionContext:
    return CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        region=REGION,
        collected_at=COLLECTED_AT,
        supplemental_regions=supplemental_regions,
        supplemental_region_source_complete=region_source_complete,
    )


def _analyzer(
    region: str,
    name: str = "external-access",
    *,
    analyzer_type: str = "ACCOUNT",
    status: str = "ACTIVE",
) -> dict[str, object]:
    return {
        "arn": f"arn:aws:access-analyzer:{region}:{ACCOUNT_ID}:analyzer/{name}",
        "name": name,
        "type": analyzer_type,
        "createdAt": OBSERVED_AT,
        "status": status,
    }


def _finding(
    finding_id: str = "finding-1",
    *,
    bucket_name: str = "customer-records",
    owner: str = ACCOUNT_ID,
    status: str = "ACTIVE",
) -> dict[str, object]:
    return {
        "analyzedAt": OBSERVED_AT,
        "createdAt": OBSERVED_AT,
        "id": finding_id,
        "resource": f"arn:aws:s3:::{bucket_name}",
        "resourceType": "AWS::S3::Bucket",
        "resourceOwnerAccount": owner,
        "status": status,
        "updatedAt": OBSERVED_AT,
        "findingType": "ExternalAccess",
    }


def _detail_page(
    finding: dict[str, object],
    details: list[object] | None = None,
    *,
    next_token: str | None = None,
) -> dict[str, object]:
    page = deepcopy(finding)
    page["findingDetails"] = details if details is not None else [_external_detail()]
    if next_token is not None:
        page["nextToken"] = next_token
    return page


def _external_detail() -> dict[str, object]:
    return {
        "externalAccessDetails": {
            "action": ["s3:GetObject", "s3:ListBucket"],
            "condition": {"aws:PrincipalOrgID": "o-example"},
            "isPublic": False,
            "principal": {"AWS": "arn:aws:iam::210987654321:root"},
            "sources": [
                {
                    "type": "S3_ACCESS_POINT",
                    "detail": {
                        "accessPointArn": (
                            "arn:aws:s3:us-west-2:123456789012:accesspoint/customer"
                        ),
                        "accessPointAccount": ACCOUNT_ID,
                    },
                },
                {"type": "POLICY"},
            ],
            "resourceControlPolicyRestriction": "NOT_APPLICABLE",
        }
    }


def _client(
    *,
    analyzer_pages: list[object] | None = None,
    finding_paginators: list[FakePaginator] | None = None,
    detail_paginators: list[FakePaginator] | None = None,
    analyzer_error: BaseException | None = None,
) -> FakeAWSClient:
    return FakeAWSClient(
        paginators={
            "list_analyzers": FakePaginator(
                analyzer_pages if analyzer_pages is not None else [{"analyzers": []}],
                error=analyzer_error,
            ),
            **({"list_findings_v2": finding_paginators} if finding_paginators is not None else {}),
            **({"get_finding_v2": detail_paginators} if detail_paginators is not None else {}),
        }
    )


def _collector(clients: dict[tuple[str, str], FakeAWSClient]) -> AccessAnalyzerCollector:
    return AccessAnalyzerCollector(
        FakeClientProvider(
            clients,
            region_name=REGION,
            account_id=ACCOUNT_ID,
            partition="aws",
        )
    )


def _outcomes(result: object, evidence_kind_prefix: str):
    return [
        item
        for item in result.source_outcomes  # type: ignore[attr-defined]
        if item.evidence_kind.startswith(evidence_kind_prefix)
    ]


def _reconstructed_status(result: object) -> CollectionStatus:
    return graph_collection_status_for(
        collector_name=AccessAnalyzerCollector.collector_name,
        outcomes=result.source_outcomes,  # type: ignore[attr-defined]
        artifacts=result.artifacts,  # type: ignore[attr-defined]
    )


def test_collects_every_region_page_detail_and_bucket_reference_deterministically() -> None:
    east_analyzer = _analyzer(SUPPLEMENTAL_REGION, "east")
    east_finding = _finding("shared-id", bucket_name="east-records")
    west_analyzer = _analyzer(REGION, "west", analyzer_type="ORGANIZATION")
    irrelevant_analyzer = _analyzer(REGION, "unused", analyzer_type="ACCOUNT_UNUSED_ACCESS")
    west_finding = _finding("shared-id", bucket_name="west-records")
    east_analyzer_pages = [
        {"analyzers": [], "nextToken": "analyzer-page-2"},
        {"analyzers": [east_analyzer]},
    ]
    east_finding_pages = [
        {"findings": [], "nextToken": "finding-page-2"},
        {"findings": [east_finding]},
    ]
    east_detail_pages = [
        _detail_page(east_finding, [_external_detail()], next_token="detail-page-2"),
        _detail_page(east_finding, []),
    ]
    east = _client(
        analyzer_pages=east_analyzer_pages,
        finding_paginators=[FakePaginator(east_finding_pages)],
        detail_paginators=[FakePaginator(east_detail_pages)],
    )
    west = _client(
        analyzer_pages=[{"analyzers": [irrelevant_analyzer, west_analyzer]}],
        finding_paginators=[FakePaginator([{"findings": [west_finding]}])],
        detail_paginators=[FakePaginator([_detail_page(west_finding)])],
    )
    collector = _collector(
        {
            ("accessanalyzer", SUPPLEMENTAL_REGION): east,
            ("accessanalyzer", REGION): west,
        }
    )

    result = collector.collect_with_context(_context(supplemental_regions=(SUPPLEMENTAL_REGION,)))

    assert result.status is CollectionStatus.SUCCEEDED
    assert _reconstructed_status(result) is result.status
    assert collector.client_provider.client_requests == [
        ("accessanalyzer", SUPPLEMENTAL_REGION),
        ("accessanalyzer", REGION),
    ]
    assert len(result.resources) == 2
    assert {resource.region for resource in result.resources} == {
        SUPPLEMENTAL_REGION,
        REGION,
    }
    assert len({resource.aws_resource_id for resource in result.resources}) == 2
    assert all(resource.account_id == ACCOUNT_ID for resource in result.resources)
    assert all(resource.arn is None for resource in result.resources)
    east_resource = next(
        resource for resource in result.resources if resource.region == SUPPLEMENTAL_REGION
    )
    external = east_resource.configuration["finding_details"][0]["external_access_details"]
    assert external == {
        "action": ["s3:GetObject", "s3:ListBucket"],
        "condition": {"aws:PrincipalOrgID": "o-example"},
        "is_public": False,
        "principal": {"AWS": "arn:aws:iam::210987654321:root"},
        "sources": [
            {"detail": None, "type": "POLICY"},
            {
                "detail": {
                    "accessPointAccount": ACCOUNT_ID,
                    "accessPointArn": ("arn:aws:s3:us-west-2:123456789012:accesspoint/customer"),
                },
                "type": "S3_ACCESS_POINT",
            },
        ],
        "resource_control_policy_restriction": "NOT_APPLICABLE",
    }

    assert len(result.relationships) == 2
    targets = {
        (relationship.target.aws_resource_id, relationship.target.region)
        for relationship in result.relationships
    }
    assert targets == {
        ("east-records", SUPPLEMENTAL_REGION),
        ("west-records", REGION),
    }
    assert all(
        relationship.target_collector_name == "s3_buckets" for relationship in result.relationships
    )
    assert all(
        relationship.provenance.source_api == "access-analyzer:ListFindings"
        for relationship in result.relationships
    )

    assert east.paginator_requests == [
        "list_analyzers",
        "list_findings_v2",
        "get_finding_v2",
    ]
    finding_outcomes = _outcomes(result, "access-analyzer.findings.discovery.")
    assert len(finding_outcomes) == 2
    assert len({item.evidence_kind for item in finding_outcomes}) == 2
    analyzer_artifacts = [
        artifact
        for artifact in result.artifacts
        if artifact.evidence_schema == "access-analyzer.analyzers.discovery"
    ]
    assert len(analyzer_artifacts) == 2
    for artifact in analyzer_artifacts:
        assert artifact.normalized_payload["required_regions"] == (
            SUPPLEMENTAL_REGION,
            REGION,
        )
        assert artifact.normalized_payload["s3_region_discovery_complete"] is True


def test_calls_list_analyzers_unfiltered_and_filters_each_finding_source() -> None:
    analyzer = _analyzer(REGION)
    finding = _finding()
    analyzer_paginator = FakePaginator([{"analyzers": [analyzer]}])
    finding_paginator = FakePaginator([{"findings": [finding]}])
    detail_paginator = FakePaginator([_detail_page(finding)])
    client = FakeAWSClient(
        paginators={
            "list_analyzers": analyzer_paginator,
            "list_findings_v2": finding_paginator,
            "get_finding_v2": detail_paginator,
        }
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert analyzer_paginator.calls == [{}]
    assert finding_paginator.calls == [
        {
            "analyzerArn": analyzer["arn"],
            "filter": {
                "findingType": {"eq": ["ExternalAccess"]},
                "resourceType": {"eq": ["AWS::S3::Bucket"]},
            },
        }
    ]
    assert detail_paginator.calls == [{"analyzerArn": analyzer["arn"], "id": finding["id"]}]


def test_complete_region_without_external_analyzer_is_explicit_absence() -> None:
    irrelevant = _analyzer(REGION, analyzer_type="ACCOUNT_INTERNAL_ACCESS")
    client = _client(analyzer_pages=[{"analyzers": [irrelevant]}])

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert not result.resources
    assert len(result.source_outcomes) == 1
    assert result.source_outcomes[0].state is EvidenceSourceState.EXPECTED_ABSENCE
    artifact = result.artifacts[0]
    assert artifact.normalized_payload["relevant_analyzer_arns"] == ()
    assert artifact.normalized_payload["complete"] is True


def test_incomplete_s3_region_source_prevents_complete_analyzer_coverage() -> None:
    client = _client()

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(
        _context(region_source_complete=False)
    )

    assert result.status is CollectionStatus.PARTIAL
    assert _reconstructed_status(result) is result.status
    assert result.source_outcomes[0].state is EvidenceSourceState.EXPECTED_ABSENCE
    assert result.artifacts[0].normalized_payload["s3_region_discovery_complete"] is False


def test_malformed_analyzer_does_not_erase_valid_sibling_finding() -> None:
    valid = _analyzer(REGION)
    malformed = _analyzer(REGION, "malformed", status="UNKNOWN")
    finding = _finding()
    client = _client(
        analyzer_pages=[{"analyzers": [None, malformed, valid]}],
        finding_paginators=[FakePaginator([{"findings": [finding]}])],
        detail_paginators=[FakePaginator([_detail_page(finding)])],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert len(result.resources) == 1
    analyzer_outcome = _outcomes(result, "access-analyzer.analyzers.discovery")[0]
    assert analyzer_outcome.state is EvidenceSourceState.MALFORMED
    assert analyzer_outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert _outcomes(result, "access-analyzer.finding-summary")[0].state is (
        EvidenceSourceState.PRESENT
    )


def test_access_denied_is_sanitized_and_fails_closed() -> None:
    client = _client(analyzer_error=client_error("AccessDeniedException", "ListAnalyzers"))

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.FAILED
    assert not result.resources
    assert result.source_outcomes[0].state is EvidenceSourceState.UNAVAILABLE
    assert result.source_outcomes[0].failure_category is EvidenceFailureCategory.ACCESS_DENIED
    assert result.artifacts[0].normalized_payload["failure_category"] == "ACCESS_DENIED"
    assert "simulated" not in result.artifacts[0].model_dump_json()


@pytest.mark.parametrize("pagination_case", ["analyzers", "findings", "details"])
def test_unconsumed_pagination_tokens_are_malformed_without_erasing_safe_facts(
    pagination_case: str,
) -> None:
    analyzer = _analyzer(REGION)
    finding = _finding()
    analyzer_pages = [{"analyzers": [analyzer]}]
    finding_pages = [{"findings": [finding]}]
    detail_pages = [_detail_page(finding)]
    if pagination_case == "analyzers":
        analyzer_pages[0]["nextToken"] = "unconsumed"
    elif pagination_case == "findings":
        finding_pages[0]["nextToken"] = "unconsumed"
    else:
        detail_pages[0]["nextToken"] = "unconsumed"
    client = _client(
        analyzer_pages=analyzer_pages,
        finding_paginators=[FakePaginator(finding_pages)],
        detail_paginators=[FakePaginator(detail_pages)],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    malformed = [
        outcome
        for outcome in result.source_outcomes
        if outcome.state is EvidenceSourceState.MALFORMED
    ]
    assert len(malformed) == 1
    assert malformed[0].failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert len(result.resources) == 1


def test_repeated_pagination_token_is_rejected() -> None:
    client = _client(
        analyzer_pages=[
            {"analyzers": [], "nextToken": "same-token"},
            {"analyzers": [], "nextToken": "same-token"},
            {"analyzers": []},
        ]
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert result.source_outcomes[0].state is EvidenceSourceState.MALFORMED


def test_malformed_external_detail_is_local_to_that_finding() -> None:
    analyzer = _analyzer(REGION)
    first = _finding("finding-1")
    second = _finding("finding-2", bucket_name="other-records")
    malformed_detail = _external_detail()
    malformed_detail["externalAccessDetails"]["condition"] = []  # type: ignore[index]
    client = _client(
        analyzer_pages=[{"analyzers": [analyzer]}],
        finding_paginators=[FakePaginator([{"findings": [first, second]}])],
        detail_paginators=[
            FakePaginator([_detail_page(first, [malformed_detail])]),
            FakePaginator([_detail_page(second)]),
        ],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert len(result.resources) == 2
    detail_outcomes = _outcomes(result, "access-analyzer.finding-details")
    assert {item.state for item in detail_outcomes} == {
        EvidenceSourceState.MALFORMED,
        EvidenceSourceState.PRESENT,
    }
    incomplete = next(item for item in result.resources if item.name == "finding-1")
    assert incomplete.configuration["detail_complete"] is False
    assert incomplete.configuration["detail_failure_category"] == "MALFORMED_RESPONSE"


def test_disappeared_finding_retains_summary_with_typed_outcome() -> None:
    analyzer = _analyzer(REGION)
    finding = _finding()
    client = _client(
        analyzer_pages=[{"analyzers": [analyzer]}],
        finding_paginators=[FakePaginator([{"findings": [finding]}])],
        detail_paginators=[
            FakePaginator(error=client_error("ResourceNotFoundException", "GetFindingV2"))
        ],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert len(result.resources) == 1
    detail_outcome = _outcomes(result, "access-analyzer.finding-details")[0]
    assert detail_outcome.state is EvidenceSourceState.RESOURCE_DISAPPEARED
    assert detail_outcome.failure_category is EvidenceFailureCategory.RESOURCE_NOT_FOUND
    assert result.resources[0].configuration["finding_details"] == []
    assert len(result.relationships) == 1


def test_get_finding_accepts_omitted_optional_identity_fields() -> None:
    analyzer = _analyzer(REGION)
    finding = _finding()
    detail_page = _detail_page(finding)
    detail_page.pop("findingType")
    detail_page.pop("resource")
    client = _client(
        analyzer_pages=[{"analyzers": [analyzer]}],
        finding_paginators=[FakePaginator([{"findings": [finding]}])],
        detail_paginators=[FakePaginator([detail_page])],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    detail_outcome = _outcomes(result, "access-analyzer.finding-details")[0]
    assert detail_outcome.state is EvidenceSourceState.PRESENT
    resource = result.resources[0]
    assert resource.configuration["finding"]["finding_type"] == "ExternalAccess"
    assert resource.configuration["finding"]["resource_arn"] == finding["resource"]
    assert resource.configuration["finding_details"] == [
        {
            "external_access_details": {
                "action": ["s3:GetObject", "s3:ListBucket"],
                "condition": {"aws:PrincipalOrgID": "o-example"},
                "is_public": False,
                "principal": {"AWS": "arn:aws:iam::210987654321:root"},
                "resource_control_policy_restriction": "NOT_APPLICABLE",
                "sources": [
                    {"detail": None, "type": "POLICY"},
                    {
                        "detail": {
                            "accessPointAccount": ACCOUNT_ID,
                            "accessPointArn": (
                                "arn:aws:s3:us-west-2:123456789012:accesspoint/customer"
                            ),
                        },
                        "type": "S3_ACCESS_POINT",
                    },
                ],
            }
        }
    ]


def test_conflicting_duplicate_finding_is_removed_without_erasing_other_finding() -> None:
    analyzer = _analyzer(REGION)
    conflicted = _finding("finding-1")
    conflicting = _finding("finding-1", status="RESOLVED")
    sibling = _finding("finding-2", bucket_name="other-records")
    client = _client(
        analyzer_pages=[{"analyzers": [analyzer]}],
        finding_paginators=[FakePaginator([{"findings": [conflicted, conflicting, sibling]}])],
        detail_paginators=[FakePaginator([_detail_page(sibling)])],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert [resource.name for resource in result.resources] == ["finding-2"]
    discovery = _outcomes(result, "access-analyzer.findings.discovery.")[0]
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert discovery.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE


def test_detail_identity_change_is_a_conflict_not_a_retargeted_resource() -> None:
    analyzer = _analyzer(REGION)
    finding = _finding()
    changed = _finding(bucket_name="different-bucket")
    client = _client(
        analyzer_pages=[{"analyzers": [analyzer]}],
        finding_paginators=[FakePaginator([{"findings": [finding]}])],
        detail_paginators=[FakePaginator([_detail_page(changed)])],
    )

    result = _collector({("accessanalyzer", REGION): client}).collect_with_context(_context())

    detail_outcome = _outcomes(result, "access-analyzer.finding-details")[0]
    assert detail_outcome.state is EvidenceSourceState.CONFLICT
    assert result.resources[0].configuration["summary"]["resource_arn"] == (
        "arn:aws:s3:::customer-records"
    )
    assert result.relationships[0].target.aws_resource_id == "customer-records"


def test_direct_collect_scans_only_the_provider_region() -> None:
    client = _client()
    collector = _collector({("accessanalyzer", REGION): client})

    assert collector.collect() == []
    assert collector.client_provider.client_requests == [("accessanalyzer", REGION)]


def test_finding_resource_id_uses_unambiguous_composite_serialization() -> None:
    assert _finding_resource_id("ab", "c") != _finding_resource_id("a", "bc")
    assert _finding_resource_id("ab", "c") == _finding_resource_id("ab", "c")
