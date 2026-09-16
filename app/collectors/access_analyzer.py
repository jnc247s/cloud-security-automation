"""Sprint 5D fact-only IAM Access Analyzer evidence collection.

The collector preserves Regional analyzer and external-access finding facts.  It deliberately
does not interpret those facts as an S3 exposure decision; direct S3 evidence and rule evaluation
remain separate boundaries.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.relationships import RelationshipEndpoint, RelationshipType
from app.assessment.s3_identity import S3BucketIdentity
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
)
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceConflictError,
    CollectorEvidenceError,
    CollectorResult,
    RelationshipReference,
    ResourceCollector,
    SourceObservation,
    build_source_observation,
    collection_status_for,
    require_boolean,
    require_datetime,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    source_failure,
)
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import NormalizedResource, ResourceScope

_COLLECTOR_VERSION = "1.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)
_EXTERNAL_ANALYZER_TYPES = frozenset({"ACCOUNT", "ORGANIZATION"})
_ANALYZER_TYPES = frozenset(
    {
        "ACCOUNT",
        "ORGANIZATION",
        "ACCOUNT_UNUSED_ACCESS",
        "ORGANIZATION_UNUSED_ACCESS",
        "ACCOUNT_INTERNAL_ACCESS",
        "ORGANIZATION_INTERNAL_ACCESS",
    }
)
_ANALYZER_STATUSES = frozenset({"ACTIVE", "CREATING", "DISABLED", "FAILED"})
_FINDING_STATUSES = frozenset({"ACTIVE", "ARCHIVED", "RESOLVED"})
_FINDING_SOURCE_TYPES = frozenset(
    {"POLICY", "BUCKET_ACL", "S3_ACCESS_POINT", "S3_ACCESS_POINT_ACCOUNT"}
)
_RCP_RESTRICTIONS = frozenset({"APPLICABLE", "FAILED_TO_EVALUATE_RCP", "NOT_APPLICABLE", "APPLIED"})
_NOT_FOUND_CODES = frozenset({"ResourceNotFoundException"})


@dataclass(frozen=True, slots=True)
class _AnalyzerFacts:
    arn: str
    name: str
    analyzer_type: str
    status: str
    region: str
    created_at: str

    @property
    def is_external_access(self) -> bool:
        return self.analyzer_type in _EXTERNAL_ANALYZER_TYPES

    def as_payload(self) -> dict[str, object]:
        return {
            "arn": self.arn,
            "name": self.name,
            "type": self.analyzer_type,
            "status": self.status,
            "region": self.region,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class _FindingSummary:
    analyzer: _AnalyzerFacts
    finding_id: str
    composite_id: str
    resource_arn: str
    bucket_name: str
    resource_owner_account: str
    status: str
    analyzed_at: str
    created_at: str
    updated_at: str
    analysis_error_present: bool

    def as_payload(self) -> dict[str, object]:
        return {
            "analyzer_arn": self.analyzer.arn,
            "finding_id": self.finding_id,
            "finding_type": "ExternalAccess",
            "resource_arn": self.resource_arn,
            "resource_type": "AWS::S3::Bucket",
            "resource_owner_account": self.resource_owner_account,
            "status": self.status,
            "analyzed_at": self.analyzed_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "analysis_error_present": self.analysis_error_present,
        }


@dataclass(frozen=True, slots=True)
class _AnalyzerCollection:
    analyzers: tuple[_AnalyzerFacts, ...]
    error: BaseException | None


@dataclass(frozen=True, slots=True)
class _FindingCollection:
    findings: tuple[_FindingSummary, ...]
    error: BaseException | None


@dataclass(frozen=True, slots=True)
class _FindingDetails:
    metadata: Mapping[str, object] | None
    details: tuple[Mapping[str, object], ...]
    error: BaseException | None


class AccessAnalyzerCollector(ResourceCollector):
    """Collect Regional analyzer and external-access S3 finding facts."""

    collector_name = "access_analyzer_evidence"
    produces_evidence_graph = True

    def collect(self) -> list[NormalizedResource]:
        """Preserve the direct collector API by scanning only the provider's Region."""

        context = CollectionContext(
            scan_id=uuid4(),
            collection_account_id=self.client_provider.account_id,
            region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
        )
        return list(self.collect_with_context(context).resources)

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Collect the requested and exact bucket-backed supplemental Regions."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        if context.region != self.client_provider.region_name:
            raise ValueError("collection context Region does not match the AWS client provider")

        required_regions = tuple(sorted({context.region, *context.supplemental_regions}))
        observations: list[SourceObservation] = []
        resources: list[NormalizedResource] = []
        relationships: list[RelationshipReference] = []

        for region in required_regions:
            client = self.client_provider.client("accessanalyzer", region_name=region)
            analyzer_collection = self._collect_analyzers(client, context, region)
            analyzer_observation = self._analyzer_discovery_observation(
                context=context,
                region=region,
                required_regions=required_regions,
                collection=analyzer_collection,
            )
            observations.append(analyzer_observation)

            for analyzer in analyzer_collection.analyzers:
                if not analyzer.is_external_access:
                    continue
                finding_collection = self._collect_findings(client, context, analyzer)
                finding_discovery = self._finding_discovery_observation(
                    context=context,
                    analyzer=analyzer,
                    collection=finding_collection,
                )
                observations.append(finding_discovery)

                for summary in finding_collection.findings:
                    details = self._collect_finding_details(client, summary)
                    resource = self._finding_resource(context, summary, details)
                    resources.append(resource)

                    summary_observation = self._finding_summary_observation(
                        context=context,
                        resource=resource,
                        summary=summary,
                    )
                    observations.append(summary_observation)
                    observations.append(
                        self._finding_detail_observation(
                            context=context,
                            resource=resource,
                            summary=summary,
                            details=details,
                        )
                    )
                    relationships.append(
                        self._bucket_relationship(
                            context=context,
                            resource=resource,
                            summary=summary,
                            observation=summary_observation,
                        )
                    )

        resources.sort(key=lambda resource: resource.identity)
        relationships.sort(
            key=lambda item: (
                item.source.aws_account_id,
                item.source.service,
                item.source.resource_type,
                item.source.scope.value,
                item.source.region or "global",
                item.source.aws_resource_id,
                item.target.aws_resource_id,
                item.target.aws_account_id or "",
            )
        )
        outcomes = tuple(observation.outcome for observation in observations)
        status = collection_status_for(outcomes)
        if status is CollectionStatus.SUCCEEDED and not context.supplemental_region_source_complete:
            status = CollectionStatus.PARTIAL
        return CollectorResult(
            resources=tuple(resources),
            status=status,
            source_contracts=tuple(observation.contract for observation in observations),
            artifacts=tuple(observation.artifact for observation in observations),
            source_outcomes=outcomes,
            relationships=tuple(relationships),
        )

    def _collect_analyzers(
        self,
        client: Any,
        context: CollectionContext,
        region: str,
    ) -> _AnalyzerCollection:
        analyzers: dict[str, _AnalyzerFacts] = {}
        blocked_arns: set[str] = set()
        error: BaseException | None = None
        try:
            for item_path, raw_item in _iter_paginated_items_strict(
                client,
                operation_name="list_analyzers",
                result_key="analyzers",
            ):
                try:
                    item = require_mapping(
                        raw_item,
                        operation_name="list_analyzers",
                        fact_path=item_path,
                    )
                    analyzer = _normalize_analyzer(
                        item,
                        operation_name="list_analyzers",
                        fact_path=item_path,
                        region=region,
                        account_id=context.collection_account_id,
                        partition=self.client_provider.partition,
                    )
                    if analyzer.arn in blocked_arns:
                        continue
                    existing = analyzers.get(analyzer.arn)
                    if existing is None:
                        analyzers[analyzer.arn] = analyzer
                    elif existing != analyzer:
                        analyzers.pop(analyzer.arn, None)
                        blocked_arns.add(analyzer.arn)
                        error = error or CollectorEvidenceConflictError(
                            "list_analyzers", f"{item_path}.arn"
                        )
                except CollectorEvidenceError as caught:
                    error = error or caught
        except _EXPECTED_FAILURES as caught:
            error = error or caught
        return _AnalyzerCollection(
            analyzers=tuple(analyzers[key] for key in sorted(analyzers)),
            error=error,
        )

    def _collect_findings(
        self,
        client: Any,
        context: CollectionContext,
        analyzer: _AnalyzerFacts,
    ) -> _FindingCollection:
        findings: dict[str, _FindingSummary] = {}
        blocked_ids: set[str] = set()
        error: BaseException | None = None
        try:
            for item_path, raw_item in _iter_paginated_items_strict(
                client,
                operation_name="list_findings_v2",
                result_key="findings",
                analyzerArn=analyzer.arn,
                filter={
                    "findingType": {"eq": ["ExternalAccess"]},
                    "resourceType": {"eq": ["AWS::S3::Bucket"]},
                },
            ):
                try:
                    item = require_mapping(
                        raw_item,
                        operation_name="list_findings_v2",
                        fact_path=item_path,
                    )
                    finding = _normalize_finding_summary(
                        item,
                        operation_name="list_findings_v2",
                        fact_path=item_path,
                        analyzer=analyzer,
                        partition=self.client_provider.partition,
                    )
                    if finding.finding_id in blocked_ids:
                        continue
                    existing = findings.get(finding.finding_id)
                    if existing is None:
                        findings[finding.finding_id] = finding
                    elif existing != finding:
                        findings.pop(finding.finding_id, None)
                        blocked_ids.add(finding.finding_id)
                        error = error or CollectorEvidenceConflictError(
                            "list_findings_v2", f"{item_path}.id"
                        )
                except CollectorEvidenceError as caught:
                    error = error or caught
        except _EXPECTED_FAILURES as caught:
            error = error or caught
        return _FindingCollection(
            findings=tuple(findings[key] for key in sorted(findings)),
            error=error,
        )

    def _collect_finding_details(
        self,
        client: Any,
        summary: _FindingSummary,
    ) -> _FindingDetails:
        metadata: dict[str, object] | None = None
        details: list[Mapping[str, object]] = []
        error: BaseException | None = None
        try:
            for page_path, page in _iter_paginated_pages_strict(
                client,
                operation_name="get_finding_v2",
                analyzerArn=summary.analyzer.arn,
                id=summary.finding_id,
            ):
                page_metadata = _normalize_finding_detail_metadata(
                    page,
                    operation_name="get_finding_v2",
                    fact_path=page_path,
                    summary=summary,
                    partition=self.client_provider.partition,
                )
                if metadata is None:
                    metadata = page_metadata
                elif metadata != page_metadata:
                    raise CollectorEvidenceConflictError("get_finding_v2", f"{page_path}.metadata")
                raw_details = require_list(
                    require_member(
                        page,
                        "findingDetails",
                        operation_name="get_finding_v2",
                        fact_path=f"{page_path}.findingDetails",
                    ),
                    operation_name="get_finding_v2",
                    fact_path=f"{page_path}.findingDetails",
                )
                for index, raw_detail in enumerate(raw_details):
                    details.append(
                        _normalize_external_access_detail(
                            raw_detail,
                            operation_name="get_finding_v2",
                            fact_path=f"{page_path}.findingDetails[{index}]",
                        )
                    )
            if metadata is None:
                raise CollectorEvidenceError("get_finding_v2", "pages")
        except _EXPECTED_FAILURES as caught:
            error = caught
        details.sort(key=_canonical_json)
        return _FindingDetails(metadata=metadata, details=tuple(details), error=error)

    def _analyzer_discovery_observation(
        self,
        *,
        context: CollectionContext,
        region: str,
        required_regions: tuple[str, ...],
        collection: _AnalyzerCollection,
    ) -> SourceObservation:
        state, failure_category = _collection_state(
            collection.error,
            has_items=bool(collection.analyzers),
        )
        relevant_arns = sorted(item.arn for item in collection.analyzers if item.is_external_access)
        if collection.error is None and not relevant_arns:
            state = EvidenceSourceState.EXPECTED_ABSENCE
        return build_source_observation(
            context=context,
            contract_key="access-analyzer.analyzers.discovery",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_regional_subject(context, region),
            evidence_kind="access-analyzer.analyzers.discovery",
            collector="access-analyzer.analyzers",
            collector_version=_COLLECTOR_VERSION,
            source_api="access-analyzer:ListAnalyzers",
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference=f"normalized://aws/access-analyzer/{region}/analyzers",
            evidence_schema="access-analyzer.analyzers.discovery",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": region,
                "required_regions": list(required_regions),
                "s3_region_discovery_complete": context.supplemental_region_source_complete,
                "analyzers": [item.as_payload() for item in collection.analyzers],
                "relevant_analyzer_arns": relevant_arns,
                "complete": collection.error is None,
                "failure_category": (
                    failure_category.value if failure_category is not None else None
                ),
            },
            state=state,
            failure_category=failure_category,
            allows_supplemental_region=region != context.region,
        )

    def _finding_discovery_observation(
        self,
        *,
        context: CollectionContext,
        analyzer: _AnalyzerFacts,
        collection: _FindingCollection,
    ) -> SourceObservation:
        state, failure_category = _collection_state(
            collection.error,
            has_items=bool(collection.findings),
        )
        if collection.error is None and not collection.findings:
            state = EvidenceSourceState.EXPECTED_ABSENCE
        analyzer_digest = _identity_digest(analyzer.arn)
        evidence_kind = f"access-analyzer.findings.discovery.{analyzer_digest}"
        return build_source_observation(
            context=context,
            contract_key=evidence_kind,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_regional_subject(context, analyzer.region),
            evidence_kind=evidence_kind,
            collector="access-analyzer.findings",
            collector_version=_COLLECTOR_VERSION,
            source_api="access-analyzer:ListFindings",
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference=(
                "normalized://aws/access-analyzer/"
                f"{analyzer.region}/analyzers/{analyzer_digest}/findings"
            ),
            evidence_schema="access-analyzer.findings.discovery",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": analyzer.region,
                "analyzer": analyzer.as_payload(),
                "findings": [item.as_payload() for item in collection.findings],
                "finding_ids": [item.finding_id for item in collection.findings],
                "resource_arns": [item.resource_arn for item in collection.findings],
                "complete": collection.error is None,
                "failure_category": (
                    failure_category.value if failure_category is not None else None
                ),
            },
            state=state,
            failure_category=failure_category,
            allows_supplemental_region=analyzer.region != context.region,
        )

    def _finding_summary_observation(
        self,
        *,
        context: CollectionContext,
        resource: NormalizedResource,
        summary: _FindingSummary,
    ) -> SourceObservation:
        return build_source_observation(
            context=context,
            contract_key="access-analyzer.finding-summary",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_resource_subject(context, resource),
            evidence_kind="access-analyzer.finding-summary",
            collector="access-analyzer.findings",
            collector_version=_COLLECTOR_VERSION,
            source_api="access-analyzer:ListFindings",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=_finding_evidence_reference(summary, segment="summary"),
            evidence_schema="access-analyzer.finding-summary",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload=summary.as_payload(),
            state=EvidenceSourceState.PRESENT,
            identity_authoritative=True,
            allows_supplemental_region=summary.analyzer.region != context.region,
        )

    def _finding_detail_observation(
        self,
        *,
        context: CollectionContext,
        resource: NormalizedResource,
        summary: _FindingSummary,
        details: _FindingDetails,
    ) -> SourceObservation:
        state, failure_category = _detail_state(details.error)
        return build_source_observation(
            context=context,
            contract_key="access-analyzer.finding-details",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_resource_subject(context, resource),
            evidence_kind="access-analyzer.finding-details",
            collector="access-analyzer.finding-details",
            collector_version=_COLLECTOR_VERSION,
            source_api="access-analyzer:GetFinding",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=_finding_evidence_reference(summary, segment="details"),
            evidence_schema="access-analyzer.finding-details",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": summary.analyzer.region,
                "analyzer_arn": summary.analyzer.arn,
                "finding_id": summary.finding_id,
                "finding": details.metadata,
                "finding_details": list(details.details),
                "complete": details.error is None,
                "failure_category": (
                    failure_category.value if failure_category is not None else None
                ),
            },
            state=state,
            failure_category=failure_category,
            identity_authoritative=True,
            allows_supplemental_region=summary.analyzer.region != context.region,
        )

    @staticmethod
    def _finding_resource(
        context: CollectionContext,
        summary: _FindingSummary,
        details: _FindingDetails,
    ) -> NormalizedResource:
        _, failure_category = _detail_state(details.error)
        effective = details.metadata or summary.as_payload()
        configuration = {
            "analyzer": summary.analyzer.as_payload(),
            "summary": summary.as_payload(),
            "finding": effective,
            "finding_details": list(details.details),
            "detail_complete": details.error is None,
            "detail_failure_category": (
                failure_category.value if failure_category is not None else None
            ),
        }
        return NormalizedResource(
            account_id=context.collection_account_id,
            service="access-analyzer",
            resource_type="access_analyzer_finding",
            aws_resource_id=summary.composite_id,
            name=summary.finding_id,
            scope=ResourceScope.REGIONAL,
            region=summary.analyzer.region,
            configuration=configuration,
        )

    @staticmethod
    def _bucket_relationship(
        *,
        context: CollectionContext,
        resource: NormalizedResource,
        summary: _FindingSummary,
        observation: SourceObservation,
    ) -> RelationshipReference:
        return RelationshipReference(
            relationship_type=RelationshipType.REFERENCES_RESOURCE,
            source=RelationshipEndpoint.for_aws_resource(
                aws_account_id=resource.account_id,
                service=resource.service,
                resource_type=resource.resource_type,
                aws_resource_id=resource.aws_resource_id,
                scope=resource.scope,
                region=resource.region,
                observed_in_scan_id=context.scan_id,
            ),
            target=RelationshipEndpoint.for_aws_resource(
                aws_account_id=summary.resource_owner_account,
                service="s3",
                resource_type="s3_bucket",
                aws_resource_id=summary.bucket_name,
                scope=ResourceScope.REGIONAL,
                region=summary.analyzer.region,
                observed_in_scan_id=None,
            ),
            provenance=observation.provenance,
            target_collector_name="s3_buckets",
        )


def _iter_paginated_pages_strict(
    client: Any,
    *,
    operation_name: str,
    **paginate_options: Any,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield every page while detecting malformed, repeated, or unconsumed tokens."""

    paginator = client.get_paginator(operation_name)
    seen_tokens: set[str] = set()
    final_token: str | None = None
    page_count = 0
    for page_index, raw_page in enumerate(paginator.paginate(**paginate_options)):
        page_count += 1
        page_path = f"pages[{page_index}]"
        page = require_mapping(
            raw_page,
            operation_name=operation_name,
            fact_path=page_path,
        )
        token_error: CollectorEvidenceError | None = None
        if "nextToken" in page:
            try:
                token = require_non_empty_string(
                    page["nextToken"],
                    operation_name=operation_name,
                    fact_path=f"{page_path}.nextToken",
                )
                if token in seen_tokens:
                    raise CollectorEvidenceError(operation_name, f"{page_path}.nextToken.repeated")
                seen_tokens.add(token)
                final_token = token
            except CollectorEvidenceError as caught:
                token_error = caught
                final_token = None
        else:
            final_token = None
        yield page_path, page
        if token_error is not None:
            raise token_error
    if page_count == 0:
        raise CollectorEvidenceError(operation_name, "pages")
    if final_token is not None:
        raise CollectorEvidenceError(operation_name, "pages.nextToken.unconsumed")


def _iter_paginated_items_strict(
    client: Any,
    *,
    operation_name: str,
    result_key: str,
    **paginate_options: Any,
) -> Iterator[tuple[str, object]]:
    for page_path, page in _iter_paginated_pages_strict(
        client,
        operation_name=operation_name,
        **paginate_options,
    ):
        item_path = f"{page_path}.{result_key}"
        items = require_list(
            require_member(
                page,
                result_key,
                operation_name=operation_name,
                fact_path=item_path,
            ),
            operation_name=operation_name,
            fact_path=item_path,
        )
        for item_index, raw_item in enumerate(items):
            yield f"{item_path}[{item_index}]", raw_item


def _normalize_analyzer(
    item: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
    region: str,
    account_id: str,
    partition: str,
) -> _AnalyzerFacts:
    arn = _required_string_member(item, "arn", operation_name, fact_path)
    name = _required_string_member(item, "name", operation_name, fact_path)
    analyzer_type = _required_enum_member(
        item,
        "type",
        _ANALYZER_TYPES,
        operation_name,
        fact_path,
    )
    status = _required_enum_member(
        item,
        "status",
        _ANALYZER_STATUSES,
        operation_name,
        fact_path,
    )
    created_at = _required_timestamp_member(item, "createdAt", operation_name, fact_path)
    expected_prefix = f"arn:{partition}:access-analyzer:{region}:{account_id}:analyzer/"
    if not arn.startswith(expected_prefix) or arn.removeprefix(expected_prefix) != name:
        raise CollectorEvidenceError(operation_name, f"{fact_path}.arn")
    _reject_unsafe_identity(arn, operation_name, f"{fact_path}.arn")
    _reject_unsafe_identity(name, operation_name, f"{fact_path}.name")
    return _AnalyzerFacts(
        arn=arn,
        name=name,
        analyzer_type=analyzer_type,
        status=status,
        region=region,
        created_at=created_at,
    )


def _normalize_finding_summary(
    item: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
    analyzer: _AnalyzerFacts,
    partition: str,
) -> _FindingSummary:
    finding_id = _required_string_member(item, "id", operation_name, fact_path)
    _reject_unsafe_identity(finding_id, operation_name, f"{fact_path}.id")
    resource_type = _required_string_member(item, "resourceType", operation_name, fact_path)
    finding_type = _required_string_member(item, "findingType", operation_name, fact_path)
    if resource_type != "AWS::S3::Bucket":
        raise CollectorEvidenceError(operation_name, f"{fact_path}.resourceType")
    if finding_type != "ExternalAccess":
        raise CollectorEvidenceError(operation_name, f"{fact_path}.findingType")
    resource_arn = _required_string_member(item, "resource", operation_name, fact_path)
    owner = _required_account_member(
        item,
        "resourceOwnerAccount",
        operation_name,
        fact_path,
    )
    try:
        bucket_identity = S3BucketIdentity.for_bucket(
            aws_account_id=owner,
            bucket_region=analyzer.region,
            bucket_arn=resource_arn,
        )
    except ValueError as error:
        raise CollectorEvidenceError(operation_name, f"{fact_path}.resource") from error
    if not resource_arn.startswith(f"arn:{partition}:s3:::"):
        raise CollectorEvidenceError(operation_name, f"{fact_path}.resource")
    status = _required_enum_member(
        item,
        "status",
        _FINDING_STATUSES,
        operation_name,
        fact_path,
    )
    analysis_error = _optional_string_member(
        item,
        "error",
        operation_name,
        fact_path,
    )
    return _FindingSummary(
        analyzer=analyzer,
        finding_id=finding_id,
        composite_id=_finding_resource_id(analyzer.arn, finding_id),
        resource_arn=resource_arn,
        bucket_name=bucket_identity.bucket_name,
        resource_owner_account=owner,
        status=status,
        analyzed_at=_required_timestamp_member(item, "analyzedAt", operation_name, fact_path),
        created_at=_required_timestamp_member(item, "createdAt", operation_name, fact_path),
        updated_at=_required_timestamp_member(item, "updatedAt", operation_name, fact_path),
        analysis_error_present=analysis_error is not None,
    )


def _normalize_finding_detail_metadata(
    page: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
    summary: _FindingSummary,
    partition: str,
) -> dict[str, object]:
    finding_id = _required_string_member(page, "id", operation_name, fact_path)
    resource_type = _required_string_member(page, "resourceType", operation_name, fact_path)
    owner = _required_account_member(
        page,
        "resourceOwnerAccount",
        operation_name,
        fact_path,
    )
    if resource_type != "AWS::S3::Bucket":
        raise CollectorEvidenceError(operation_name, f"{fact_path}.resourceType")

    finding_type = None
    if "findingType" in page:
        finding_type = _required_string_member(page, "findingType", operation_name, fact_path)
        if finding_type != "ExternalAccess":
            raise CollectorEvidenceError(operation_name, f"{fact_path}.findingType")

    resource_arn = None
    if "resource" in page:
        resource_arn = _required_string_member(page, "resource", operation_name, fact_path)
        if not resource_arn.startswith(f"arn:{partition}:s3:::"):
            raise CollectorEvidenceError(operation_name, f"{fact_path}.resource")

    if (
        finding_id != summary.finding_id
        or owner != summary.resource_owner_account
        or (resource_arn is not None and resource_arn != summary.resource_arn)
    ):
        raise CollectorEvidenceConflictError(operation_name, f"{fact_path}.identity")

    analysis_error = _optional_string_member(
        page,
        "error",
        operation_name,
        fact_path,
    )
    return {
        "analyzer_arn": summary.analyzer.arn,
        "finding_id": finding_id,
        "finding_type": finding_type or "ExternalAccess",
        "resource_arn": resource_arn or summary.resource_arn,
        "resource_type": resource_type,
        "resource_owner_account": owner,
        "status": _required_enum_member(
            page,
            "status",
            _FINDING_STATUSES,
            operation_name,
            fact_path,
        ),
        "analyzed_at": _required_timestamp_member(page, "analyzedAt", operation_name, fact_path),
        "created_at": _required_timestamp_member(page, "createdAt", operation_name, fact_path),
        "updated_at": _required_timestamp_member(page, "updatedAt", operation_name, fact_path),
        "analysis_error_present": analysis_error is not None,
    }


def _normalize_external_access_detail(
    raw_detail: object,
    *,
    operation_name: str,
    fact_path: str,
) -> Mapping[str, object]:
    detail = require_mapping(raw_detail, operation_name=operation_name, fact_path=fact_path)
    if set(detail) != {"externalAccessDetails"}:
        raise CollectorEvidenceError(operation_name, fact_path)
    external_path = f"{fact_path}.externalAccessDetails"
    external = require_mapping(
        detail["externalAccessDetails"],
        operation_name=operation_name,
        fact_path=external_path,
    )
    condition = _string_map_member(
        external,
        "condition",
        operation_name=operation_name,
        fact_path=external_path,
        required=True,
    )
    principal = _string_map_member(
        external,
        "principal",
        operation_name=operation_name,
        fact_path=external_path,
        required=False,
    )
    action = _optional_string_list_member(
        external,
        "action",
        operation_name=operation_name,
        fact_path=external_path,
    )
    is_public = None
    if "isPublic" in external:
        is_public = require_boolean(
            external["isPublic"],
            operation_name=operation_name,
            fact_path=f"{external_path}.isPublic",
        )
    sources: list[dict[str, object]] = []
    if "sources" in external:
        raw_sources = require_list(
            external["sources"],
            operation_name=operation_name,
            fact_path=f"{external_path}.sources",
        )
        for index, raw_source in enumerate(raw_sources):
            source_path = f"{external_path}.sources[{index}]"
            source = require_mapping(
                raw_source,
                operation_name=operation_name,
                fact_path=source_path,
            )
            source_type = _required_enum_member(
                source,
                "type",
                _FINDING_SOURCE_TYPES,
                operation_name,
                source_path,
            )
            source_detail = None
            if "detail" in source:
                source_detail = _strict_json_mapping(
                    source["detail"],
                    operation_name=operation_name,
                    fact_path=f"{source_path}.detail",
                )
            unknown_source_fields = set(source) - {"type", "detail"}
            if unknown_source_fields:
                raise CollectorEvidenceError(operation_name, source_path)
            sources.append({"type": source_type, "detail": source_detail})
    rcp_restriction = None
    if "resourceControlPolicyRestriction" in external:
        rcp_restriction = require_non_empty_string(
            external["resourceControlPolicyRestriction"],
            operation_name=operation_name,
            fact_path=f"{external_path}.resourceControlPolicyRestriction",
        )
        if rcp_restriction not in _RCP_RESTRICTIONS:
            raise CollectorEvidenceError(
                operation_name, f"{external_path}.resourceControlPolicyRestriction"
            )
    unknown_external_fields = set(external) - {
        "action",
        "condition",
        "isPublic",
        "principal",
        "sources",
        "resourceControlPolicyRestriction",
    }
    if unknown_external_fields:
        raise CollectorEvidenceError(operation_name, external_path)
    return {
        "external_access_details": {
            "action": action,
            "condition": condition,
            "is_public": is_public,
            "principal": principal,
            "sources": sorted(sources, key=_canonical_json),
            "resource_control_policy_restriction": rcp_restriction,
        }
    }


def _strict_json_mapping(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> Mapping[str, object]:
    mapping = require_mapping(value, operation_name=operation_name, fact_path=fact_path)
    result: dict[str, object] = {}
    for index, (raw_key, item) in enumerate(mapping.items()):
        key = require_non_empty_string(
            raw_key,
            operation_name=operation_name,
            fact_path=f"{fact_path}[{index}].key",
        )
        result[key] = _strict_json_value(
            item,
            operation_name=operation_name,
            fact_path=f"{fact_path}[{index}].value",
        )
    return {key: result[key] for key in sorted(result)}


def _strict_json_value(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> object:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CollectorEvidenceError(operation_name, fact_path)
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return _normalized_timestamp(value, operation_name, fact_path)
    if isinstance(value, Mapping):
        return _strict_json_mapping(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
    if isinstance(value, list | tuple):
        return [
            _strict_json_value(
                item,
                operation_name=operation_name,
                fact_path=f"{fact_path}[{index}]",
            )
            for index, item in enumerate(value)
        ]
    raise CollectorEvidenceError(operation_name, fact_path)


def _string_map_member(
    value: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
    required: bool,
) -> dict[str, str]:
    if key not in value:
        if required:
            raise CollectorEvidenceError(operation_name, f"{fact_path}.{key}")
        return {}
    mapping = require_mapping(
        value[key],
        operation_name=operation_name,
        fact_path=f"{fact_path}.{key}",
    )
    result: dict[str, str] = {}
    for index, (raw_key, raw_value) in enumerate(mapping.items()):
        normalized_key = require_non_empty_string(
            raw_key,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{key}[{index}].key",
        )
        result[normalized_key] = require_string(
            raw_value,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{key}[{index}].value",
        )
    return {item_key: result[item_key] for item_key in sorted(result)}


def _optional_string_list_member(
    value: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> list[str]:
    if key not in value:
        return []
    raw_items = require_list(
        value[key],
        operation_name=operation_name,
        fact_path=f"{fact_path}.{key}",
    )
    return sorted(
        require_non_empty_string(
            item,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{key}[{index}]",
        )
        for index, item in enumerate(raw_items)
    )


def _required_string_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str:
    return require_non_empty_string(
        require_member(
            item,
            key,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{key}",
        ),
        operation_name=operation_name,
        fact_path=f"{fact_path}.{key}",
    )


def _optional_string_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in item or item[key] is None:
        return None
    return require_string(
        item[key],
        operation_name=operation_name,
        fact_path=f"{fact_path}.{key}",
    )


def _required_enum_member(
    item: Mapping[str, Any],
    key: str,
    allowed: frozenset[str],
    operation_name: str,
    fact_path: str,
) -> str:
    value = _required_string_member(item, key, operation_name, fact_path)
    if value not in allowed:
        raise CollectorEvidenceError(operation_name, f"{fact_path}.{key}")
    return value


def _required_account_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str:
    value = _required_string_member(item, key, operation_name, fact_path)
    if len(value) != 12 or not value.isascii() or not value.isdigit():
        raise CollectorEvidenceError(operation_name, f"{fact_path}.{key}")
    return value


def _required_timestamp_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str:
    value = require_datetime(
        require_member(
            item,
            key,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{key}",
        ),
        operation_name=operation_name,
        fact_path=f"{fact_path}.{key}",
    )
    return value.astimezone(UTC).isoformat()


def _normalized_timestamp(
    value: datetime,
    operation_name: str,
    fact_path: str,
) -> str:
    return (
        require_datetime(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
        .astimezone(UTC)
        .isoformat()
    )


def _regional_subject(context: CollectionContext, region: str) -> AccountEvidenceSubject:
    return AccountEvidenceSubject(
        aws_account_id=context.collection_account_id,
        scope=ResourceScope.REGIONAL,
        region=region,
    )


def _resource_subject(
    context: CollectionContext,
    resource: NormalizedResource,
) -> ResourceEvidenceSubject:
    return ResourceEvidenceSubject.for_aws_resource(
        scan_id=context.scan_id,
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
    )


def _collection_state(
    error: BaseException | None,
    *,
    has_items: bool,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if error is None:
        return (
            EvidenceSourceState.PRESENT if has_items else EvidenceSourceState.EXPECTED_ABSENCE,
            None,
        )
    return source_failure(error)


def _detail_state(
    error: BaseException | None,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if error is None:
        return EvidenceSourceState.PRESENT, None
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        if code in _NOT_FOUND_CODES:
            return (
                EvidenceSourceState.RESOURCE_DISAPPEARED,
                EvidenceFailureCategory.RESOURCE_NOT_FOUND,
            )
    return source_failure(error)


def _finding_resource_id(analyzer_arn: str, finding_id: str) -> str:
    """Encode a collision-safe, reversible composite without delimiter ambiguity."""

    document = json.dumps(
        [analyzer_arn, finding_id],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(document).decode("ascii").rstrip("=")
    return f"aa1.{encoded}"


def _identity_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _finding_evidence_reference(summary: _FindingSummary, *, segment: str) -> str:
    return (
        "normalized://aws/access-analyzer/"
        f"{summary.analyzer.region}/findings/{_identity_digest(summary.composite_id)}/{segment}"
    )


def _reject_unsafe_identity(value: str, operation_name: str, fact_path: str) -> None:
    if any(separator in value for separator in ("\x1f", "\r", "\n")):
        raise CollectorEvidenceError(operation_name, fact_path)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
