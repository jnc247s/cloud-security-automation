"""CloudTrail trail resource collection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
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
    iter_paginated_items,
    require_boolean,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    should_skip_exact_duplicate,
    source_failure,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import NormalizedResource, ResourceScope


class CloudTrailCollector(ResourceCollector):
    """Collect account trails and enrich them through their home-region clients."""

    collector_name = "cloudtrail_trails"

    def __init__(
        self,
        client_provider: Any,
        *,
        collection_bundle: CloudTrailCollectionBundle | None = None,
    ) -> None:
        super().__init__(client_provider)
        self.collection_bundle = collection_bundle

    def collect(self) -> list[NormalizedResource]:
        discovery_client = self.client_provider.client("cloudtrail")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        seen_trails: dict[str, dict[str, Any]] = {}

        for trail_summary in iter_paginated_items(
            discovery_client,
            "list_trails",
            "Trails",
        ):
            trail_arn = require_non_empty_string(
                require_member(
                    trail_summary,
                    "TrailARN",
                    operation_name="list_trails",
                    fact_path="Trails[].TrailARN",
                ),
                operation_name="list_trails",
                fact_path="Trails[].TrailARN",
            )
            home_region = require_non_empty_string(
                require_member(
                    trail_summary,
                    "HomeRegion",
                    operation_name="list_trails",
                    fact_path="Trails[].HomeRegion",
                ),
                operation_name="list_trails",
                fact_path="Trails[].HomeRegion",
            )
            summary_name = _optional_non_empty_string(
                trail_summary,
                "Name",
                operation_name="list_trails",
                fact_path="Trails[].Name",
            )
            if should_skip_exact_duplicate(
                seen_trails,
                trail_arn,
                trail_summary,
                operation_name="list_trails",
                fact_path="Trails[].duplicate_identity",
            ):
                continue

            client = self.client_provider.client("cloudtrail", region_name=home_region)
            get_trail_response = require_mapping(
                client.get_trail(Name=trail_arn),
                operation_name="get_trail",
                fact_path="response",
            )
            trail = require_mapping(
                require_member(
                    get_trail_response,
                    "Trail",
                    operation_name="get_trail",
                    fact_path="Trail",
                ),
                operation_name="get_trail",
                fact_path="Trail",
            )
            trail_fields = _validate_trail(trail, trail_arn, home_region)
            status_response = require_mapping(
                client.get_trail_status(Name=trail_arn),
                operation_name="get_trail_status",
                fact_path="response",
            )
            is_logging = require_boolean(
                require_member(
                    status_response,
                    "IsLogging",
                    operation_name="get_trail_status",
                    fact_path="IsLogging",
                ),
                operation_name="get_trail_status",
                fact_path="IsLogging",
            )
            trail_status = _without_response_metadata(status_response)
            tags = self._get_tags(client, trail_arn)

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="cloudtrail",
                    resource_type="cloudtrail_trail",
                    aws_resource_id=trail_arn,
                    arn=trail_arn,
                    name=trail_fields["Name"] or summary_name,
                    scope=ResourceScope.REGIONAL,
                    region=home_region,
                    tags=tags,
                    configuration={
                        "home_region": home_region,
                        "s3_bucket_name": trail_fields["S3BucketName"],
                        "s3_key_prefix": trail_fields["S3KeyPrefix"],
                        "include_global_service_events": trail_fields["IncludeGlobalServiceEvents"],
                        "is_multi_region_trail": trail_fields["IsMultiRegionTrail"],
                        "log_file_validation_enabled": trail_fields["LogFileValidationEnabled"],
                        "cloudwatch_logs_log_group_arn": trail_fields["CloudWatchLogsLogGroupArn"],
                        "kms_key_id": trail_fields["KmsKeyId"],
                        "is_organization_trail": trail_fields["IsOrganizationTrail"],
                        "is_logging": is_logging,
                        "status": to_json_safe(trail_status),
                    },
                    raw_configuration={
                        "summary": to_json_safe(trail_summary),
                        "trail": to_json_safe(trail),
                        "status": to_json_safe(trail_status),
                    },
                )
            )

        return resources

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Project the shared 5F bundle without changing direct/pre-5F collection."""

        if self.collection_bundle is None:
            return super().collect_with_context(context)
        collected = self.collection_bundle.collect(context)
        return CollectorResult(
            resources=collected.resources,
            status=collected.legacy_status,
        )

    @staticmethod
    def _get_tags(client: Any, trail_arn: str) -> dict[str, str]:
        tag_entries: list[Any] = []
        for resource_tags in iter_paginated_items(
            client,
            "list_tags",
            "ResourceTagList",
            ResourceIdList=[trail_arn],
        ):
            resource_id = require_non_empty_string(
                require_member(
                    resource_tags,
                    "ResourceId",
                    operation_name="list_tags",
                    fact_path="ResourceTagList[].ResourceId",
                ),
                operation_name="list_tags",
                fact_path="ResourceTagList[].ResourceId",
            )
            if resource_id != trail_arn:
                raise CollectorEvidenceError(
                    "list_tags",
                    "ResourceTagList[].ResourceId",
                )
            if "TagsList" not in resource_tags:
                continue
            tag_entries.extend(
                require_list(
                    resource_tags["TagsList"],
                    operation_name="list_tags",
                    fact_path="ResourceTagList[].TagsList",
                )
            )
        return tags_to_dict(
            tag_entries,
            operation_name="list_tags",
            fact_path="ResourceTagList[].TagsList",
            allow_missing_value=True,
        )


_TRAIL_STRING_FIELDS = (
    "S3BucketName",
    "S3KeyPrefix",
    "CloudWatchLogsLogGroupArn",
    "KmsKeyId",
)
_TRAIL_BOOLEAN_FIELDS = (
    "IncludeGlobalServiceEvents",
    "IsMultiRegionTrail",
    "LogFileValidationEnabled",
    "IsOrganizationTrail",
)


def _validate_trail(
    trail: dict[str, Any],
    expected_arn: str,
    expected_home_region: str,
) -> dict[str, str | bool | None]:
    """Validate the CloudTrail fields promoted into normalized configuration."""

    fields: dict[str, str | bool | None] = {
        "Name": _optional_non_empty_string(
            trail,
            "Name",
            operation_name="get_trail",
            fact_path="Trail.Name",
        )
    }
    for field_name in _TRAIL_STRING_FIELDS:
        fields[field_name] = _optional_string(
            trail,
            field_name,
            operation_name="get_trail",
            fact_path=f"Trail.{field_name}",
        )
    for field_name in _TRAIL_BOOLEAN_FIELDS:
        fields[field_name] = _optional_boolean(
            trail,
            field_name,
            operation_name="get_trail",
            fact_path=f"Trail.{field_name}",
        )

    returned_arn = _optional_non_empty_string(
        trail,
        "TrailARN",
        operation_name="get_trail",
        fact_path="Trail.TrailARN",
    )
    if returned_arn is not None and returned_arn != expected_arn:
        raise CollectorEvidenceError("get_trail", "Trail.TrailARN")

    returned_home_region = _optional_non_empty_string(
        trail,
        "HomeRegion",
        operation_name="get_trail",
        fact_path="Trail.HomeRegion",
    )
    if returned_home_region is not None and returned_home_region != expected_home_region:
        raise CollectorEvidenceError("get_trail", "Trail.HomeRegion")

    return fields


def _optional_string(
    container: dict[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container:
        return None
    return require_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_non_empty_string(
    container: dict[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container:
        return None
    return require_non_empty_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_boolean(
    container: dict[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> bool | None:
    if key not in container:
        return None
    return require_boolean(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _without_response_metadata(response: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in response.items() if key != "ResponseMetadata"}


_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)
_RESOURCE_DISAPPEARED_CODES = {
    "ResourceNotFoundException",
    "TrailNotFoundException",
}
_SUPPORTED_MANAGEMENT_EVENT_EXCLUSIONS = {
    "kms.amazonaws.com",
    "rdsdata.amazonaws.com",
}
_READ_WRITE_TYPES = {"All", "ReadOnly", "WriteOnly"}
_ADVANCED_OPERATORS = (
    ("Equals", "equals"),
    ("StartsWith", "starts_with"),
    ("EndsWith", "ends_with"),
    ("NotEquals", "not_equals"),
    ("NotStartsWith", "not_starts_with"),
    ("NotEndsWith", "not_ends_with"),
)
_COLLECTOR_VERSION = "1.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_TAG_BATCH_SIZE = 20
_AWS_REGION_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$", re.ASCII)
_TRAIL_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9]|[._-](?=[A-Za-z0-9])){1,126}[A-Za-z0-9]$",
    re.ASCII,
)
_IP_SHAPED_NAME_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){3}$", re.ASCII)
_UNSAFE_IDENTITY_SEPARATORS = ("\x00", "\x1f", "\r", "\n")


@dataclass(frozen=True, slots=True)
class _SourceValue:
    """One independently collected and normalized CloudTrail response."""

    value: object | None = None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _TrailIdentity:
    """Identity established only by one validated ListTrails summary."""

    trail_arn: str
    name: str
    home_region: str
    owner_account_id: str
    partition: str

    @property
    def summary(self) -> dict[str, str]:
        return {
            "TrailARN": self.trail_arn,
            "Name": self.name,
            "HomeRegion": self.home_region,
        }


@dataclass(frozen=True, slots=True)
class _TrailRecord:
    """Independent 5F evidence retained for one discovered trail identity."""

    identity: _TrailIdentity
    configuration: _SourceValue
    status: _SourceValue
    event_selectors: _SourceValue
    tags: _SourceValue
    resource: NormalizedResource


@dataclass(frozen=True, slots=True)
class _BundleResult:
    """One immutable CloudTrail collection projected by both operational collectors."""

    discovery: _SourceValue
    discarded_item_count: int
    records: tuple[_TrailRecord, ...]
    resources: tuple[NormalizedResource, ...]
    legacy_status: CollectionStatus


class CloudTrailCollectionBundle:
    """Collect 5F CloudTrail evidence once for one immutable scan context."""

    def __init__(self, client_provider: Any) -> None:
        self.client_provider = client_provider
        self._scan_id: UUID | None = None
        self._result: _BundleResult | None = None

    def collect(self, context: CollectionContext) -> _BundleResult:
        """Return the one complete CloudTrail collection for ``context.scan_id``."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        if context.region != self.client_provider.region_name:
            raise ValueError("collection context Region does not match the AWS client provider")
        if self._scan_id == context.scan_id and self._result is not None:
            return self._result

        result = self._collect(context)
        self._scan_id = context.scan_id
        self._result = result
        return result

    def _collect(self, context: CollectionContext) -> _BundleResult:
        clients: dict[str, Any] = {context.region: self.client_provider.client("cloudtrail")}
        discovery, discarded_item_count = self._collect_discovery(
            clients[context.region],
            context,
        )
        identities = discovery.value if isinstance(discovery.value, tuple) else ()
        for identity in identities:
            if identity.home_region not in clients:
                clients[identity.home_region] = self.client_provider.client(
                    "cloudtrail",
                    region_name=identity.home_region,
                )

        source_records: list[tuple[_TrailIdentity, _SourceValue, _SourceValue, _SourceValue]] = []
        for identity in identities:
            client = clients[identity.home_region]
            source_records.append(
                (
                    identity,
                    self._collect_configuration(client, identity),
                    self._collect_status(client, identity),
                    self._collect_event_selectors(client, identity),
                )
            )

        tags = self._collect_tags(clients, identities)
        records: list[_TrailRecord] = []
        for identity, configuration, status, selectors in source_records:
            tag_source = tags[identity.trail_arn]
            records.append(
                _TrailRecord(
                    identity=identity,
                    configuration=configuration,
                    status=status,
                    event_selectors=selectors,
                    tags=tag_source,
                    resource=_trail_resource(
                        identity=identity,
                        configuration=configuration,
                        status=status,
                        event_selectors=selectors,
                        tags=tag_source,
                    ),
                )
            )

        ordered_records = tuple(sorted(records, key=lambda item: item.identity.trail_arn))
        return _BundleResult(
            discovery=discovery,
            discarded_item_count=discarded_item_count,
            records=ordered_records,
            resources=tuple(record.resource for record in ordered_records),
            legacy_status=_legacy_status(discovery, ordered_records),
        )

    def _collect_discovery(
        self,
        client: Any,
        context: CollectionContext,
    ) -> tuple[_SourceValue, int]:
        identities: dict[str, _TrailIdentity] = {}
        seen_raw: dict[str, dict[str, Any]] = {}
        conflicted: set[str] = set()
        errors: list[BaseException] = []
        discarded_item_count = 0

        try:
            for raw_summary in iter_paginated_items(
                client,
                "list_trails",
                "Trails",
            ):
                candidate_arn = raw_summary.get("TrailARN")
                candidate = (
                    candidate_arn
                    if isinstance(candidate_arn, str) and candidate_arn.strip()
                    else None
                )
                try:
                    if candidate is not None and candidate in conflicted:
                        discarded_item_count += 1
                        continue
                    previous = seen_raw.get(candidate) if candidate is not None else None
                    if previous is not None:
                        if previous == raw_summary:
                            continue
                        identities.pop(candidate, None)
                        conflicted.add(candidate)
                        discarded_item_count += 2
                        errors.append(
                            CollectorEvidenceConflictError(
                                "list_trails",
                                "Trails[].duplicate_identity",
                            )
                        )
                        continue
                    identity = _normalize_trail_identity(
                        raw_summary,
                        expected_partition=self.client_provider.partition,
                    )
                    trail_arn = identity.trail_arn
                    seen_raw[trail_arn] = dict(raw_summary)
                    identities[trail_arn] = identity
                except CollectorEvidenceError as error:
                    if candidate is not None:
                        identities.pop(candidate, None)
                    errors.append(error)
                    discarded_item_count += 1
        except _EXPECTED_FAILURES as error:
            errors.append(error)

        ordered = tuple(identities[key] for key in sorted(identities))
        return (
            _SourceValue(
                value=ordered,
                error=_preferred_error(errors),
            ),
            discarded_item_count,
        )

    def _collect_configuration(
        self,
        client: Any,
        identity: _TrailIdentity,
    ) -> _SourceValue:
        try:
            response = require_mapping(
                client.get_trail(Name=identity.trail_arn),
                operation_name="get_trail",
                fact_path="response",
            )
            trail = require_mapping(
                require_member(
                    response,
                    "Trail",
                    operation_name="get_trail",
                    fact_path="Trail",
                ),
                operation_name="get_trail",
                fact_path="Trail",
            )
            return _SourceValue(
                value=_normalize_trail_configuration(
                    trail,
                    identity=identity,
                    collection_account_id=self.client_provider.account_id,
                )
            )
        except _EXPECTED_FAILURES as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_status(client: Any, identity: _TrailIdentity) -> _SourceValue:
        try:
            response = require_mapping(
                client.get_trail_status(Name=identity.trail_arn),
                operation_name="get_trail_status",
                fact_path="response",
            )
            is_logging = require_boolean(
                require_member(
                    response,
                    "IsLogging",
                    operation_name="get_trail_status",
                    fact_path="IsLogging",
                ),
                operation_name="get_trail_status",
                fact_path="IsLogging",
            )
            return _SourceValue(
                value={
                    "is_logging": is_logging,
                    "status": to_json_safe(_without_response_metadata(response)),
                }
            )
        except _EXPECTED_FAILURES as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_event_selectors(client: Any, identity: _TrailIdentity) -> _SourceValue:
        try:
            response = require_mapping(
                client.get_event_selectors(TrailName=identity.trail_arn),
                operation_name="get_event_selectors",
                fact_path="response",
            )
            returned_arn = require_non_empty_string(
                require_member(
                    response,
                    "TrailARN",
                    operation_name="get_event_selectors",
                    fact_path="TrailARN",
                ),
                operation_name="get_event_selectors",
                fact_path="TrailARN",
            )
            if returned_arn != identity.trail_arn:
                raise CollectorEvidenceConflictError(
                    "get_event_selectors",
                    "TrailARN",
                )
            return _SourceValue(value=_normalize_event_selectors(response))
        except _EXPECTED_FAILURES as error:
            return _SourceValue(error=error)

    def _collect_tags(
        self,
        clients: Mapping[str, Any],
        identities: tuple[_TrailIdentity, ...],
    ) -> dict[str, _SourceValue]:
        results: dict[str, _SourceValue] = {}
        by_region: dict[str, list[str]] = {}
        for identity in identities:
            by_region.setdefault(identity.home_region, []).append(identity.trail_arn)

        for region in sorted(by_region):
            arns = sorted(by_region[region])
            for offset in range(0, len(arns), _TAG_BATCH_SIZE):
                batch = tuple(arns[offset : offset + _TAG_BATCH_SIZE])
                results.update(self._collect_tag_batch(clients[region], batch))
        return results

    @staticmethod
    def _collect_tag_batch(
        client: Any,
        batch: tuple[str, ...],
    ) -> dict[str, _SourceValue]:
        entries: dict[str, list[Any]] = {trail_arn: [] for trail_arn in batch}
        errors: dict[str, list[BaseException]] = {trail_arn: [] for trail_arn in batch}
        seen_resource_ids: set[str] = set()
        try:
            for resource_tags in iter_paginated_items(
                client,
                "list_tags",
                "ResourceTagList",
                ResourceIdList=list(batch),
            ):
                resource_id = require_non_empty_string(
                    require_member(
                        resource_tags,
                        "ResourceId",
                        operation_name="list_tags",
                        fact_path="ResourceTagList[].ResourceId",
                    ),
                    operation_name="list_tags",
                    fact_path="ResourceTagList[].ResourceId",
                )
                if resource_id not in entries:
                    raise CollectorEvidenceConflictError(
                        "list_tags",
                        "ResourceTagList[].ResourceId",
                    )
                if resource_id in seen_resource_ids:
                    errors[resource_id].append(
                        CollectorEvidenceConflictError(
                            "list_tags",
                            "ResourceTagList[].ResourceId",
                        )
                    )
                    continue
                seen_resource_ids.add(resource_id)
                if "TagsList" not in resource_tags:
                    continue
                try:
                    entries[resource_id].extend(
                        require_list(
                            resource_tags["TagsList"],
                            operation_name="list_tags",
                            fact_path="ResourceTagList[].TagsList",
                        )
                    )
                except CollectorEvidenceError as error:
                    errors[resource_id].append(error)
        except _EXPECTED_FAILURES as error:
            if (
                len(batch) > 1
                and isinstance(error, ClientError)
                and error.response.get("Error", {}).get("Code") in _RESOURCE_DISAPPEARED_CODES
            ):
                isolated: dict[str, _SourceValue] = {}
                for trail_arn in batch:
                    isolated.update(
                        CloudTrailCollectionBundle._collect_tag_batch(client, (trail_arn,))
                    )
                return isolated
            return {trail_arn: _SourceValue(error=error) for trail_arn in batch}

        results: dict[str, _SourceValue] = {}
        for trail_arn in batch:
            if trail_arn not in seen_resource_ids:
                errors[trail_arn].append(
                    CollectorEvidenceError(
                        "list_tags",
                        "ResourceTagList[].ResourceId",
                    )
                )
            if errors[trail_arn]:
                results[trail_arn] = _SourceValue(error=_preferred_error(errors[trail_arn]))
                continue
            try:
                tags = tags_to_dict(
                    entries[trail_arn],
                    operation_name="list_tags",
                    fact_path="ResourceTagList[].TagsList",
                    allow_missing_value=True,
                )
                if any(not _is_safe_non_empty_string(key) for key in tags):
                    raise CollectorEvidenceError(
                        "list_tags",
                        "ResourceTagList[].TagsList[].Key",
                    )
            except CollectorEvidenceError as error:
                results[trail_arn] = _SourceValue(error=error)
            else:
                results[trail_arn] = _SourceValue(value=tags)
        return results


class CloudTrailEvidenceCollector(ResourceCollector):
    """Emit the fact-only 5F CloudTrail evidence-graph fragment."""

    collector_name = "cloudtrail_evidence"
    produces_evidence_graph = True

    def __init__(
        self,
        client_provider: Any,
        *,
        collection_bundle: CloudTrailCollectionBundle | None = None,
    ) -> None:
        super().__init__(client_provider)
        self.collection_bundle = collection_bundle or CloudTrailCollectionBundle(client_provider)

    def collect(self) -> list[NormalizedResource]:
        """Support the established collector interface without duplicating trail resources."""

        context = CollectionContext(
            scan_id=uuid4(),
            collection_account_id=self.client_provider.account_id,
            region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
        )
        return list(self.collect_with_context(context).resources)

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Project exact source observations and relationship references from the bundle."""

        collected = self.collection_bundle.collect(context)
        observations: list[SourceObservation] = [self._discovery_observation(context, collected)]
        configuration_observations: dict[str, SourceObservation] = {}
        for record in collected.records:
            observations.append(self._identity_observation(context, record))
            configuration = self._resource_observation(
                context=context,
                record=record,
                source=record.configuration,
                evidence_kind="cloudtrail.trail.configuration",
                collector="cloudtrail.trail-configuration",
                source_api="cloudtrail:GetTrail",
                reference_segment="configuration",
            )
            observations.append(configuration)
            configuration_observations[record.identity.trail_arn] = configuration
            observations.append(
                self._resource_observation(
                    context=context,
                    record=record,
                    source=record.status,
                    evidence_kind="cloudtrail.trail.status",
                    collector="cloudtrail.trail-status",
                    source_api="cloudtrail:GetTrailStatus",
                    reference_segment="status",
                )
            )
            observations.append(
                self._resource_observation(
                    context=context,
                    record=record,
                    source=record.event_selectors,
                    evidence_kind="cloudtrail.trail.event-selectors",
                    collector="cloudtrail.trail-event-selectors",
                    source_api="cloudtrail:GetEventSelectors",
                    reference_segment="event-selectors",
                )
            )
            observations.append(
                self._resource_observation(
                    context=context,
                    record=record,
                    source=record.tags,
                    evidence_kind="cloudtrail.trail.tags",
                    collector="cloudtrail.trail-tags",
                    source_api="cloudtrail:ListTags",
                    reference_segment="tags",
                    value=_normalized_tags(record.tags),
                )
            )

        relationships: list[RelationshipReference] = []
        for record in collected.records:
            if record.configuration.error is not None or not isinstance(
                record.configuration.value,
                Mapping,
            ):
                continue
            configuration = record.configuration.value
            observation = configuration_observations[record.identity.trail_arn]
            source = _observed_trail_endpoint(context, record.identity)
            bucket_name = configuration.get("s3_bucket_name")
            if isinstance(bucket_name, str):
                relationships.append(
                    RelationshipReference(
                        relationship_type=RelationshipType.DELIVERS_TO_BUCKET,
                        source=source,
                        target=UnresolvedRelationshipTarget.for_aws_reference(
                            service="s3",
                            resource_type="s3_bucket",
                            aws_resource_id=bucket_name,
                            scope=ResourceScope.REGIONAL,
                        ),
                        provenance=observation.provenance,
                        target_collector_name="s3_evidence",
                        target_evidence_kind="s3.buckets.discovery",
                    )
                )
            kms_key_id = configuration.get("kms_key_id")
            if isinstance(kms_key_id, str):
                kms_region, kms_account_id = _kms_key_identity(
                    kms_key_id,
                    expected_partition=record.identity.partition,
                    operation_name="get_trail",
                    fact_path="Trail.KmsKeyId",
                )
                relationships.append(
                    RelationshipReference(
                        relationship_type=RelationshipType.ENCRYPTED_WITH,
                        source=source,
                        target=RelationshipEndpoint.for_aws_resource(
                            aws_account_id=kms_account_id,
                            service="kms",
                            resource_type="kms_key",
                            aws_resource_id=kms_key_id,
                            scope=ResourceScope.REGIONAL,
                            region=kms_region,
                            observed_in_scan_id=None,
                        ),
                        provenance=observation.provenance,
                        target_collector_name="s3_evidence",
                        target_evidence_kind=(
                            "kms.key."
                            + hashlib.sha256(f"{kms_region}\x00{kms_key_id}".encode()).hexdigest()
                        ),
                    )
                )

        outcomes = tuple(observation.outcome for observation in observations)
        return CollectorResult(
            status=collection_status_for(outcomes),
            source_contracts=tuple(observation.contract for observation in observations),
            artifacts=tuple(observation.artifact for observation in observations),
            source_outcomes=outcomes,
            relationships=tuple(
                sorted(
                    relationships,
                    key=lambda item: (
                        item.source.aws_resource_id,
                        item.relationship_type.value,
                        item.target.aws_resource_id,
                    ),
                )
            ),
        )

    @staticmethod
    def _discovery_observation(
        context: CollectionContext,
        collected: _BundleResult,
    ) -> SourceObservation:
        state, category = _state_for(collected.discovery)
        identities = (
            collected.discovery.value if isinstance(collected.discovery.value, tuple) else ()
        )
        return build_source_observation(
            context=context,
            contract_key="cloudtrail.trails.discovery",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=AccountEvidenceSubject(
                aws_account_id=context.collection_account_id,
                scope=ResourceScope.GLOBAL,
            ),
            evidence_kind="cloudtrail.trails.discovery",
            collector="cloudtrail.trails",
            collector_version=_COLLECTOR_VERSION,
            source_api="cloudtrail:ListTrails",
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference="normalized://aws/cloudtrail/trails/discovery",
            evidence_schema="cloudtrail.trails.discovery",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "collection_account_id": context.collection_account_id,
                "invocation_region": context.region,
                "trail_arns": [identity.trail_arn for identity in identities],
                "trail_count": len(identities),
                "discarded_item_count": collected.discarded_item_count,
                "admission_complete": True,
                "unadmitted_resources": [],
                "complete": collected.discovery.error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    @staticmethod
    def _identity_observation(
        context: CollectionContext,
        record: _TrailRecord,
    ) -> SourceObservation:
        identity = record.identity
        return build_source_observation(
            context=context,
            contract_key="cloudtrail.trail.identity",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_trail_subject(context, identity),
            evidence_kind="cloudtrail.trail.identity",
            collector="cloudtrail.trails",
            collector_version=_COLLECTOR_VERSION,
            source_api="cloudtrail:ListTrails",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=_trail_evidence_reference(identity, "identity"),
            evidence_schema="cloudtrail.trail.identity",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "collection_account_id": context.collection_account_id,
                "owner_account_id": identity.owner_account_id,
                "partition": identity.partition,
                "trail_arn": identity.trail_arn,
                "name": identity.name,
                "home_region": identity.home_region,
                "complete": True,
                "failure_category": None,
            },
            state=EvidenceSourceState.PRESENT,
            identity_authoritative=True,
        )

    @staticmethod
    def _resource_observation(
        *,
        context: CollectionContext,
        record: _TrailRecord,
        source: _SourceValue,
        evidence_kind: str,
        collector: str,
        source_api: str,
        reference_segment: str,
        value: object | None = None,
    ) -> SourceObservation:
        state, category = _state_for(source, allow_resource_disappeared=True)
        return build_source_observation(
            context=context,
            contract_key=evidence_kind,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_trail_subject(context, record.identity),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=_trail_evidence_reference(
                record.identity,
                reference_segment,
            ),
            evidence_schema=evidence_kind,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "trail_arn": record.identity.trail_arn,
                "home_region": record.identity.home_region,
                "value": source.value if value is None else value,
                "complete": source.error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )


def _normalize_trail_identity(
    summary: Mapping[str, Any],
    *,
    expected_partition: str,
) -> _TrailIdentity:
    operation_name = "list_trails"
    fact_path = "Trails[]"
    if set(summary) != {"TrailARN", "Name", "HomeRegion"}:
        raise CollectorEvidenceError(operation_name, fact_path)
    trail_arn = require_non_empty_string(
        require_member(
            summary,
            "TrailARN",
            operation_name=operation_name,
            fact_path=f"{fact_path}.TrailARN",
        ),
        operation_name=operation_name,
        fact_path=f"{fact_path}.TrailARN",
    )
    name = require_non_empty_string(
        require_member(
            summary,
            "Name",
            operation_name=operation_name,
            fact_path=f"{fact_path}.Name",
        ),
        operation_name=operation_name,
        fact_path=f"{fact_path}.Name",
    )
    home_region = require_non_empty_string(
        require_member(
            summary,
            "HomeRegion",
            operation_name=operation_name,
            fact_path=f"{fact_path}.HomeRegion",
        ),
        operation_name=operation_name,
        fact_path=f"{fact_path}.HomeRegion",
    )
    if not _AWS_REGION_PATTERN.fullmatch(home_region):
        raise CollectorEvidenceError(operation_name, f"{fact_path}.HomeRegion")
    if not _TRAIL_NAME_PATTERN.fullmatch(name) or _IP_SHAPED_NAME_PATTERN.fullmatch(name):
        raise CollectorEvidenceError(operation_name, f"{fact_path}.Name")
    parts = trail_arn.split(":", maxsplit=5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or parts[1] != expected_partition
        or parts[2] != "cloudtrail"
        or parts[3] != home_region
        or not _is_account_id(parts[4])
        or parts[5] != f"trail/{name}"
    ):
        raise CollectorEvidenceError(operation_name, f"{fact_path}.TrailARN")
    return _TrailIdentity(
        trail_arn=trail_arn,
        name=name,
        home_region=home_region,
        owner_account_id=parts[4],
        partition=parts[1],
    )


def _normalize_trail_configuration(
    trail: Mapping[str, Any],
    *,
    identity: _TrailIdentity,
    collection_account_id: str,
) -> dict[str, object]:
    operation_name = "get_trail"
    allowed_fields = {
        "Name",
        "S3BucketName",
        "S3KeyPrefix",
        "SnsTopicName",
        "SnsTopicARN",
        "IncludeGlobalServiceEvents",
        "IsMultiRegionTrail",
        "HomeRegion",
        "TrailARN",
        "LogFileValidationEnabled",
        "CloudWatchLogsLogGroupArn",
        "CloudWatchLogsRoleArn",
        "KmsKeyId",
        "HasCustomEventSelectors",
        "HasInsightSelectors",
        "IsOrganizationTrail",
        "RecursiveLogging",
    }
    if not set(trail).issubset(allowed_fields):
        raise CollectorEvidenceError(operation_name, "Trail")

    returned_arn = require_non_empty_string(
        require_member(
            trail,
            "TrailARN",
            operation_name=operation_name,
            fact_path="Trail.TrailARN",
        ),
        operation_name=operation_name,
        fact_path="Trail.TrailARN",
    )
    returned_region = require_non_empty_string(
        require_member(
            trail,
            "HomeRegion",
            operation_name=operation_name,
            fact_path="Trail.HomeRegion",
        ),
        operation_name=operation_name,
        fact_path="Trail.HomeRegion",
    )
    returned_name = require_non_empty_string(
        require_member(
            trail,
            "Name",
            operation_name=operation_name,
            fact_path="Trail.Name",
        ),
        operation_name=operation_name,
        fact_path="Trail.Name",
    )
    if (
        returned_arn != identity.trail_arn
        or returned_region != identity.home_region
        or returned_name != identity.name
    ):
        raise CollectorEvidenceConflictError(operation_name, "Trail.identity")

    s3_bucket_name = _strict_optional_non_empty_string(
        trail,
        "S3BucketName",
        operation_name=operation_name,
        fact_path="Trail.S3BucketName",
    )
    if s3_bucket_name is not None and not _is_safe_non_empty_string(s3_bucket_name):
        raise CollectorEvidenceError(operation_name, "Trail.S3BucketName")
    s3_key_prefix = _strict_optional_string(
        trail,
        "S3KeyPrefix",
        operation_name=operation_name,
        fact_path="Trail.S3KeyPrefix",
    )
    cloudwatch_group = _strict_optional_non_empty_string(
        trail,
        "CloudWatchLogsLogGroupArn",
        operation_name=operation_name,
        fact_path="Trail.CloudWatchLogsLogGroupArn",
    )
    cloudwatch_role = _strict_optional_non_empty_string(
        trail,
        "CloudWatchLogsRoleArn",
        operation_name=operation_name,
        fact_path="Trail.CloudWatchLogsRoleArn",
    )
    for field_name, field_value in (
        ("CloudWatchLogsLogGroupArn", cloudwatch_group),
        ("CloudWatchLogsRoleArn", cloudwatch_role),
    ):
        if field_value is not None and not _is_safe_non_empty_string(field_value):
            raise CollectorEvidenceError(operation_name, f"Trail.{field_name}")
    if (cloudwatch_group is None) != (cloudwatch_role is None):
        raise CollectorEvidenceConflictError(
            operation_name,
            "Trail.CloudWatchLogsIntegration",
        )
    if "RecursiveLogging" in trail:
        require_boolean(
            trail["RecursiveLogging"],
            operation_name=operation_name,
            fact_path="Trail.RecursiveLogging",
        )
    kms_key_id = _strict_optional_non_empty_string(
        trail,
        "KmsKeyId",
        operation_name=operation_name,
        fact_path="Trail.KmsKeyId",
    )
    if kms_key_id is not None:
        if not _is_safe_non_empty_string(kms_key_id):
            raise CollectorEvidenceError(operation_name, "Trail.KmsKeyId")
        _kms_key_identity(
            kms_key_id,
            expected_partition=identity.partition,
            operation_name=operation_name,
            fact_path="Trail.KmsKeyId",
        )

    is_organization_trail = _strict_optional_boolean(
        trail,
        "IsOrganizationTrail",
        operation_name=operation_name,
        fact_path="Trail.IsOrganizationTrail",
    )
    if identity.owner_account_id != collection_account_id:
        if is_organization_trail is None:
            raise CollectorEvidenceError(operation_name, "Trail.IsOrganizationTrail")
        if not is_organization_trail:
            raise CollectorEvidenceConflictError(operation_name, "Trail.IsOrganizationTrail")

    return {
        "name": returned_name,
        "s3_bucket_name": s3_bucket_name,
        "s3_key_prefix": s3_key_prefix,
        "include_global_service_events": _strict_optional_boolean(
            trail,
            "IncludeGlobalServiceEvents",
            operation_name=operation_name,
            fact_path="Trail.IncludeGlobalServiceEvents",
        ),
        "is_multi_region_trail": _strict_optional_boolean(
            trail,
            "IsMultiRegionTrail",
            operation_name=operation_name,
            fact_path="Trail.IsMultiRegionTrail",
        ),
        "log_file_validation_enabled": _strict_optional_boolean(
            trail,
            "LogFileValidationEnabled",
            operation_name=operation_name,
            fact_path="Trail.LogFileValidationEnabled",
        ),
        "cloudwatch_logs_log_group_arn": cloudwatch_group,
        "cloudwatch_logs_role_arn": cloudwatch_role,
        "kms_key_id": kms_key_id,
        "is_organization_trail": is_organization_trail,
    }


def _normalize_event_selectors(response: Mapping[str, Any]) -> dict[str, object]:
    operation_name = "get_event_selectors"
    allowed_response_fields = {
        "TrailARN",
        "EventSelectors",
        "AdvancedEventSelectors",
        "ResponseMetadata",
    }
    if not set(response).issubset(allowed_response_fields):
        raise CollectorEvidenceError(operation_name, "response")
    basic_raw = require_list(
        response.get("EventSelectors", []),
        operation_name=operation_name,
        fact_path="EventSelectors",
    )
    advanced_raw = require_list(
        response.get("AdvancedEventSelectors", []),
        operation_name=operation_name,
        fact_path="AdvancedEventSelectors",
    )
    if bool(basic_raw) == bool(advanced_raw):
        raise CollectorEvidenceConflictError(operation_name, "selector_form")

    basic = _unique_sorted_documents(
        [_normalize_basic_selector(item, index) for index, item in enumerate(basic_raw)],
        operation_name=operation_name,
        fact_path="EventSelectors",
    )
    advanced = _unique_sorted_documents(
        [_normalize_advanced_selector(item, index) for index, item in enumerate(advanced_raw)],
        operation_name=operation_name,
        fact_path="AdvancedEventSelectors",
    )
    return {
        "selector_form": "BASIC" if basic else "ADVANCED",
        "basic_selectors": basic,
        "advanced_selectors": advanced,
    }


def _normalize_basic_selector(value: object, index: int) -> dict[str, object]:
    operation_name = "get_event_selectors"
    path = f"EventSelectors[{index}]"
    selector = require_mapping(value, operation_name=operation_name, fact_path=path)
    allowed = {
        "ReadWriteType",
        "IncludeManagementEvents",
        "DataResources",
        "ExcludeManagementEventSources",
    }
    if not set(selector).issubset(allowed):
        raise CollectorEvidenceError(operation_name, path)

    raw_presence = {
        "include_management_events": "IncludeManagementEvents" in selector,
        "read_write_type": "ReadWriteType" in selector,
        "exclude_management_event_sources": "ExcludeManagementEventSources" in selector,
        "data_resources": "DataResources" in selector,
    }
    include_management = (
        require_boolean(
            selector["IncludeManagementEvents"],
            operation_name=operation_name,
            fact_path=f"{path}.IncludeManagementEvents",
        )
        if "IncludeManagementEvents" in selector
        else True
    )
    read_write_type = (
        require_non_empty_string(
            selector["ReadWriteType"],
            operation_name=operation_name,
            fact_path=f"{path}.ReadWriteType",
        )
        if "ReadWriteType" in selector
        else "All"
    )
    if read_write_type not in _READ_WRITE_TYPES:
        raise CollectorEvidenceError(operation_name, f"{path}.ReadWriteType")

    raw_exclusions = require_list(
        selector.get("ExcludeManagementEventSources", []),
        operation_name=operation_name,
        fact_path=f"{path}.ExcludeManagementEventSources",
    )
    exclusions = _unique_sorted_strings(
        raw_exclusions,
        operation_name=operation_name,
        fact_path=f"{path}.ExcludeManagementEventSources",
    )
    if any(item not in _SUPPORTED_MANAGEMENT_EVENT_EXCLUSIONS for item in exclusions):
        raise CollectorEvidenceError(
            operation_name,
            f"{path}.ExcludeManagementEventSources",
        )

    raw_data_resources = require_list(
        selector.get("DataResources", []),
        operation_name=operation_name,
        fact_path=f"{path}.DataResources",
    )
    data_resources = _unique_sorted_documents(
        [
            _normalize_data_resource(item, path, item_index)
            for item_index, item in enumerate(raw_data_resources)
        ],
        operation_name=operation_name,
        fact_path=f"{path}.DataResources",
    )
    return {
        "raw_presence": raw_presence,
        "include_management_events": include_management,
        "read_write_type": read_write_type,
        "exclude_management_event_sources": exclusions,
        "data_resources": data_resources,
    }


def _normalize_data_resource(
    value: object,
    parent_path: str,
    index: int,
) -> dict[str, object]:
    operation_name = "get_event_selectors"
    path = f"{parent_path}.DataResources[{index}]"
    resource = require_mapping(value, operation_name=operation_name, fact_path=path)
    if set(resource) != {"Type", "Values"}:
        raise CollectorEvidenceError(operation_name, path)
    resource_type = require_non_empty_string(
        resource["Type"],
        operation_name=operation_name,
        fact_path=f"{path}.Type",
    )
    if not _is_safe_non_empty_string(resource_type):
        raise CollectorEvidenceError(operation_name, f"{path}.Type")
    raw_values = require_list(
        resource["Values"],
        operation_name=operation_name,
        fact_path=f"{path}.Values",
    )
    if not raw_values:
        raise CollectorEvidenceError(operation_name, f"{path}.Values")
    return {
        "type": resource_type,
        "values": _unique_sorted_strings(
            raw_values,
            operation_name=operation_name,
            fact_path=f"{path}.Values",
        ),
    }


def _normalize_advanced_selector(value: object, index: int) -> dict[str, object]:
    operation_name = "get_event_selectors"
    path = f"AdvancedEventSelectors[{index}]"
    selector = require_mapping(value, operation_name=operation_name, fact_path=path)
    if not set(selector).issubset({"Name", "FieldSelectors"}):
        raise CollectorEvidenceError(operation_name, path)
    name = _strict_optional_non_empty_string(
        selector,
        "Name",
        operation_name=operation_name,
        fact_path=f"{path}.Name",
    )
    if name is not None and not _is_safe_non_empty_string(name):
        raise CollectorEvidenceError(operation_name, f"{path}.Name")
    raw_fields = require_list(
        require_member(
            selector,
            "FieldSelectors",
            operation_name=operation_name,
            fact_path=f"{path}.FieldSelectors",
        ),
        operation_name=operation_name,
        fact_path=f"{path}.FieldSelectors",
    )
    if not raw_fields:
        raise CollectorEvidenceError(operation_name, f"{path}.FieldSelectors")
    fields = _unique_sorted_documents(
        [
            _normalize_advanced_field(item, path, field_index)
            for field_index, item in enumerate(raw_fields)
        ],
        operation_name=operation_name,
        fact_path=f"{path}.FieldSelectors",
    )
    return {
        "name": name,
        "field_selectors": fields,
    }


def _normalize_advanced_field(
    value: object,
    parent_path: str,
    index: int,
) -> dict[str, object]:
    operation_name = "get_event_selectors"
    path = f"{parent_path}.FieldSelectors[{index}]"
    field = require_mapping(value, operation_name=operation_name, fact_path=path)
    allowed = {"Field", *(aws_name for aws_name, _ in _ADVANCED_OPERATORS)}
    if not set(field).issubset(allowed):
        raise CollectorEvidenceError(operation_name, path)
    field_name = require_non_empty_string(
        require_member(
            field,
            "Field",
            operation_name=operation_name,
            fact_path=f"{path}.Field",
        ),
        operation_name=operation_name,
        fact_path=f"{path}.Field",
    )
    if not _is_safe_non_empty_string(field_name):
        raise CollectorEvidenceError(operation_name, f"{path}.Field")
    normalized: dict[str, object] = {"field": field_name}
    operator_count = 0
    for aws_name, normalized_name in _ADVANCED_OPERATORS:
        raw_values = require_list(
            field.get(aws_name, []),
            operation_name=operation_name,
            fact_path=f"{path}.{aws_name}",
        )
        values = _unique_sorted_strings(
            raw_values,
            operation_name=operation_name,
            fact_path=f"{path}.{aws_name}",
        )
        operator_count += bool(values)
        normalized[normalized_name] = values
    if operator_count == 0:
        raise CollectorEvidenceError(operation_name, path)
    return normalized


def _trail_resource(
    *,
    identity: _TrailIdentity,
    configuration: _SourceValue,
    status: _SourceValue,
    event_selectors: _SourceValue,
    tags: _SourceValue,
) -> NormalizedResource:
    config_value = configuration.value if isinstance(configuration.value, Mapping) else {}
    status_value = status.value if isinstance(status.value, Mapping) else {}
    selectors_value = event_selectors.value if isinstance(event_selectors.value, Mapping) else None
    tag_value = tags.value if isinstance(tags.value, dict) else {}
    source_states = {
        "identity": EvidenceSourceState.PRESENT.value,
        "configuration": _state_for(
            configuration,
            allow_resource_disappeared=True,
        )[0].value,
        "status": _state_for(status, allow_resource_disappeared=True)[0].value,
        "event_selectors": _state_for(
            event_selectors,
            allow_resource_disappeared=True,
        )[0].value,
        "tags": _state_for(tags, allow_resource_disappeared=True)[0].value,
    }
    trail_configuration = {
        "home_region": identity.home_region,
        "s3_bucket_name": config_value.get("s3_bucket_name"),
        "s3_key_prefix": config_value.get("s3_key_prefix"),
        "include_global_service_events": config_value.get("include_global_service_events"),
        "is_multi_region_trail": config_value.get("is_multi_region_trail"),
        "log_file_validation_enabled": config_value.get("log_file_validation_enabled"),
        "cloudwatch_logs_log_group_arn": config_value.get("cloudwatch_logs_log_group_arn"),
        "cloudwatch_logs_role_arn": config_value.get("cloudwatch_logs_role_arn"),
        "kms_key_id": config_value.get("kms_key_id"),
        "is_organization_trail": config_value.get("is_organization_trail"),
        "is_logging": status_value.get("is_logging"),
        "status": status_value.get("status"),
        "event_selectors": selectors_value,
        "source_states": source_states,
    }
    return NormalizedResource(
        account_id=identity.owner_account_id,
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=identity.trail_arn,
        arn=identity.trail_arn,
        name=identity.name,
        scope=ResourceScope.REGIONAL,
        region=identity.home_region,
        tags=dict(tag_value),
        configuration=trail_configuration,
        raw_configuration={
            "summary": identity.summary,
            "trail": dict(config_value) if config_value else None,
            "status": status_value.get("status"),
            "event_selectors": selectors_value,
        },
    )


def _legacy_status(
    discovery: _SourceValue,
    records: tuple[_TrailRecord, ...],
) -> CollectionStatus:
    states = [_state_for(discovery)[0]]
    for record in records:
        states.extend(
            (
                _state_for(
                    record.configuration,
                    allow_resource_disappeared=True,
                )[0],
                _state_for(record.status, allow_resource_disappeared=True)[0],
            )
        )
    if all(state is EvidenceSourceState.PRESENT for state in states):
        return CollectionStatus.SUCCEEDED
    if states and all(state is EvidenceSourceState.UNAVAILABLE for state in states):
        return CollectionStatus.FAILED
    return CollectionStatus.PARTIAL


def _state_for(
    source: _SourceValue,
    *,
    allow_resource_disappeared: bool = False,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if source.error is None:
        return EvidenceSourceState.PRESENT, None
    if (
        allow_resource_disappeared
        and isinstance(source.error, ClientError)
        and source.error.response.get("Error", {}).get("Code") in _RESOURCE_DISAPPEARED_CODES
    ):
        return EvidenceSourceState.RESOURCE_DISAPPEARED, EvidenceFailureCategory.RESOURCE_NOT_FOUND
    return source_failure(source.error)


def _preferred_error(errors: list[BaseException]) -> BaseException | None:
    if not errors:
        return None
    priorities = (
        CollectorEvidenceConflictError,
        CollectorEvidenceError,
        ClientError,
        BotoCoreError,
    )
    for error_type in priorities:
        match = next((error for error in errors if isinstance(error, error_type)), None)
        if match is not None:
            return match
    return errors[0]


def _trail_subject(
    context: CollectionContext,
    identity: _TrailIdentity,
) -> ResourceEvidenceSubject:
    return ResourceEvidenceSubject.for_aws_resource(
        scan_id=context.scan_id,
        aws_account_id=identity.owner_account_id,
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=identity.trail_arn,
        scope=ResourceScope.REGIONAL,
        region=identity.home_region,
    )


def _observed_trail_endpoint(
    context: CollectionContext,
    identity: _TrailIdentity,
) -> RelationshipEndpoint:
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=identity.owner_account_id,
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=identity.trail_arn,
        scope=ResourceScope.REGIONAL,
        region=identity.home_region,
        observed_in_scan_id=context.scan_id,
    )


def _trail_evidence_reference(identity: _TrailIdentity, segment: str) -> str:
    digest = hashlib.sha256(identity.trail_arn.encode()).hexdigest()
    return f"normalized://aws/cloudtrail/{identity.home_region}/trails/{digest}/{segment}"


def _normalized_tags(source: _SourceValue) -> list[dict[str, str]] | None:
    if not isinstance(source.value, dict):
        return None
    return [{"key": key, "value": value} for key, value in sorted(source.value.items())]


def _kms_key_identity(
    key_arn: str,
    *,
    expected_partition: str,
    operation_name: str,
    fact_path: str,
) -> tuple[str, str]:
    parts = key_arn.split(":", maxsplit=5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or parts[1] != expected_partition
        or parts[2] != "kms"
        or not _AWS_REGION_PATTERN.fullmatch(parts[3])
        or not _is_account_id(parts[4])
        or not parts[5].startswith("key/")
        or not parts[5].removeprefix("key/")
    ):
        raise CollectorEvidenceError(operation_name, fact_path)
    return parts[3], parts[4]


def _is_account_id(value: str) -> bool:
    return len(value) == 12 and value.isascii() and value.isdigit()


def _strict_optional_string(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container:
        return None
    return require_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _strict_optional_non_empty_string(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container:
        return None
    return require_non_empty_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _strict_optional_boolean(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> bool | None:
    if key not in container:
        return None
    return require_boolean(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _unique_sorted_strings(
    values: list[Any],
    *,
    operation_name: str,
    fact_path: str,
) -> list[str]:
    normalized = [
        require_non_empty_string(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
        for value in values
    ]
    if any(not _is_safe_non_empty_string(value) for value in normalized):
        raise CollectorEvidenceError(operation_name, fact_path)
    if len(normalized) != len(set(normalized)):
        raise CollectorEvidenceConflictError(operation_name, fact_path)
    return sorted(normalized)


def _unique_sorted_documents(
    values: list[dict[str, object]],
    *,
    operation_name: str,
    fact_path: str,
) -> list[dict[str, object]]:
    documents = [(_canonical_json(value), value) for value in values]
    if len(documents) != len({document for document, _ in documents}):
        raise CollectorEvidenceConflictError(operation_name, fact_path)
    return [value for _, value in sorted(documents, key=lambda item: item[0])]


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _is_safe_non_empty_string(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and not any(separator in value for separator in _UNSAFE_IDENTITY_SEPARATORS)
    )
