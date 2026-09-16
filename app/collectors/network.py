"""Sprint 5B VPC, subnet, and Flow Log evidence collection.

This collector records network topology facts and source completeness only.  It does not decide
whether a VPC, subnet, or Flow Log satisfies a security control.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.relationships import RelationshipEndpoint, RelationshipType
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
    require_integer,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    source_failure,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_COLLECTOR_VERSION = "1.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)
_FLOW_LOG_STATES = frozenset({"ACTIVE"})
_TRAFFIC_TYPES = frozenset({"ACCEPT", "REJECT", "ALL"})
_DESTINATION_TYPES = frozenset({"cloud-watch-logs", "s3", "kinesis-data-firehose"})


@dataclass(frozen=True, slots=True)
class _SourceCollection:
    """Validated resources and joins retained from one independently paginated API."""

    resources: tuple[NormalizedResource, ...]
    related_vpc_ids: Mapping[str, str]
    error: BaseException | None
    discarded_item_count: int


_Normalizer = Callable[
    [Mapping[str, Any], str, CollectionContext],
    tuple[NormalizedResource, str | None],
]


class VPCNetworkCollector(ResourceCollector):
    """Collect Regional VPC, subnet, and Flow Log evidence independently."""

    collector_name = "vpc_network_evidence"
    produces_evidence_graph = True

    def collect(self) -> list[NormalizedResource]:
        """Preserve the direct collector API for offline and CLI callers."""

        from datetime import UTC, datetime

        context = CollectionContext(
            scan_id=uuid4(),
            collection_account_id=self.client_provider.account_id,
            region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
        )
        return list(self.collect_with_context(context).resources)

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Collect three independent Regional sources and build exact topology references."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        if context.region != self.client_provider.region_name:
            raise ValueError("collection context Region does not match the AWS client provider")

        client = self.client_provider.client("ec2")
        vpcs = self._collect_paginated_source(
            client=client,
            operation_name="describe_vpcs",
            result_key="Vpcs",
            identity_key="VpcId",
            context=context,
            normalizer=self._normalize_vpc,
        )
        subnets = self._collect_paginated_source(
            client=client,
            operation_name="describe_subnets",
            result_key="Subnets",
            identity_key="SubnetId",
            context=context,
            normalizer=self._normalize_subnet,
        )
        flow_logs = self._collect_paginated_source(
            client=client,
            operation_name="describe_flow_logs",
            result_key="FlowLogs",
            identity_key="FlowLogId",
            context=context,
            normalizer=self._normalize_flow_log,
        )

        observations: list[SourceObservation] = []
        observations.extend(
            self._observations_for_source(
                context=context,
                source=vpcs,
                discovery_contract_key="ec2.vpcs.discovery",
                discovery_evidence_kind="ec2.vpcs.discovery",
                resource_contract_key="ec2.vpc",
                resource_evidence_kind="ec2.vpc",
                collector="ec2.vpcs",
                source_api="ec2:DescribeVpcs",
                reference_segment="vpcs",
            )
        )
        observations.extend(
            self._observations_for_source(
                context=context,
                source=subnets,
                discovery_contract_key="ec2.subnets.discovery",
                discovery_evidence_kind="ec2.subnets.discovery",
                resource_contract_key="ec2.subnet",
                resource_evidence_kind="ec2.subnet",
                collector="ec2.subnets",
                source_api="ec2:DescribeSubnets",
                reference_segment="subnets",
            )
        )
        observations.extend(
            self._observations_for_source(
                context=context,
                source=flow_logs,
                discovery_contract_key="ec2.flow-logs.discovery",
                discovery_evidence_kind="ec2.flow-logs.discovery",
                resource_contract_key="ec2.vpc-flow-log",
                resource_evidence_kind="ec2.vpc-flow-log",
                collector="ec2.flow-logs",
                source_api="ec2:DescribeFlowLogs",
                reference_segment="flow-logs",
            )
        )

        observation_by_identity = {
            (
                observation.outcome.subject.service,
                observation.outcome.subject.resource_type,
                observation.outcome.subject.aws_resource_id,
            ): observation
            for observation in observations
            if isinstance(observation.outcome.subject, ResourceEvidenceSubject)
        }
        relationships = self._relationships(
            context=context,
            vpcs=vpcs,
            subnets=subnets,
            flow_logs=flow_logs,
            observation_by_identity=observation_by_identity,
        )
        resources = tuple(
            sorted(
                (*vpcs.resources, *subnets.resources, *flow_logs.resources),
                key=lambda resource: resource.identity,
            )
        )
        outcomes = tuple(observation.outcome for observation in observations)
        return CollectorResult(
            resources=resources,
            status=collection_status_for(outcomes),
            source_contracts=tuple(observation.contract for observation in observations),
            artifacts=tuple(observation.artifact for observation in observations),
            source_outcomes=outcomes,
            relationships=relationships,
        )

    def _collect_paginated_source(
        self,
        *,
        client: Any,
        operation_name: str,
        result_key: str,
        identity_key: str,
        context: CollectionContext,
        normalizer: _Normalizer,
    ) -> _SourceCollection:
        resources: dict[str, NormalizedResource] = {}
        related_vpc_ids: dict[str, str] = {}
        seen_raw: dict[str, dict[str, Any]] = {}
        discarded_count = 0
        errors: list[BaseException] = []

        try:
            paginator = client.get_paginator(operation_name)
            for page_index, raw_page in enumerate(paginator.paginate()):
                page = require_mapping(
                    raw_page,
                    operation_name=operation_name,
                    fact_path=f"pages[{page_index}]",
                )
                items_path = f"pages[{page_index}].{result_key}"
                items = require_list(
                    require_member(
                        page,
                        result_key,
                        operation_name=operation_name,
                        fact_path=items_path,
                    ),
                    operation_name=operation_name,
                    fact_path=items_path,
                )
                for item_index, raw_item in enumerate(items):
                    item_path = f"{items_path}[{item_index}]"
                    identity: str | None = None
                    try:
                        item = require_mapping(
                            raw_item,
                            operation_name=operation_name,
                            fact_path=item_path,
                        )
                        identity_path = f"{item_path}.{identity_key}"
                        identity = require_non_empty_string(
                            require_member(
                                item,
                                identity_key,
                                operation_name=operation_name,
                                fact_path=identity_path,
                            ),
                            operation_name=operation_name,
                            fact_path=identity_path,
                        )
                        previous = seen_raw.get(identity)
                        if previous is not None:
                            if previous == item:
                                continue
                            if identity in resources:
                                discarded_count += 1
                            resources.pop(identity, None)
                            related_vpc_ids.pop(identity, None)
                            discarded_count += 1
                            errors.append(
                                CollectorEvidenceConflictError(operation_name, identity_path)
                            )
                            continue
                        seen_raw[identity] = item
                        resource, related_vpc_id = normalizer(item, item_path, context)
                        resources[identity] = resource
                        if related_vpc_id is not None:
                            related_vpc_ids[identity] = related_vpc_id
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded_count += 1
                        if identity is not None:
                            resources.pop(identity, None)
                            related_vpc_ids.pop(identity, None)
        except _EXPECTED_FAILURES as error:
            errors.append(error)

        return _SourceCollection(
            resources=tuple(sorted(resources.values(), key=lambda item: item.identity)),
            related_vpc_ids=dict(related_vpc_ids),
            error=_preferred_error(errors),
            discarded_item_count=discarded_count,
        )

    def _normalize_vpc(
        self,
        item: Mapping[str, Any],
        item_path: str,
        context: CollectionContext,
    ) -> tuple[NormalizedResource, None]:
        operation_name = "describe_vpcs"
        vpc_id = _required_id_member(item, "VpcId", operation_name, item_path)
        owner_id = _required_account_member(item, "OwnerId", operation_name, item_path)
        tags = _normalize_tags(item, operation_name, item_path)
        resource = NormalizedResource(
            account_id=owner_id,
            service="ec2",
            resource_type="vpc",
            aws_resource_id=vpc_id,
            arn=(
                f"arn:{self.client_provider.partition}:ec2:{context.region}:{owner_id}:vpc/{vpc_id}"
            ),
            name=tags.get("Name"),
            scope=ResourceScope.REGIONAL,
            region=context.region,
            tags=tags,
            configuration={
                "state": _optional_string(item, "State", operation_name, item_path),
                "cidr_block": _optional_string(item, "CidrBlock", operation_name, item_path),
                "dhcp_options_id": _optional_string(
                    item, "DhcpOptionsId", operation_name, item_path
                ),
                "instance_tenancy": _optional_string(
                    item, "InstanceTenancy", operation_name, item_path
                ),
                "is_default": _optional_boolean(item, "IsDefault", operation_name, item_path),
            },
            raw_configuration=to_json_safe(item),
        )
        return resource, None

    def _normalize_subnet(
        self,
        item: Mapping[str, Any],
        item_path: str,
        context: CollectionContext,
    ) -> tuple[NormalizedResource, str]:
        operation_name = "describe_subnets"
        subnet_id = _required_id_member(item, "SubnetId", operation_name, item_path)
        owner_id = _required_account_member(item, "OwnerId", operation_name, item_path)
        vpc_id = _required_id_member(item, "VpcId", operation_name, item_path)
        map_public_ip = require_boolean(
            require_member(
                item,
                "MapPublicIpOnLaunch",
                operation_name=operation_name,
                fact_path=f"{item_path}.MapPublicIpOnLaunch",
            ),
            operation_name=operation_name,
            fact_path=f"{item_path}.MapPublicIpOnLaunch",
        )
        tags = _normalize_tags(item, operation_name, item_path)
        arn = _optional_string(item, "SubnetArn", operation_name, item_path)
        expected_arn = (
            f"arn:{self.client_provider.partition}:ec2:{context.region}:"
            f"{owner_id}:subnet/{subnet_id}"
        )
        if arn is not None and arn != expected_arn:
            raise CollectorEvidenceError(operation_name, f"{item_path}.SubnetArn")
        resource = NormalizedResource(
            account_id=owner_id,
            service="ec2",
            resource_type="subnet",
            aws_resource_id=subnet_id,
            arn=expected_arn,
            name=tags.get("Name"),
            scope=ResourceScope.REGIONAL,
            region=context.region,
            tags=tags,
            configuration={
                "vpc_id": vpc_id,
                "state": _optional_string(item, "State", operation_name, item_path),
                "cidr_block": _optional_string(item, "CidrBlock", operation_name, item_path),
                "availability_zone": _optional_string(
                    item, "AvailabilityZone", operation_name, item_path
                ),
                "availability_zone_id": _optional_string(
                    item, "AvailabilityZoneId", operation_name, item_path
                ),
                "available_ip_address_count": _optional_integer(
                    item, "AvailableIpAddressCount", operation_name, item_path
                ),
                "map_public_ip_on_launch": map_public_ip,
                "assign_ipv6_address_on_creation": _optional_boolean(
                    item, "AssignIpv6AddressOnCreation", operation_name, item_path
                ),
                "default_for_az": _optional_boolean(
                    item, "DefaultForAz", operation_name, item_path
                ),
                "ipv6_native": _optional_boolean(item, "Ipv6Native", operation_name, item_path),
            },
            raw_configuration=to_json_safe(item),
        )
        return resource, vpc_id

    def _normalize_flow_log(
        self,
        item: Mapping[str, Any],
        item_path: str,
        context: CollectionContext,
    ) -> tuple[NormalizedResource, str]:
        operation_name = "describe_flow_logs"
        flow_log_id = _required_id_member(item, "FlowLogId", operation_name, item_path)
        resource_id = _required_id_member(item, "ResourceId", operation_name, item_path)
        flow_log_status = _required_string_member(item, "FlowLogStatus", operation_name, item_path)
        if flow_log_status not in _FLOW_LOG_STATES:
            raise CollectorEvidenceError(operation_name, f"{item_path}.FlowLogStatus")
        traffic_type = _required_string_member(item, "TrafficType", operation_name, item_path)
        if traffic_type not in _TRAFFIC_TYPES:
            raise CollectorEvidenceError(operation_name, f"{item_path}.TrafficType")
        destination_type = _required_string_member(
            item, "LogDestinationType", operation_name, item_path
        )
        if destination_type not in _DESTINATION_TYPES:
            raise CollectorEvidenceError(operation_name, f"{item_path}.LogDestinationType")
        log_group_name = _optional_string(item, "LogGroupName", operation_name, item_path)
        log_destination = _optional_string(item, "LogDestination", operation_name, item_path)
        if destination_type == "cloud-watch-logs":
            if log_group_name is None and log_destination is None:
                raise CollectorEvidenceError(operation_name, f"{item_path}.LogGroupName")
        elif log_destination is None:
            raise CollectorEvidenceError(operation_name, f"{item_path}.LogDestination")
        tags = _normalize_tags(item, operation_name, item_path)
        resource = NormalizedResource(
            account_id=context.collection_account_id,
            service="ec2",
            resource_type="vpc_flow_log",
            aws_resource_id=flow_log_id,
            arn=(
                f"arn:{self.client_provider.partition}:ec2:{context.region}:"
                f"{context.collection_account_id}:vpc-flow-log/{flow_log_id}"
            ),
            name=tags.get("Name"),
            scope=ResourceScope.REGIONAL,
            region=context.region,
            tags=tags,
            configuration={
                "resource_id": resource_id,
                "flow_log_status": flow_log_status,
                "traffic_type": traffic_type,
                "log_destination_type": destination_type,
                "log_group_name": log_group_name,
                "log_destination": log_destination,
                "deliver_logs_permission_arn": _optional_string(
                    item, "DeliverLogsPermissionArn", operation_name, item_path
                ),
                "deliver_cross_account_role": _optional_string(
                    item, "DeliverCrossAccountRole", operation_name, item_path
                ),
                "deliver_logs_status": _optional_string(
                    item, "DeliverLogsStatus", operation_name, item_path
                ),
                "max_aggregation_interval": _optional_integer(
                    item, "MaxAggregationInterval", operation_name, item_path
                ),
            },
            raw_configuration=to_json_safe(item),
        )
        return resource, resource_id

    def _observations_for_source(
        self,
        *,
        context: CollectionContext,
        source: _SourceCollection,
        discovery_contract_key: str,
        discovery_evidence_kind: str,
        resource_contract_key: str,
        resource_evidence_kind: str,
        collector: str,
        source_api: str,
        reference_segment: str,
    ) -> tuple[SourceObservation, ...]:
        state, category = _state_for(source.error)
        observations = [
            build_source_observation(
                context=context,
                contract_key=discovery_contract_key,
                contract_version=_CONTRACT_VERSION,
                phase=EvidenceCollectionPhase.DISCOVERY,
                subject=_regional_account_subject(context),
                evidence_kind=discovery_evidence_kind,
                collector=collector,
                collector_version=_COLLECTOR_VERSION,
                source_api=source_api,
                cardinality=EvidenceCardinality.COLLECTION,
                evidence_reference=(
                    f"normalized://aws/ec2/{context.region}/{reference_segment}/discovery"
                ),
                evidence_schema=discovery_evidence_kind,
                evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
                normalized_payload={
                    "account_id": context.collection_account_id,
                    "region": context.region,
                    "resource_ids": sorted(
                        resource.aws_resource_id for resource in source.resources
                    ),
                    "resource_count": len(source.resources),
                    "discarded_item_count": source.discarded_item_count,
                    "admission_complete": True,
                    "unadmitted_resources": [],
                    "complete": source.error is None,
                    "failure_category": category.value if category is not None else None,
                },
                state=state,
                failure_category=category,
            )
        ]
        for resource in source.resources:
            observations.append(
                _build_resource_observation(
                    context=context,
                    resource=resource,
                    contract_key=resource_contract_key,
                    evidence_kind=resource_evidence_kind,
                    collector=collector,
                    source_api=source_api,
                    evidence_reference=(
                        f"normalized://aws/ec2/{context.region}/{reference_segment}/"
                        f"{resource.account_id}/{resource.aws_resource_id}"
                    ),
                )
            )
        return tuple(observations)

    def _relationships(
        self,
        *,
        context: CollectionContext,
        vpcs: _SourceCollection,
        subnets: _SourceCollection,
        flow_logs: _SourceCollection,
        observation_by_identity: Mapping[tuple[str, str, str], SourceObservation],
    ) -> tuple[RelationshipReference, ...]:
        vpcs_by_id: dict[str, list[NormalizedResource]] = {}
        for vpc in vpcs.resources:
            vpcs_by_id.setdefault(vpc.aws_resource_id, []).append(vpc)

        relationships: list[RelationshipReference] = []
        for subnet in subnets.resources:
            vpc_id = subnets.related_vpc_ids[subnet.aws_resource_id]
            matches = [
                vpc
                for vpc in vpcs_by_id.get(vpc_id, [])
                if vpc.account_id == subnet.account_id and vpc.region == subnet.region
            ]
            if len(matches) != 1:
                continue
            observation = observation_by_identity[("ec2", "subnet", subnet.aws_resource_id)]
            relationships.append(
                _relationship_reference(
                    context=context,
                    relationship_type=RelationshipType.CONTAINS_SUBNET,
                    source=matches[0],
                    target=subnet,
                    observation=observation,
                    target_evidence_kind="ec2.subnets.discovery",
                )
            )

        for flow_log in flow_logs.resources:
            vpc_id = flow_logs.related_vpc_ids[flow_log.aws_resource_id]
            matches = [
                vpc
                for vpc in vpcs_by_id.get(vpc_id, [])
                if vpc.account_id == context.collection_account_id and vpc.region == flow_log.region
            ]
            if len(matches) != 1:
                continue
            observation = observation_by_identity[("ec2", "vpc_flow_log", flow_log.aws_resource_id)]
            relationships.append(
                _relationship_reference(
                    context=context,
                    relationship_type=RelationshipType.HAS_FLOW_LOG,
                    source=matches[0],
                    target=flow_log,
                    observation=observation,
                    target_evidence_kind="ec2.flow-logs.discovery",
                )
            )
        return tuple(relationships)


def _build_resource_observation(
    *,
    context: CollectionContext,
    resource: NormalizedResource,
    contract_key: str,
    evidence_kind: str,
    collector: str,
    source_api: str,
    evidence_reference: str,
) -> SourceObservation:
    return build_source_observation(
        context=context,
        contract_key=contract_key,
        contract_version=_CONTRACT_VERSION,
        phase=EvidenceCollectionPhase.ENRICHMENT,
        subject=ResourceEvidenceSubject.for_aws_resource(
            scan_id=context.scan_id,
            aws_account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            aws_resource_id=resource.aws_resource_id,
            scope=resource.scope,
            region=resource.region,
        ),
        evidence_kind=evidence_kind,
        collector=collector,
        collector_version=_COLLECTOR_VERSION,
        source_api=source_api,
        cardinality=EvidenceCardinality.SINGLE,
        evidence_reference=evidence_reference,
        evidence_schema=evidence_kind,
        evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
        normalized_payload={
            "account_id": resource.account_id,
            "region": resource.region,
            "resource_type": resource.resource_type,
            "resource_id": resource.aws_resource_id,
            "arn": resource.arn,
            "tags": [{"key": key, "value": value} for key, value in sorted(resource.tags.items())],
            "configuration": resource.configuration,
        },
        state=EvidenceSourceState.PRESENT,
        identity_authoritative=True,
    )


def _relationship_reference(
    *,
    context: CollectionContext,
    relationship_type: RelationshipType,
    source: NormalizedResource,
    target: NormalizedResource,
    observation: SourceObservation,
    target_evidence_kind: str,
) -> RelationshipReference:
    return RelationshipReference(
        relationship_type=relationship_type,
        source=_observed_endpoint(context, source),
        target=RelationshipEndpoint.for_aws_resource(
            aws_account_id=target.account_id,
            service=target.service,
            resource_type=target.resource_type,
            aws_resource_id=target.aws_resource_id,
            scope=target.scope,
            region=target.region,
            observed_in_scan_id=None,
        ),
        provenance=observation.provenance,
        target_collector_name=VPCNetworkCollector.collector_name,
        target_evidence_kind=target_evidence_kind,
    )


def _observed_endpoint(
    context: CollectionContext,
    resource: NormalizedResource,
) -> RelationshipEndpoint:
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
        observed_in_scan_id=context.scan_id,
    )


def _regional_account_subject(context: CollectionContext) -> AccountEvidenceSubject:
    return AccountEvidenceSubject(
        aws_account_id=context.collection_account_id,
        scope=ResourceScope.REGIONAL,
        region=context.region,
    )


def _required_string_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    item_path: str,
) -> str:
    fact_path = f"{item_path}.{key}"
    return require_non_empty_string(
        require_member(
            item,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _required_account_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    item_path: str,
) -> str:
    account_id = _required_string_member(item, key, operation_name, item_path)
    if len(account_id) != 12 or not account_id.isascii() or not account_id.isdigit():
        raise CollectorEvidenceError(operation_name, f"{item_path}.{key}")
    return account_id


def _required_id_member(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    item_path: str,
) -> str:
    fact_path = f"{item_path}.{key}"
    identifier = _required_string_member(item, key, operation_name, item_path)
    if "\x1f" in identifier or "\r" in identifier or "\n" in identifier:
        raise CollectorEvidenceError(operation_name, fact_path)
    return identifier


def _optional_string(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    item_path: str,
) -> str | None:
    if key not in item or item[key] is None:
        return None
    return require_non_empty_string(
        item[key],
        operation_name=operation_name,
        fact_path=f"{item_path}.{key}",
    )


def _optional_boolean(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    item_path: str,
) -> bool | None:
    if key not in item or item[key] is None:
        return None
    return require_boolean(
        item[key],
        operation_name=operation_name,
        fact_path=f"{item_path}.{key}",
    )


def _optional_integer(
    item: Mapping[str, Any],
    key: str,
    operation_name: str,
    item_path: str,
) -> int | None:
    if key not in item or item[key] is None:
        return None
    return require_integer(
        item[key],
        operation_name=operation_name,
        fact_path=f"{item_path}.{key}",
    )


def _normalize_tags(
    item: Mapping[str, Any],
    operation_name: str,
    item_path: str,
) -> dict[str, str]:
    if "Tags" not in item:
        return {}
    tags_path = f"{item_path}.Tags"
    tags = require_list(
        item["Tags"],
        operation_name=operation_name,
        fact_path=tags_path,
    )
    return tags_to_dict(
        tags,
        operation_name=operation_name,
        fact_path=tags_path,
        allow_missing_value=True,
    )


def _state_for(
    error: BaseException | None,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if error is None:
        return EvidenceSourceState.PRESENT, None
    return source_failure(error)


def _preferred_error(errors: list[BaseException]) -> BaseException | None:
    for expected_type in (CollectorEvidenceConflictError, CollectorEvidenceError):
        for error in errors:
            if isinstance(error, expected_type):
                return error
    return errors[0] if errors else None
