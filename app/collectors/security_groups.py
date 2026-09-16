"""EC2 security group resource collection."""

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any

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
    require_integer,
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
from app.schemas.resource import NormalizedResource, ResourceScope

_OPERATION_NAME = "describe_security_groups"
_NAMED_PROTOCOLS = {"-1", "tcp", "udp", "icmp", "icmpv6"}
_COLLECTOR_VERSION = "2.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)


@dataclass(frozen=True, slots=True)
class _SourceCollection:
    resources: tuple[NormalizedResource, ...]
    error: BaseException | None
    discarded_item_count: int


class SecurityGroupCollector(ResourceCollector):
    """Collect regional security groups and normalize their network-rule facts."""

    collector_name = "security_groups"
    produces_evidence_graph = True

    def collect(self) -> list[NormalizedResource]:
        client = self.client_provider.client("ec2")
        resources: list[NormalizedResource] = []
        seen_groups: dict[str, dict[str, Any]] = {}

        for group_index, security_group in enumerate(
            iter_paginated_items(
                client,
                _OPERATION_NAME,
                "SecurityGroups",
            )
        ):
            group_path = f"SecurityGroups[{group_index}]"
            group_id = _validate_id_value(
                require_member(
                    security_group,
                    "GroupId",
                    operation_name=_OPERATION_NAME,
                    fact_path=f"{group_path}.GroupId",
                ),
                operation_name=_OPERATION_NAME,
                fact_path=f"{group_path}.GroupId",
            )
            if should_skip_exact_duplicate(
                seen_groups,
                group_id,
                security_group,
                operation_name=_OPERATION_NAME,
                fact_path=f"{group_path}.GroupId",
            ):
                continue

            account_id = self.client_provider.account_id
            resources.append(
                self._normalize_security_group(
                    security_group,
                    group_path,
                    group_id=group_id,
                    account_id=account_id,
                    include_graph_facts=False,
                )
            )

        return resources

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Emit graph evidence without coupling security-group coverage to other network APIs."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        if context.region != self.client_provider.region_name:
            raise ValueError("collection context Region does not match the AWS client provider")

        client = self.client_provider.client("ec2")
        source = self._collect_graph_resources(client)
        observations: list[SourceObservation] = [
            self._build_discovery_observation(context=context, source=source)
        ]
        relationships: list[RelationshipReference] = []
        for resource in source.resources:
            observation = self._build_resource_observation(
                context=context,
                resource=resource,
            )
            observations.append(observation)
            vpc_id = resource.configuration.get("vpc_id")
            if isinstance(vpc_id, str):
                relationships.append(
                    RelationshipReference(
                        relationship_type=RelationshipType.IN_VPC,
                        source=_observed_endpoint(context, resource),
                        target=UnresolvedRelationshipTarget.for_aws_reference(
                            service="ec2",
                            resource_type="vpc",
                            aws_resource_id=vpc_id,
                            scope=ResourceScope.REGIONAL,
                            region=context.region,
                        ),
                        provenance=observation.provenance,
                        target_collector_name="vpc_network_evidence",
                        target_evidence_kind="ec2.vpcs.discovery",
                    )
                )

        outcomes = tuple(observation.outcome for observation in observations)
        return CollectorResult(
            resources=source.resources,
            status=collection_status_for(outcomes),
            source_contracts=tuple(observation.contract for observation in observations),
            artifacts=tuple(observation.artifact for observation in observations),
            source_outcomes=outcomes,
            relationships=tuple(relationships),
        )

    def _collect_graph_resources(self, client: Any) -> _SourceCollection:
        resources: dict[str, NormalizedResource] = {}
        seen_raw: dict[str, dict[str, Any]] = {}
        discarded_count = 0
        errors: list[BaseException] = []

        try:
            paginator = client.get_paginator(_OPERATION_NAME)
            for page_index, raw_page in enumerate(paginator.paginate()):
                page = require_mapping(
                    raw_page,
                    operation_name=_OPERATION_NAME,
                    fact_path=f"pages[{page_index}]",
                )
                items_path = f"pages[{page_index}].SecurityGroups"
                items = require_list(
                    require_member(
                        page,
                        "SecurityGroups",
                        operation_name=_OPERATION_NAME,
                        fact_path=items_path,
                    ),
                    operation_name=_OPERATION_NAME,
                    fact_path=items_path,
                )
                for item_index, raw_group in enumerate(items):
                    group_path = f"{items_path}[{item_index}]"
                    group_id: str | None = None
                    try:
                        group = require_mapping(
                            raw_group,
                            operation_name=_OPERATION_NAME,
                            fact_path=group_path,
                        )
                        group_id_path = f"{group_path}.GroupId"
                        group_id = _validate_id_value(
                            require_member(
                                group,
                                "GroupId",
                                operation_name=_OPERATION_NAME,
                                fact_path=group_id_path,
                            ),
                            operation_name=_OPERATION_NAME,
                            fact_path=group_id_path,
                        )
                        previous = seen_raw.get(group_id)
                        if previous is not None:
                            if previous == group:
                                continue
                            if group_id in resources:
                                discarded_count += 1
                            resources.pop(group_id, None)
                            discarded_count += 1
                            errors.append(
                                CollectorEvidenceConflictError(
                                    _OPERATION_NAME,
                                    group_id_path,
                                )
                            )
                            continue
                        seen_raw[group_id] = group
                        owner_path = f"{group_path}.OwnerId"
                        owner_id = require_non_empty_string(
                            require_member(
                                group,
                                "OwnerId",
                                operation_name=_OPERATION_NAME,
                                fact_path=owner_path,
                            ),
                            operation_name=_OPERATION_NAME,
                            fact_path=owner_path,
                        )
                        if len(owner_id) != 12 or not owner_id.isascii() or not owner_id.isdigit():
                            raise CollectorEvidenceError(_OPERATION_NAME, owner_path)
                        for required_string in ("GroupName",):
                            fact_path = f"{group_path}.{required_string}"
                            require_non_empty_string(
                                require_member(
                                    group,
                                    required_string,
                                    operation_name=_OPERATION_NAME,
                                    fact_path=fact_path,
                                ),
                                operation_name=_OPERATION_NAME,
                                fact_path=fact_path,
                            )
                        vpc_path = f"{group_path}.VpcId"
                        _validate_id_value(
                            require_member(
                                group,
                                "VpcId",
                                operation_name=_OPERATION_NAME,
                                fact_path=vpc_path,
                            ),
                            operation_name=_OPERATION_NAME,
                            fact_path=vpc_path,
                        )
                        expected_arn = (
                            f"arn:{self.client_provider.partition}:ec2:"
                            f"{self.client_provider.region_name}:{owner_id}:"
                            f"security-group/{group_id}"
                        )
                        observed_arn = _optional_string(
                            group,
                            "SecurityGroupArn",
                            fact_path=f"{group_path}.SecurityGroupArn",
                            non_empty=True,
                        )
                        if observed_arn is not None and observed_arn != expected_arn:
                            raise CollectorEvidenceError(
                                _OPERATION_NAME,
                                f"{group_path}.SecurityGroupArn",
                            )
                        for required_permissions in ("IpPermissions", "IpPermissionsEgress"):
                            fact_path = f"{group_path}.{required_permissions}"
                            require_list(
                                require_member(
                                    group,
                                    required_permissions,
                                    operation_name=_OPERATION_NAME,
                                    fact_path=fact_path,
                                ),
                                operation_name=_OPERATION_NAME,
                                fact_path=fact_path,
                            )
                        resources[group_id] = self._normalize_security_group(
                            group,
                            group_path,
                            group_id=group_id,
                            account_id=owner_id,
                            include_graph_facts=True,
                        )
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded_count += 1
                        if group_id is not None:
                            resources.pop(group_id, None)
        except _EXPECTED_FAILURES as error:
            errors.append(error)

        return _SourceCollection(
            resources=tuple(sorted(resources.values(), key=lambda item: item.identity)),
            error=_preferred_error(errors),
            discarded_item_count=discarded_count,
        )

    def _normalize_security_group(
        self,
        security_group: Mapping[str, Any],
        group_path: str,
        *,
        group_id: str,
        account_id: str,
        include_graph_facts: bool,
    ) -> NormalizedResource:
        region = self.client_provider.region_name
        group_name = _optional_string(
            security_group,
            "GroupName",
            fact_path=f"{group_path}.GroupName",
            non_empty=True,
        )
        vpc_id = _optional_string(
            security_group,
            "VpcId",
            fact_path=f"{group_path}.VpcId",
            non_empty=True,
        )
        is_default: bool | None
        if group_name is None:
            is_default = None
        elif group_name == "default":
            is_default = True if vpc_id is not None else None
        else:
            is_default = False
        configuration: dict[str, Any] = {
            "description": _optional_string(
                security_group,
                "Description",
                fact_path=f"{group_path}.Description",
            ),
            "vpc_id": vpc_id,
            "ingress_rules": _normalize_permissions(
                security_group,
                "IpPermissions",
                group_path,
            ),
            "egress_rules": _normalize_permissions(
                security_group,
                "IpPermissionsEgress",
                group_path,
            ),
        }
        if include_graph_facts:
            configuration["group_name"] = group_name
            configuration["is_default"] = is_default
        return NormalizedResource(
            account_id=account_id,
            service="ec2",
            resource_type="security_group",
            aws_resource_id=group_id,
            arn=(
                f"arn:{self.client_provider.partition}:ec2:{region}:"
                f"{account_id}:security-group/{group_id}"
            ),
            name=group_name,
            scope=ResourceScope.REGIONAL,
            region=region,
            tags=_normalize_tags(security_group, group_path),
            configuration=configuration,
            raw_configuration=to_json_safe(security_group),
        )

    @staticmethod
    def _build_discovery_observation(
        *,
        context: CollectionContext,
        source: _SourceCollection,
    ) -> SourceObservation:
        state, category = _state_for(source.error)
        return build_source_observation(
            context=context,
            contract_key="ec2.security-groups.discovery",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=AccountEvidenceSubject(
                aws_account_id=context.collection_account_id,
                scope=ResourceScope.REGIONAL,
                region=context.region,
            ),
            evidence_kind="ec2.security-groups.discovery",
            collector="ec2.security-groups",
            collector_version=_COLLECTOR_VERSION,
            source_api="ec2:DescribeSecurityGroups",
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference=(f"normalized://aws/ec2/{context.region}/security-groups/discovery"),
            evidence_schema="ec2.security-groups.discovery",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": context.region,
                "resource_ids": sorted(resource.aws_resource_id for resource in source.resources),
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

    @staticmethod
    def _build_resource_observation(
        *,
        context: CollectionContext,
        resource: NormalizedResource,
    ) -> SourceObservation:
        return build_source_observation(
            context=context,
            contract_key="ec2.security-group",
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
            evidence_kind="ec2.security-group",
            collector="ec2.security-groups",
            collector_version=_COLLECTOR_VERSION,
            source_api="ec2:DescribeSecurityGroups",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=(
                f"normalized://aws/ec2/{context.region}/security-groups/"
                f"{resource.account_id}/{resource.aws_resource_id}"
            ),
            evidence_schema="ec2.security-group",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": resource.account_id,
                "region": resource.region,
                "resource_type": resource.resource_type,
                "resource_id": resource.aws_resource_id,
                "arn": resource.arn,
                "tags": [
                    {"key": key, "value": value} for key, value in sorted(resource.tags.items())
                ],
                "configuration": resource.configuration,
            },
            state=EvidenceSourceState.PRESENT,
            identity_authoritative=True,
        )


def _normalize_tags(security_group: Mapping[str, Any], group_path: str) -> dict[str, str]:
    """Preserve an absent optional tag list while rejecting a malformed present list."""

    if "Tags" not in security_group:
        return {}
    tag_path = f"{group_path}.Tags"
    tags = require_list(
        security_group["Tags"],
        operation_name=_OPERATION_NAME,
        fact_path=tag_path,
    )
    return tags_to_dict(
        tags,
        operation_name=_OPERATION_NAME,
        fact_path=tag_path,
        allow_missing_value=True,
    )


def _normalize_permissions(
    security_group: Mapping[str, Any],
    field_name: str,
    group_path: str,
) -> list[dict[str, Any]] | None:
    """Preserve an absent permission list while rejecting a malformed present list."""

    if field_name not in security_group:
        return None
    permission_path = f"{group_path}.{field_name}"
    permissions = require_list(
        security_group[field_name],
        operation_name=_OPERATION_NAME,
        fact_path=permission_path,
    )
    return [
        _normalize_permission(
            require_mapping(
                permission,
                operation_name=_OPERATION_NAME,
                fact_path=f"{permission_path}[{index}]",
            ),
            f"{permission_path}[{index}]",
        )
        for index, permission in enumerate(permissions)
    ]


def _normalize_permission(permission: Mapping[str, Any], permission_path: str) -> dict[str, Any]:
    """Normalize one EC2 IP permission without evaluating whether it is secure."""

    protocol_path = f"{permission_path}.IpProtocol"
    protocol = require_non_empty_string(
        require_member(
            permission,
            "IpProtocol",
            operation_name=_OPERATION_NAME,
            fact_path=protocol_path,
        ),
        operation_name=_OPERATION_NAME,
        fact_path=protocol_path,
    )
    if not _is_valid_protocol(protocol):
        raise CollectorEvidenceError(_OPERATION_NAME, protocol_path)

    return {
        "protocol": protocol,
        "from_port": _optional_integer(
            permission,
            "FromPort",
            fact_path=f"{permission_path}.FromPort",
        ),
        "to_port": _optional_integer(
            permission,
            "ToPort",
            fact_path=f"{permission_path}.ToPort",
        ),
        "ipv4_ranges": _normalize_ip_ranges(
            permission,
            "IpRanges",
            "CidrIp",
            expected_network_type=IPv4Network,
            permission_path=permission_path,
        ),
        "ipv6_ranges": _normalize_ip_ranges(
            permission,
            "Ipv6Ranges",
            "CidrIpv6",
            expected_network_type=IPv6Network,
            permission_path=permission_path,
        ),
        "prefix_lists": _normalize_prefix_lists(permission, permission_path),
        "referenced_security_groups": _normalize_group_pairs(permission, permission_path),
    }


def _normalize_ip_ranges(
    permission: Mapping[str, Any],
    field_name: str,
    cidr_key: str,
    *,
    expected_network_type: type[IPv4Network] | type[IPv6Network],
    permission_path: str,
) -> list[dict[str, Any]] | None:
    """Validate one optional IP range list without changing the CIDR supplied by AWS."""

    if field_name not in permission:
        return None
    range_path = f"{permission_path}.{field_name}"
    ranges = require_list(
        permission[field_name],
        operation_name=_OPERATION_NAME,
        fact_path=range_path,
    )
    normalized: list[dict[str, Any]] = []
    for index, raw_range in enumerate(ranges):
        item_path = f"{range_path}[{index}]"
        item = require_mapping(
            raw_range,
            operation_name=_OPERATION_NAME,
            fact_path=item_path,
        )
        cidr_path = f"{item_path}.{cidr_key}"
        cidr = require_non_empty_string(
            require_member(
                item,
                cidr_key,
                operation_name=_OPERATION_NAME,
                fact_path=cidr_path,
            ),
            operation_name=_OPERATION_NAME,
            fact_path=cidr_path,
        )
        try:
            network = ip_network(cidr, strict=False)
        except ValueError as error:
            raise CollectorEvidenceError(_OPERATION_NAME, cidr_path) from error
        if "/" not in cidr or not isinstance(network, expected_network_type):
            raise CollectorEvidenceError(_OPERATION_NAME, cidr_path)
        normalized.append(
            {
                "cidr": cidr,
                "description": _optional_string(
                    item,
                    "Description",
                    fact_path=f"{item_path}.Description",
                ),
            }
        )
    return normalized


def _normalize_prefix_lists(
    permission: Mapping[str, Any],
    permission_path: str,
) -> list[dict[str, Any]]:
    """Validate optional managed-prefix-list sources."""

    field_name = "PrefixListIds"
    if field_name not in permission:
        return []
    list_path = f"{permission_path}.{field_name}"
    items = require_list(
        permission[field_name],
        operation_name=_OPERATION_NAME,
        fact_path=list_path,
    )
    normalized: list[dict[str, Any]] = []
    for index, raw_item in enumerate(items):
        item_path = f"{list_path}[{index}]"
        item = require_mapping(
            raw_item,
            operation_name=_OPERATION_NAME,
            fact_path=item_path,
        )
        identifier_path = f"{item_path}.PrefixListId"
        normalized.append(
            {
                "prefix_list_id": require_non_empty_string(
                    require_member(
                        item,
                        "PrefixListId",
                        operation_name=_OPERATION_NAME,
                        fact_path=identifier_path,
                    ),
                    operation_name=_OPERATION_NAME,
                    fact_path=identifier_path,
                ),
                "description": _optional_string(
                    item,
                    "Description",
                    fact_path=f"{item_path}.Description",
                ),
            }
        )
    return normalized


def _normalize_group_pairs(
    permission: Mapping[str, Any],
    permission_path: str,
) -> list[dict[str, Any]]:
    """Validate optional security-group-reference sources."""

    field_name = "UserIdGroupPairs"
    if field_name not in permission:
        return []
    list_path = f"{permission_path}.{field_name}"
    items = require_list(
        permission[field_name],
        operation_name=_OPERATION_NAME,
        fact_path=list_path,
    )
    normalized: list[dict[str, Any]] = []
    for index, raw_item in enumerate(items):
        item_path = f"{list_path}[{index}]"
        item = require_mapping(
            raw_item,
            operation_name=_OPERATION_NAME,
            fact_path=item_path,
        )
        group_id_path = f"{item_path}.GroupId"
        normalized.append(
            {
                "group_id": require_non_empty_string(
                    require_member(
                        item,
                        "GroupId",
                        operation_name=_OPERATION_NAME,
                        fact_path=group_id_path,
                    ),
                    operation_name=_OPERATION_NAME,
                    fact_path=group_id_path,
                ),
                "group_name": _optional_string(
                    item,
                    "GroupName",
                    fact_path=f"{item_path}.GroupName",
                    non_empty=True,
                ),
                "user_id": _optional_string(
                    item,
                    "UserId",
                    fact_path=f"{item_path}.UserId",
                    non_empty=True,
                ),
                "vpc_id": _optional_string(
                    item,
                    "VpcId",
                    fact_path=f"{item_path}.VpcId",
                    non_empty=True,
                ),
                "vpc_peering_connection_id": _optional_string(
                    item,
                    "VpcPeeringConnectionId",
                    fact_path=f"{item_path}.VpcPeeringConnectionId",
                    non_empty=True,
                ),
                "peering_status": _optional_string(
                    item,
                    "PeeringStatus",
                    fact_path=f"{item_path}.PeeringStatus",
                ),
                "description": _optional_string(
                    item,
                    "Description",
                    fact_path=f"{item_path}.Description",
                ),
            }
        )
    return normalized


def _optional_string(
    container: Mapping[str, Any],
    key: str,
    *,
    fact_path: str,
    non_empty: bool = False,
) -> str | None:
    """Return a valid optional string, preserving missing and explicit null as unknown."""

    if key not in container or container[key] is None:
        return None
    validator = require_non_empty_string if non_empty else require_string
    return validator(
        container[key],
        operation_name=_OPERATION_NAME,
        fact_path=fact_path,
    )


def _optional_integer(
    container: Mapping[str, Any],
    key: str,
    *,
    fact_path: str,
) -> int | None:
    """Return a strict optional integer without accepting booleans or strings."""

    if key not in container or container[key] is None:
        return None
    return require_integer(
        container[key],
        operation_name=_OPERATION_NAME,
        fact_path=fact_path,
    )


def _is_valid_protocol(protocol: str) -> bool:
    """Accept documented EC2 protocol names or a decimal IP protocol number."""

    folded = protocol.casefold()
    if folded in _NAMED_PROTOCOLS:
        return True
    return protocol.isascii() and protocol.isdigit() and 0 <= int(protocol) <= 255


def _validate_id_value(value: object, *, operation_name: str, fact_path: str) -> str:
    identifier = require_non_empty_string(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if "\x1f" in identifier or "\r" in identifier or "\n" in identifier:
        raise CollectorEvidenceError(operation_name, fact_path)
    return identifier


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
