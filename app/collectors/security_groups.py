"""EC2 security group resource collection."""

from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any

from app.collectors.base import (
    CollectorEvidenceError,
    ResourceCollector,
    iter_paginated_items,
    require_integer,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    should_skip_exact_duplicate,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_OPERATION_NAME = "describe_security_groups"
_NAMED_PROTOCOLS = {"-1", "tcp", "udp", "icmp", "icmpv6"}


class SecurityGroupCollector(ResourceCollector):
    """Collect regional security groups and normalize their network-rule facts."""

    collector_name = "security_groups"

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
            group_id = require_non_empty_string(
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

            region = self.client_provider.region_name
            account_id = self.client_provider.account_id
            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="ec2",
                    resource_type="security_group",
                    aws_resource_id=group_id,
                    arn=(
                        f"arn:{self.client_provider.partition}:ec2:{region}:"
                        f"{account_id}:security-group/{group_id}"
                    ),
                    name=_optional_string(
                        security_group,
                        "GroupName",
                        fact_path=f"{group_path}.GroupName",
                        non_empty=True,
                    ),
                    scope=ResourceScope.REGIONAL,
                    region=region,
                    tags=_normalize_tags(security_group, group_path),
                    configuration={
                        "description": _optional_string(
                            security_group,
                            "Description",
                            fact_path=f"{group_path}.Description",
                        ),
                        "vpc_id": _optional_string(
                            security_group,
                            "VpcId",
                            fact_path=f"{group_path}.VpcId",
                            non_empty=True,
                        ),
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
                    },
                    raw_configuration=to_json_safe(security_group),
                )
            )

        return resources


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
