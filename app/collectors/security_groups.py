"""EC2 security group resource collection."""

from typing import Any

from app.collectors.base import (
    ResourceCollector,
    iter_paginated_items,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope


class SecurityGroupCollector(ResourceCollector):
    """Collect regional security groups and normalize their network-rule facts."""

    collector_name = "security_groups"

    def collect(self) -> list[NormalizedResource]:
        client = self.client_provider.client("ec2")
        resources: list[NormalizedResource] = []

        for security_group in iter_paginated_items(
            client,
            "describe_security_groups",
            "SecurityGroups",
        ):
            group_id = str(security_group["GroupId"])
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
                    name=security_group.get("GroupName"),
                    scope=ResourceScope.REGIONAL,
                    region=region,
                    tags=tags_to_dict(security_group.get("Tags", [])),
                    configuration={
                        "description": security_group.get("Description"),
                        "vpc_id": security_group.get("VpcId"),
                        "ingress_rules": [
                            _normalize_permission(permission)
                            for permission in security_group.get("IpPermissions", [])
                        ],
                        "egress_rules": [
                            _normalize_permission(permission)
                            for permission in security_group.get("IpPermissionsEgress", [])
                        ],
                    },
                    raw_configuration=to_json_safe(security_group),
                )
            )

        return resources


def _normalize_permission(permission: dict[str, Any]) -> dict[str, Any]:
    """Normalize one EC2 IP permission without evaluating whether it is secure."""

    return {
        "protocol": permission.get("IpProtocol"),
        "from_port": permission.get("FromPort"),
        "to_port": permission.get("ToPort"),
        "ipv4_ranges": [
            {
                "cidr": item.get("CidrIp"),
                "description": item.get("Description"),
            }
            for item in permission.get("IpRanges", [])
        ],
        "ipv6_ranges": [
            {
                "cidr": item.get("CidrIpv6"),
                "description": item.get("Description"),
            }
            for item in permission.get("Ipv6Ranges", [])
        ],
        "prefix_lists": [
            {
                "prefix_list_id": item.get("PrefixListId"),
                "description": item.get("Description"),
            }
            for item in permission.get("PrefixListIds", [])
        ],
        "referenced_security_groups": [
            {
                "group_id": item.get("GroupId"),
                "group_name": item.get("GroupName"),
                "user_id": item.get("UserId"),
                "vpc_id": item.get("VpcId"),
                "vpc_peering_connection_id": item.get("VpcPeeringConnectionId"),
                "peering_status": item.get("PeeringStatus"),
                "description": item.get("Description"),
            }
            for item in permission.get("UserIdGroupPairs", [])
        ],
    }
