"""Tests for EC2 security group collection."""

import pytest
from botocore.exceptions import ClientError

from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.resource import ResourceScope
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error


def test_collects_all_pages_and_normalizes_security_group_rules() -> None:
    paginator = FakePaginator(
        [
            {
                "SecurityGroups": [
                    {
                        "Description": "administrative access",
                        "GroupId": "sg-0123456789abcdef0",
                        "GroupName": "admin",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "IpProtocol": "tcp",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "IPv4 source"}],
                                "Ipv6Ranges": [{"CidrIpv6": "::/0", "Description": "IPv6 source"}],
                                "PrefixListIds": [
                                    {
                                        "PrefixListId": "pl-0123456789abcdef0",
                                        "Description": "managed network",
                                    }
                                ],
                                "ToPort": 22,
                                "UserIdGroupPairs": [
                                    {
                                        "Description": "application tier",
                                        "GroupId": "sg-0fedcba9876543210",
                                        "GroupName": "application",
                                        "PeeringStatus": "active",
                                        "UserId": "210987654321",
                                        "VpcId": "vpc-0123456789abcdef0",
                                        "VpcPeeringConnectionId": "pcx-0123456789abcdef0",
                                    }
                                ],
                            }
                        ],
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "-1",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                        "OwnerId": "123456789012",
                        "Tags": [
                            {"Key": "Owner", "Value": "security"},
                            {"Key": "EmptyValue"},
                        ],
                        "VpcId": "vpc-0123456789abcdef0",
                    }
                ]
            },
            {
                "SecurityGroups": [
                    {
                        "Description": "default group",
                        "GroupId": "sg-11111111111111111",
                        "GroupName": "default",
                        "IpPermissions": [],
                        "IpPermissionsEgress": [],
                        "OwnerId": "123456789012",
                    }
                ]
            },
        ]
    )
    client = FakeAWSClient(paginators={"describe_security_groups": paginator})
    provider = FakeClientProvider(
        {("ec2", "us-gov-west-1"): client},
        region_name="us-gov-west-1",
        partition="aws-us-gov",
    )

    resources = SecurityGroupCollector(provider).collect()

    assert len(resources) == 2
    assert paginator.calls == [{}]
    assert resources[0].arn == (
        "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:security-group/sg-0123456789abcdef0"
    )
    assert resources[0].scope is ResourceScope.REGIONAL
    assert resources[0].region == "us-gov-west-1"
    assert resources[0].tags == {"Owner": "security", "EmptyValue": ""}

    ingress = resources[0].configuration["ingress_rules"][0]
    assert ingress == {
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": "IPv4 source"}],
        "ipv6_ranges": [{"cidr": "::/0", "description": "IPv6 source"}],
        "prefix_lists": [
            {
                "prefix_list_id": "pl-0123456789abcdef0",
                "description": "managed network",
            }
        ],
        "referenced_security_groups": [
            {
                "group_id": "sg-0fedcba9876543210",
                "group_name": "application",
                "user_id": "210987654321",
                "vpc_id": "vpc-0123456789abcdef0",
                "vpc_peering_connection_id": "pcx-0123456789abcdef0",
                "peering_status": "active",
                "description": "application tier",
            }
        ],
    }
    egress = resources[0].configuration["egress_rules"][0]
    assert egress["protocol"] == "-1"
    assert egress["from_port"] is None
    assert egress["to_port"] is None
    assert resources[1].tags == {}


def test_propagates_security_group_listing_errors() -> None:
    error = client_error("UnauthorizedOperation", "DescribeSecurityGroups", status_code=403)
    paginator = FakePaginator(error=error)
    client = FakeAWSClient(paginators={"describe_security_groups": paginator})
    provider = FakeClientProvider({("ec2", "us-east-1"): client})

    with pytest.raises(ClientError) as exc_info:
        SecurityGroupCollector(provider).collect()

    assert exc_info.value.response["Error"]["Code"] == "UnauthorizedOperation"
