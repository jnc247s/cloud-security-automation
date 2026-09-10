"""Tests for EC2 security group collection."""

import pytest
from botocore.exceptions import ClientError

from app.collectors.base import CollectorEvidenceError
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


def test_preserves_missing_ingress_or_cidr_lists_as_unknown_evidence() -> None:
    paginator = FakePaginator(
        [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-missing-ingress",
                        "IpPermissionsEgress": [],
                    },
                    {
                        "GroupId": "sg-missing-ranges",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "Ipv6Ranges": [],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    },
                ]
            }
        ]
    )
    client = FakeAWSClient(paginators={"describe_security_groups": paginator})
    resources = SecurityGroupCollector(FakeClientProvider({("ec2", "us-east-1"): client})).collect()

    assert resources[0].configuration["ingress_rules"] is None
    assert resources[1].configuration["ingress_rules"][0]["ipv4_ranges"] is None


def _security_group(**overrides: object) -> dict[str, object]:
    group: dict[str, object] = {
        "GroupId": "sg-boundary",
        "GroupName": "boundary",
        "Description": "boundary fixture",
        "VpcId": "vpc-boundary",
        "IpPermissions": [],
        "IpPermissionsEgress": [],
    }
    group.update(overrides)
    return group


def _collect_pages(pages: list[object]) -> list[object]:
    client = FakeAWSClient(
        paginators={"describe_security_groups": FakePaginator(pages)},
    )
    provider = FakeClientProvider({("ec2", "us-east-1"): client})
    return SecurityGroupCollector(provider).collect()


@pytest.mark.parametrize(
    ("present", "value"),
    (
        (False, None),
        (True, None),
        (True, 123),
        (True, ""),
        (True, "   "),
    ),
)
def test_rejects_missing_null_or_malformed_group_identity(
    present: bool,
    value: object,
) -> None:
    group = _security_group()
    if present:
        group["GroupId"] = value
    else:
        group.pop("GroupId")

    with pytest.raises(CollectorEvidenceError, match=r"GroupId$") as exc_info:
        _collect_pages([{"SecurityGroups": [group]}])

    assert "None" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("GroupName", 123),
        ("GroupName", ""),
        ("Description", False),
        ("VpcId", []),
        ("VpcId", " "),
    ),
)
def test_rejects_malformed_optional_group_strings(field_name: str, value: object) -> None:
    group = _security_group(**{field_name: value})

    with pytest.raises(CollectorEvidenceError, match=field_name):
        _collect_pages([{"SecurityGroups": [group]}])


def test_preserves_absent_or_null_optional_group_strings() -> None:
    group = _security_group(GroupName=None, Description=None, VpcId=None)

    resource = _collect_pages([{"SecurityGroups": [group]}])[0]

    assert resource.name is None
    assert resource.configuration["description"] is None
    assert resource.configuration["vpc_id"] is None


@pytest.mark.parametrize(
    "tags",
    (
        None,
        "not-a-list",
        ["not-an-object"],
        [{}],
        [{"Key": None, "Value": "security"}],
        [{"Key": "", "Value": "security"}],
        [{"Key": "Owner", "Value": None}],
        [{"Key": "Owner", "Value": 123}],
    ),
)
def test_rejects_malformed_present_tags(tags: object) -> None:
    group = _security_group(Tags=tags)

    with pytest.raises(CollectorEvidenceError, match="Tags"):
        _collect_pages([{"SecurityGroups": [group]}])


def test_accepts_absent_tags_and_missing_ec2_tag_value() -> None:
    untagged = _security_group(GroupId="sg-untagged")
    missing_value = _security_group(
        GroupId="sg-empty-tag-value",
        Tags=[{"Key": "Owner"}],
    )

    resources = _collect_pages([{"SecurityGroups": [untagged, missing_value]}])

    assert resources[0].tags == {}
    assert resources[1].tags == {"Owner": ""}


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("IpPermissions", None),
        ("IpPermissions", {}),
        ("IpPermissions", "not-a-list"),
        ("IpPermissionsEgress", None),
        ("IpPermissionsEgress", {}),
    ),
)
def test_rejects_malformed_present_permission_lists(field_name: str, value: object) -> None:
    group = _security_group(**{field_name: value})

    with pytest.raises(CollectorEvidenceError, match=field_name):
        _collect_pages([{"SecurityGroups": [group]}])


@pytest.mark.parametrize("permission", (None, "not-an-object", 123))
def test_rejects_non_mapping_permission_items(permission: object) -> None:
    group = _security_group(IpPermissions=[permission])

    with pytest.raises(CollectorEvidenceError, match="IpPermissions"):
        _collect_pages([{"SecurityGroups": [group]}])


@pytest.mark.parametrize(
    ("present", "protocol"),
    (
        (False, None),
        (True, None),
        (True, 6),
        (True, ""),
        (True, "gre"),
        (True, "-2"),
        (True, "256"),
    ),
)
def test_rejects_missing_or_unsupported_ip_protocol(
    present: bool,
    protocol: object,
) -> None:
    permission: dict[str, object] = {}
    if present:
        permission["IpProtocol"] = protocol
    group = _security_group(IpPermissions=[permission])

    with pytest.raises(CollectorEvidenceError, match="IpProtocol"):
        _collect_pages([{"SecurityGroups": [group]}])


@pytest.mark.parametrize(
    "protocol",
    ("-1", "tcp", "udp", "icmp", "icmpv6", "0", "6", "255", "TCP"),
)
def test_accepts_documented_named_and_numeric_ip_protocols(protocol: str) -> None:
    group = _security_group(IpPermissions=[{"IpProtocol": protocol}])

    resource = _collect_pages([{"SecurityGroups": [group]}])[0]

    assert resource.configuration["ingress_rules"][0]["protocol"] == protocol


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("FromPort", True),
        ("FromPort", "22"),
        ("ToPort", False),
        ("ToPort", 22.0),
    ),
)
def test_rejects_non_integer_present_ports(field_name: str, value: object) -> None:
    permission = {"IpProtocol": "tcp", field_name: value}
    group = _security_group(IpPermissions=[permission])

    with pytest.raises(CollectorEvidenceError, match=field_name):
        _collect_pages([{"SecurityGroups": [group]}])


def test_allows_absent_or_null_optional_ports() -> None:
    group = _security_group(IpPermissions=[{"IpProtocol": "-1", "FromPort": None, "ToPort": None}])

    permission = _collect_pages([{"SecurityGroups": [group]}])[0].configuration["ingress_rules"][0]

    assert permission["from_port"] is None
    assert permission["to_port"] is None


@pytest.mark.parametrize(
    ("field_name", "cidr_key", "value"),
    (
        ("IpRanges", "CidrIp", None),
        ("IpRanges", "CidrIp", {}),
        ("IpRanges", "CidrIp", ["not-an-object"]),
        ("IpRanges", "CidrIp", [{}]),
        ("IpRanges", "CidrIp", [{"CidrIp": None}]),
        ("IpRanges", "CidrIp", [{"CidrIp": "not-a-cidr"}]),
        ("IpRanges", "CidrIp", [{"CidrIp": "192.0.2.1"}]),
        ("IpRanges", "CidrIp", [{"CidrIp": "::/0"}]),
        ("Ipv6Ranges", "CidrIpv6", [{"CidrIpv6": "0.0.0.0/0"}]),
        ("Ipv6Ranges", "CidrIpv6", [{"CidrIpv6": "::/129"}]),
    ),
)
def test_rejects_malformed_or_wrong_family_ip_ranges(
    field_name: str,
    cidr_key: str,
    value: object,
) -> None:
    permission = {"IpProtocol": "tcp", field_name: value}
    group = _security_group(IpPermissions=[permission])

    with pytest.raises(CollectorEvidenceError, match=field_name) as error_info:
        _collect_pages([{"SecurityGroups": [group]}])

    if isinstance(value, list) and value and isinstance(value[0], dict):
        assert cidr_key in str(error_info.value)


@pytest.mark.parametrize(
    ("field_name", "cidr_key", "cidr"),
    (
        ("IpRanges", "CidrIp", "0.0.0.0/0"),
        ("IpRanges", "CidrIp", "192.0.2.0/24"),
        ("Ipv6Ranges", "CidrIpv6", "::/0"),
        ("Ipv6Ranges", "CidrIpv6", "2001:db8::/32"),
    ),
)
def test_accepts_valid_ip_ranges(field_name: str, cidr_key: str, cidr: str) -> None:
    permission = {"IpProtocol": "tcp", field_name: [{cidr_key: cidr}]}
    group = _security_group(IpPermissions=[permission])

    normalized = _collect_pages([{"SecurityGroups": [group]}])[0].configuration["ingress_rules"][0]

    normalized_name = "ipv4_ranges" if field_name == "IpRanges" else "ipv6_ranges"
    assert normalized[normalized_name] == [{"cidr": cidr, "description": None}]


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("PrefixListIds", None),
        ("PrefixListIds", {}),
        ("PrefixListIds", ["not-an-object"]),
        ("PrefixListIds", [{}]),
        ("PrefixListIds", [{"PrefixListId": None}]),
        ("PrefixListIds", [{"PrefixListId": ""}]),
        ("PrefixListIds", [{"PrefixListId": "pl-123", "Description": 123}]),
        ("UserIdGroupPairs", None),
        ("UserIdGroupPairs", {}),
        ("UserIdGroupPairs", ["not-an-object"]),
        ("UserIdGroupPairs", [{}]),
        ("UserIdGroupPairs", [{"GroupId": None}]),
        ("UserIdGroupPairs", [{"GroupId": ""}]),
        ("UserIdGroupPairs", [{"GroupId": "sg-peer", "UserId": 123}]),
    ),
)
def test_rejects_malformed_prefix_list_or_group_sources(
    field_name: str,
    value: object,
) -> None:
    permission = {"IpProtocol": "tcp", field_name: value}
    group = _security_group(IpPermissions=[permission])

    with pytest.raises(CollectorEvidenceError, match=field_name):
        _collect_pages([{"SecurityGroups": [group]}])


def test_absent_optional_permission_sources_are_known_empty() -> None:
    group = _security_group(IpPermissions=[{"IpProtocol": "tcp"}])

    permission = _collect_pages([{"SecurityGroups": [group]}])[0].configuration["ingress_rules"][0]

    assert permission["prefix_lists"] == []
    assert permission["referenced_security_groups"] == []
    assert permission["ipv4_ranges"] is None
    assert permission["ipv6_ranges"] is None


def test_skips_exact_duplicate_group_across_pages() -> None:
    group = _security_group()

    resources = _collect_pages(
        [
            {"SecurityGroups": [group]},
            {"SecurityGroups": [group]},
        ]
    )

    assert [resource.aws_resource_id for resource in resources] == ["sg-boundary"]


def test_rejects_conflicting_duplicate_group_identity() -> None:
    first = _security_group(Description="first observation")
    second = _security_group(Description="conflicting observation")

    with pytest.raises(CollectorEvidenceError, match="GroupId"):
        _collect_pages(
            [
                {"SecurityGroups": [first]},
                {"SecurityGroups": [second]},
            ]
        )


def test_continues_after_empty_intermediate_page() -> None:
    resources = _collect_pages(
        [
            {"SecurityGroups": [_security_group(GroupId="sg-first")]},
            {"SecurityGroups": []},
            {"SecurityGroups": [_security_group(GroupId="sg-second")]},
        ]
    )

    assert [resource.aws_resource_id for resource in resources] == ["sg-first", "sg-second"]


def test_valid_empty_security_group_inventory_succeeds() -> None:
    assert _collect_pages([{"SecurityGroups": []}]) == []


@pytest.mark.parametrize(
    "error_code",
    ("UnauthorizedOperation", "RequestLimitExceeded"),
)
def test_propagates_access_and_throttling_errors(error_code: str) -> None:
    error = client_error(error_code, "DescribeSecurityGroups", status_code=403)
    client = FakeAWSClient(paginators={"describe_security_groups": FakePaginator(error=error)})
    provider = FakeClientProvider({("ec2", "us-east-1"): client})

    with pytest.raises(ClientError) as exc_info:
        SecurityGroupCollector(provider).collect()

    assert exc_info.value.response["Error"]["Code"] == error_code
