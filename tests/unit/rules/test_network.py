"""Tests for public administrative-port security-group controls."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from app.rules.base import RuleEvaluationError, SecurityRule
from app.rules.network import PublicRDPRule, PublicSSHRule
from app.schemas.finding import ControlCategory, Severity
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
GROUP_ID = "sg-network-tests"
GROUP_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:security-group/{GROUP_ID}"
COLLECTED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

RuleFactory = Callable[[], SecurityRule]


def _security_group(
    *,
    ingress_rules: object = (),
    egress_rules: object = (),
    configuration: dict[str, Any] | None = None,
) -> NormalizedResource:
    resource_configuration = (
        configuration
        if configuration is not None
        else {
            "description": "network rule test fixture",
            "vpc_id": "vpc-network-tests",
            "ingress_rules": list(ingress_rules),
            "egress_rules": list(egress_rules),
        }
    )
    return NormalizedResource(
        account_id=ACCOUNT_ID,
        service="ec2",
        resource_type="security_group",
        aws_resource_id=GROUP_ID,
        arn=GROUP_ARN,
        name="administrative-access",
        scope=ResourceScope.REGIONAL,
        region=REGION,
        configuration=resource_configuration,
    )


def _snapshot(*resources: NormalizedResource) -> InventorySnapshot:
    return InventorySnapshot(
        account_id=ACCOUNT_ID,
        requested_region=REGION,
        collected_at=COLLECTED_AT,
        resources=resources,
    )


def _permission(
    *,
    protocol: object,
    from_port: object,
    to_port: object,
    ipv4_ranges: object = (),
    ipv6_ranges: object = (),
    prefix_lists: object = (),
    referenced_security_groups: object = (),
) -> dict[str, object]:
    return {
        "protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
        "ipv4_ranges": list(ipv4_ranges),
        "ipv6_ranges": list(ipv6_ranges),
        "prefix_lists": list(prefix_lists),
        "referenced_security_groups": list(referenced_security_groups),
    }


RULE_CASES: tuple[tuple[RuleFactory, int, str, str], ...] = (
    (PublicSSHRule, 22, "NET-001", "Public SSH Access"),
    (PublicRDPRule, 3389, "NET-002", "Public RDP Access"),
)


@pytest.mark.parametrize(
    ("rule_factory", "target_port", "control_id", "title"),
    RULE_CASES,
)
@pytest.mark.parametrize(
    ("range_key", "cidr"),
    (
        ("ipv4_ranges", "0.0.0.0/0"),
        ("ipv6_ranges", "::/0"),
    ),
)
@pytest.mark.parametrize(
    ("lower_offset", "upper_offset"),
    (
        (0, 0),
        (0, 10),
        (-10, 0),
        (-10, 10),
    ),
    ids=("exact", "lower-boundary", "upper-boundary", "inside-range"),
)
def test_detects_public_tcp_target_at_inclusive_range_boundaries(
    rule_factory: RuleFactory,
    target_port: int,
    control_id: str,
    title: str,
    range_key: str,
    cidr: str,
    lower_offset: int,
    upper_offset: int,
) -> None:
    from_port = target_port + lower_offset
    to_port = target_port + upper_offset
    ranges = [{"cidr": cidr, "description": "public administration"}]
    permission = _permission(
        protocol="TCP",
        from_port=from_port,
        to_port=to_port,
        **{range_key: ranges},
    )

    candidates = rule_factory().evaluate(_snapshot(_security_group(ingress_rules=[permission])))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.control_id == control_id
    assert candidate.title == title
    assert candidate.category is ControlCategory.NETWORK
    assert candidate.severity is Severity.HIGH
    assert candidate.account_id == ACCOUNT_ID
    assert candidate.service == "ec2"
    assert candidate.resource_type == "security_group"
    assert candidate.aws_resource_id == GROUP_ID
    assert candidate.arn == GROUP_ARN
    assert candidate.name == "administrative-access"
    assert candidate.scope is ResourceScope.REGIONAL
    assert candidate.region == REGION
    assert candidate.impact
    assert candidate.recommendation
    assert candidate.evidence == {
        "group_id": GROUP_ID,
        "vpc_id": "vpc-network-tests",
        "region": REGION,
        "target_port": target_port,
        "matched_ingress": [
            {
                "protocol": "tcp",
                "from_port": from_port,
                "to_port": to_port,
                "effective_port_coverage": f"{from_port}-{to_port}",
                "source_type": range_key.removesuffix("_ranges"),
                "cidr": cidr,
                "description": "public administration",
            }
        ],
    }


@pytest.mark.parametrize(
    ("rule_factory", "target_port", "control_id", "_title"),
    RULE_CASES,
)
@pytest.mark.parametrize(
    ("protocol", "from_port", "to_port"),
    (
        ("-1", None, None),
        ("-1", 65000, 65000),
        ("6", None, None),
        ("6", 65000, 65000),
    ),
    ids=("all-no-ports", "all-ignores-ports", "tcp-number-no-ports", "tcp-number-ignores-ports"),
)
def test_detects_protocols_that_effectively_include_all_tcp_ports(
    rule_factory: RuleFactory,
    target_port: int,
    control_id: str,
    _title: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
) -> None:
    permission = _permission(
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        ipv4_ranges=[{"cidr": "0.0.0.0/0", "description": None}],
    )

    candidates = rule_factory().evaluate(_snapshot(_security_group(ingress_rules=[permission])))

    assert len(candidates) == 1
    assert candidates[0].control_id == control_id
    assert candidates[0].evidence["target_port"] == target_port
    assert candidates[0].evidence["matched_ingress"] == [
        {
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "effective_port_coverage": "all_ports",
            "source_type": "ipv4",
            "cidr": "0.0.0.0/0",
            "description": None,
        }
    ]


@pytest.mark.parametrize(
    ("rule_factory", "target_port", "_control_id", "_title"),
    RULE_CASES,
)
def test_aggregates_deduplicates_and_deterministically_orders_public_matches(
    rule_factory: RuleFactory,
    target_port: int,
    _control_id: str,
    _title: str,
) -> None:
    ranged_permission = _permission(
        protocol="tcp",
        from_port=target_port - 1,
        to_port=target_port + 1,
        ipv4_ranges=[
            {"cidr": "10.0.0.0/8", "description": "private"},
            {"cidr": "0.0.0.0/0", "description": "duplicate"},
            {"cidr": "0.0.0.0/0", "description": "duplicate"},
        ],
        ipv6_ranges=[{"cidr": "::/0", "description": "public IPv6"}],
    )
    all_protocols_permission = _permission(
        protocol="-1",
        from_port=None,
        to_port=None,
        ipv4_ranges=[{"cidr": "0.0.0.0/0", "description": "all protocols"}],
    )
    first_resource = _security_group(ingress_rules=[all_protocols_permission, ranged_permission])
    second_resource = _security_group(
        ingress_rules=[
            {
                **ranged_permission,
                "ipv4_ranges": list(reversed(ranged_permission["ipv4_ranges"])),
                "ipv6_ranges": list(reversed(ranged_permission["ipv6_ranges"])),
            },
            all_protocols_permission,
        ]
    )
    first_before = first_resource.model_dump(mode="json")
    second_before = second_resource.model_dump(mode="json")

    first_candidates = rule_factory().evaluate(_snapshot(first_resource))
    second_candidates = rule_factory().evaluate(_snapshot(second_resource))

    assert len(first_candidates) == 1
    assert len(second_candidates) == 1
    assert first_candidates[0].model_dump(mode="json") == second_candidates[0].model_dump(
        mode="json"
    )
    assert len(first_candidates[0].evidence["matched_ingress"]) == 3
    assert {
        (
            match["protocol"],
            match["from_port"],
            match["to_port"],
            match["cidr"],
            match["source_type"],
        )
        for match in first_candidates[0].evidence["matched_ingress"]
    } == {
        ("-1", None, None, "0.0.0.0/0", "ipv4"),
        ("tcp", target_port - 1, target_port + 1, "0.0.0.0/0", "ipv4"),
        ("tcp", target_port - 1, target_port + 1, "::/0", "ipv6"),
    }
    assert first_resource.model_dump(mode="json") == first_before
    assert second_resource.model_dump(mode="json") == second_before


@pytest.mark.parametrize(
    ("rule_factory", "target_port", "_control_id", "_title"),
    RULE_CASES,
)
@pytest.mark.parametrize(
    ("ingress_rules", "egress_rules"),
    (
        (
            [
                _permission(
                    protocol="tcp",
                    from_port=22,
                    to_port=3389,
                    ipv4_ranges=[{"cidr": "10.0.0.0/8"}],
                    ipv6_ranges=[{"cidr": "2001:db8::/32"}],
                )
            ],
            [],
        ),
        (
            [
                _permission(
                    protocol="udp",
                    from_port=0,
                    to_port=65535,
                    ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                )
            ],
            [],
        ),
        (
            [
                _permission(
                    protocol="icmp",
                    from_port=22,
                    to_port=22,
                    ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                )
            ],
            [],
        ),
        (
            [
                _permission(
                    protocol="47",
                    from_port=None,
                    to_port=None,
                    ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                )
            ],
            [],
        ),
        (
            [
                _permission(
                    protocol="tcp",
                    from_port=23,
                    to_port=3388,
                    ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                )
            ],
            [],
        ),
        (
            [
                _permission(
                    protocol="tcp",
                    from_port=0,
                    to_port=65535,
                    ipv4_ranges=[{"cidr": "0.0.0.0/1"}],
                    ipv6_ranges=[{"cidr": "::/1"}],
                )
            ],
            [],
        ),
        (
            [
                _permission(
                    protocol="tcp",
                    from_port=0,
                    to_port=65535,
                    prefix_lists=[{"prefix_list_id": "pl-public-unknown"}],
                    referenced_security_groups=[{"group_id": "sg-source"}],
                )
            ],
            [],
        ),
        (
            [],
            [
                _permission(
                    protocol="tcp",
                    from_port=0,
                    to_port=65535,
                    ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                    ipv6_ranges=[{"cidr": "::/0"}],
                )
            ],
        ),
    ),
    ids=(
        "private-sources",
        "udp",
        "icmp",
        "unrelated-numeric-protocol",
        "adjacent-port-range",
        "broad-but-not-anywhere-cidrs",
        "unresolved-reference-sources",
        "public-egress-only",
    ),
)
def test_ignores_nonmatching_or_unproven_public_access(
    rule_factory: RuleFactory,
    target_port: int,
    _control_id: str,
    _title: str,
    ingress_rules: list[dict[str, object]],
    egress_rules: list[dict[str, object]],
) -> None:
    # Shift the generic adjacent range so it excludes the rule's own target.
    if ingress_rules and ingress_rules[0].get("from_port") == 23:
        ingress_rules = [
            {
                **ingress_rules[0],
                "from_port": target_port + 1,
                "to_port": target_port + 10,
            }
        ]

    candidates = rule_factory().evaluate(
        _snapshot(
            _security_group(
                ingress_rules=ingress_rules,
                egress_rules=egress_rules,
            )
        )
    )

    assert candidates == ()


@pytest.mark.parametrize(
    ("rule_factory", "_target_port", "_control_id", "_title"),
    RULE_CASES,
)
def test_ignores_resources_outside_the_security_group_contract(
    rule_factory: RuleFactory,
    _target_port: int,
    _control_id: str,
    _title: str,
) -> None:
    unrelated = NormalizedResource(
        account_id=ACCOUNT_ID,
        service="s3",
        resource_type="bucket",
        aws_resource_id="not-a-security-group",
        scope=ResourceScope.REGIONAL,
        region=REGION,
        configuration={"ingress_rules": "TOP-SECRET-MALFORMED-VALUE"},
    )

    assert rule_factory().evaluate(_snapshot(unrelated)) == ()


def _malformed_cases(target_port: int) -> tuple[tuple[dict[str, Any], str, str | None], ...]:
    return (
        ({}, "configuration.ingress_rules", None),
        (
            {"ingress_rules": "TOP-SECRET-NOT-A-LIST"},
            "configuration.ingress_rules",
            "TOP-SECRET-NOT-A-LIST",
        ),
        (
            {"ingress_rules": ["TOP-SECRET-NOT-A-RULE"]},
            "configuration.ingress_rules[0]",
            "TOP-SECRET-NOT-A-RULE",
        ),
        (
            {
                "ingress_rules": [
                    {
                        "from_port": target_port,
                        "to_port": target_port,
                        "ipv4_ranges": [{"cidr": "0.0.0.0/0"}],
                        "ipv6_ranges": [],
                    }
                ]
            },
            "configuration.ingress_rules[0].protocol",
            None,
        ),
        (
            {
                "ingress_rules": [
                    _permission(
                        protocol="tcp",
                        from_port="TOP-SECRET-START-PORT",
                        to_port=target_port,
                        ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                    )
                ]
            },
            "configuration.ingress_rules[0].from_port",
            "TOP-SECRET-START-PORT",
        ),
        (
            {
                "ingress_rules": [
                    _permission(
                        protocol="tcp",
                        from_port=target_port,
                        to_port="TOP-SECRET-END-PORT",
                        ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                    )
                ]
            },
            "configuration.ingress_rules[0].to_port",
            "TOP-SECRET-END-PORT",
        ),
        (
            {
                "ingress_rules": [
                    _permission(
                        protocol="tcp",
                        from_port=target_port + 1,
                        to_port=target_port,
                        ipv4_ranges=[{"cidr": "0.0.0.0/0"}],
                    )
                ]
            },
            "configuration.ingress_rules[0].port_range",
            None,
        ),
        (
            {
                "ingress_rules": [
                    {
                        **_permission(
                            protocol="tcp",
                            from_port=target_port,
                            to_port=target_port,
                        ),
                        "ipv4_ranges": "TOP-SECRET-NOT-RANGES",
                    }
                ]
            },
            "configuration.ingress_rules[0].ipv4_ranges",
            "TOP-SECRET-NOT-RANGES",
        ),
        (
            {
                "ingress_rules": [
                    _permission(
                        protocol="tcp",
                        from_port=target_port,
                        to_port=target_port,
                        ipv4_ranges=[{"cidr": "TOP-SECRET-MALFORMED-CIDR"}],
                    )
                ]
            },
            "configuration.ingress_rules[0].ipv4_ranges[0].cidr",
            "TOP-SECRET-MALFORMED-CIDR",
        ),
    )


@pytest.mark.parametrize(
    ("rule_factory", "target_port", "control_id", "_title"),
    RULE_CASES,
)
def test_reports_sanitized_errors_for_malformed_required_facts(
    rule_factory: RuleFactory,
    target_port: int,
    control_id: str,
    _title: str,
) -> None:
    for configuration, fact_path, malformed_value in _malformed_cases(target_port):
        resource = _security_group(configuration=configuration)

        with pytest.raises(RuleEvaluationError) as exc_info:
            rule_factory().evaluate(_snapshot(resource))

        message = str(exc_info.value)
        assert control_id in message
        assert GROUP_ID in message
        assert fact_path in message
        if malformed_value is not None:
            assert malformed_value not in message
