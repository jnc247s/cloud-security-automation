"""Offline AWS inputs using the real security-group/network collectors and graph assembly."""

from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.assessment.security_group_evidence import NETWORK_CONTROL_IDS
from app.collectors.network import VPCNetworkCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.ec2_fixtures import ACCOUNT, OBSERVED
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator
from tests.foundation_fixtures import extended_profile
from tests.unit.collectors.test_network import _vpc
from tests.unit.collectors.test_security_group_evidence import _security_group


def network_profile(**updates):
    return extended_profile(
        **{
            "version": "6.4.0",
            "enabled_controls": NETWORK_CONTROL_IDS,
            "high_risk_public_tcp_ports": (3306, 5432, 6379, 9200, 27017),
            **updates,
        }
    )


def permission(protocol="-1", first=None, last=None, *, ipv4="0.0.0.0/0", ipv6=None):
    rule = {
        "IpProtocol": protocol,
        "IpRanges": [] if ipv4 is None else [{"CidrIp": ipv4}],
        "Ipv6Ranges": [] if ipv6 is None else [{"CidrIpv6": ipv6}],
        "PrefixListIds": [],
        "UserIdGroupPairs": [],
    }
    if first is not None:
        rule["FromPort"] = first
    if last is not None:
        rule["ToPort"] = last
    return rule


def network_client(
    *,
    groups=None,
    vpcs=None,
    flow_logs=None,
    group_error=None,
    vpc_error=None,
    subnet_error=None,
    flow_error=None,
):
    if groups is None:
        group = _security_group()
        group["IpPermissions"] = [permission()]
        groups = [group]
    groups = deepcopy(groups)
    for group in groups:
        # The reused fixture's optional ARN is GovCloud-specific; the real collector
        # constructs the canonical ARN from the requested partition/Region and OwnerId.
        group.pop("SecurityGroupArn", None)
    return FakeAWSClient(
        paginators={
            "describe_security_groups": FakePaginator(
                [{"SecurityGroups": groups}], error=group_error
            ),
            "describe_vpcs": FakePaginator(
                [{"Vpcs": [_vpc()] if vpcs is None else vpcs}], error=vpc_error
            ),
            "describe_subnets": FakePaginator([{"Subnets": []}], error=subnet_error),
            "describe_flow_logs": FakePaginator([{"FlowLogs": flow_logs or []}], error=flow_error),
        }
    )


def network_snapshot(*, region="us-east-1", account=ACCOUNT, observed=OBSERVED, **options):
    provider = FakeClientProvider(
        {("ec2", region): network_client(**options)}, region_name=region, account_id=account
    )
    service = InventoryService(
        provider, collectors=(SecurityGroupCollector(provider), VPCNetworkCollector(provider))
    )
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        return service.collect(scan_id=uuid4())


def network_bundle(*, profile=None, snapshot=None, **options):
    snapshot = snapshot or network_snapshot(**options)
    profile = profile or network_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.6.0")
    return {
        "snapshot": snapshot,
        "profile": profile,
        "catalog": catalog,
        "scope": _scope_for(
            snapshot,
            profile,
            catalog,
            requested_services=("ec2",),
            requested_collectors=("security_groups", "vpc_network_evidence"),
            resource_types=("security_group", "vpc", "subnet", "vpc_flow_log", "aws_account"),
        ),
        "assessments": RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        "started_at": snapshot.collected_at - timedelta(seconds=1),
        "completed_at": snapshot.collected_at + timedelta(seconds=1),
        "scanner_version": "6d1-test",
    }
