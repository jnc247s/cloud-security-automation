"""Offline AWS responses through all unchanged real collectors for the 11 taggable families."""

from collections import deque
from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.assessment.extended_profiles import GOVERNED_RESOURCE_TYPES
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.cloudtrail_destination_fixtures import destination_provider
from tests.ec2_fixtures import OBSERVED, ec2_client
from tests.fakes import FakePaginator
from tests.foundation_fixtures import extended_profile
from tests.iam_policy_fixtures import policy_client
from tests.integration.test_persistence_postgres import _empty_provider
from tests.network_control_fixtures import network_client
from tests.unit.collectors.test_network import _flow_log, _subnet

DEFAULT_TAGS = {"Owner": "platform", "Environment": "production"}


def governance_profile(**updates):
    return extended_profile(
        **{
            "version": "6.10.0",
            "enabled_controls": ("GOV-001",),
            "required_tags": ("Owner", "Environment"),
            "governed_resource_types": tuple(sorted(GOVERNED_RESOURCE_TYPES)),
            **updates,
        }
    )


def governance_provider(
    region="us-east-1",
    *,
    tags=None,
    empty=False,
    error_operation=None,
    instance_count=1,
    empty_family=None,
):
    if empty:
        provider = _empty_provider(region)
    else:
        provider = destination_provider(region)
        ec2 = ec2_client()
        log = _flow_log()
        log["LogDestination"] = f"arn:aws:logs:{region}:123456789012:log-group:/aws/vpc/flow-logs"
        log["DeliverLogsPermissionArn"] = "arn:aws:iam::123456789012:role/vpc-flow-logs"
        network = network_client(flow_logs=[log])
        subnet = _subnet()
        subnet["AvailabilityZone"] = f"{region}a"
        subnet["AvailabilityZoneId"] = "use1-az1"
        network._paginators["describe_subnets"] = deque([FakePaginator([{"Subnets": [subnet]}])])
        ec2._paginators.update(network._paginators)
        provider._clients[("ec2", region)] = ec2
        provider._clients[("iam", region)] = policy_client()

        def aws_tags(kind):
            value = (tags or {}).get(kind, DEFAULT_TAGS)
            return (
                [{"Key": k, "Value": v} for k, v in value.items()]
                if isinstance(value, dict)
                else value
            )

        for operation, field, kind in (
            ("describe_volumes", "Volumes", "ebs_volume"),
            ("describe_vpcs", "Vpcs", "vpc"),
            ("describe_subnets", "Subnets", "subnet"),
            ("describe_flow_logs", "FlowLogs", "vpc_flow_log"),
            ("describe_security_groups", "SecurityGroups", "security_group"),
        ):
            for item in ec2._paginators[operation][0].pages[0][field]:
                item["Tags"] = aws_tags(kind)
        instances = ec2._paginators["describe_instances"][0].pages[0]["Reservations"][0][
            "Instances"
        ]
        instances[0]["Tags"] = aws_tags("ec2_instance")
        for index in range(1, instance_count):
            instance = deepcopy(instances[0])
            instance["InstanceId"] = f"i-{index:017x}"
            instances.append(instance)
        iam = provider._clients[("iam", region)]
        for operation, kind in (
            ("list_user_tags", "iam_user"),
            ("list_role_tags", "iam_role"),
            ("list_policy_tags", "iam_customer_managed_policy"),
        ):
            iam._paginators[operation][0].pages[0]["Tags"] = aws_tags(kind)
        provider._clients[("s3", region)]._responses["get_bucket_tagging"] = deque(
            [{"TagSet": aws_tags("s3_bucket")}]
        )
        for record in (
            provider._clients[("cloudtrail", region)]
            ._paginators["list_tags"][0]
            .pages[0]["ResourceTagList"]
        ):
            record["TagsList"] = aws_tags("cloudtrail_trail")
        if empty_family == "s3_bucket":
            provider._clients[("s3", region)]._paginators["list_buckets"][0].pages[0][
                "Buckets"
            ] = []
        elif empty_family == "ec2_instance":
            instances.clear()
        elif empty_family is not None:
            raise ValueError("unsupported fixture empty family")
    if error_operation:
        from tests.fakes import client_error

        service, operation = error_operation
        client = provider._clients[(service, region)]
        error = client_error("AccessDenied", operation)
        if operation in client._paginators:
            client._paginators[operation][0].error = error
        else:
            client._responses[operation][0] = error
    return provider


def governance_bundle(*, snapshot=None, profile=None, observed=OBSERVED, provider=None, **options):
    if snapshot is None:
        with patch("app.services.inventory_service.datetime") as clock:
            clock.now.return_value = observed
            snapshot = InventoryService(provider or governance_provider(**options)).collect(
                scan_id=uuid4()
            )
    profile = profile or governance_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.13.0")
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        scope=_scope_for(snapshot, profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        started_at=snapshot.collected_at - timedelta(seconds=1),
        completed_at=snapshot.collected_at + timedelta(seconds=1),
        scanner_version="6g-test",
    )
