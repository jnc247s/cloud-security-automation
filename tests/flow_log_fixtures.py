"""NET-006 explicit policy and offline inputs through the existing production collectors."""

from datetime import timedelta

from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.scan_executor import _scope_for
from tests.foundation_fixtures import extended_profile
from tests.network_control_fixtures import network_snapshot


def flow_profile(**updates):
    return extended_profile(
        **{
            "version": "6.4.2",
            "enabled_controls": ("NET-006",),
            "vpc_flow_log_required_environments": ("production",),
            "acceptable_vpc_flow_log_traffic_types": ("REJECT", "ALL"),
            **updates,
        }
    )


def flow_bundle(*, profile=None, snapshot=None, **options):
    snapshot = snapshot or network_snapshot(**options)
    profile = profile or flow_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.7.0")
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
        "scanner_version": "6d2-test",
    }
