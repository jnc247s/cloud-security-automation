"""Offline 6F.1 fixtures through the unchanged real CloudTrail collection/scan path."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.ec2_fixtures import OBSERVED
from tests.fakes import FakeAWSClient, FakePaginator
from tests.foundation_fixtures import extended_profile
from tests.integration.test_persistence_postgres import _empty_provider
from tests.unit.collectors.test_cloudtrail import _trail

ACCOUNT = "123456789012"


def logging_profile(**updates):
    return extended_profile(
        **{
            "version": "6.8.1",
            "enabled_controls": ("LOG-002", "LOG-003"),
            **updates,
        }
    )


def cloudtrail_provider(
    region="us-east-1", *, specs=None, empty=False, discovery_error=None, tag_error=None
):
    provider = _empty_provider(region)
    specs = [{"multi": False, "validation": False}] if specs is None else specs
    specs = [] if empty else specs
    records = []
    for index, spec in enumerate(specs):
        name = spec.get("name", f"CoverageTrail{index}")
        home = spec.get("home", region)
        owner = spec.get("owner", ACCOUNT)
        arn = f"arn:aws:cloudtrail:{home}:{owner}:trail/{name}"
        records.append((arn, name, home, spec))
    records.sort()
    summaries = [
        {"TrailARN": arn, "Name": name, "HomeRegion": home} for arn, name, home, _ in records
    ]
    for home in sorted({region, *(record[2] for record in records)}):
        selected = [r for r in records if r[2] == home]
        configurations, statuses, selectors = [], [], []
        tags = []
        for arn, name, _, spec in selected:
            config = _trail(arn, name, home, multi_region=spec.get("multi", True))
            config.update(
                IsOrganizationTrail=spec.get("organization", False),
                LogFileValidationEnabled=spec.get("validation", True),
            )
            config.update(spec.get("configuration_updates", {}))
            for key in spec.get("omit", ()):
                config.pop(key)
            configurations.append(spec.get("configuration_error") or {"Trail": config})
            statuses.append(spec.get("status_error") or {"IsLogging": spec.get("logging", True)})
            selector = {"TrailARN": arn, "EventSelectors": spec.get("basic", [{}])}
            if "advanced" in spec:
                selector = {"TrailARN": arn, "AdvancedEventSelectors": spec["advanced"]}
            selectors.append(
                spec.get("selector_response") or spec.get("selector_error") or selector
            )
            tags.append({"ResourceId": arn, "TagsList": []})
        paginators = {"list_tags": FakePaginator([{"ResourceTagList": tags}], error=tag_error)}
        if home == region:
            paginators["list_trails"] = FakePaginator(
                [{"Trails": summaries}], error=discovery_error
            )
        provider._clients[("cloudtrail", home)] = FakeAWSClient(
            paginators=paginators,
            responses={
                "get_trail": configurations,
                "get_trail_status": statuses,
                "get_event_selectors": selectors,
            },
        )
    return provider


def logging_bundle(*, profile=None, observed=OBSERVED, provider=None, **options):
    provider = provider or cloudtrail_provider(**options)
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(provider).collect(scan_id=uuid4())
    profile = profile or logging_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.11.0")
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        scope=_scope_for(snapshot, profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        started_at=observed - timedelta(seconds=1),
        completed_at=observed + timedelta(seconds=1),
        scanner_version="6f1-test",
    )


def results(bundle):
    return {a.control_id: a.result for a in bundle["assessments"]}
