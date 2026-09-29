"""Offline 6E.1 input through the unchanged production S3 collectors."""

from collections import deque
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.ec2_fixtures import OBSERVED
from tests.fakes import FakeAWSClient, FakePaginator, client_error, empty_access_analyzer_client
from tests.foundation_fixtures import extended_profile
from tests.integration.test_persistence_postgres import _empty_provider
from tests.unit.collectors.test_s3 import _complete_5e_s3_client

BUCKET = "offline-configuration-bucket"
FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def block(value):
    return {"PublicAccessBlockConfiguration": dict.fromkeys(FLAGS, value)}


def s3_profile(**updates):
    return extended_profile(
        **{"version": "6.5.1", "enabled_controls": ("S3-001", "S3-003"), **updates}
    )


def s3_provider(region="us-east-1", *, account=None, empty=False, discovery_error=None, **options):
    provider = _empty_provider(region)
    client = _complete_5e_s3_client(bucket_name=BUCKET, **options)
    if empty or discovery_error:
        client._paginators["list_buckets"] = deque(
            [FakePaginator([{"Buckets": []}], error=discovery_error)]
        )
    provider._clients[("s3", "us-east-1")] = client
    provider._clients[("s3", "eu-west-1")] = client
    provider._clients[("accessanalyzer", "eu-west-1")] = empty_access_analyzer_client()
    provider._clients[("s3control", region)] = FakeAWSClient(
        responses={"get_public_access_block": [account if account is not None else block(True)]}
    )
    return provider


def failing_provider(region="us-east-1"):
    return s3_provider(
        region,
        account=block(False),
        public_access_block_response=block(False),
        policy_response=client_error("NoSuchBucketPolicy", "GetBucketPolicy"),
    )


def s3_bundle(*, profile=None, observed=OBSERVED, provider=None, **options):
    provider = provider or s3_provider(**options)
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(provider).collect(scan_id=uuid4())
    profile = profile or s3_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.8.0")
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        scope=_scope_for(snapshot, profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        started_at=observed - timedelta(seconds=1),
        completed_at=observed + timedelta(seconds=1),
        scanner_version="6e1-test",
    )
