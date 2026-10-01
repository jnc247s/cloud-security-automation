"""Offline joined 6F.2 input through the real unchanged collection path."""

from collections import defaultdict
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.cloudtrail_fixtures import cloudtrail_provider
from tests.ec2_fixtures import OBSERVED
from tests.fakes import FakeAWSClient, FakePaginator, client_error
from tests.s3_configuration_fixtures import BUCKET, block
from tests.s3_exposure_fixtures import (
    exposure_profile,
    exposure_provider,
    policy_response,
    statement,
)
from tests.unit.collectors.test_s3 import _complete_5e_s3_client

PRIVATE_BUCKET = "offline-private-log-bucket"


def destination_profile(**updates):
    return exposure_profile(
        **{"version": "6.9.1", "enabled_controls": ("LOG-004", "S3-002"), **updates}
    )


def destination_provider(region="us-east-1", *, specs=None, trail_options=None, **s3_options):
    provider = exposure_provider(region, **s3_options)
    specs = [{"configuration_updates": {"S3BucketName": BUCKET}}] if specs is None else specs
    trails = cloudtrail_provider(region, specs=specs, **(trail_options or {}))
    provider._clients.update(
        {key: value for key, value in trails._clients.items() if key[0] == "cloudtrail"}
    )
    return provider


def mixed_destination_provider():
    """Two real buckets, mixed results and distinct/shared cross-Region destinations."""
    specs = [
        {"name": "Exposed", "configuration_updates": {"S3BucketName": BUCKET}},
        {"name": "Private", "configuration_updates": {"S3BucketName": PRIVATE_BUCKET}},
        {
            "name": "Shared",
            "home": "eu-west-1",
            "configuration_updates": {"S3BucketName": BUCKET},
        },
    ]
    provider = destination_provider(specs=specs)
    responses = defaultdict(list)
    summaries = []
    for name in sorted((BUCKET, PRIVATE_BUCKET)):
        exposed = name == BUCKET
        client = _complete_5e_s3_client(
            bucket_name=name,
            location_constraint=None if exposed else "eu-west-1",
            public_access_block_response=block(False),
            ownership_response={
                "OwnershipControls": {"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
            },
            policy_response=policy_response(statement())
            if exposed
            else client_error("NoSuchBucketPolicy", "GetBucketPolicy"),
            policy_status_response={"PolicyStatus": {"IsPublic": exposed}},
        )
        summaries.extend(client._paginators["list_buckets"][0].pages[0]["Buckets"])
        for operation, queued in client._responses.items():
            responses[operation].extend(queued)
    client = FakeAWSClient(
        paginators={"list_buckets": FakePaginator([{"Buckets": summaries}])},
        responses=responses,
    )
    for region in ("us-east-1", "eu-west-1"):
        provider._clients[("s3", region)] = client
    return provider


def assert_mixed_destination_bindings(bundle):
    """Every trail selects its exact dependency and source IDs, not tuple position."""
    dependencies = {a.aws_resource_id: a for a in bundle["assessments"] if a.control_id == "S3-002"}
    assert {name: a.result for name, a in dependencies.items()} == {
        BUCKET: "FAIL",
        PRIVATE_BUCKET: "PASS",
    }
    destinations = [a for a in bundle["assessments"] if a.control_id == "LOG-004"]
    assert len(destinations) == 3
    for assessment in destinations:
        proof = assessment.evidence_artifacts[0].payload["source_proof"]
        dependency = dependencies[proof["cloudtrail"]["trails"][0]["s3_bucket_name"]]
        binding = proof["destination_dependency"]
        assert assessment.result == dependency.result
        assert binding["resource_snapshot_id"] == str(dependency.resource_snapshot_id)
        assert binding["bucket_identity"]["bucket_region"] == dependency.region
        assert binding["evidence"] == sorted(
            (
                {"evidence_id": str(a.evidence_id), "payload_sha256": a.payload_sha256}
                for a in dependency.evidence_artifacts
            ),
            key=lambda a: a["evidence_id"],
        )


def destination_bundle(*, profile=None, provider=None, observed=OBSERVED, **options):
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(provider or destination_provider(**options)).collect(
            scan_id=uuid4()
        )
    profile = profile or destination_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.12.0")
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        scope=_scope_for(snapshot, profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        started_at=observed - timedelta(seconds=1),
        completed_at=observed + timedelta(seconds=1),
        scanner_version="6f2-test",
    )
