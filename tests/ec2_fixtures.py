"""Offline EC2 AWS fixtures; production collection and normalization remain real."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from app.assessment.ec2_evidence import EC2_CONTROL_IDS
from app.collectors.ec2 import EC2EbsCollector
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.fakes import FakeClientProvider
from tests.foundation_fixtures import extended_profile
from tests.unit.collectors.test_ec2 import _client, _instance, _volume

OBSERVED = datetime(2026, 9, 28, 12, tzinfo=UTC)
ACCOUNT = "123456789012"


def ec2_profile(**updates):
    return extended_profile(**{"version": "6.3.0", "enabled_controls": EC2_CONTROL_IDS, **updates})


def ec2_client(
    *,
    instances=True,
    volumes=True,
    tokens="optional",
    endpoint="enabled",
    state="applied",
    public=True,
    encrypted=False,
    default=False,
    instance_error=None,
    volume_error=None,
    setting_error=None,
    kms_error=None,
    instance=None,
):
    item = _instance() if instance is None else instance
    if instance is None:
        item["MetadataOptions"] = {"State": state, "HttpEndpoint": endpoint, "HttpTokens": tokens}
        if not public:
            item.pop("PublicIpAddress", None)
            for interface in item["NetworkInterfaces"]:
                interface.pop("Association", None)
                for private in interface["PrivateIpAddresses"]:
                    private.pop("Association", None)
    volume = _volume(encrypted=encrypted)
    volume.pop("KmsKeyId")
    return _client(
        instance_pages=[{"Reservations": [{"Instances": [item] if instances else []}]}],
        volume_pages=[{"Volumes": [volume] if volumes else []}],
        encryption_response=setting_error or {"EbsEncryptionByDefault": default},
        kms_response=kms_error or {},
        instance_error=instance_error,
        volume_error=volume_error,
    )


def ec2_snapshot(*, region="us-east-1", account=ACCOUNT, **options):
    provider = FakeClientProvider(
        {("ec2", region): ec2_client(**options)}, region_name=region, account_id=account
    )
    service = InventoryService(provider, collectors=(EC2EbsCollector(provider),))
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = OBSERVED
        return service.collect(scan_id=uuid4())


def ec2_bundle(*, profile=None, **options):
    snapshot = ec2_snapshot(**options)
    profile = profile or ec2_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.5.0")
    return {
        "snapshot": snapshot,
        "profile": profile,
        "catalog": catalog,
        "scope": _scope_for(
            snapshot,
            profile,
            catalog,
            requested_services=("ec2",),
            requested_collectors=("ec2_ebs_evidence",),
            resource_types=("ec2_instance", "ebs_volume", "aws_account"),
        ),
        "assessments": RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        "started_at": OBSERVED - timedelta(seconds=1),
        "completed_at": OBSERVED + timedelta(seconds=1),
        "scanner_version": "6c-test",
    }
