"""Offline AWS inputs exercise the production S3/KMS collection and assessment path."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.assessment.sensitive_buckets import SensitiveBucketClassifier, SensitiveBucketTagRule
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.ec2_fixtures import OBSERVED
from tests.fakes import FakeAWSClient
from tests.foundation_fixtures import extended_profile
from tests.s3_configuration_fixtures import s3_provider

KEY_ID = "12345678-1234-1234-1234-123456789012"
KEY_ARN = f"arn:aws:kms:us-east-1:123456789012:key/{KEY_ID}"


def sensitive_kms_profile(*, classifier=None, **updates):
    return extended_profile(
        **{
            "version": "6.7.1",
            "enabled_controls": ("S3-004",),
            "restricted_data_requires_kms": True,
            "sensitive_bucket_classifier": classifier
            or SensitiveBucketClassifier.create(
                version="1.0.0",
                sensitive_tag_rules=(
                    SensitiveBucketTagRule(key="DataClassification", value="Restricted"),
                ),
            ),
            **updates,
        }
    )


def encryption_rule(algorithm="aws:kms", reference=None, **updates):
    default = {"SSEAlgorithm": algorithm}
    if reference is not None:
        default["KMSMasterKeyID"] = reference
    return {"ApplyServerSideEncryptionByDefault": default, **updates}


def key_response(*, account="123456789012", region="us-east-1", manager="CUSTOMER", **updates):
    return {
        "KeyMetadata": {
            "AWSAccountId": account,
            "KeyId": KEY_ID,
            "Arn": f"arn:aws:kms:{region}:{account}:key/{KEY_ID}",
            "KeyManager": manager,
            **updates,
        }
    }


def sensitive_kms_provider(region="us-east-1", *, kms_responses=None, **options):
    provider = s3_provider(
        region,
        **{
            "tag_response": {"TagSet": [{"Key": "DataClassification", "Value": "Restricted"}]},
            **options,
        },
    )
    for key_region, responses in (kms_responses or {}).items():
        provider._clients[("kms", key_region)] = FakeAWSClient(
            responses={"describe_key": responses}
        )
    return provider


def sensitive_kms_bundle(*, profile=None, provider=None, observed=OBSERVED, **options):
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(provider or sensitive_kms_provider(**options)).collect(
            scan_id=uuid4()
        )
    profile = profile or sensitive_kms_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.10.0")
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        scope=_scope_for(snapshot, profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        started_at=observed - timedelta(seconds=1),
        completed_at=observed + timedelta(seconds=1),
        scanner_version="6e3-test",
    )
