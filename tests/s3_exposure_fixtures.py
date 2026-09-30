"""Offline exposure fixtures using the unchanged production collection path."""

import json
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from app.assessment.s3_exposure import S3BucketExposureApproval, S3ExposureApprovalPolicy
from app.assessment.s3_identity import S3BucketIdentity
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import _scope_for
from tests.ec2_fixtures import OBSERVED
from tests.fakes import client_error
from tests.foundation_fixtures import extended_profile
from tests.s3_configuration_fixtures import BUCKET, block, s3_provider

ACCOUNT = "123456789012"
EXTERNAL = "111122223333"
CANONICAL = "a" * 64
ARN = f"arn:aws:s3:::{BUCKET}"


def exposure_profile(
    *, public=False, principals=(), region="us-east-1", policy_version="1.0.0", **updates
):
    approvals = ()
    if public or principals:
        approvals = (
            S3BucketExposureApproval(
                bucket_identity=S3BucketIdentity.for_bucket(
                    aws_account_id=ACCOUNT,
                    bucket_region=region,
                    bucket_arn=ARN,
                ),
                allow_public=public,
                approved_external_principals=principals,
            ),
        )
    return extended_profile(
        **{
            "version": "6.6.1",
            "enabled_controls": ("S3-002",),
            "s3_exposure_approvals": S3ExposureApprovalPolicy.create(
                version=policy_version, bucket_approvals=approvals
            ),
            **updates,
        }
    )


def statement(principal="*", **updates):
    return {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "s3:GetObject",
        "Resource": f"{ARN}/*",
        **updates,
    }


def policy_response(*statements):
    return {"Policy": json.dumps({"Statement": list(statements)})}


def acl_response(*grantees):
    return {
        "Owner": {"ID": "canonical-owner"},
        "Grants": [
            {
                "Grantee": {"Type": "CanonicalUser", "ID": "canonical-owner"},
                "Permission": "FULL_CONTROL",
            },
            *({"Grantee": g, "Permission": "READ_ACP"} for g in grantees),
        ],
    }


def exposure_provider(region="us-east-1", **options):
    return s3_provider(
        region,
        **{
            "account": block(False),
            "public_access_block_response": block(False),
            "ownership_response": {
                "OwnershipControls": {"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
            },
            "policy_response": client_error("NoSuchBucketPolicy", "GetBucketPolicy"),
            **options,
        },
    )


def failing_provider(region="us-east-1"):
    return exposure_provider(
        region,
        policy_response=policy_response(statement()),
        policy_status_response={"PolicyStatus": {"IsPublic": True}},
    )


def exposure_bundle(*, profile=None, provider=None, observed=OBSERVED, **options):
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(provider or exposure_provider(**options)).collect(
            scan_id=uuid4()
        )
    profile = profile or exposure_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.9.0")
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        scope=_scope_for(snapshot, profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, profile),
        started_at=observed - timedelta(seconds=1),
        completed_at=observed + timedelta(seconds=1),
        scanner_version="6e2-test",
    )
