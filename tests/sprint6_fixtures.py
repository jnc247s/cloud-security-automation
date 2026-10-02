"""Whole-Sprint-6 acceptance inputs; real collectors/rules, explicit test-only policy."""

from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.scan_executor import _scope_for
from tests.governance_fixtures import governance_bundle, governance_profile
from tests.s3_exposure_fixtures import exposure_profile
from tests.s3_sensitive_kms_fixtures import sensitive_kms_profile

CATALOG_ID = "aws-cloud-security-controls"
# Golden definitions captured from accepted main 5043f61, before this test-only slice.
CATALOG_CHECKSUMS = {
    "0.2.1": "0b19063db2954f0d5f8dea8b5f00d85c74f0c1988b0ae0f276bc262dd01c617d",
    "0.3.0": "23d10e15bd3361988bd271b424c3c55738f81ef6c7e39a8fabd4a3b3e1f498db",
    "0.4.0": "c4b98645a9c059ea577b74d4a34c6208289e1f26fae44cd072e82e745d8c2a6b",
    "0.5.0": "c37c7f4cfade81279c62c9bb0d38b61517ef3f72cb3d6ecd933d4b5d14272b9e",
    "0.6.0": "22e1c0ebe239cc86ed9ad37c32db9bbf8878b299a5ab540d0457bb9834a8591d",
    "0.7.0": "6172142d8d38e8567f0794b80b3d049d4dc95d8a761e20b6bc5ba75b86ac5ff1",
    "0.8.0": "4ba5d55b42f435bed8001d466aa68155163f784a42cdeef5b4a06d0cf3681f77",
    "0.9.0": "776ec64a10c54ee68295206cf24ded9e5fe7b8490f58c1049a277dcbdaaa6e30",
    "0.10.0": "f18794a8e36ab4eafa8bf67bae262c8ea74034e30cf2c146065f261900c16236",
    "0.11.0": "b8f65ea1c06dc4a66d7813249798e52dc5c4e6dc37d495f1d103d3d9b7612ce2",
    "0.12.0": "a60d2fa6c30f28226243233047b331b513ae58c3c4c1db156992f2d1954a2efe",
    "0.13.0": "a00217f5502ed4278d33a35013ca4494d8cd7e52bffe19daebb08fdab7c128d1",
}
CORE_IDS = frozenset(
    [f"IAM-{n:03d}" for n in range(1, 7)]
    + [f"EC2-{n:03d}" for n in range(1, 5)]
    + [f"NET-{n:03d}" for n in range(1, 7)]
    + [f"S3-{n:03d}" for n in range(1, 5)]
    + [f"LOG-{n:03d}" for n in range(1, 5)]
    + ["GOV-001"]
)
SUPPORTED_IDS = CORE_IDS | {"S3-900"}


def sprint6_profile(catalog_version="0.13.0", **updates):
    catalog, _ = resolve_catalog(CATALOG_ID, catalog_version)
    policy = {
        "profile_id": "sprint-6h-acceptance",
        "version": f"6.11.{catalog_version.split('.')[1]}",
        "enabled_controls": tuple(c.control_id for c in catalog.controls),
        **updates,
    }
    if catalog_version == "0.2.1":
        return AssessmentProfile.model_validate(
            {**DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"}), **policy}
        )
    return governance_profile(
        max_unused_access_key_days=90,
        high_risk_public_tcp_ports=(3306, 5432, 6379, 9200, 27017),
        vpc_flow_log_required_environments=("production",),
        acceptable_vpc_flow_log_traffic_types=("ALL", "REJECT"),
        s3_exposure_approvals=exposure_profile().s3_exposure_approvals,
        sensitive_bucket_classifier=sensitive_kms_profile().sensitive_bucket_classifier,
        **policy,
    )


def sprint6_bundle(*, catalog_version="0.13.0", **options):
    profile = sprint6_profile(catalog_version)
    bundle = governance_bundle(profile=profile, **options)
    catalog, registry = resolve_catalog(CATALOG_ID, catalog_version)
    bundle.update(
        catalog=catalog,
        scope=_scope_for(bundle["snapshot"], profile, catalog),
        assessments=RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], profile),
        scanner_version="6h-test",
    )
    return bundle
