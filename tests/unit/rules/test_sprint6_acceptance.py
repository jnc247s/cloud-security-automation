"""Combined production-control matrix, immutable releases and no-AWS assessment boundary."""

from collections import Counter

import boto3
import pytest

from app.assessment.models import AssessmentResult as R
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE
from app.assessment.provenance import control_catalog_sha256
from app.rules.engine import RuleEngine
from app.rules.registry import RuleRegistry, resolve_catalog
from tests.governance_fixtures import governance_provider
from tests.sprint6_fixtures import (
    CATALOG_CHECKSUMS,
    CATALOG_ID,
    CORE_IDS,
    SUPPORTED_IDS,
    sprint6_bundle,
    sprint6_profile,
)


@pytest.mark.parametrize("version", CATALOG_CHECKSUMS)
def test_every_supported_catalog_keeps_its_accepted_definition(version):
    catalog, registry = resolve_catalog(CATALOG_ID, version)
    assert control_catalog_sha256(catalog) == CATALOG_CHECKSUMS[version]
    assert {c.control_id for c in catalog.controls} == {r.control_id for r in registry.rules}
    catalog.validate_profile_inputs(sprint6_profile(version))
    assert all(c.control_id in SUPPORTED_IDS for c in catalog.controls)
    if version == "0.13.0":
        assert len(CORE_IDS) == 25 and {c.control_id for c in catalog.controls} == SUPPORTED_IDS
    if version == "0.2.1":
        assert set(DEFAULT_ASSESSMENT_PROFILE.enabled_controls) == {
            "IAM-001",
            "LOG-001",
            "NET-001",
            "NET-002",
            "S3-900",
        }


def test_all_26_controls_share_exact_same_scan_and_preserve_prior_results(monkeypatch):
    provider = governance_provider()
    bundle = sprint6_bundle(provider=provider)
    assessments = bundle["assessments"]
    assert len(assessments) == 39
    assert {a.control_id for a in assessments} == SUPPORTED_IDS
    assert {a.scan_id for a in assessments} == {bundle["snapshot"].scan_id}
    assert {a.profile_checksum for a in assessments} == {bundle["profile"].content_checksum}
    expected_failures = {
        "EC2-001",
        "EC2-002",
        "EC2-003",
        "EC2-004",
        "IAM-002",
        "IAM-003",
        "IAM-004",
        "NET-001",
        "NET-002",
        "NET-003",
        "NET-004",
        "NET-005",
        "S3-001",
        "S3-003",
    }
    assert {a.control_id for a in assessments if a.result is R.FAIL} == expected_failures
    assert Counter(a.result for a in assessments) == {R.PASS: 21, R.FAIL: 17, R.NOT_APPLICABLE: 1}
    assert (
        next(a for a in assessments if a.control_id == "LOG-004").result
        is next(a for a in assessments if a.control_id == "S3-002").result
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("assessment must not call AWS")

    monkeypatch.setattr(boto3, "client", forbidden)
    monkeypatch.setattr(boto3.session.Session, "client", forbidden)
    _, registry = resolve_catalog(CATALOG_ID, "0.13.0")
    reversed_snapshot = bundle["snapshot"].model_copy(
        update={"resources": tuple(reversed(bundle["snapshot"].resources))}
    )
    assert (
        RuleEngine(RuleRegistry(reversed(registry.rules)), catalog=bundle["catalog"]).assess(
            reversed_snapshot, bundle["profile"]
        )
        == assessments
    )
    prior = sprint6_profile(
        version="6.11.14", enabled_controls=tuple(sorted(SUPPORTED_IDS - {"GOV-001"}))
    )
    old_results = RuleEngine(registry, catalog=bundle["catalog"]).assess(bundle["snapshot"], prior)
    assert {(a.control_id, a.resource_snapshot_id, a.result) for a in old_results} == {
        (a.control_id, a.resource_snapshot_id, a.result)
        for a in assessments
        if a.control_id != "GOV-001"
    }
