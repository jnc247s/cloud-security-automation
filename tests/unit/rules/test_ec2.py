"""Canonical 6C truth tables, proof boundaries and policy compatibility."""

import json
from uuid import uuid4

import pytest

from app.assessment.ec2_controls import ec2_execution
from app.assessment.evidence_reader import AssessmentEvidenceReader
from app.assessment.identities import stable_resource_id
from app.assessment.models import AssessmentResult
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.ec2_fixtures import ec2_bundle, ec2_profile, ec2_snapshot
from tests.fakes import client_error
from tests.unit.collectors.test_ec2 import _instance


def results(**kwargs):
    return {a.control_id: a.result.value for a in ec2_bundle(**kwargs)["assessments"]}


@pytest.mark.parametrize(
    "tokens,endpoint,state,expected",
    [
        ("required", "enabled", "applied", "PASS"),
        ("optional", "enabled", "applied", "FAIL"),
        ("required", "disabled", "applied", "NOT_APPLICABLE"),
        ("optional", "disabled", "applied", "NOT_APPLICABLE"),
        ("required", "enabled", "pending", "INSUFFICIENT_EVIDENCE"),
        ("optional", "disabled", "pending", "INSUFFICIENT_EVIDENCE"),
        ("unknown", "enabled", "applied", "INSUFFICIENT_EVIDENCE"),
        ("required", "unknown", "applied", "INSUFFICIENT_EVIDENCE"),
        ("required", "enabled", "unknown", "INSUFFICIENT_EVIDENCE"),
    ],
)
def test_imds_truth_table(tokens, endpoint, state, expected):
    assert results(tokens=tokens, endpoint=endpoint, state=state)["EC2-001"] == expected


@pytest.mark.parametrize(
    "encrypted,default,expected3,expected4",
    [
        (True, True, "PASS", "PASS"),
        (False, False, "FAIL", "FAIL"),
        (True, False, "PASS", "FAIL"),
        (False, True, "FAIL", "PASS"),
        (None, True, "INSUFFICIENT_EVIDENCE", "PASS"),
        (True, "true", "PASS", "INSUFFICIENT_EVIDENCE"),
    ],
)
def test_encryption_settings_independent(encrypted, default, expected3, expected4):
    actual = results(encrypted=encrypted, default=default)
    assert (actual["EC2-003"], actual["EC2-004"]) == (expected3, expected4)


def test_empty_population_is_not_missing_and_setting_never_na():
    assert results(instances=False, volumes=False) == {
        "EC2-001": "NOT_APPLICABLE",
        "EC2-002": "NOT_APPLICABLE",
        "EC2-003": "NOT_APPLICABLE",
        "EC2-004": "FAIL",
    }


@pytest.mark.parametrize(
    "field,affected",
    [
        ("instance_error", {"EC2-001", "EC2-002"}),
        ("volume_error", {"EC2-003"}),
        ("setting_error", {"EC2-004"}),
        ("kms_error", set()),
    ],
)
def test_failure_of_one_source_does_not_erase_independent_evidence(field, affected):
    actual = results(**{field: client_error("AccessDenied", "offline")})
    assert {k for k, v in actual.items() if v == "INSUFFICIENT_EVIDENCE"} == affected
    assert {v for k, v in actual.items() if k not in affected} == {"FAIL"}


def resource_uuid(resource):
    return str(
        stable_resource_id(
            provider="aws",
            aws_account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            scope=resource.scope,
            region=resource.region,
            aws_resource_id=resource.aws_resource_id,
        )
    )


def test_public_address_policy_binds_account_region_and_instance():
    snapshot = ec2_snapshot()
    instance = next(r for r in snapshot.resources if r.resource_type == "ec2_instance")
    profile = ec2_profile(public_ec2_exceptions=(resource_uuid(instance),))
    assert results(profile=profile)["EC2-002"] == "PASS"
    assert results(profile=profile, region="us-west-2")["EC2-002"] == "FAIL"
    assert results(profile=profile, account="999999999999")["EC2-002"] == "FAIL"
    assert results(public=False)["EC2-002"] == "PASS"
    assert results()["EC2-002"] == "FAIL"


@pytest.mark.parametrize("location", ["instance", "interface", "private"])
def test_every_public_ipv4_location_is_decisive(location):
    instance = _instance()
    if location != "instance":
        instance.pop("PublicIpAddress")
    for interface in instance["NetworkInterfaces"]:
        if location != "interface":
            interface.pop("Association")
        for private in interface["PrivateIpAddresses"]:
            if location != "private":
                private.pop("Association")
    assert results(instance=instance)["EC2-002"] == "FAIL"


@pytest.mark.parametrize("value", ["i-0123456789abcdef0", "*", "not-a-uuid", str(uuid4())])
def test_allowlist_invalid_only_for_enabled_ec2_002(value):
    catalog, _ = resolve_catalog("aws-cloud-security-controls", "0.5.0")
    with pytest.raises(ValueError, match="stable resource UUID"):
        catalog.validate_profile_inputs(ec2_profile(public_ec2_exceptions=(value,)))
    historical = ec2_profile(enabled_controls=("IAM-001",), public_ec2_exceptions=(value,))
    for version in ("0.2.1", "0.3.0", "0.4.0", "0.5.0"):
        resolve_catalog(catalog.catalog_id, version)[0].validate_profile_inputs(historical)


@pytest.mark.parametrize("control_id", ["EC2-001", "EC2-002", "EC2-003", "EC2-004"])
def test_false_na_rejected(control_id):
    bundle = ec2_bundle()
    candidate = next(a for a in bundle["assessments"] if a.control_id == control_id)
    forged = candidate.model_copy(
        update={"result": AssessmentResult.NOT_APPLICABLE, "evidence_artifacts": ()}
    )
    with pytest.raises(ValueError, match="applicability"):
        AssessmentEvidenceReader(bundle["snapshot"]).validate_candidate(
            ec2_execution(control_id),
            forged,
        )


def test_reordering_does_not_change_assessments_and_old_catalogs_are_preserved():
    bundle = ec2_bundle()
    snapshot = bundle["snapshot"]
    catalog, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.5.0")
    old, _ = resolve_catalog(catalog.catalog_id, "0.4.0")
    assert all(catalog.get(c.control_id) == c for c in old.controls)
    assert catalog.framework_catalogs[:-1] == old.framework_catalogs
    reordered = snapshot.model_copy(update={"resources": tuple(reversed(snapshot.resources))})
    assert (
        RuleEngine(registry, catalog=catalog).assess(reordered, bundle["profile"])
        == bundle["assessments"]
    )


def test_resource_configuration_cannot_diverge_from_retained_source():
    bundle = ec2_bundle()
    snapshot = bundle["snapshot"]
    resources = tuple(
        r.model_copy(update={"configuration": {**r.configuration, "encrypted": True}})
        if r.resource_type == "ebs_volume"
        else r
        for r in snapshot.resources
    )
    changed = snapshot.model_copy(update={"resources": resources})
    catalog, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.5.0")
    assessments = RuleEngine(registry, catalog=catalog).assess(changed, bundle["profile"])
    assert (
        next(a for a in assessments if a.control_id == "EC2-003").result
        is AssessmentResult.INSUFFICIENT_EVIDENCE
    )


def test_invalid_allowlist_is_rejected_at_deployment_boundary(tmp_path):
    from app.assessment.deployment_policy import PolicyConfigurationError, load_deployment_policy
    from app.config import Settings

    profile = ec2_profile(public_ec2_exceptions=("i-0123456789abcdef0",))
    path = tmp_path / "invalid-ec2-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.5.0",
                "profile": profile.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        assessment_profile_file=str(path),
        assessment_profile_version=profile.version,
    )
    with pytest.raises(
        PolicyConfigurationError, match="Assessment policy configuration is invalid"
    ):
        load_deployment_policy(settings)
