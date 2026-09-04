"""Canonical Sprint 2.1 assessment-state tests for the existing control library."""

import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest

from app.assessment.controls import build_default_control_catalog
from app.assessment.identities import inventory_sha256
from app.assessment.models import AssessmentResult
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
from app.assessment.provenance import control_catalog_sha256
from app.rules.audit_logging import MissingCloudTrailRule
from app.rules.base import RuleEvaluationError, assessment_scan_id
from app.rules.engine import RuleContractError, RuleEngine
from app.rules.identity import IAMUserWithoutMFARule
from app.rules.network import PublicRDPRule, PublicSSHRule
from app.rules.registry import RuleRegistry, build_default_registry
from app.rules.storage import MissingBucketEncryptionRule
from app.schemas.inventory import CollectionStatus, CollectorOutcome
from app.schemas.resource import ResourceScope
from tests.unit.rules.factories import ACCOUNT_ID, REGION, resource, snapshot


def _profile_with_controls(*control_ids: str) -> AssessmentProfile:
    values = DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"})
    values["enabled_controls"] = control_ids
    return AssessmentProfile.model_validate(values)


def _security_group(*, public_ssh: bool = False):
    ingress_rules: list[dict[str, object]] = []
    if public_ssh:
        ingress_rules.append(
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": "public SSH"}],
                "ipv6_ranges": [],
                "prefix_lists": [],
                "referenced_security_groups": [],
            }
        )
    return resource(
        service="ec2",
        resource_type="security_group",
        aws_resource_id="sg-assessment",
        name="assessment-group",
        configuration={
            "vpc_id": "vpc-assessment",
            "ingress_rules": ingress_rules,
            "egress_rules": [],
        },
    )


def _bucket(default_encryption: object):
    return resource(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="assessment-bucket",
        arn="arn:aws:s3:::assessment-bucket",
        name="assessment-bucket",
        configuration={"default_encryption": default_encryption},
    )


def _iam_user(mfa_devices: object):
    return resource(
        service="iam",
        resource_type="iam_user",
        aws_resource_id="AIDAASSESSMENT",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:user/assessment",
        name="assessment",
        scope=ResourceScope.GLOBAL,
        region=None,
        configuration={"mfa_devices": mfa_devices},
    )


def _trail(is_logging: object):
    trail_arn = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/assessment"
    return resource(
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=trail_arn,
        arn=trail_arn,
        name="assessment",
        configuration={"is_logging": is_logging},
    )


@pytest.mark.parametrize(
    ("rule", "applicable_resource", "expected_result"),
    (
        (PublicSSHRule(), _security_group(public_ssh=False), AssessmentResult.PASS),
        (PublicSSHRule(), _security_group(public_ssh=True), AssessmentResult.FAIL),
        (
            PublicRDPRule(),
            _security_group(public_ssh=False),
            AssessmentResult.PASS,
        ),
        (
            MissingBucketEncryptionRule(),
            _bucket(
                {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
            ),
            AssessmentResult.PASS,
        ),
        (MissingBucketEncryptionRule(), _bucket(None), AssessmentResult.FAIL),
        (IAMUserWithoutMFARule(), _iam_user([{"SerialNumber": "example"}]), AssessmentResult.PASS),
        (IAMUserWithoutMFARule(), _iam_user([]), AssessmentResult.FAIL),
        (MissingCloudTrailRule(), _trail(True), AssessmentResult.PASS),
        (MissingCloudTrailRule(), _trail(False), AssessmentResult.FAIL),
    ),
)
def test_rules_return_explicit_pass_and_fail_with_structured_evidence(
    rule,
    applicable_resource,
    expected_result: AssessmentResult,
) -> None:
    assessment = rule.assess(snapshot(applicable_resource), DEFAULT_ASSESSMENT_PROFILE)[0]

    assert assessment.result is expected_result
    assert assessment.profile_id == DEFAULT_ASSESSMENT_PROFILE.profile_id
    assert assessment.profile_version == DEFAULT_ASSESSMENT_PROFILE.version
    assert len(assessment.evidence_artifacts) == 1
    artifact = assessment.evidence_artifacts[0]
    assert artifact.control_id == rule.control_id
    assert artifact.account_id == ACCOUNT_ID
    assert artifact.collected_at == snapshot().collected_at
    assert artifact.payload


@pytest.mark.parametrize(
    ("rule", "malformed_resource", "expected_path"),
    (
        (
            PublicSSHRule(),
            resource(
                service="ec2",
                resource_type="security_group",
                aws_resource_id="sg-malformed",
                configuration={},
            ),
            "configuration.ingress_rules",
        ),
        (
            MissingBucketEncryptionRule(),
            resource(
                service="s3",
                resource_type="s3_bucket",
                aws_resource_id="bucket-malformed",
                configuration={},
            ),
            "configuration.default_encryption",
        ),
        (
            IAMUserWithoutMFARule(),
            resource(
                service="iam",
                resource_type="iam_user",
                aws_resource_id="AIDAMALFORMED",
                scope=ResourceScope.GLOBAL,
                region=None,
                configuration={},
            ),
            "configuration.mfa_devices",
        ),
        (
            MissingCloudTrailRule(),
            resource(
                service="cloudtrail",
                resource_type="cloudtrail_trail",
                aws_resource_id="malformed-trail",
                configuration={},
            ),
            "configuration.is_logging",
        ),
    ),
)
def test_missing_or_malformed_required_facts_are_insufficient_evidence(
    rule,
    malformed_resource,
    expected_path: str,
) -> None:
    assessment = rule.assess(snapshot(malformed_resource), DEFAULT_ASSESSMENT_PROFILE)[0]

    assert assessment.result is AssessmentResult.INSUFFICIENT_EVIDENCE
    assert assessment.evidence_artifacts == ()
    assert any(expected_path in path for path in assessment.missing_evidence)


@pytest.mark.parametrize(
    ("rule", "collector_name"),
    (
        (PublicSSHRule(), "security_groups"),
        (MissingBucketEncryptionRule(), "s3_buckets"),
        (IAMUserWithoutMFARule(), "iam_users"),
        (MissingCloudTrailRule(), "cloudtrail_trails"),
    ),
)
@pytest.mark.parametrize("status", (None, CollectionStatus.FAILED, CollectionStatus.PARTIAL))
def test_unrequested_failed_or_partial_collection_is_insufficient_evidence(
    rule,
    collector_name: str,
    status: CollectionStatus | None,
) -> None:
    outcomes = tuple(
        outcome
        for outcome in snapshot().collector_outcomes
        if outcome.collector_name != collector_name
    )
    if status is not None:
        outcomes = (
            *outcomes,
            CollectorOutcome(collector_name=collector_name, status=status),
        )
    incomplete_snapshot = snapshot().model_copy(update={"collector_outcomes": outcomes})

    assessment = rule.assess(incomplete_snapshot, DEFAULT_ASSESSMENT_PROFILE)[0]

    assert assessment.result is AssessmentResult.INSUFFICIENT_EVIDENCE
    assert f"collector_outcomes.{collector_name}.SUCCEEDED" in assessment.missing_evidence


@pytest.mark.parametrize(
    ("rule", "collector_name"),
    (
        (PublicSSHRule(), "security_groups"),
        (MissingBucketEncryptionRule(), "s3_buckets"),
        (IAMUserWithoutMFARule(), "iam_users"),
        (MissingCloudTrailRule(), "cloudtrail_trails"),
    ),
)
def test_legacy_evaluation_rejects_incomplete_collection(rule, collector_name: str) -> None:
    outcomes = tuple(
        outcome
        for outcome in snapshot().collector_outcomes
        if outcome.collector_name != collector_name
    )
    incomplete_snapshot = snapshot().model_copy(update={"collector_outcomes": outcomes})

    with pytest.raises(
        RuleEvaluationError,
        match=rf"collector_outcomes\.{collector_name}\.SUCCEEDED",
    ):
        rule.evaluate(incomplete_snapshot)


def test_cloudtrail_does_not_hide_malformed_evidence_behind_an_active_trail() -> None:
    assessment = MissingCloudTrailRule().assess(
        snapshot(
            _trail(True),
            resource(
                service="cloudtrail",
                resource_type="cloudtrail_trail",
                aws_resource_id="malformed-trail",
                configuration={},
            ),
        ),
        DEFAULT_ASSESSMENT_PROFILE,
    )[0]

    assert assessment.result is AssessmentResult.INSUFFICIENT_EVIDENCE
    assert "resources[malformed-trail].configuration.is_logging" in (assessment.missing_evidence)


def test_superficially_shaped_iam_and_s3_evidence_cannot_pass() -> None:
    iam_assessment = IAMUserWithoutMFARule().assess(
        snapshot(_iam_user([{}])),
        DEFAULT_ASSESSMENT_PROFILE,
    )[0]
    s3_assessment = MissingBucketEncryptionRule().assess(
        snapshot(_bucket({"Rules": [{}]})),
        DEFAULT_ASSESSMENT_PROFILE,
    )[0]

    assert iam_assessment.result is AssessmentResult.INSUFFICIENT_EVIDENCE
    assert s3_assessment.result is AssessmentResult.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    "rule",
    (PublicSSHRule(), PublicRDPRule(), MissingBucketEncryptionRule(), IAMUserWithoutMFARule()),
)
def test_resource_rules_return_not_applicable_when_target_resources_are_absent(rule) -> None:
    assessment = rule.assess(snapshot(), DEFAULT_ASSESSMENT_PROFILE)[0]

    assert assessment.result is AssessmentResult.NOT_APPLICABLE
    assert assessment.resource_type == "aws_account"
    assert assessment.evidence_artifacts == ()
    assert assessment.missing_evidence == ()


def test_account_control_remains_applicable_when_no_trails_exist() -> None:
    assessment = MissingCloudTrailRule().assess(snapshot(), DEFAULT_ASSESSMENT_PROFILE)[0]

    assert assessment.result is AssessmentResult.FAIL
    assert assessment.evidence_artifacts[0].payload["reason"] == "no_trails"


def test_engine_returns_one_explicit_result_per_enabled_control_in_stable_order() -> None:
    inventory = snapshot(
        _security_group(public_ssh=True),
        _bucket(None),
        _iam_user([{"SerialNumber": "example"}]),
        _trail(True),
    )
    engine = RuleEngine(build_default_registry())

    first = engine.assess(inventory, DEFAULT_ASSESSMENT_PROFILE)
    second = engine.assess(inventory, DEFAULT_ASSESSMENT_PROFILE)

    assert tuple(assessment.control_id for assessment in first) == (
        "IAM-001",
        "LOG-001",
        "NET-001",
        "NET-002",
        "S3-900",
    )
    assert tuple(assessment.result for assessment in first) == (
        AssessmentResult.PASS,
        AssessmentResult.PASS,
        AssessmentResult.FAIL,
        AssessmentResult.PASS,
        AssessmentResult.FAIL,
    )
    assert first == second
    assert tuple(item.identity for item in first) == tuple(sorted(item.identity for item in first))
    assert {item.inventory_sha256 for item in first} == {inventory_sha256(inventory)}
    assert {item.control_catalog_sha256 for item in first} == {
        control_catalog_sha256(build_default_control_catalog())
    }


def test_profile_enabled_controls_are_applied_without_changing_rule_logic() -> None:
    profile = _profile_with_controls("IAM-001")
    assessments = RuleEngine(build_default_registry()).assess(snapshot(), profile)

    assert len(assessments) == 1
    assert assessments[0].control_id == "IAM-001"
    assert assessments[0].result is AssessmentResult.NOT_APPLICABLE


def test_engine_rejects_profile_control_that_is_not_registered() -> None:
    profile = _profile_with_controls("IAM-999")

    with pytest.raises(RuleContractError, match="unregistered controls: IAM-999"):
        RuleEngine(build_default_registry()).assess(snapshot(), profile)


def test_engine_validates_every_assessment_contract_guard(monkeypatch) -> None:
    rule = IAMUserWithoutMFARule()
    profile = _profile_with_controls("IAM-001")
    inventory = snapshot(_iam_user([]))
    valid = rule.assess(inventory, profile)[0]
    engine = RuleEngine(RuleRegistry((rule,)))

    invalid_cases = (
        ((), "returned no assessment"),
        ((object(),), "non-assessment candidate"),
        ((valid.model_copy(update={"control_id": "IAM-999"}),), "assessment for IAM-999"),
        (
            (valid.model_copy(update={"account_id": "999999999999"}),),
            "different AWS account",
        ),
        (
            (valid.model_copy(update={"profile_version": "9.9.9"}),),
            "different profile version",
        ),
        (
            (valid.model_copy(update={"scan_id": UUID("00000000-0000-0000-0000-000000000001")}),),
            "different inventory snapshot",
        ),
        (
            (valid.model_copy(update={"inventory_sha256": "0" * 64}),),
            "different inventory facts",
        ),
        (
            (valid.model_copy(update={"control_catalog_sha256": "0" * 64}),),
            "different control catalog",
        ),
        (
            (
                valid.model_copy(
                    update={"resource_snapshot_id": UUID("00000000-0000-0000-0000-000000000002")}
                ),
            ),
            "different resource snapshot",
        ),
        ((valid, valid), "duplicate assessment identity"),
    )

    for returned, message in invalid_cases:
        monkeypatch.setattr(rule, "assess", lambda _snapshot, _profile, value=returned: value)
        with pytest.raises(RuleContractError, match=message):
            engine.assess(inventory, profile)


def test_scan_identity_is_allocated_before_assessment_and_survives_coverage_updates() -> None:
    complete = snapshot(_security_group())
    partial = complete.model_copy(
        update={
            "collector_outcomes": tuple(
                outcome.model_copy(update={"status": CollectionStatus.PARTIAL})
                if outcome.collector_name == "security_groups"
                else outcome
                for outcome in complete.collector_outcomes
            )
        }
    )

    assert assessment_scan_id(complete) == complete.scan_id
    assert assessment_scan_id(partial) == complete.scan_id


def test_registry_and_versioned_control_catalog_have_exactly_the_same_ids() -> None:
    registry = build_default_registry()
    catalog = build_default_control_catalog()
    registry_ids = {rule.control_id for rule in registry.rules}
    catalog_ids = {contract.control_id for contract in catalog.controls}

    assert registry_ids == catalog_ids
    for rule in registry.rules:
        technical = catalog.get(rule.control_id).technical
        assert technical.title == rule.title
        assert technical.category is rule.category
        assert technical.severity is rule.default_severity
        assert technical.impact == rule.impact
        assert technical.remediation_guidance == rule.recommendation
        assert set(technical.profile_parameters) <= set(AssessmentProfile.model_fields)


def test_framework_metadata_is_not_consulted_during_technical_evaluation() -> None:
    rule = PublicSSHRule()
    inventory = snapshot(_security_group(public_ssh=True))

    # The evaluator accepts only normalized facts and the versioned policy profile; mappings
    # live in a separate catalog and are deliberately absent from this decision path.
    assessment = rule.assess(inventory, DEFAULT_ASSESSMENT_PROFILE)[0]

    assert assessment.result is AssessmentResult.FAIL
    assert "framework" not in assessment.model_dump()


def test_technical_rule_import_does_not_load_framework_or_mapping_catalog() -> None:
    project_root = Path(__file__).resolve().parents[3]
    script = """
import sys
from app.rules.network import PublicSSHRule

PublicSSHRule()
assert "app.assessment.controls" not in sys.modules
assert "app.assessment.frameworks" not in sys.modules
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=project_root,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
