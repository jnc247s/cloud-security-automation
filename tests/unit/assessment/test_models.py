"""Tests for technical assessment results and structured evidence artifacts."""

import copy
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.assessment.models import AssessmentCandidate, AssessmentResult, EvidenceArtifact
from app.schemas.resource import ResourceScope

SCAN_ID = UUID("0b8bf2d2-cd63-5dca-af97-59f68aa27b32")
SNAPSHOT_ID = UUID("164f9ea4-0677-5bd4-a04b-506fc98d1c4f")
COLLECTED_AT = datetime(2026, 9, 3, 5, 0, tzinfo=UTC)


def _artifact(**overrides: object) -> EvidenceArtifact:
    values: dict[str, object] = {
        "resource_snapshot_id": SNAPSHOT_ID,
        "scan_id": SCAN_ID,
        "control_id": "NET-001",
        "account_id": "123456789012",
        "service": "ec2",
        "resource_type": "ec2_security_group",
        "aws_resource_id": "sg-0123456789abcdef0",
        "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
        "scope": ResourceScope.REGIONAL,
        "region": "us-east-1",
        "collector": "NetworkCollector",
        "source": "aws-api",
        "source_api": "ec2:DescribeSecurityGroups",
        "collected_at": COLLECTED_AT,
        "schema_name": "network.security-group-ingress",
        "schema_version": "1.0.0",
        "payload": {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidrs": ["0.0.0.0/0"],
        },
    }
    values.update(overrides)
    return EvidenceArtifact.for_assessment(**values)  # type: ignore[arg-type]


def _candidate(**overrides: object) -> AssessmentCandidate:
    artifact = _artifact()
    values: dict[str, object] = {
        "control_id": "NET-001",
        "result": AssessmentResult.FAIL,
        "profile_id": "default",
        "profile_version": "1.0.0",
        "profile_checksum": "a" * 64,
        "scan_id": SCAN_ID,
        "account_id": "123456789012",
        "service": "ec2",
        "resource_type": "ec2_security_group",
        "aws_resource_id": "sg-0123456789abcdef0",
        "arn": artifact.arn,
        "name": "public-management",
        "scope": ResourceScope.REGIONAL,
        "region": "us-east-1",
        "evidence_artifacts": (artifact,),
        "missing_evidence": (),
        "reason": "SSH is reachable from an unrestricted IPv4 CIDR.",
    }
    values.update(overrides)
    return AssessmentCandidate.model_validate(values)


def test_assessment_result_states_are_explicit() -> None:
    assert {result.value for result in AssessmentResult} == {
        "PASS",
        "FAIL",
        "INSUFFICIENT_EVIDENCE",
        "NOT_APPLICABLE",
    }


def test_evidence_artifact_has_deterministic_id_and_structured_payload() -> None:
    artifact = _artifact()

    assert artifact.evidence_id == _artifact().evidence_id
    assert artifact.evidence_id != _artifact(evidence_key="secondary").evidence_id
    assert artifact.payload["cidrs"] == ["0.0.0.0/0"]
    assert artifact.payload_sha256 is not None
    assert artifact.verify_integrity()
    assert artifact.identity == (
        artifact.evidence_id,
        SCAN_ID,
        "NET-001",
        "123456789012",
        "ec2_security_group",
        "sg-0123456789abcdef0",
    )


def test_evidence_identity_is_bound_to_canonical_payload_and_provenance() -> None:
    first = _artifact(payload={"b": [2], "a": 1})
    reordered = _artifact(payload={"a": 1, "b": [2]})
    changed_payload = _artifact(payload={"a": 1, "b": [3]})
    changed_source = _artifact(payload={"a": 1, "b": [2]}, source_api="ec2:DescribeVpcs")

    assert first.evidence_id == reordered.evidence_id
    assert first.payload_sha256 == reordered.payload_sha256
    assert first.evidence_id != changed_payload.evidence_id
    assert first.evidence_id != changed_source.evidence_id


def test_evidence_payload_is_deeply_immutable_and_copied_from_caller() -> None:
    source_payload = {"nested": [1, {"fact": True}]}
    artifact = _artifact(payload=source_payload)

    source_payload["nested"].append(2)
    assert artifact.payload["nested"] == [1, {"fact": True}]

    with pytest.raises(TypeError, match="immutable"):
        artifact.payload["new"] = True
    with pytest.raises(TypeError, match="immutable"):
        artifact.payload["nested"].append(3)
    with pytest.raises(TypeError, match="immutable"):
        artifact.payload["nested"][1]["fact"] = False

    assert copy.deepcopy(artifact) == artifact
    assert artifact.model_copy(deep=True) == artifact


def test_evidence_rejects_forged_digest_or_identifier() -> None:
    artifact = _artifact()
    payload = artifact.model_dump()
    payload["payload_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="payload_sha256 does not match"):
        EvidenceArtifact.model_validate(payload)

    payload = artifact.model_dump()
    payload["evidence_id"] = UUID("00000000-0000-0000-0000-000000000001")
    with pytest.raises(ValidationError, match="evidence_id does not match"):
        EvidenceArtifact.model_validate(payload)


def test_evidence_requires_consistent_scope_and_absolute_timestamp() -> None:
    with pytest.raises(ValidationError, match="regional evidence requires a region"):
        _artifact(region=None)

    with pytest.raises(ValidationError, match="timezone-aware"):
        _artifact(collected_at=datetime(2026, 9, 3, 5, 0))


def test_assessment_candidate_has_stable_target_identity() -> None:
    candidate = _candidate()

    assert candidate.identity == (
        "NET-001",
        "123456789012",
        "ec2",
        "ec2_security_group",
        "regional",
        "us-east-1",
        "sg-0123456789abcdef0",
    )


@pytest.mark.parametrize("result", [AssessmentResult.PASS, AssessmentResult.FAIL])
def test_pass_and_fail_require_evidence(result: AssessmentResult) -> None:
    with pytest.raises(ValidationError, match="requires at least one evidence artifact"):
        _candidate(result=result, evidence_artifacts=())


def test_missing_evidence_never_becomes_pass() -> None:
    with pytest.raises(ValidationError, match="only INSUFFICIENT_EVIDENCE"):
        _candidate(
            result=AssessmentResult.PASS,
            evidence_artifacts=(_artifact(),),
            missing_evidence=("configuration.ip_permissions",),
        )


def test_insufficient_evidence_requires_named_missing_facts() -> None:
    with pytest.raises(ValidationError, match="requires missing_evidence"):
        _candidate(
            result=AssessmentResult.INSUFFICIENT_EVIDENCE,
            evidence_artifacts=(),
        )

    candidate = _candidate(
        result=AssessmentResult.INSUFFICIENT_EVIDENCE,
        evidence_artifacts=(),
        missing_evidence=("configuration.ip_permissions",),
        reason="The collector did not provide ingress permissions.",
    )
    assert candidate.result is AssessmentResult.INSUFFICIENT_EVIDENCE


def test_not_applicable_is_distinct_from_pass() -> None:
    candidate = _candidate(
        result=AssessmentResult.NOT_APPLICABLE,
        evidence_artifacts=(),
        reason="The snapshot contains no supported security-group resources.",
    )

    assert candidate.result is AssessmentResult.NOT_APPLICABLE
    assert candidate.evidence_artifacts == ()
    assert candidate.missing_evidence == ()

    with pytest.raises(ValidationError, match="must not contain evidence artifacts"):
        _candidate(result=AssessmentResult.NOT_APPLICABLE)


def test_candidate_rejects_evidence_from_a_different_scan() -> None:
    other_scan_artifact = _artifact(scan_id=UUID("c93346ce-df33-58ea-9602-4353216da95a"))

    with pytest.raises(ValidationError, match="evidence scan_id must match"):
        _candidate(evidence_artifacts=(other_scan_artifact,))


def test_candidate_rejects_evidence_for_a_different_target() -> None:
    other_resource_artifact = _artifact(aws_resource_id="sg-0fedcba9876543210")

    with pytest.raises(ValidationError, match="evidence aws_resource_id must match"):
        _candidate(evidence_artifacts=(other_resource_artifact,))


def test_assessment_models_are_frozen_and_forbid_extra_fields() -> None:
    candidate = _candidate()

    with pytest.raises(ValidationError, match="frozen"):
        candidate.reason = "changed"

    payload = candidate.model_dump()
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AssessmentCandidate.model_validate(payload)
