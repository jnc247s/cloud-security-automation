"""Canonical four-state IAM rules use real normalized collector evidence."""

import json
from datetime import timedelta

import pytest

from app.assessment.controls import build_default_control_catalog
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import ExecutionContract
from app.assessment.iam_controls import iam_execution
from app.assessment.models import AssessmentResult
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.fakes import client_error
from tests.iam_credentials_fixtures import iam_bundle, iam_profile, iam_snapshot


def results(**options):
    return {a.control_id: a.result.value for a in iam_bundle(**options)["assessments"]}


@pytest.mark.parametrize(
    "age,unused,expected",
    [
        (90, 90, "PASS"),
        (91, 91, "FAIL"),
        (90 + 1 / 86400, 90 + 1 / 86400, "FAIL"),
        (1, 1, "PASS"),
    ],
)
def test_exact_age_and_use_threshold(age, unused, expected):
    actual = results(age=age, unused=unused)
    assert actual["IAM-002"] == actual["IAM-003"] == expected


@pytest.mark.parametrize("age,expected", [(90, "PASS"), (91, "FAIL")])
def test_explicit_no_recorded_use_uses_creation_age(age, expected):
    assert results(age=age, unused=None)["IAM-003"] == expected


@pytest.mark.parametrize("options", [{"keys": False}, {"users": False}, {"active": False}])
def test_complete_empty_active_key_population_is_not_applicable(options):
    bundle = iam_bundle(**options)
    for assessment in bundle["assessments"]:
        if assessment.control_id in {"IAM-002", "IAM-003"}:
            assert assessment.result is AssessmentResult.NOT_APPLICABLE
            assert assessment.evidence_artifacts == ()


@pytest.mark.parametrize("root_key,root_mfa,expected", [(0, 1, "PASS"), (1, 0, "FAIL")])
def test_root_flags(root_key, root_mfa, expected):
    actual = results(root_key=root_key, root_mfa=root_mfa)
    assert actual["IAM-005"] == actual["IAM-006"] == expected


@pytest.mark.parametrize("field", ["root_key", "root_mfa"])
@pytest.mark.parametrize("value", [None, "1", True, 2])
def test_malformed_summary_cannot_pass(field, value):
    actual = results(**{field: value})
    assert actual["IAM-005"] == actual["IAM-006"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("field", ["discovery_error", "key_error"])
def test_incomplete_key_population_cannot_be_na_or_pass(field):
    actual = results(**{field: client_error("AccessDenied", "ListAccessKeys")})
    assert actual["IAM-002"] == actual["IAM-003"] == "INSUFFICIENT_EVIDENCE"


def test_usage_failure_does_not_invalidate_key_age():
    actual = results(usage_error=client_error("AccessDenied", "GetAccessKeyLastUsed"))
    assert actual["IAM-002"] == "FAIL"
    assert actual["IAM-003"] == "INSUFFICIENT_EVIDENCE"


def test_unrelated_group_failure_does_not_invalidate_user_evidence():
    assert results(groups_error=client_error("AccessDenied", "ListGroups")) == results()


@pytest.mark.parametrize("age,unused", [(-1, None), (1, -1), (1, 2)])
def test_incoherent_chronology_is_insufficient(age, unused):
    assert results(age=age, unused=unused)["IAM-003"] == "INSUFFICIENT_EVIDENCE"


def test_policies_are_explicit_and_old_catalog_is_unchanged():
    old = build_default_control_catalog()
    new, _ = resolve_catalog(old.catalog_id, "0.3.0")
    assert len(old.controls) == 5 and len(new.controls) == 9
    assert [c.model_dump() for c in old.controls] == [
        new.get(c.control_id).model_dump() for c in old.controls
    ]
    assert old.framework_catalogs[0] == new.framework_catalogs[0]
    document = DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"})
    document["enabled_controls"] = ("IAM-003",)
    with pytest.raises(ValueError, match="explicit policy"):
        new.validate_profile_inputs(AssessmentProfile.model_validate(document))
    with pytest.raises(ValueError):
        iam_profile(max_unused_access_key_days=None)


def test_legacy_execution_schema_cannot_select_joined_strategy():
    document = iam_execution("IAM-002").model_dump(mode="json")
    document["schema_version"] = "1.0.0"

    with pytest.raises(ValueError):
        ExecutionContract.model_validate_json(json.dumps(document))


def test_replay_and_input_order_are_deterministic():
    snapshot = iam_snapshot()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.3.0")
    engine = RuleEngine(registry, catalog=catalog)
    first = engine.assess(snapshot, iam_profile())
    reordered = snapshot.model_copy(update={"resources": tuple(reversed(snapshot.resources))})
    assert engine.assess(reordered, iam_profile()) == first
    assert engine.assess(snapshot, iam_profile()) == first


def test_missing_edge_is_not_proof_of_no_keys():
    snapshot = iam_snapshot()
    graph = snapshot.evidence_graph.model_copy(update={"relationships": ()})
    altered = snapshot.model_copy(update={"evidence_graph": graph})
    reader = AssessmentEvidenceReader(altered)
    user = next(r for r in snapshot.resources if r.resource_type == "iam_user")
    with pytest.raises(IncompleteAssessmentEvidence):
        reader.proof(iam_execution("IAM-002"), user)


def test_age_uses_observation_not_clock():
    bundle = iam_bundle(age=90, unused=90)
    key = next(r for r in bundle["snapshot"].resources if r.resource_type == "iam_access_key")
    from app.assessment.iam_key_evidence import evidence_time

    assert bundle["snapshot"].collected_at - evidence_time(key.configuration["created_at"]) == (
        timedelta(days=90)
    )
    assert all(a.result is AssessmentResult.PASS for a in bundle["assessments"][:2])


@pytest.mark.parametrize("control_id", ["IAM-002", "IAM-003", "IAM-005", "IAM-006"])
def test_shared_validator_rejects_false_iam_non_applicability(control_id):
    bundle = iam_bundle()
    actual = next(a for a in bundle["assessments"] if a.control_id == control_id)
    forged = actual.model_copy(
        update={
            "result": AssessmentResult.NOT_APPLICABLE,
            "evidence_artifacts": (),
        }
    )
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    with pytest.raises(ValueError, match="cannot be not applicable"):
        reader.validate_candidate(iam_execution(control_id), forged)
