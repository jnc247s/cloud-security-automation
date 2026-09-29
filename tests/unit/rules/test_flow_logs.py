"""NET-006 applicability, exact graph coverage and evidence failure truth table."""

import pytest
from pydantic import ValidationError

from app.assessment.models import AssessmentResult as R
from app.assessment.relationships import RelationshipType
from app.rules.registry import build_default_registry, resolve_catalog
from tests.fakes import client_error
from tests.flow_log_fixtures import flow_bundle, flow_profile
from tests.network_control_fixtures import network_snapshot
from tests.unit.collectors.test_network import _flow_log, _vpc


@pytest.mark.parametrize(
    "traffic,result", [("ALL", R.PASS), ("REJECT", R.PASS), ("ACCEPT", R.FAIL)]
)
def test_traffic_policy(traffic, result):
    log = _flow_log()
    log["TrafficType"] = traffic
    (assessment,) = flow_bundle(flow_logs=[log])["assessments"]
    assert assessment.result is result
    proof = assessment.evidence_artifacts[0].payload["source_proof"]
    assert len(proof["relationship_observation_ids"]) == 1
    assert len(proof["vpc_flow_logs"]["flow_logs"]) == 1


@pytest.mark.parametrize(
    "environment,result",
    [
        ("production", R.FAIL),
        ("Production", R.NOT_APPLICABLE),
        ("development", R.NOT_APPLICABLE),
        ("", R.INSUFFICIENT_EVIDENCE),
        ("   ", R.INSUFFICIENT_EVIDENCE),
        (None, R.INSUFFICIENT_EVIDENCE),
    ],
)
def test_environment_is_explicit_case_sensitive(environment, result):
    vpc = _vpc()
    vpc["Tags"] = [] if environment is None else [{"Key": "Environment", "Value": environment}]
    (assessment,) = flow_bundle(vpcs=[vpc])["assessments"]
    assert assessment.result is result


@pytest.mark.parametrize(
    "resource_id",
    [
        "subnet-0123456789abcdef0",
        "eni-0123456789abcdef0",
        "tgw-0123456789abcdef0",
        "vpc-aaaaaaaaaaaaaaaaa",
    ],
)
def test_other_resource_logs_do_not_satisfy_vpc(resource_id):
    (assessment,) = flow_bundle(flow_logs=[_flow_log(resource_id=resource_id)])["assessments"]
    assert assessment.result is R.FAIL
    assert (
        assessment.evidence_artifacts[0].payload["source_proof"]["relationship_observation_ids"]
        == []
    )


@pytest.mark.parametrize(
    "source,result",
    [
        ("flow_error", R.INSUFFICIENT_EVIDENCE),
        ("vpc_error", R.INSUFFICIENT_EVIDENCE),
        ("subnet_error", R.PASS),
        ("group_error", R.PASS),
    ],
)
def test_required_and_unrelated_source_failures(source, result):
    (assessment,) = flow_bundle(
        flow_logs=[_flow_log()], **{source: client_error("AccessDenied", "offline")}
    )["assessments"]
    assert assessment.result is result


def test_complete_empty_vpcs_is_not_applicable():
    (assessment,) = flow_bundle(vpcs=[], groups=[])["assessments"]
    assert assessment.result is R.NOT_APPLICABLE


def test_cross_owner_bare_id_cannot_satisfy_coverage():
    (assessment,) = flow_bundle(vpcs=[_vpc(owner_id="210987654321")], flow_logs=[_flow_log()])[
        "assessments"
    ]
    assert assessment.result is R.INSUFFICIENT_EVIDENCE


def test_missing_relationship_is_insufficient_not_false_failure():
    snapshot = network_snapshot(flow_logs=[_flow_log()])
    snapshot = snapshot.model_copy(
        update={
            "evidence_graph": snapshot.evidence_graph.model_copy(
                update={
                    "relationships": tuple(
                        edge
                        for edge in snapshot.evidence_graph.relationships
                        if edge.relationship_type is not RelationshipType.HAS_FLOW_LOG
                    )
                }
            )
        }
    )
    (assessment,) = flow_bundle(snapshot=snapshot)["assessments"]
    assert assessment.result is R.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    "field", ["vpc_flow_log_required_environments", "acceptable_vpc_flow_log_traffic_types"]
)
@pytest.mark.parametrize("value", [None, ()])
def test_missing_or_empty_policy_rejected(field, value):
    with pytest.raises(ValidationError):
        flow_profile(**{field: value})


@pytest.mark.parametrize(
    "mutation",
    [
        {"FlowLogStatus": "PENDING"},
        {"TrafficType": "INVALID"},
        {"LogDestinationType": None},
    ],
)
def test_malformed_log_fails_safely(mutation):
    log = _flow_log()
    log.update(mutation)
    (assessment,) = flow_bundle(flow_logs=[log])["assessments"]
    assert assessment.result is R.INSUFFICIENT_EVIDENCE


def test_order_independent_proof_and_mixed_logs():
    first, second = _flow_log(), _flow_log("fl-aaaaaaaaaaaaaaaaa")
    first["TrafficType"] = "ACCEPT"
    snapshot = network_snapshot(flow_logs=[first, second])
    reordered = snapshot.model_copy(
        update={
            "resources": tuple(reversed(snapshot.resources)),
            "evidence_graph": snapshot.evidence_graph.model_copy(
                update={
                    "relationships": tuple(reversed(snapshot.evidence_graph.relationships)),
                }
            ),
        }
    )
    (original,) = flow_bundle(snapshot=snapshot)["assessments"]
    (repeated,) = flow_bundle(snapshot=reordered)["assessments"]
    assert original.result is repeated.result is R.PASS
    # The raw inventory digest retains accepted graph-order semantics; the proof does not.
    assert original.evidence_artifacts[0].payload == repeated.evidence_artifacts[0].payload


def test_previous_catalog_and_defaults_unchanged():
    previous, _ = resolve_catalog("aws-cloud-security-controls", "0.6.0")
    current, _ = resolve_catalog("aws-cloud-security-controls", "0.7.0")
    assert tuple(c for c in current.controls if c.control_id != "NET-006") == previous.controls
    assert "NET-006" not in {r.control_id for r in build_default_registry().rules}
