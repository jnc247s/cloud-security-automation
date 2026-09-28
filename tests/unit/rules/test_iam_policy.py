"""IAM-004 accepted syntax, coverage, identity and deterministic proof contracts."""

import pytest

from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import ExecutionContract
from app.assessment.iam_policy_control import iam_policy_contract
from app.assessment.models import AssessmentResult
from app.assessment.relationships import RelationshipType
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry, resolve_catalog
from tests.iam_policy_fixtures import policy_bundle, policy_profile, policy_snapshot


@pytest.mark.parametrize(
    "statement,expected",
    [
        ({"Effect": "Allow", "Action": "*", "Resource": "*"}, "FAIL"),
        ({"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}, "FAIL"),
        (
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
            "FAIL",
        ),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, "PASS"),
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, "PASS"),
        ({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::example/*"}, "PASS"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, "PASS"),
        ({"Effect": "Allow", "Action": "*", "NotResource": "example"}, "PASS"),
        ({"Effect": "allow", "Action": "*", "Resource": "*"}, "INSUFFICIENT_EVIDENCE"),
        ({"Effect": "Allow", "Action": [], "Resource": "*"}, "INSUFFICIENT_EVIDENCE"),
        ({"Effect": "Allow", "Action": "*"}, "INSUFFICIENT_EVIDENCE"),
        (
            {"Effect": "Allow", "Action": "*", "NotAction": "*", "Resource": "*"},
            "INSUFFICIENT_EVIDENCE",
        ),
    ],
)
def test_exact_policy_syntax(statement, expected):
    bundle = policy_bundle(document={"Statement": statement})
    assert len(bundle["assessments"]) == 4
    assert {a.result.value for a in bundle["assessments"]} == {expected}


def test_documents_deduplicated_across_attachment_and_boundary_contexts():
    results = policy_bundle(group_inline=True)["assessments"]
    assert len(results) == 5
    assert {a.resource_type for a in results} == {"iam_inline_policy", "iam_managed_policy_version"}
    for a in results:
        fact = a.evidence_artifacts[0].payload["source_proof"]["iam_policy_document"]
        assert fact["resource_snapshot_id"] == str(a.resource_snapshot_id)
        if a.resource_type == "iam_managed_policy_version":
            assert {c["usage"] for c in fact["usage_contexts"]} == {
                "attachment",
                "permissions_boundary",
            }
            assert "version_id" in fact
        else:
            assert "version_id" not in fact
            assert fact["policy_name"] == "Emergency"


def test_boundary_only_is_in_scope_but_never_described_as_effective_access():
    for a in policy_bundle(boundary_only=True)["assessments"]:
        assert a.result is AssessmentResult.FAIL
        assert "effective access is not assessed" in a.reason
        if a.resource_type == "iam_managed_policy_version":
            fact = a.evidence_artifacts[0].payload["source_proof"]["iam_policy_document"]
            assert {c["usage"] for c in fact["usage_contexts"]} == {"permissions_boundary"}


def test_complete_empty_policy_population_is_na():
    (a,) = policy_bundle(empty=True)["assessments"]
    assert a.result is AssessmentResult.NOT_APPLICABLE
    assert a.resource_type == "aws_account" and not a.evidence_artifacts


@pytest.mark.parametrize(
    "operation",
    [
        "list_users",
        "list_groups",
        "list_roles",
        "list_policies",
        "list_user_policies",
        "list_attached_user_policies",
        "get_user",
    ],
)
def test_incomplete_population_or_usage_never_passes(operation):
    results = policy_bundle(error_operation=operation)["assessments"]
    assert results and {a.result for a in results} == {AssessmentResult.INSUFFICIENT_EVIDENCE}


@pytest.mark.parametrize("operation", ["get_policy", "get_policy_version", "get_user_policy"])
def test_missing_document_or_selected_version_remains_explicit(operation):
    results = policy_bundle(error_operation=operation)["assessments"]
    assert len(results) == 4
    assert any(a.result is AssessmentResult.INSUFFICIENT_EVIDENCE for a in results)
    assert any(a.result is AssessmentResult.FAIL for a in results)
    if operation == "get_policy":
        assert any(a.resource_type == "iam_customer_managed_policy" for a in results)


@pytest.mark.parametrize(
    "kind",
    [
        RelationshipType.ATTACHED_MANAGED_POLICY,
        RelationshipType.ATTACHED_INLINE_POLICY,
        RelationshipType.PERMISSIONS_BOUNDARY,
        RelationshipType.SELECTS_DEFAULT_VERSION,
    ],
)
def test_missing_required_edge_fails_safely(kind):
    snapshot = policy_snapshot()
    graph = snapshot.evidence_graph.model_copy(
        update={
            "relationships": tuple(
                e for e in snapshot.evidence_graph.relationships if e.relationship_type != kind
            )
        }
    )
    altered = snapshot.model_copy(update={"evidence_graph": graph})
    reader = AssessmentEvidenceReader(altered)
    target = next(
        r
        for r in snapshot.resources
        if r.resource_type
        == (
            "iam_inline_policy"
            if kind is RelationshipType.ATTACHED_INLINE_POLICY
            else "iam_managed_policy_version"
        )
        and r.account_id == snapshot.account_id
    )
    with pytest.raises(IncompleteAssessmentEvidence):
        reader.proof(iam_policy_contract().technical.execution_contract, target)


def test_reordered_inventory_and_graph_replay_exactly():
    bundle = policy_bundle()
    snapshot = bundle["snapshot"]
    graph = snapshot.evidence_graph.model_copy(
        update={
            field: tuple(reversed(getattr(snapshot.evidence_graph, field)))
            for field in ("source_contracts", "source_outcomes", "artifacts", "relationships")
        }
    )
    shuffled = snapshot.model_copy(
        update={"resources": tuple(reversed(snapshot.resources)), "evidence_graph": graph}
    )
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.4.0")
    engine = RuleEngine(registry, catalog=catalog)
    assert engine.assess(snapshot, policy_profile()) == bundle["assessments"]
    resource_order = snapshot.model_copy(update={"resources": tuple(reversed(snapshot.resources))})
    assert engine.assess(resource_order, policy_profile()) == bundle["assessments"]
    # The established inventory digest retains graph tuple order. Preserve that contract;
    # technical results, canonical proofs, evidence IDs and all other assessment fields match.
    from app.assessment.identities import inventory_sha256

    actual = engine.assess(shuffled, policy_profile())
    assert all(a.inventory_sha256 == inventory_sha256(shuffled) for a in actual)
    assert [a.model_dump(exclude={"inventory_sha256"}) for a in actual] == [
        a.model_dump(exclude={"inventory_sha256"}) for a in bundle["assessments"]
    ]


def test_catalog_additive_and_schema_version_bound():
    old, _ = resolve_catalog("aws-cloud-security-controls", "0.3.0")
    new, registry = resolve_catalog(old.catalog_id, "0.4.0")
    assert len(new.controls) == 10 and len(registry.rules) == 10
    assert [new.get(c.control_id) for c in old.controls] == list(old.controls)
    assert new.framework_catalogs[:-1] == old.framework_catalogs
    assert "IAM-004" not in {r.control_id for r in build_default_registry().rules}
    execution = iam_policy_contract().technical.execution_contract.model_dump(mode="json")
    execution["schema_version"] = "1.1.0"
    with pytest.raises(ValueError):
        ExecutionContract.model_validate(execution)


@pytest.mark.parametrize(
    "document",
    [
        "%NOT-ENCODED",
        {"Statement": []},
        {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": True}},
    ],
)
def test_malformed_or_undecodable_document_is_insufficient(document):
    assert {a.result for a in policy_bundle(document=document)["assessments"]} == {
        AssessmentResult.INSUFFICIENT_EVIDENCE
    }


def test_group_membership_coverage_is_required():
    assert {a.result for a in policy_bundle(error_operation="get_group")["assessments"]} == {
        AssessmentResult.INSUFFICIENT_EVIDENCE
    }


@pytest.mark.parametrize(
    "field,value",
    [("document_sha256", "0" * 64), ("owner_resource_id", "different-owner"), ("policy_name", [])],
)
def test_inline_snapshot_identity_digest_must_match_source(field, value):
    snapshot = policy_snapshot()
    target = next(r for r in snapshot.resources if r.resource_type == "iam_inline_policy")
    altered_target = target.model_copy(
        update={"configuration": {**target.configuration, field: value}}
    )
    altered = snapshot.model_copy(
        update={
            "resources": tuple(
                altered_target if r.identity == target.identity else r for r in snapshot.resources
            )
        }
    )
    reader = AssessmentEvidenceReader(altered)
    with pytest.raises(IncompleteAssessmentEvidence):
        reader.proof(iam_policy_contract().technical.execution_contract, altered_target)


def test_in_scope_document_cannot_be_forged_as_artifact_free_na():
    bundle = policy_bundle()
    a = bundle["assessments"][0].model_copy(
        update={
            "result": AssessmentResult.NOT_APPLICABLE,
            "evidence_artifacts": (),
        }
    )
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    with pytest.raises(ValueError, match="cannot be not applicable"):
        reader.validate_candidate(iam_policy_contract().technical.execution_contract, a)


@pytest.mark.parametrize("action", ["*", "s3:GetObject"])
@pytest.mark.parametrize(
    "condition",
    [
        {"Bool": True},
        {},
        {"Bool": {}},
        {"Bool": {"aws:SecureTransport": None}},
        {"Bool": {"aws:SecureTransport": []}},
        {"StringEquals": {"aws:PrincipalTag/team": {"nested": "value"}}},
    ],
)
def test_malformed_nested_condition_never_has_a_decisive_result(action, condition):
    results = policy_bundle(
        document={
            "Statement": {
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
                "Condition": condition,
            }
        }
    )["assessments"]
    assert len(results) == 4
    assert {a.result for a in results} == {AssessmentResult.INSUFFICIENT_EVIDENCE}


@pytest.mark.parametrize(
    "condition",
    [
        {"Bool": {"aws:SecureTransport": True}},
        {"NumericLessThan": {"s3:max-keys": [10, 20]}},
        {"StringEquals": {"aws:PrincipalTag/team": ["security", "platform"]}},
    ],
)
def test_valid_condition_structure_does_not_erase_literal_match(condition):
    results = policy_bundle(
        document={
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": condition,
            }
        }
    )["assessments"]
    assert {a.result for a in results} == {AssessmentResult.FAIL}
