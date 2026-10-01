"""Canonical 6F.2 composition, exact bindings, conservative gaps and historical contracts."""

import pytest

from app.assessment.models import AssessmentResult as R
from app.assessment.provenance import control_catalog_sha256
from app.rules.cloudtrail_destination import CloudTrailDestinationRule
from app.rules.engine import RuleEngine
from app.rules.registry import RuleRegistry, resolve_catalog
from tests.cloudtrail_destination_fixtures import (
    assert_mixed_destination_bindings,
    destination_bundle,
    destination_profile,
    destination_provider,
    mixed_destination_provider,
)
from tests.fakes import client_error
from tests.s3_configuration_fixtures import BUCKET
from tests.s3_exposure_fixtures import policy_response, statement


def destination_results(bundle):
    return [a.result for a in bundle["assessments"] if a.control_id == "LOG-004"]


@pytest.mark.parametrize(
    "public,approved,expected",
    [(False, False, R.PASS), (True, False, R.FAIL), (True, True, R.PASS)],
)
def test_exact_destination_composition(public, approved, expected):
    options = {}
    if public:
        options.update(
            policy_response=policy_response(statement()),
            policy_status_response={"PolicyStatus": {"IsPublic": True}},
        )
    bundle = destination_bundle(
        profile=destination_profile(public=approved, region="eu-west-1"),
        location_constraint="eu-west-1",
        **options,
    )
    assert destination_results(bundle) == [expected]
    dependency = next(a for a in bundle["assessments"] if a.control_id == "S3-002")
    destination = next(a for a in bundle["assessments"] if a.control_id == "LOG-004")
    binding = destination.evidence_artifacts[0].payload["source_proof"]["destination_dependency"]
    assert binding["resource_snapshot_id"] == str(dependency.resource_snapshot_id)
    assert binding["result"] == expected.value
    assert (
        binding["evidence"][0]["payload_sha256"] == dependency.evidence_artifacts[0].payload_sha256
    )
    assert binding["profile_checksum"] == bundle["profile"].content_checksum


def test_disabled_dependency_and_direct_call_fail_closed():
    bundle = destination_bundle(profile=destination_profile(enabled_controls=("LOG-004",)))
    assert destination_results(bundle) == [R.INSUFFICIENT_EVIDENCE]
    assert {a.control_id for a in bundle["assessments"]} == {"LOG-004"}
    valid = destination_bundle()
    assert (
        CloudTrailDestinationRule().assess(valid["snapshot"], valid["profile"])[0].result
        is R.INSUFFICIENT_EVIDENCE
    )


@pytest.mark.parametrize(
    "options",
    [
        {"trail_options": {"discovery_error": client_error("AccessDeniedException", "ListTrails")}},
        {"specs": [{"configuration_updates": {"S3BucketName": "not-collected-bucket"}}]},
        {"specs": [{"omit": ("S3BucketName",)}]},
        {"policy_response": client_error("AccessDenied", "GetBucketPolicy")},
        {"trail_options": {"tag_error": client_error("AccessDeniedException", "ListTags")}},
    ],
)
def test_missing_required_destinations_or_collection(options):
    assert destination_results(destination_bundle(**options)) == [R.INSUFFICIENT_EVIDENCE]


def test_complete_empty_discovery_is_account_na_without_dependency():
    bundle = destination_bundle(
        specs=[], profile=destination_profile(enabled_controls=("LOG-004",))
    )
    assert destination_results(bundle) == [R.NOT_APPLICABLE]
    assert bundle["assessments"][0].resource_type == "aws_account"


def test_shared_bucket_different_home_regions_and_registration_order():
    specs = [
        {"home": home, "configuration_updates": {"S3BucketName": BUCKET}}
        for home in ("us-east-1", "eu-west-1")
    ]
    bundle = destination_bundle(specs=specs)
    assert destination_results(bundle) == [R.PASS, R.PASS]
    _, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.12.0")
    reverse = RuleRegistry(reversed(registry.rules))
    assert (
        RuleEngine(reverse, catalog=bundle["catalog"]).assess(bundle["snapshot"], bundle["profile"])
        == bundle["assessments"]
    )
    assert tuple(a.identity for a in bundle["assessments"]) == tuple(
        sorted(a.identity for a in bundle["assessments"])
    )


def test_mixed_real_bucket_destinations_and_reversed_order():
    bundle = destination_bundle(provider=mixed_destination_provider())
    assert_mixed_destination_bindings(bundle)
    _, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.12.0")
    reversed_snapshot = bundle["snapshot"].model_copy(
        update={"resources": tuple(reversed(bundle["snapshot"].resources))}
    )
    assert (
        RuleEngine(RuleRegistry(reversed(registry.rules)), catalog=bundle["catalog"]).assess(
            reversed_snapshot, bundle["profile"]
        )
        == bundle["assessments"]
    )


@pytest.mark.parametrize("trail_count", [1, 2, 4, 8])
def test_composition_inventory_binding_cost_is_constant(monkeypatch, trail_count):
    from app.assessment import identities

    bundle = destination_bundle(
        specs=[{"configuration_updates": {"S3BucketName": BUCKET}}] * trail_count
    )
    calls = []
    original = identities.inventory_sha256

    def record(snapshot):
        calls.append(snapshot)
        return original(snapshot)

    monkeypatch.setattr(identities, "inventory_sha256", record)
    _, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.12.0")
    assert (
        RuleEngine(registry, catalog=bundle["catalog"]).assess(
            bundle["snapshot"], bundle["profile"]
        )
        == bundle["assessments"]
    )
    # One engine-validation reader and one rule reader, regardless of destination count.
    assert len(calls) == 2
    assert calls[0] is not calls[1]


def test_bound_reader_is_deeply_immutable_and_substituted_readers_fail_closed():
    from app.assessment.composition import validated_context
    from app.assessment.evidence_reader import AssessmentEvidenceReader
    from app.assessment.identities import inventory_sha256

    bundle = destination_bundle()
    original = bundle["snapshot"]
    before = original.model_dump_json()
    reader = AssessmentEvidenceReader(original)
    context = validated_context(reader, bundle["profile"], bundle["catalog"], bundle["assessments"])
    assert context.matches(reader, bundle["profile"])
    assert reader.composition_inventory_sha256() == inventory_sha256(original)
    assert original.model_dump_json() == before
    trail = next(r for r in reader.snapshot.resources if r.resource_type == "cloudtrail_trail")
    with pytest.raises(TypeError):
        trail.configuration["s3_bucket_name"] = "substituted"
    with pytest.raises(TypeError):
        trail.configuration["event_selectors"]["basic_selectors"].append({})
    with pytest.raises(TypeError):
        trail.tags["Owner"] = "substituted"
    with pytest.raises(TypeError):
        trail.raw_configuration["substituted"] = True
    from app.schemas.inventory import CollectionStatus

    substituted = original.model_copy(
        update={
            "collector_outcomes": (
                original.collector_outcomes[0].model_copy(
                    update={"status": CollectionStatus.PARTIAL}
                ),
                *original.collector_outcomes[1:],
            )
        }
    )
    assert not context.matches(AssessmentEvidenceReader(substituted), bundle["profile"])
    # Caller mutation cannot change the private reader. A new reader must bind again.
    original.resources[0].configuration["extra"] = "substituted"
    assert context.matches(reader, bundle["profile"])
    with pytest.raises(ValueError, match="contradicts its source artifacts"):
        AssessmentEvidenceReader(original)
    profile = destination_profile(version="6.9.2")
    assert not context.matches(reader, profile)


def test_closed_metadata_and_historical_bytes():
    old, _ = resolve_catalog("aws-cloud-security-controls", "0.11.0")
    new, _ = resolve_catalog(old.catalog_id, "0.12.0")
    assert all(
        new.get(c.control_id).model_dump(mode="json") == c.model_dump(mode="json")
        for c in old.controls
    )
    assert (
        control_catalog_sha256(old)
        == "b8f65ea1c06dc4a66d7813249798e52dc5c4e6dc37d495f1d103d3d9b7612ce2"
    )
    execution = new.get("LOG-004").technical.execution_contract
    assert execution.assessment_dependencies == ("S3-002",)
    for updates in (
        {"assessment_dependencies": ()},
        {"schema_version": "1.8.0"},
        {"required_relationships": ()},
    ):
        with pytest.raises(ValueError):
            type(execution).model_validate_json(
                execution.model_copy(update=updates).model_dump_json()
            )
    assert "assessment_dependencies" not in old.get(
        "S3-002"
    ).technical.execution_contract.model_dump(mode="json")


@pytest.mark.parametrize(
    "options,dependency_result",
    [
        ({"empty": True}, R.NOT_APPLICABLE),
        (
            {"policy_response": client_error("AccessDenied", "GetBucketPolicy")},
            R.INSUFFICIENT_EVIDENCE,
        ),
        (
            {
                "policy_response": policy_response(statement()),
                "policy_status_response": {"PolicyStatus": {"IsPublic": True}},
                "acl_response": client_error("AccessDenied", "GetBucketAcl"),
            },
            R.FAIL,
        ),
    ],
)
def test_nondecisive_dependency_or_partial_collector_never_composes(options, dependency_result):
    bundle = destination_bundle(**options)
    assert (
        next(a.result for a in bundle["assessments"] if a.control_id == "S3-002")
        is dependency_result
    )
    assert destination_results(bundle) == [R.INSUFFICIENT_EVIDENCE]


def test_no_aws_calls_or_second_dependency_assessment(monkeypatch):
    from app.rules.s3_exposure import S3ExposureRule

    provider = destination_provider()
    bundle = destination_bundle(provider=provider)
    before = [
        (key, len(c.calls), len(c.paginator_requests)) for key, c in provider._clients.items()
    ]
    called = []
    original = S3ExposureRule.assess

    def record(self, snapshot, profile):
        called.append(self.control_id)
        return original(self, snapshot, profile)

    monkeypatch.setattr(S3ExposureRule, "assess", record)
    catalog, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.12.0")
    assert (
        RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], bundle["profile"])
        == bundle["assessments"]
    )
    assert called == ["S3-002"]
    assert before == [
        (key, len(c.calls), len(c.paginator_requests)) for key, c in provider._clients.items()
    ]


@pytest.mark.parametrize("kind", ["missing", "ambiguous", "wrong_provenance", "other_snapshot"])
def test_exact_edge_requirements(kind):
    from uuid import uuid4

    from app.assessment.cloudtrail_destination_evidence import destination_proof
    from app.assessment.composition import validated_context
    from app.assessment.evidence_reader import (
        AssessmentEvidenceReader,
        IncompleteAssessmentEvidence,
    )
    from app.assessment.relationships import RelationshipType

    bundle = destination_bundle()
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    context = validated_context(reader, bundle["profile"], bundle["catalog"], bundle["assessments"])
    target = next(r for r in reader.snapshot.resources if r.resource_type == "cloudtrail_trail")
    key = (reader._target_id(target), RelationshipType.DELIVERS_TO_BUCKET)
    edge = reader._edges[key][0]
    if kind == "missing":
        reader._edges[key] = []
    elif kind == "ambiguous":
        reader._edges[key] = [edge, edge]
    elif kind == "other_snapshot":
        reader._edges[key] = [
            edge.model_copy(
                update={"target": edge.target.model_copy(update={"resource_snapshot_id": uuid4()})}
            )
        ]
    else:
        other = next(
            o for o in reader.graph.source_outcomes if o.evidence_kind == "cloudtrail.trail.tags"
        )
        provenance = type(edge.provenance)(
            **{field: getattr(other, field) for field in type(edge.provenance).model_fields}
        )
        reader._edges[key] = [edge.model_copy(update={"provenance": provenance})]
    with pytest.raises(IncompleteAssessmentEvidence):
        destination_proof(
            reader,
            bundle["catalog"].get("LOG-004").technical.execution_contract,
            target,
            context=context,
            profile=bundle["profile"],
        )
