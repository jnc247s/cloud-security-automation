"""GOV-001 exact keys, complete-source boundaries, deterministic targets and opt-in metadata."""

import pytest

from app.assessment.extended_profiles import GOVERNED_RESOURCE_TYPES
from app.assessment.models import AssessmentResult as R
from app.assessment.provenance import control_catalog_sha256
from app.rules.engine import RuleEngine
from app.rules.governance import RequiredTagsRule
from app.rules.registry import RuleRegistry, resolve_catalog
from tests.governance_fixtures import DEFAULT_TAGS, governance_bundle, governance_profile

KINDS = tuple(sorted(GOVERNED_RESOURCE_TYPES))
DISCOVERIES = (
    ("ec2", "describe_instances", "ec2_instance"),
    ("ec2", "describe_volumes", "ebs_volume"),
    ("ec2", "describe_vpcs", "vpc"),
    ("ec2", "describe_subnets", "subnet"),
    ("ec2", "describe_security_groups", "security_group"),
    ("ec2", "describe_flow_logs", "vpc_flow_log"),
    ("s3", "list_buckets", "s3_bucket"),
    ("iam", "list_users", "iam_user"),
    ("iam", "list_roles", "iam_role"),
    ("iam", "list_policies", "iam_customer_managed_policy"),
    ("cloudtrail", "list_trails", "cloudtrail_trail"),
)


def by_type(bundle):
    return {a.resource_type: a for a in bundle["assessments"]}


def test_all_initial_families_use_real_complete_tag_sources():
    bundle = governance_bundle()
    assert set(by_type(bundle)) == set(KINDS)
    assert {a.result for a in bundle["assessments"]} == {R.PASS}
    for assessment in bundle["assessments"]:
        proof = assessment.evidence_artifacts[0].payload["source_proof"]
        assert proof["schema_version"] == "1.10.0"
        assert proof["profile_checksum"] == bundle["profile"].content_checksum
        assert proof["relationship_observation_ids"] == []
        assert len(proof["sources"]) == (12 if assessment.service == "ec2" else 13)
        assert proof["governance"]["tags"] == [
            {"key_utf8_hex": k.encode().hex(), "value_utf8_hex": v.encode().hex()}
            for k, v in sorted(DEFAULT_TAGS.items())
        ]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "tags",
    [
        {},
        {"Owner": "platform"},
        {"owner": "platform", "Environment": "production"},
        {"aws:Owner": "platform", "Environment": "production"},
        {"Owner": "", "Environment": "production"},
        {"Owner": " \t\n", "Environment": "production"},
    ],
)
def test_complete_missing_or_unusable_required_tags_fail(kind, tags):
    assessments = by_type(governance_bundle(tags={kind: tags}))
    assert assessments[kind].result is R.FAIL
    assert {a.result for key, a in assessments.items() if key != kind} == {R.PASS}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("owner", [" Platform \t", " équipe/所有者 "])
def test_case_and_nonblank_value_whitespace_are_preserved(kind, owner):
    tags = {"Owner": owner, "Environment": "Production "}
    assessment = by_type(governance_bundle(tags={kind: tags}))[kind]
    assert assessment.result is R.PASS
    assert assessment.evidence_artifacts[0].payload["source_proof"]["governance"]["tags"] == [
        {"key_utf8_hex": k.encode().hex(), "value_utf8_hex": v.encode().hex()}
        for k, v in sorted(tags.items())
    ]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "tags",
    [
        None,
        [{"Key": "Owner", "Value": None}],
        [{"Key": "Owner", "Value": 1}],
        [{"Key": "Owner", "Value": "a"}, {"Key": "Owner", "Value": "b"}],
    ],
)
def test_malformed_raw_tag_sources_never_pass(kind, tags):
    bundle = governance_bundle(tags={kind: tags})
    target = by_type(bundle).get(kind)
    # Embedded malformed EC2 tags quarantine admission; the missing population is not PASS.
    assert target is None or target.result is R.INSUFFICIENT_EVIDENCE
    if target is not None:
        assert not target.evidence_artifacts
    if target is None:
        assert {a.result for a in bundle["assessments"]} == {R.INSUFFICIENT_EVIDENCE}


@pytest.mark.parametrize(
    "service,operation,kind",
    [
        ("ec2", "describe_instances", "ec2_instance"),
        ("ec2", "describe_volumes", "ebs_volume"),
        ("ec2", "describe_vpcs", "vpc"),
        ("ec2", "describe_subnets", "subnet"),
        ("ec2", "describe_security_groups", "security_group"),
        ("ec2", "describe_flow_logs", "vpc_flow_log"),
        ("s3", "get_bucket_tagging", "s3_bucket"),
        ("iam", "list_user_tags", "iam_user"),
        ("iam", "list_role_tags", "iam_role"),
        ("iam", "list_policy_tags", "iam_customer_managed_policy"),
        ("cloudtrail", "list_tags", "cloudtrail_trail"),
    ],
)
def test_required_source_failure_is_not_a_tag_failure_or_pass(service, operation, kind):
    bundle = governance_bundle(error_operation=(service, operation))
    target = by_type(bundle).get(kind)
    assert target is None or target.result is R.INSUFFICIENT_EVIDENCE
    assert not any(
        a.resource_type == kind and a.result in {R.PASS, R.FAIL} for a in bundle["assessments"]
    )
    if operation.startswith("describe_"):
        assert {a.result for a in bundle["assessments"]} == {R.INSUFFICIENT_EVIDENCE}


def test_profile_subset_is_explicit_and_other_known_types_are_na():
    bundle = governance_bundle(profile=governance_profile(governed_resource_types=("s3_bucket",)))
    assert by_type(bundle)["s3_bucket"].result is R.PASS
    assert {a.result for a in bundle["assessments"] if a.resource_type != "s3_bucket"} == {
        R.NOT_APPLICABLE
    }
    assert all(
        not a.evidence_artifacts for a in bundle["assessments"] if a.result is R.NOT_APPLICABLE
    )


def test_complete_empty_population_and_failed_empty_discovery():
    complete = governance_bundle(empty=True)
    assert [(a.resource_type, a.service, a.result) for a in complete["assessments"]] == [
        ("aws_account", "iam", R.NOT_APPLICABLE)
    ]
    failed = governance_bundle(empty=True, error_operation=("ec2", "describe_subnets"))
    assert [a.result for a in failed["assessments"]] == [R.INSUFFICIENT_EVIDENCE]
    subset = governance_bundle(
        empty=True,
        error_operation=("ec2", "describe_subnets"),
        profile=governance_profile(governed_resource_types=("s3_bucket",)),
    )
    assert [a.result for a in subset["assessments"]] == [R.NOT_APPLICABLE]


def test_ungoverned_target_is_na_even_when_governed_sources_fail():
    bundle = governance_bundle(
        profile=governance_profile(governed_resource_types=("s3_bucket",)),
        error_operation=("s3", "get_bucket_tagging"),
    )
    assert by_type(bundle)["s3_bucket"].result is R.INSUFFICIENT_EVIDENCE
    assert {a.result for a in bundle["assessments"] if a.resource_type != "s3_bucket"} == {
        R.NOT_APPLICABLE
    }


@pytest.mark.parametrize("service,operation,kind", DISCOVERIES)
def test_ungoverned_targets_cannot_hide_failed_governed_coverage(service, operation, kind):
    bundle = governance_bundle(
        profile=governance_profile(governed_resource_types=(kind,)),
        error_operation=(service, operation),
    )
    assessments = by_type(bundle)
    if kind == "iam_customer_managed_policy":
        # An attached policy can still be independently admitted by GetPolicy even
        # when ListPolicies fails. Preserve that target and its insufficient result.
        assert assessments[kind].result is R.INSUFFICIENT_EVIDENCE
        assert "aws_account" not in assessments
        coverage_target = kind
    else:
        assert kind not in assessments
        assert assessments["aws_account"].result is R.INSUFFICIENT_EVIDENCE
        assert assessments["aws_account"].service == "iam"
        coverage_target = "aws_account"
    assert len(assessments) > 1
    assert {a.result for k, a in assessments.items() if k != coverage_target} == {R.NOT_APPLICABLE}
    assert not any(a.evidence_artifacts for a in assessments.values())


@pytest.mark.parametrize("kind", ["s3_bucket", "ec2_instance"])
def test_ungoverned_targets_and_complete_empty_governed_discovery_are_explicit_na(kind):
    bundle = governance_bundle(
        profile=governance_profile(governed_resource_types=(kind,)), empty_family=kind
    )
    assessments = by_type(bundle)
    assert kind not in assessments and len(assessments) > 1
    assert assessments["aws_account"].service == "iam"
    assert {a.result for a in assessments.values()} == {R.NOT_APPLICABLE}
    assert not any(a.evidence_artifacts for a in assessments.values())
    assert tuple(a.identity for a in bundle["assessments"]) == tuple(
        sorted(a.identity for a in bundle["assessments"])
    )


def test_missing_governed_discovery_rejects_forged_account_na_with_ungoverned_targets():
    from app.assessment.evidence_reader import AssessmentEvidenceReader
    from app.assessment.governance_evidence import GOVERNANCE_SOURCES_BY_TYPE

    bundle = governance_bundle(
        profile=governance_profile(governed_resource_types=("s3_bucket",)),
        empty_family="s3_bucket",
    )
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    required = GOVERNANCE_SOURCES_BY_TYPE["s3_bucket"][0]
    reader._sources.pop((required.collector, required.evidence_kind, required.source_api))
    candidate = by_type(bundle)["aws_account"]
    contract = bundle["catalog"].get("GOV-001").technical.execution_contract
    with pytest.raises(ValueError, match="incomplete required sources"):
        reader.validate_candidate(contract, candidate, profile=bundle["profile"])
    reader.validate_candidate(
        contract,
        candidate.model_copy(
            update={"result": R.INSUFFICIENT_EVIDENCE, "missing_evidence": ("gap",)}
        ),
        profile=bundle["profile"],
    )


@pytest.mark.parametrize("instance_count", [1, 2, 4, 8, 16])
def test_governed_population_validation_is_constant_per_engine_reader(monkeypatch, instance_count):
    from collections import Counter

    from app.assessment import governance_evidence
    from app.assessment.evidence_reader import AssessmentEvidenceReader

    bundle = governance_bundle(instance_count=instance_count)
    assert len(bundle["assessments"]) == instance_count + 10
    calls, indexes = [], []
    original = governance_evidence._population
    original_index = AssessmentEvidenceReader.governance_resource_families

    def population(reader, family, target, citations):
        calls.append((reader, family.resource_type))
        return original(reader, family, target, citations)

    def index(reader):
        if reader._governance_resource_families is None:
            indexes.append(reader)
        return original_index(reader)

    monkeypatch.setattr(governance_evidence, "_population", population)
    monkeypatch.setattr(AssessmentEvidenceReader, "governance_resource_families", index)
    _, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.13.0")
    assert (
        RuleEngine(registry, catalog=bundle["catalog"]).assess(
            bundle["snapshot"], bundle["profile"]
        )
        == bundle["assessments"]
    )
    assert len(calls) == 22
    assert set(Counter(calls).values()) == {1}
    assert len(indexes) == len(set(indexes)) == 2


def test_cached_population_is_private_immutable_and_bound_to_fresh_policy(monkeypatch):
    from app.assessment import governance_evidence
    from app.assessment.evidence_reader import AssessmentEvidenceReader

    bundle = governance_bundle()
    snapshot, profile = bundle["snapshot"], bundle["profile"]
    before = snapshot.model_dump_json()
    reader = AssessmentEvidenceReader(snapshot)
    target = next(r for r in reader.snapshot.resources if r.resource_type == "s3_bucket")
    contract = bundle["catalog"].get("GOV-001").technical.execution_contract
    calls = []
    original = governance_evidence._population

    def population(*args):
        calls.append(args[1].resource_type)
        return original(*args)

    monkeypatch.setattr(governance_evidence, "_population", population)
    proof = reader.proof(contract, target, profile=profile)
    assert snapshot.model_dump_json() == before and len(calls) == 11
    proof["sources"][0]["artifact_id"] = "substituted"
    rebound = reader.proof(contract, target, profile=profile)
    assert rebound["sources"][0]["artifact_id"] != "substituted" and len(calls) == 11
    for field in ("tags", "configuration", "raw_configuration"):
        with pytest.raises(TypeError):
            getattr(target, field)["substituted"] = True
    original_target = next(r for r in snapshot.resources if r.resource_type == "s3_bucket")
    original_target.tags["Owner"] = "substituted"
    assert reader.proof(contract, target, profile=profile) == rebound
    with pytest.raises(ValueError):
        AssessmentEvidenceReader(snapshot)
    stale = profile.model_copy(update={"required_tags": ("Other",)})
    with pytest.raises(ValueError, match="exact explicit"):
        reader.proof(contract, target, profile=stale)
    subset = governance_profile(governed_resource_types=("s3_bucket",))
    subset_proof = reader.proof(contract, target, profile=subset)
    assert len(calls) == 12 and len(subset_proof["sources"]) == 3
    assert subset_proof["profile_checksum"] == subset.content_checksum
    fresh = AssessmentEvidenceReader(
        bundle["snapshot"].model_copy(update={"resources": reader.snapshot.resources})
    )
    fresh_target = next(r for r in fresh.snapshot.resources if r.resource_type == "s3_bucket")
    assert fresh.proof(contract, fresh_target, profile=profile) == rebound
    assert len(calls) == 23


def test_failed_population_is_cached_without_affecting_ungoverned_na(monkeypatch):
    from app.assessment import governance_evidence
    from app.assessment.evidence_reader import AssessmentEvidenceReader

    bundle = governance_bundle(error_operation=("s3", "list_buckets"))
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    contract = bundle["catalog"].get("GOV-001").technical.execution_contract
    calls = []
    original = governance_evidence._population

    def population(*args):
        calls.append(args[1].resource_type)
        return original(*args)

    monkeypatch.setattr(governance_evidence, "_population", population)
    for candidate in bundle["assessments"]:
        reader.validate_candidate(contract, candidate, profile=bundle["profile"])
    assert calls and len(calls) == len(set(calls)) <= 11
    subset = governance_profile(governed_resource_types=("s3_bucket",))
    target = next(r for r in reader.snapshot.resources if r.resource_type == "ec2_instance")
    proof = reader.proof(contract, target, profile=subset)
    assert governance_evidence.governance_result(proof, subset) is R.NOT_APPLICABLE
    assert proof["sources"] == []


def test_required_policy_keys_are_exact_and_reserved_keys_are_ineligible():
    keys = (" Owner ", " Environment ")
    bundle = governance_bundle(
        profile=governance_profile(required_tags=keys),
        tags={kind: dict.fromkeys(keys, " value ") for kind in KINDS},
    )
    assert {a.result for a in bundle["assessments"]} == {R.PASS}
    reserved = governance_bundle(
        profile=governance_profile(required_tags=("aws:Owner",)),
        tags={kind: {"aws:Owner": "platform"} for kind in KINDS},
    )
    assert {a.result for a in reserved["assessments"]} == {R.FAIL}


def test_registration_and_inventory_order_do_not_change_results():
    bundle = governance_bundle(tags={"s3_bucket": {}})
    _, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.13.0")
    reverse = RuleRegistry(reversed(registry.rules))
    snapshot = bundle["snapshot"].model_copy(
        update={"resources": tuple(reversed(bundle["snapshot"].resources))}
    )
    assert (
        RuleEngine(reverse, catalog=bundle["catalog"]).assess(snapshot, bundle["profile"])
        == bundle["assessments"]
    )


def test_old_releases_default_and_catalog_bytes_remain_unchanged():
    previous, old_rules = resolve_catalog("aws-cloud-security-controls", "0.12.0")
    current, rules = resolve_catalog("aws-cloud-security-controls", "0.13.0")
    assert {r.control_id for r in rules.rules} - {r.control_id for r in old_rules.rules} == {
        "GOV-001"
    }
    assert all(current.get(c.control_id) == c for c in previous.controls)
    assert current.framework_catalogs[:-1] == previous.framework_catalogs
    assert control_catalog_sha256(previous) != control_catalog_sha256(current)
    assert resolve_catalog("aws-cloud-security-controls", "0.2.1")[0].version == "0.2.1"
    with pytest.raises(KeyError):
        old_rules.get("GOV-001")
    with pytest.raises(ValueError):
        RequiredTagsRule().evaluate(governance_bundle()["snapshot"])


@pytest.mark.parametrize(
    "kind",
    [
        "absent",
        "ambiguous",
        "version",
        "admission",
        "identity",
        "tags",
        "count_type",
        "discarded_type",
        "schema_version",
        "phase",
    ],
)
def test_closed_source_join_rejects_inconsistent_normalized_facts(kind):
    from app.assessment.evidence_reader import (
        AssessmentEvidenceReader,
        IncompleteAssessmentEvidence,
    )
    from app.assessment.governance_evidence import GOVERNANCE_SOURCES_BY_TYPE

    bundle = governance_bundle()
    reader = AssessmentEvidenceReader(bundle["snapshot"])
    target = next(r for r in reader.snapshot.resources if r.resource_type == "iam_user")
    required = GOVERNANCE_SOURCES_BY_TYPE["iam_user"][
        0 if kind in {"count_type", "discarded_type"} else 2 if kind == "tags" else 1
    ]
    key = (required.collector, required.evidence_kind, required.source_api)
    declaration = next(
        s for s in reader._sources[key] if reader._subject_matches(s.subject, required, target)
    )
    if kind == "absent":
        reader._sources[key] = []
    elif kind == "ambiguous":
        reader._sources[key].append(declaration)
    elif kind in {"version", "admission"}:
        reader._sources[key] = [
            declaration.model_copy(
                update={"contract_version": "9.9.9"}
                if kind == "version"
                else {"identity_authoritative": False}
            )
        ]
    else:
        outcome = reader._outcomes[declaration.source_outcome_id]
        artifact = reader._artifacts[outcome.evidence_reference]
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if kind == "schema_version":
            reader._artifacts[outcome.evidence_reference] = artifact.model_copy(
                update={"evidence_schema_version": "9.9.9"}
            )
        elif kind == "phase":
            from app.assessment.source_outcomes import EvidenceCollectionPhase

            reader._outcomes[declaration.source_outcome_id] = outcome.model_copy(
                update={"phase": EvidenceCollectionPhase.DISCOVERY}
            )
        elif kind == "identity":
            payload["resource_id"] = "other-user"
        elif kind == "tags":
            payload["tags"] = [{"key": "Owner", "value": None}]
        elif kind == "count_type":
            payload["resource_count"] = True
        else:
            payload["discarded_item_count"] = False
        if kind not in {"schema_version", "phase"}:
            reader._artifacts[outcome.evidence_reference] = artifact.model_copy(
                update={"normalized_payload": payload}
            )
    with pytest.raises(IncompleteAssessmentEvidence):
        reader.proof(
            bundle["catalog"].get("GOV-001").technical.execution_contract,
            target,
            profile=bundle["profile"],
        )


def test_rules_make_no_additional_aws_calls():
    from tests.governance_fixtures import governance_provider

    provider = governance_provider()
    bundle = governance_bundle(provider=provider)
    before = [
        (key, len(client.calls), len(client.paginator_requests))
        for key, client in provider._clients.items()
    ]
    _, registry = resolve_catalog(bundle["catalog"].catalog_id, "0.13.0")
    assert (
        RuleEngine(registry, catalog=bundle["catalog"]).assess(
            bundle["snapshot"], bundle["profile"]
        )
        == bundle["assessments"]
    )
    assert before == [
        (key, len(client.calls), len(client.paginator_requests))
        for key, client in provider._clients.items()
    ]


def test_expected_absent_s3_tag_set_is_complete_missing_tag_failure():
    from app.assessment.source_outcomes import EvidenceSourceState
    from tests.fakes import client_error
    from tests.governance_fixtures import governance_provider

    provider = governance_provider()
    provider._clients[("s3", "us-east-1")]._responses["get_bucket_tagging"][0] = client_error(
        "NoSuchTagSet", "GetBucketTagging"
    )
    bundle = governance_bundle(provider=provider)
    assert by_type(bundle)["s3_bucket"].result is R.FAIL
    outcome = next(
        o
        for o in bundle["snapshot"].evidence_graph.source_outcomes
        if o.evidence_kind == "s3.bucket-tags"
    )
    assert outcome.state is EvidenceSourceState.EXPECTED_ABSENCE
