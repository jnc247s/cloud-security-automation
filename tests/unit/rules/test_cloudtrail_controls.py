"""Canonical LOG-002/003 truth tables through real retained sources and engine validation."""

import json

import pytest
from pydantic import ValidationError

from app.assessment.cloudtrail_controls import cloudtrail_contract
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import ExecutionContract
from app.assessment.models import AssessmentResult as R
from app.rules.cloudtrail import CloudTrailRule, selector_coverage
from app.rules.engine import RuleEngine
from app.rules.registry import RuleRegistry, resolve_catalog
from tests.cloudtrail_fixtures import cloudtrail_provider, logging_bundle, logging_profile, results
from tests.fakes import client_error

DENIED = client_error("AccessDenied", "GetEventSelectors")


def advanced(*fields):
    return {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}, *fields]}


CASES = [
    ({}, R.PASS),
    ({"multi": False}, R.FAIL),
    ({"logging": False}, R.FAIL),
    ({"basic": [{"IncludeManagementEvents": False}]}, R.FAIL),
    ({"basic": [{"ReadWriteType": "ReadOnly"}]}, R.FAIL),
    ({"basic": [{"ReadWriteType": "WriteOnly"}]}, R.FAIL),
    ({"basic": [{"ReadWriteType": "ReadOnly"}, {"ReadWriteType": "WriteOnly"}]}, R.PASS),
    ({"basic": [{"ExcludeManagementEventSources": ["kms.amazonaws.com"]}]}, R.FAIL),
    (
        {
            "basic": [
                {"ExcludeManagementEventSources": ["kms.amazonaws.com"]},
                {"ExcludeManagementEventSources": ["rdsdata.amazonaws.com"]},
            ]
        },
        R.PASS,
    ),
    (
        {
            "basic": [
                {
                    "ReadWriteType": "ReadOnly",
                    "ExcludeManagementEventSources": ["kms.amazonaws.com"],
                },
                {
                    "ReadWriteType": "WriteOnly",
                    "ExcludeManagementEventSources": ["rdsdata.amazonaws.com"],
                },
            ]
        },
        R.FAIL,
    ),
    ({"advanced": [advanced()]}, R.PASS),
    ({"advanced": [advanced({"Field": "readOnly", "Equals": ["true"]})]}, R.FAIL),
    ({"advanced": [advanced({"Field": "readOnly", "Equals": ["false"]})]}, R.FAIL),
    ({"advanced": [advanced({"Field": "readOnly", "Equals": ["true", "false"]})]}, R.PASS),
    (
        {
            "advanced": [
                advanced({"Field": "readOnly", "Equals": ["true"]}),
                advanced({"Field": "readOnly", "Equals": ["false"]}),
            ]
        },
        R.PASS,
    ),
    (
        {"advanced": [advanced({"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]})]},
        R.INSUFFICIENT_EVIDENCE,
    ),
    (
        {
            "advanced": [
                advanced({"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]}),
                advanced(),
            ]
        },
        R.PASS,
    ),
    (
        {
            "advanced": [
                {"FieldSelectors": [{"Field": "eventCategory", "StartsWith": ["Management"]}]}
            ]
        },
        R.INSUFFICIENT_EVIDENCE,
    ),
    ({"advanced": [advanced({"Field": "readOnly", "Equals": ["TRUE"]})]}, R.INSUFFICIENT_EVIDENCE),
    (
        {"basic": [{"ExcludeManagementEventSources": ["unknown.amazonaws.com"]}]},
        R.INSUFFICIENT_EVIDENCE,
    ),
    (
        {"basic": [{"ExcludeManagementEventSources": ["kms.amazonaws.com", "kms.amazonaws.com"]}]},
        R.INSUFFICIENT_EVIDENCE,
    ),
    ({"basic": [{"ExcludeManagementEventSources": [None]}]}, R.INSUFFICIENT_EVIDENCE),
    ({"omit": ("IsMultiRegionTrail",)}, R.INSUFFICIENT_EVIDENCE),
    ({"omit": ("IsOrganizationTrail",)}, R.INSUFFICIENT_EVIDENCE),
    ({"selector_error": DENIED}, R.INSUFFICIENT_EVIDENCE),
    (
        {"selector_response": {"EventSelectors": [{}], "AdvancedEventSelectors": [advanced()]}},
        R.INSUFFICIENT_EVIDENCE,
    ),
]


@pytest.mark.parametrize("spec,expected", CASES)
def test_coverage_truth_table(spec, expected):
    bundle = logging_bundle(specs=[spec])
    assert results(bundle)["LOG-002"] is expected
    account = next(a for a in bundle["assessments"] if a.control_id == "LOG-002")
    assert account.service == "cloudtrail" and account.resource_type == "aws_account"
    assert account.account_id == bundle["snapshot"].account_id
    assert account.region is None


@pytest.mark.parametrize("field", ["configuration_error", "status_error", "selector_error"])
def test_required_failure_outranks_qualifying_sibling(field):
    assert (
        results(logging_bundle(specs=[{}, {field: DENIED}]))["LOG-002"] is R.INSUFFICIENT_EVIDENCE
    )


def test_unknown_restricting_sibling_does_not_hide_independent_coverage():
    restricted = {
        "advanced": [advanced({"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]})]
    }
    assert results(logging_bundle(specs=[{}, restricted]))["LOG-002"] is R.PASS
    assert (
        results(logging_bundle(specs=[{"multi": False}, restricted]))["LOG-002"]
        is R.INSUFFICIENT_EVIDENCE
    )


def test_separate_trails_cannot_union_partial_read_and_write():
    bundle = logging_bundle(
        specs=[
            {"basic": [{"ReadWriteType": "ReadOnly"}]},
            {"basic": [{"ReadWriteType": "WriteOnly"}]},
        ]
    )
    assert results(bundle)["LOG-002"] is R.FAIL


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, R.PASS),
        (False, R.FAIL),
        (None, R.INSUFFICIENT_EVIDENCE),
        ("true", R.INSUFFICIENT_EVIDENCE),
    ],
)
def test_integrity_requires_explicit_boolean(value, expected):
    assert results(logging_bundle(specs=[{"validation": value}]))["LOG-003"] is expected


def test_empty_differs_from_failed_discovery():
    assert results(logging_bundle(empty=True)) == {"LOG-002": R.FAIL, "LOG-003": R.NOT_APPLICABLE}
    assert set(results(logging_bundle(discovery_error=DENIED)).values()) == {
        R.INSUFFICIENT_EVIDENCE
    }


def test_integrity_source_isolation_and_per_trail_targets():
    bundle = logging_bundle(
        specs=[{"selector_error": DENIED}, {"status_error": DENIED}], tag_error=DENIED
    )
    integrity = [a for a in bundle["assessments"] if a.control_id == "LOG-003"]
    assert len(integrity) == 2 and all(a.result is R.PASS for a in integrity)
    assert all(a.resource_type == "cloudtrail_trail" for a in integrity)
    assert results(bundle)["LOG-002"] is R.INSUFFICIENT_EVIDENCE


def test_tags_do_not_decide_coverage_and_default_presence_is_retained():
    bundle = logging_bundle(specs=[{}], tag_error=DENIED)
    assert set(results(bundle).values()) == {R.PASS}
    proof = bundle["assessments"][0].evidence_artifacts[0].payload["source_proof"]
    basic = proof["cloudtrail"]["trails"][0]["event_selectors"]["basic_selectors"][0]
    assert set(basic["raw_presence"].values()) == {False}
    assert basic["include_management_events"] is True and basic["read_write_type"] == "All"


def test_unadmitted_external_owner_is_not_empty_coverage():
    bundle = logging_bundle(specs=[{"owner": "210987654321", "organization": True}])
    assert set(results(bundle).values()) == {R.INSUFFICIENT_EVIDENCE}


def test_exact_home_regions_deterministic_replay_and_no_second_aws_calls():
    provider = cloudtrail_provider(specs=[{}, {"home": "eu-west-1"}])
    bundle = logging_bundle(provider=provider)
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.11.0")
    before = [
        (key, len(client.calls), len(client.paginator_requests))
        for key, client in provider._clients.items()
    ]
    reordered = bundle["snapshot"].model_copy(
        update={"resources": tuple(reversed(bundle["snapshot"].resources))}
    )
    engine = RuleEngine(RuleRegistry(reversed(registry.rules)), catalog=catalog)
    assert engine.assess(reordered, bundle["profile"]) == bundle["assessments"]
    assert before == [
        (key, len(client.calls), len(client.paginator_requests))
        for key, client in provider._clients.items()
    ]
    assert {a.region for a in bundle["assessments"] if a.control_id == "LOG-003"} == {
        "us-east-1",
        "eu-west-1",
    }


def test_versioned_registration_preserves_prior_definitions_and_defaults():
    old, _ = resolve_catalog("aws-cloud-security-controls", "0.10.0")
    new, registry = resolve_catalog(old.catalog_id, "0.11.0")
    assert {c.control_id for c in new.controls} - {c.control_id for c in old.controls} == {
        "LOG-002",
        "LOG-003",
    }
    assert {r.control_id for r in registry.rules} == {c.control_id for c in new.controls}
    assert all(new.get(c.control_id).model_dump_json() == c.model_dump_json() for c in old.controls)
    assert new.framework_catalogs[:-1] == old.framework_catalogs
    default, _ = resolve_catalog(old.catalog_id, "0.2.1")
    assert len(default.controls) == 5 and "LOG-004" not in {c.control_id for c in new.controls}
    with pytest.raises(ValueError, match="unsupported"):
        resolve_catalog(old.catalog_id, "0.12.0")
    with pytest.raises(ValueError, match="explicit"):
        CloudTrailRule("LOG-002").evaluate(logging_bundle()["snapshot"])


@pytest.mark.parametrize(
    "update",
    [
        {"schema_version": "1.7.0"},
        {"target_kind": "regional_account"},
        {"account_service": "s3"},
        {"validation_strategy": "s3_exposure_v1"},
    ],
)
def test_execution_schema_is_closed(update):
    document = cloudtrail_contract("LOG-002").technical.execution_contract.model_dump()
    with pytest.raises(ValidationError):
        ExecutionContract.model_validate({**document, **update})


def test_missing_graph_and_disabled_controls_fail_closed():
    bundle = logging_bundle(specs=[{}])
    snapshot = bundle["snapshot"].model_copy(update={"evidence_graph": None})
    rule = CloudTrailRule("LOG-002")
    assert rule.assess(snapshot, bundle["profile"])[0].result is R.INSUFFICIENT_EVIDENCE
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.11.0")
    profile = logging_profile(enabled_controls=("LOG-003",))
    assert {
        a.control_id
        for a in RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], profile)
    } == {"LOG-003"}


def test_malformed_normalized_defaults_cannot_forge_complete_coverage():
    bundle = logging_bundle(specs=[{}])
    selectors = json.loads(bundle["assessments"][0].evidence_artifacts[0].model_dump_json())[
        "payload"
    ]["source_proof"]["cloudtrail"]["trails"][0]["event_selectors"]
    selectors["basic_selectors"][0]["read_write_type"] = "ReadOnly"
    with pytest.raises(IncompleteAssessmentEvidence):
        selector_coverage(selectors)


def test_empty_integrity_fallback_is_bound_to_exact_account_identity():
    from app.assessment.execution import account_target

    bundle = logging_bundle(empty=True)
    contract = cloudtrail_contract("LOG-003").technical.execution_contract
    target = account_target(bundle["snapshot"], contract).model_copy(
        update={"account_id": "210987654321", "aws_resource_id": "210987654321"}
    )
    with pytest.raises(IncompleteAssessmentEvidence):
        AssessmentEvidenceReader(bundle["snapshot"]).proof(contract, target)


def _snapshot_with_configuration_value(bundle, path, value):
    trail = next(r for r in bundle["snapshot"].resources if r.resource_type == "cloudtrail_trail")
    configuration = json.loads(trail.model_dump_json())["configuration"]
    node = configuration
    for segment in path[:-1]:
        node = node[segment]
    node[path[-1]] = value
    replacement = trail.model_copy(update={"configuration": configuration})
    return bundle["snapshot"].model_copy(
        update={
            "resources": tuple(
                replacement if r.identity == trail.identity else r
                for r in bundle["snapshot"].resources
            )
        }
    )


@pytest.mark.parametrize(
    "field,spec_field,control_id",
    [
        ("is_multi_region_trail", "multi", "LOG-002"),
        ("is_organization_trail", "organization", "LOG-002"),
        ("is_logging", "logging", "LOG-002"),
        ("log_file_validation_enabled", "validation", "LOG-003"),
    ],
)
@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("numeric_type", [int, float])
def test_numeric_boolean_projection_is_insufficient(
    field, spec_field, control_id, value, numeric_type
):
    bundle = logging_bundle(specs=[{spec_field: value}])
    snapshot = _snapshot_with_configuration_value(bundle, (field,), numeric_type(value))
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.11.0")
    assessed = RuleEngine(registry, catalog=catalog).assess(snapshot, bundle["profile"])
    actual = {a.control_id: a.result for a in assessed}
    assert actual[control_id] is R.INSUFFICIENT_EVIDENCE
    other = "LOG-003" if control_id == "LOG-002" else "LOG-002"
    assert actual[other] is results(bundle)[other]


@pytest.mark.parametrize(
    "path,value",
    [
        (("event_selectors", "basic_selectors", 0, "include_management_events"), True),
        (
            ("event_selectors", "basic_selectors", 0, "raw_presence", "include_management_events"),
            False,
        ),
    ],
)
@pytest.mark.parametrize("numeric_type", [int, float])
def test_numeric_nested_selector_projection_is_insufficient(path, value, numeric_type):
    bundle = logging_bundle(specs=[{}])
    snapshot = _snapshot_with_configuration_value(bundle, path, numeric_type(value))
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.11.0")
    assessed = RuleEngine(registry, catalog=catalog).assess(snapshot, bundle["profile"])
    assert {a.control_id: a.result for a in assessed} == {
        "LOG-002": R.INSUFFICIENT_EVIDENCE,
        "LOG-003": R.PASS,
    }
