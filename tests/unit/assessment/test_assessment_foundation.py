"""Versioned foundation and fail-closed source/target regression tests."""

import json

import pytest
from pydantic import ValidationError

from app.assessment.controls import build_default_control_catalog
from app.assessment.deployment_policy import PolicyConfigurationError
from app.assessment.evidence_reader import AssessmentEvidenceReader, IncompleteAssessmentEvidence
from app.assessment.execution import (
    ExecutionContract,
    ResourceFamily,
    account_target,
    assessment_targets,
    validate_execution_targets,
)
from app.assessment.extended_profiles import validate_profile_document
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE
from app.assessment.provenance import control_catalog_sha256
from app.config import Settings
from app.rules.registry import resolve_catalog
from app.schemas.resource import NormalizedResource, ResourceScope
from tests.foundation_fixtures import (
    extended_profile,
    regional_bundle,
    regional_contract,
    regional_snapshot,
)


def test_legacy_documents_and_digests_are_unchanged():
    assert (
        DEFAULT_ASSESSMENT_PROFILE.content_checksum
        == "bf2e84e4b8ffba791ecc71284bf34a8098027773a679da59c5b215af6befa671"
    )
    catalog = build_default_control_catalog()
    assert (
        control_catalog_sha256(catalog)
        == "0b19063db2954f0d5f8dea8b5f00d85c74f0c1988b0ae0f276bc262dd01c617d"
    )
    assert "schema_version" not in DEFAULT_ASSESSMENT_PROFILE.model_dump()
    assert all("execution_contract" not in c.technical.model_dump() for c in catalog.controls)
    assert {
        r.control_id for r in resolve_catalog(catalog.catalog_id, catalog.version)[1].rules
    } == set(DEFAULT_ASSESSMENT_PROFILE.enabled_controls)
    with pytest.raises(ValueError, match="unsupported"):
        resolve_catalog(catalog.catalog_id, "6.0.0")


def test_extended_profile_dispatch_checksum_and_exact_policy_values():
    profile = extended_profile(required_tags=(" Owner ",), high_risk_public_tcp_ports=(443, 22))
    restored = validate_profile_document(profile.model_dump(mode="json"), persisted=True)
    assert restored == profile
    assert restored.required_tags == (" Owner ",)
    assert restored.high_risk_public_tcp_ports == (22, 443)
    doc = profile.model_dump(mode="json")
    doc["stale_key_days"] += 1
    with pytest.raises(ValueError):
        validate_profile_document(doc, persisted=True)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": "3.0.0"},
        {"max_unused_access_key_days": True},
        {"high_risk_public_tcp_ports": (0,)},
        {"high_risk_public_tcp_ports": (22, 22)},
        {"governed_resource_types": ("invented",)},
        {"enabled_controls": ("IAM-003",)},
        {"enabled_controls": ("S3-004",)},
        {"acceptable_vpc_flow_log_traffic_types": ("ACCEPT",)},
    ],
)
def test_extended_profile_rejects_invalid_or_missing_policy(changes):
    with pytest.raises(ValidationError):
        extended_profile(**changes)


def test_file_selection_is_cached_and_does_not_merge_environment_policy(tmp_path):
    path = tmp_path / "policy.json"
    profile = extended_profile(required_tags=("Exact",), stale_key_days=17)
    path.write_text(
        json.dumps(
            dict(
                catalog_id="aws-cloud-security-controls",
                catalog_version="0.2.1",
                profile=profile.model_dump(mode="json"),
            )
        ),
        encoding="utf-8",
    )
    settings = Settings(
        _env_file=None,
        assessment_profile_file=str(path),
        assessment_profile_version="2.0.0",
        required_tags="Ignored",
        stale_access_key_days=999,
    )
    assert settings.assessment_policy.profile == profile
    path.write_text("invalid sensitive file contents", encoding="utf-8")
    assert settings.assessment_policy.profile == profile
    with pytest.raises(
        PolicyConfigurationError, match=r"^Assessment policy configuration is invalid\.$"
    ):
        _ = Settings(
            _env_file=None, assessment_profile_file=str(path), assessment_profile_version="2.0.0"
        ).assessment_policy


@pytest.mark.parametrize(
    "body", ["{}", '{"profile":{},"profile":{}}', "secret-value", '{"catalog_version":"99.0.0"}']
)
def test_invalid_file_never_falls_back_or_exposes_contents(tmp_path, body):
    path = tmp_path / "policy.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(PolicyConfigurationError) as error:
        _ = Settings(_env_file=None, assessment_profile_file=str(path)).assessment_policy
    assert str(error.value) == "Assessment policy configuration is invalid."


@pytest.mark.parametrize("changes", [{"complete": False}, {"admission_complete": False}])
def test_present_without_complete_evidence_cannot_be_decisive(changes):
    snapshot = regional_snapshot(**changes)
    with pytest.raises(IncompleteAssessmentEvidence):
        AssessmentEvidenceReader(snapshot).proof(
            regional_contract(), account_target(snapshot, regional_contract())
        )


def test_regional_targets_proofs_and_exact_matrix():
    bundle = regional_bundle()
    snapshot, contract = bundle["snapshot"], regional_contract()
    candidate = bundle["assessments"][0]
    reader = AssessmentEvidenceReader(snapshot)
    reader.validate_candidate(contract, candidate)
    validate_execution_targets(snapshot, contract, (candidate,))
    with pytest.raises(ValueError, match="target matrix"):
        validate_execution_targets(snapshot, contract, ())
    with pytest.raises(ValueError, match="target matrix"):
        validate_execution_targets(snapshot, contract, (candidate, candidate))
    other = regional_snapshot(region="us-west-2")
    assert account_target(snapshot, contract).identity != account_target(other, contract).identity
    with pytest.raises(ValueError):
        AssessmentEvidenceReader(other).validate_candidate(contract, candidate)
    global_contract = ExecutionContract.model_validate(
        {**contract.model_dump(), "target_kind": "global_account"}
    )
    assert (
        account_target(snapshot, global_contract).identity
        != account_target(snapshot, contract).identity
    )


def test_multitype_targets_preserve_actual_identities():
    snapshot = regional_snapshot()
    resources = tuple(
        NormalizedResource(
            account_id=snapshot.account_id,
            service="ec2",
            resource_type=kind,
            aws_resource_id=f"test-{kind}",
            scope=ResourceScope.REGIONAL,
            region=snapshot.requested_region,
        )
        for kind in ("ec2_instance", "ebs_volume", "security_group")
    )
    snapshot = snapshot.model_copy(update={"resources": resources, "evidence_graph": None})
    contract = ExecutionContract.model_validate(
        {
            **regional_contract().model_dump(),
            "target_kind": "resources",
            "resource_families": tuple(
                ResourceFamily(service="ec2", resource_type=kind).model_dump()
                for kind in ("ec2_instance", "ebs_volume")
            ),
        }
    )
    assert {r.identity for r in assessment_targets(snapshot, contract)} == {
        r.identity for r in resources[:2]
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"target_selection": "latest"},
        {"validation_strategy": "allow_partial"},
        {"target_kind": "any"},
        {"required_sources": ()},
    ],
)
def test_unknown_execution_strategies_fail_closed(changes):
    with pytest.raises(ValueError):
        ExecutionContract.model_validate({**regional_contract().model_dump(), **changes})


@pytest.mark.parametrize("edge_mode", ["resolved", "missing", "unresolved"])
def test_admitted_resource_and_required_relationship_proof(edge_mode):
    from uuid import uuid4

    from app.assessment.evidence_graph import EvidenceCardinality, EvidenceGraph
    from app.assessment.execution import RequiredSource
    from app.assessment.relationships import (
        RelationshipResolution,
        RelationshipType,
        ResourceRelationship,
    )
    from app.assessment.source_outcomes import (
        AccountEvidenceSubject,
        EvidenceCollectionPhase,
        EvidenceSourceState,
    )
    from app.collectors.base import CollectionContext, build_source_observation
    from app.schemas.inventory import InventorySnapshot
    from tests.unit.database.factories import scaled_graph_scan_bundle

    original = scaled_graph_scan_bundle(1, scan_id=uuid4())["snapshot"]
    graph = original.evidence_graph
    coverage = build_source_observation(
        context=CollectionContext(
            scan_id=original.scan_id,
            collection_account_id=original.account_id,
            collected_at=original.collected_at,
            region=original.requested_region,
        ),
        contract_key="test.coverage",
        contract_version="1.0.0",
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=original.account_id,
            scope=ResourceScope.REGIONAL,
            region=original.requested_region,
        ),
        evidence_kind="test.coverage",
        collector="fixture.coverage",
        collector_version="1.0.0",
        source_api="ec2:DescribeInstances",
        cardinality=EvidenceCardinality.COLLECTION,
        evidence_reference="normalized://test/coverage",
        evidence_schema="test.coverage",
        evidence_schema_version="1.0.0",
        normalized_payload={"complete": True},
        state=EvidenceSourceState.PRESENT,
    )
    edges = graph.relationships
    if edge_mode == "missing":
        edges = ()
    elif edge_mode == "unresolved":
        edge = edges[0]
        edges = (
            ResourceRelationship.for_observation(
                scan_id=original.scan_id,
                collection_account_id=original.account_id,
                relationship_type=edge.relationship_type,
                source=edge.source,
                target=edge.target.model_copy(update={"resource_snapshot_id": None}),
                resolution=RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE,
                provenance=edge.provenance,
            ),
        )
    graph = EvidenceGraph.model_validate(
        {
            **graph.model_dump(),
            "source_contracts": (*graph.source_contracts, coverage.contract),
            "source_outcomes": (*graph.source_outcomes, coverage.outcome),
            "artifacts": (*graph.artifacts, coverage.artifact),
            "relationships": edges,
        }
    )
    snapshot = InventorySnapshot.model_validate({**original.model_dump(), "evidence_graph": graph})
    contract = ExecutionContract(
        schema_version="1.0.0",
        target_kind="resources",
        target_selection="all_observed_v1",
        account_service="ec2",
        validation_strategy="all_required_sources_complete_v1",
        resource_families=(ResourceFamily(service="ec2", resource_type="ec2_instance"),),
        required_sources=(
            RequiredSource(
                collector="fixture.coverage",
                evidence_kind="test.coverage",
                source_api="ec2:DescribeInstances",
                subject="regional_account",
                contract_version="1.0.0",
                completeness_fields=("complete",),
            ),
            RequiredSource(
                collector="ClosureFixtureCollector",
                evidence_kind="closure.ec2_instance",
                source_api="ec2:DescribeInstances",
                subject="target",
                contract_version="1.0.0",
                completion="admitted_resource_v1",
            ),
        ),
        required_relationships=(RelationshipType.ATTACHED_TO_SECURITY_GROUP,),
    )
    reader = AssessmentEvidenceReader(snapshot)
    target = assessment_targets(snapshot, contract)[0]
    if edge_mode != "resolved":
        with pytest.raises(IncompleteAssessmentEvidence, match="relationship"):
            reader.proof(contract, target)
    else:
        proof = reader.proof(contract, target)
        assert len(proof["sources"]) == 2
        assert proof["relationship_observation_ids"] == [str(edges[0].observation_id)]
