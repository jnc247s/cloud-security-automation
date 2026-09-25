"""Isolated 6A contracts; never register synthetic execution policy in production."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.assessment.controls import ControlCatalog, build_default_control_catalog
from app.assessment.evidence_graph import EvidenceCardinality, EvidenceGraph
from app.assessment.evidence_reader import AssessmentEvidenceReader
from app.assessment.execution import ExecutionContract, RequiredSource, account_target
from app.assessment.extended_profiles import ExtendedAssessmentProfile
from app.assessment.models import AssessmentResult
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceSourceState,
)
from app.collectors.base import CollectionContext, build_source_observation
from app.rules.engine import RuleEngine
from app.rules.network import PublicSSHRule
from app.rules.registry import RuleRegistry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.resource import ResourceScope


def extended_profile(**updates):
    document = DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"})
    document.update({"schema_version": "2.0.0", "version": "2.0.0", **updates})
    return ExtendedAssessmentProfile.model_validate(document)


def regional_contract():
    return ExecutionContract(
        schema_version="1.0.0",
        target_kind="regional_account",
        account_service="ec2",
        target_selection="all_observed_v1",
        validation_strategy="all_required_sources_complete_v1",
        required_sources=(
            RequiredSource(
                collector="foundation.test",
                evidence_kind="test.setting",
                source_api="ec2:GetSetting",
                subject="regional_account",
                contract_version="1.0.0",
                completeness_fields=("complete",),
            ),
        ),
    )


def synthetic_catalog(execution=None):
    document = build_default_control_catalog().model_dump()
    document["version"] = "6.0.0"
    for control in document["controls"]:
        if control["technical"]["control_id"] == "NET-001":
            control["technical"]["execution_contract"] = (
                execution or regional_contract()
            ).model_dump()
    return ControlCatalog.model_validate(document)


def regional_snapshot(*, region="us-east-1", complete=True, admission_complete=True):
    scan_id = uuid4()
    collected_at = datetime(2026, 9, 24, 12, tzinfo=UTC)
    context = CollectionContext(
        scan_id=scan_id,
        collection_account_id="123456789012",
        region=region,
        collected_at=collected_at,
    )
    observation = build_source_observation(
        context=context,
        contract_key="test.setting",
        contract_version="1.0.0",
        phase=EvidenceCollectionPhase.DISCOVERY,
        subject=AccountEvidenceSubject(
            aws_account_id=context.collection_account_id,
            scope=ResourceScope.REGIONAL,
            region=region,
        ),
        evidence_kind="test.setting",
        collector="foundation.test",
        collector_version="1.0.0",
        source_api="ec2:GetSetting",
        cardinality=EvidenceCardinality.SINGLE,
        evidence_reference="normalized://test/setting",
        evidence_schema="test.setting",
        evidence_schema_version="1.0.0",
        normalized_payload={
            "complete": complete,
            "admission_complete": admission_complete,
            "value": False,
        },
        state=EvidenceSourceState.PRESENT,
    )
    return InventorySnapshot(
        scan_id=scan_id,
        account_id=context.collection_account_id,
        requested_region=region,
        collected_at=collected_at,
        resources=(),
        collector_outcomes=(
            CollectorOutcome(collector_name="foundation_test", status=CollectionStatus.PARTIAL),
        ),
        evidence_graph=EvidenceGraph(
            scan_id=scan_id,
            collection_account_id=context.collection_account_id,
            collected_at=collected_at,
            source_contracts=(observation.contract,),
            artifacts=(observation.artifact,),
            source_outcomes=(observation.outcome,),
            relationships=(),
        ),
    )


class SyntheticRegionalRule(PublicSSHRule):
    """Fixed test failure against a Regional setting; not an executable production control."""

    def assess(self, snapshot, profile):
        contract = regional_contract()
        target = account_target(snapshot, contract)
        proof = AssessmentEvidenceReader(snapshot).proof(contract, target)
        return (
            self.assessment_for_resource(
                snapshot,
                profile,
                target,
                result=AssessmentResult.FAIL,
                evidence={"source_proof": proof},
                reason="Synthetic foundation fixture.",
                collector="foundation.test",
                source_api="ec2:GetSetting",
            ),
        )


def regional_bundle():
    snapshot = regional_snapshot()
    profile = AssessmentProfile.model_validate(
        {
            **DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"}),
            "enabled_controls": ("NET-001",),
        }
    )
    catalog = synthetic_catalog()
    registry = RuleRegistry((SyntheticRegionalRule(),))
    assessments = RuleEngine(registry, catalog=catalog).assess(snapshot, profile)
    scope = ScanScopeManifestInput(
        aws_account_id=snapshot.account_id,
        requested_regions=(snapshot.requested_region,),
        successful_regions=(),
        requested_services=("ec2",),
        requested_collectors=("foundation_test",),
        collector_outcomes=snapshot.collector_outcomes,
        resource_types=("aws_account",),
        enabled_controls=profile.enabled_controls,
        assessment_profile_id=profile.profile_id,
        assessment_profile_version=profile.version,
        assessment_profile_checksum=profile.content_checksum,
        control_catalog_id=catalog.catalog_id,
        control_catalog_version=catalog.version,
    )
    return dict(
        snapshot=snapshot,
        profile=profile,
        catalog=catalog,
        assessments=assessments,
        scope=scope,
        started_at=snapshot.collected_at - timedelta(seconds=1),
        completed_at=snapshot.collected_at + timedelta(seconds=1),
        scanner_version="test",
    )
