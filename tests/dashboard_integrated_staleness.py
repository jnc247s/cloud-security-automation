"""Owned-parent offline collection/rules/persistence, not managed verification or a public API."""

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from tests.dashboard_integrated_protocol import ControlKind, ControlMessage


@dataclass(frozen=True)
class StaleCase:
    offset: int
    assessment: str
    scan_status: str
    finding: str


def stale_case(name):
    choices = {
        "admission-stale": StaleCase(1, "FAIL", "COMPLETED", "OPEN"),
        "stale-newer-fail": StaleCase(1, "FAIL", "COMPLETED", "OPEN"),
        "stale-equal-fail": StaleCase(0, "FAIL", "COMPLETED", "OPEN"),
        "stale-newer-pass": StaleCase(1, "PASS", "COMPLETED", "RESOLVED"),
        "stale-equal-pass": StaleCase(0, "PASS", "COMPLETED", "OPEN"),
        "stale-newer-insufficient": StaleCase(1, "INSUFFICIENT_EVIDENCE", "PARTIAL", "OPEN"),
        "stale-equal-insufficient": StaleCase(0, "INSUFFICIENT_EVIDENCE", "PARTIAL", "OPEN"),
    }
    if type(name) is not str or name not in choices:
        raise ValueError("Invalid integrated stale case")
    return choices[name]


def _original(parent, message):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.integrity import canonical_json_sha256
    from app.models import AuditEvent
    from app.models.enums import AuditEventType
    from app.models.remediation import RemediationRequest
    from app.remediation.contracts import ProposalRequest
    from app.remediation.provenance import utc
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    before, original = database_state(parent.engine), parent.proposal_only_before
    changed = {"remediation_proposals", "remediation_requests", "audit_events"}
    if (
        type(original) is not dict
        or set(original) != set(before)
        or any(original[name] != before[name] for name in before if name not in changed)
        or len(before["remediation_proposals"]) != 1
        or len(before["remediation_requests"]) != 1
        or len(before["audit_events"]) != len(original["audit_events"]) + 1
        or any(row not in before["audit_events"] for row in original["audit_events"])
    ):
        raise ValueError("Invalid original stale proposal binding")
    with Session(parent.engine) as session:
        view = RemediationService(session).get_proposal(message.target_id, parent._principal())
        parent._bind_proposal(view.content)
        actor = view.content.proposer
        ledger = session.scalars(select(RemediationRequest)).one()
        audit = session.execute(
            select(AuditEvent).where(
                AuditEvent.target_id == message.target_id,
                AuditEvent.event_type == AuditEventType.REMEDIATION_PROPOSED,
            )
        ).scalar_one()
        request = ProposalRequest(
            finding_id=view.content.finding_id,
            occurrence_id=view.content.baseline.occurrence_id,
            action_id=view.content.action_id,
            action_version=view.content.action_version,
            reason=view.content.reason,
        )
        if (
            view.approval_status.value != "PROPOSED"
            or view.decisions
            or view.blocking_reasons
            or (actor.issuer, actor.subject, actor.roles, actor.capability.value)
            != (parent.issuer, "proposer", ("ANALYST",), "PROPOSE")
            or ledger.operation != "CREATE"
            or ledger.idempotency_key != message.request_id
            or ledger.proposal_id != message.target_id
            or ledger.decision_id is not None
            or (ledger.actor_issuer, ledger.actor_subject) != (parent.issuer, "proposer")
            or ledger.actor_identity_sha256 != canonical_json_sha256([parent.issuer, "proposer"])
            or ledger.request_sha256 != canonical_json_sha256(request.model_dump(mode="json"))
            or view.proposal_sha256 != canonical_json_sha256(view.content.model_dump(mode="json"))
            or audit.actor_type != "human"
            or audit.target_type != "remediation"
            or audit.actor_id != ledger.actor_identity_sha256
            or utc(audit.timestamp) != view.content.created_at
            or audit.event_metadata
            != {
                "schema_version": "1.0.0",
                "actor": actor.model_dump(mode="json"),
                "proposal_id": str(message.target_id),
                "proposal_sha256": view.proposal_sha256,
                "decision_id": None,
            }
        ):
            raise ValueError("Invalid original stale proposal binding")
    return view, before


def _collect(engine, view, case):
    from collections import deque
    from unittest.mock import patch

    from sqlalchemy.orm import Session

    from app import __version__
    from app.database.catalogs import load_assessment_profile, verify_control_catalog
    from app.database.persistence import persist_scan_result
    from app.models import Scan
    from app.rules.engine import RuleEngine
    from app.rules.registry import resolve_catalog
    from app.services.inventory_service import InventoryService
    from app.services.scan_executor import _execution_scope_for, _scope_for
    from tests.fakes import client_error
    from tests.verification_acceptance import regional_reader
    from tests.worker_http import REGION

    baseline = view.content.baseline
    with Session(engine) as session:
        source = session.get(Scan, baseline.scan_id)
        services = tuple(source.requested_services)
        profile = load_assessment_profile(
            session,
            profile_id=baseline.profile_id,
            version=baseline.profile_version,
            expected_checksum=baseline.profile_sha256,
        )
        catalog, registry = resolve_catalog(baseline.catalog_id, baseline.catalog_version)
        verify_control_catalog(session, catalog)
    observed = baseline.observed_at + timedelta(seconds=case.offset)
    if observed > datetime.now(UTC):
        raise ValueError("Invalid future stale observation")
    reader = regional_reader(enabled=case.assessment == "PASS")
    if case.assessment == "INSUFFICIENT_EVIDENCE":
        reader._clients[("ec2", REGION)]._responses["get_ebs_encryption_by_default"] = deque(
            [client_error("AccessDenied", "GetEbsEncryptionByDefault")]
        )
    # This test-parent's single collection clock only. No JWT/browser/domain clock or row rewrite.
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(reader).collect(scan_id=uuid4())
    assessments = RuleEngine(registry, catalog=catalog).assess(snapshot, profile)
    target = [item for item in assessments if item.control_id == "EC2-004"]
    if len(target) != 1 or target[0].result.value != case.assessment:
        raise ValueError("Stale collection did not produce the fixed assessment")
    collectors, resource_types = _execution_scope_for(services)
    with Session(engine) as session, session.begin():
        persist_scan_result(
            session,
            snapshot=snapshot,
            scope=_scope_for(
                snapshot,
                profile,
                catalog,
                requested_services=services,
                requested_collectors=collectors,
                resource_types=resource_types,
            ),
            profile=profile,
            catalog=catalog,
            assessments=assessments,
            started_at=observed - timedelta(seconds=1),
            completed_at=datetime.now(UTC),
            scanner_version=__version__,
            actor_type="system",
            actor_id="integrated-background-collector",
        )
    return snapshot.scan_id


def collect_bound_stale_observation(parent, message):
    if (
        os.environ.get("DASHBOARD_BROWSER_TEST") != "1"
        or type(message) is not ControlMessage
        or message.kind is not ControlKind.COLLECT_STALE
        or message.instance_id != UUID(parent.instance)
        or message.target_id is None
        or parent.stale_dispatched
        or parent.worker_dispatched
    ):
        raise ValueError("Integrated stale collection unavailable")
    case = stale_case(parent.scenario.name)
    parent.last_stage = "STALE_OWNERSHIP"
    parent._owned()
    parent.last_stage = "STALE_ORIGINAL_AUTHORITY"
    if parent.scenario.name == "admission-stale":
        from tests.dashboard_integrated_governance import bound_authority

        view, before = bound_authority(parent, message)
    else:
        view, before = _original(parent, message)
    parent.stale_dispatched = True  # No blind retry after collection/persistence uncertainty.
    parent.last_stage = "STALE_COLLECTION"
    identifier = _collect(parent.engine, view, case)
    from tests.verification_acceptance import unchanged_history
    from tests.worker_http import database_state

    after = database_state(parent.engine)
    unchanged_history(before, after)
    if any(before[name] != after[name] for name in before if name.startswith("remediation_")):
        raise ValueError("Stale collection changed remediation history")
    if before["resources"] != after["resources"]:
        raise ValueError("Stale collection changed stable resource identities")
    parent.stale_scan_id, parent.stale_view = identifier, view
    parent.stale_after = after
    assert_stale_observation(parent, None)
    return "STALE_OBSERVATION_PERSISTED"


def assert_stale_observation(parent, before_reader):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.models import ControlAssessment, Finding, ResourceSnapshot, Scan
    from app.remediation.contracts import ProposalView
    from app.remediation.provenance import utc
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    parent._owned()
    case = stale_case(parent.scenario.name)
    if (
        before_reader is not None
        or not parent.stale_dispatched
        or parent.worker_dispatched
        or parent.worker_report is not None
        or parent.worker_history is not None
        or parent.acknowledged_execution is not None
        or parent.quarantined_execution is not None
        or type(parent.stale_view) is not ProposalView
        or type(parent.stale_after) is not dict
        or database_state(parent.engine) != parent.stale_after
    ):
        raise ValueError("Invalid stale no-execution proof")
    with Session(parent.engine) as session:
        original = parent.stale_view
        current = RemediationService(session).get_proposal(
            original.content.proposal_id, parent._principal()
        )
        if (
            current.content != original.content
            or current.proposal_sha256 != original.proposal_sha256
            or original.approval_status.value
            != ("APPROVED" if parent.scenario.name == "admission-stale" else "PROPOSED")
            or len(original.decisions) != (1 if parent.scenario.name == "admission-stale" else 0)
            or current.approval_status != original.approval_status
            or current.decisions != original.decisions
            or "STALE_TARGET" not in {item.value for item in current.blocking_reasons}
        ):
            raise ValueError("Invalid stale authority projection")
        scans = session.scalars(select(Scan)).all()
        if {scan.scan_id for scan in scans} != {parent.source.scan_id, parent.stale_scan_id}:
            raise ValueError("Invalid stale scan identities")
        scan = session.get(Scan, parent.stale_scan_id)
        source = session.get(Scan, parent.source.scan_id)
        assessment = session.execute(
            select(ControlAssessment).where(
                ControlAssessment.scan_id == parent.stale_scan_id,
                ControlAssessment.resource_id == parent.source.resource_id,
                ControlAssessment.control_id == parent.source.control_id,
            )
        ).scalar_one()
        observed = session.get(ResourceSnapshot, assessment.resource_snapshot_id)
        if (
            scan.status.value != case.scan_status
            or assessment.assessment_result.value != case.assessment
            or utc(observed.observed_at)
            != original.content.baseline.observed_at + timedelta(seconds=case.offset)
            or not utc(scan.started_at) <= utc(observed.observed_at) <= utc(scan.completed_at)
            or scan.requested_services != source.requested_services
            or scan.assessment_profile_checksum != source.assessment_profile_checksum
            or scan.control_catalog_id != source.control_catalog_id
            or scan.control_catalog_version != source.control_catalog_version
            or session.get(Finding, parent.source.finding_id).status.value != case.finding
            or session.get(ControlAssessment, parent.source.assessment_id).assessment_result.value
            != "FAIL"
        ):
            raise ValueError("Invalid stale observation provenance")
    if database_state(parent.engine) != parent.stale_after:
        raise ValueError("Stale read changed durable history")
