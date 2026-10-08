"""Offline migration-backed execution admission fixtures; no worker or AWS write."""

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.persistence import persist_scan_result
from app.models import Control, Finding, FindingOccurrence
from app.remediation.contracts import ACTION_ID, ACTION_VERSION, DecisionRequest, ProposalRequest
from app.remediation.execution_contracts import AdmissionScope, ExecutionRequest
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import RemediationService
from tests.ec2_fixtures import ec2_bundle
from tests.remediation_fixtures import ADMIN, APPROVER, NOW, propose

SCOPE = AdmissionScope(enabled=True, account_id="123456789012", region="us-east-1")


def approved(engine, *, request=None, account="123456789012", region="us-east-1", at=NOW):
    if request is None:
        bundle = ec2_bundle(account=account, region=region)
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            finding = session.scalar(
                select(Finding)
                .join(Control)
                .where(
                    Control.control_key == "EC2-004",
                    Finding.aws_account_id == account,
                    Finding.region == region,
                )
            )
            occurrence = session.scalar(
                select(FindingOccurrence).where(
                    FindingOccurrence.finding_id == finding.finding_id,
                    FindingOccurrence.scan_id == bundle["snapshot"].scan_id,
                )
            )
            request = ProposalRequest(
                finding_id=finding.finding_id,
                occurrence_id=occurrence.occurrence_id,
                action_id=ACTION_ID,
                action_version=ACTION_VERSION,
                reason="Reviewed compatibility.",
            )
    proposal = propose(engine, request, at=at).value
    with Session(engine) as session:
        approval = (
            RemediationService(session, clock=lambda: at)
            .decide(
                proposal.content.proposal_id,
                DecisionRequest(
                    proposal_sha256=proposal.proposal_sha256,
                    decision="APPROVE",
                    reason="Reviewed exact intent and workload/key compatibility.",
                ),
                APPROVER,
                uuid4(),
            )
            .value
        )
    return (
        proposal,
        ExecutionRequest(
            proposal_sha256=proposal.proposal_sha256,
            approval_decision_id=approval.decision_id,
            reason="Execute within the reviewed change window.",
        ),
        request,
    )


def admit(engine, proposal, request, *, principal=ADMIN, scope=SCOPE, at=NOW, key=None):
    with Session(engine) as session:
        return RemediationExecutionService(session, scope=scope, clock=lambda: at).admit(
            proposal.content.proposal_id,
            request,
            principal,
            key or uuid4(),
        )
