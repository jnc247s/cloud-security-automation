"""Confirm request references against real READ history, not mutable operational state."""

import json
from typing import Literal
from uuid import UUID

import httpx2 as httpx
from pydantic import ValidationError

from app.dashboard.operations import (
    OperationKind,
    PreparedOperation,
    ResultReference,
    validate_json_document,
)
from app.remediation.contracts import Contract, DecisionView, ProposalView
from app.remediation.execution_contracts import ExecutionView
from app.remediation.verification_contracts import VerificationView


class SubmissionFailureDetail(Contract):
    code: Literal["verification_submission_failed"]
    message: Literal["The verification was recorded but could not be submitted."]
    verification_id: UUID
    scan_id: UUID


class SubmissionFailure(Contract):
    detail: SubmissionFailureDetail


class ResultAuthenticationRejected(Exception):
    """A history 401 also invalidates the opaque browser session."""


def _bound(value, operation: PreparedOperation) -> bool:
    body = json.loads(operation.input.body_json)
    kind = operation.input.kind
    if kind == OperationKind.PROPOSE:
        content, actor = value.content, value.content.proposer
        matches = (
            str(content.finding_id) == body["finding_id"]
            and str(content.baseline.occurrence_id) == body["occurrence_id"]
            and content.action_id == body["action_id"]
            and content.action_version == body["action_version"]
        )
    elif kind in {OperationKind.DECIDE, OperationKind.REVOKE}:
        content, actor = value, value.actor
        matches = (
            content.proposal_id == operation.input.target_id
            and content.proposal_sha256 == body["proposal_sha256"]
            and content.kind == (body["decision"] if kind == OperationKind.DECIDE else "REVOKE")
            and (
                content.approval_decision_id is None
                if kind == OperationKind.DECIDE
                else str(content.approval_decision_id) == body["approval_decision_id"]
            )
        )
    else:
        content, actor = value.content, value.content.requested_by
        matches = content.idempotency_key == operation.operation_id
        if kind == OperationKind.REQUEST_EXECUTION:
            matches = (
                matches
                and content.proposal.proposal_id == operation.input.target_id
                and content.proposal_sha256 == body["proposal_sha256"]
                and str(content.approval.decision_id) == body["approval_decision_id"]
            )
        else:
            matches = matches and content.execution_id == operation.input.target_id
    return (
        matches
        and content.reason == body["reason"]
        and (actor.issuer, actor.subject) == operation.actor
        and actor.capability == operation.input.capability
    )


async def confirm_result(
    client: httpx.AsyncClient, operation: PreparedOperation, response: httpx.Response
) -> ResultReference | None:
    """Only fixed internal API responses followed by bound READs provide references.

    All failures leave uncertainty sticky. No response/error body is cached or reflected.
    The client is internal-only and already carries this request's verified bearer token.
    """
    kind = operation.input.kind
    model = {
        OperationKind.PROPOSE: ProposalView,
        OperationKind.DECIDE: DecisionView,
        OperationKind.REVOKE: DecisionView,
        OperationKind.REQUEST_EXECUTION: ExecutionView,
        OperationKind.REQUEST_VERIFICATION: VerificationView,
    }[kind]
    first_status = (
        201 if kind in {OperationKind.PROPOSE, OperationKind.DECIDE, OperationKind.REVOKE} else 202
    )
    try:
        validate_json_document(response.content)
        failed_submission = (
            kind == OperationKind.REQUEST_VERIFICATION and response.status_code == 503
        )
        if failed_submission:
            failure = SubmissionFailure.model_validate_json(response.content, strict=True).detail
            expected = None
            result_id, scan_id = failure.verification_id, failure.scan_id
        elif response.status_code in {200, first_status}:
            expected = model.model_validate_json(response.content, strict=True)
            if not _bound(expected, operation):
                return None
            if kind == OperationKind.PROPOSE:
                result_id, scan_id = expected.content.proposal_id, None
            elif kind in {OperationKind.DECIDE, OperationKind.REVOKE}:
                result_id, scan_id = expected.decision_id, None
            elif kind == OperationKind.REQUEST_EXECUTION:
                result_id, scan_id = expected.content.execution_id, None
            else:
                result_id, scan_id = expected.content.verification_id, expected.content.scan_id
        else:
            return None

        if kind in {OperationKind.PROPOSE, OperationKind.DECIDE, OperationKind.REVOKE}:
            proposal_id = result_id if kind == OperationKind.PROPOSE else operation.input.target_id
            history_response = await client.get(f"/api/v1/remediations/{proposal_id}")
            history_model = ProposalView
        elif kind == OperationKind.REQUEST_EXECUTION:
            history_response = await client.get(f"/api/v1/remediation-executions/{result_id}")
            history_model = ExecutionView
        else:
            history_response = await client.get(f"/api/v1/remediation-verifications/{result_id}")
            history_model = VerificationView
        if history_response.status_code == 401:
            raise ResultAuthenticationRejected
        if history_response.status_code != 200:
            return None
        validate_json_document(history_response.content)
        history = history_model.model_validate_json(history_response.content, strict=True)
        if kind in {OperationKind.DECIDE, OperationKind.REVOKE}:
            return (
                ResultReference(result_id)
                if history.content.proposal_id == operation.input.target_id
                and history.proposal_sha256 == expected.proposal_sha256
                and expected in history.decisions
                else None
            )
        if not _bound(history, operation):
            return None
        if kind == OperationKind.REQUEST_VERIFICATION:
            if history.content.scan_id != scan_id or history.content.verification_id != result_id:
                return None
            if expected and history.request_audit_event_id != expected.request_audit_event_id:
                return None
        if expected is not None:
            digest_field = {
                OperationKind.PROPOSE: "proposal_sha256",
                OperationKind.REQUEST_EXECUTION: "execution_sha256",
                OperationKind.REQUEST_VERIFICATION: "verification_sha256",
            }[kind]
            if history.content != expected.content or getattr(history, digest_field) != getattr(
                expected, digest_field
            ):
                return None
        return ResultReference(result_id, scan_id)
    except (ValidationError, ValueError, KeyError, TypeError, RecursionError):
        return None
