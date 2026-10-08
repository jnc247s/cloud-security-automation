"""Generic bearer authority and execution admission, never AWS dispatch."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database.session import get_db
from app.remediation.contracts import (
    DecisionRequest,
    DecisionView,
    ProposalRequest,
    ProposalView,
    RevocationRequest,
)
from app.remediation.execution_contracts import ExecutionRequest, ExecutionView
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, require_capability
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import RemediationService

router = APIRouter(prefix="/remediations", tags=["remediations"])
Database = Annotated[Session, Depends(get_db)]
Reader = Annotated[Principal, Depends(require_capability(Capability.READ))]
Proposer = Annotated[Principal, Depends(require_capability(Capability.PROPOSE))]
Approver = Annotated[Principal, Depends(require_capability(Capability.APPROVE))]
Executor = Annotated[Principal, Depends(require_capability(Capability.EXECUTE))]
AdmissionSettings = Annotated[Settings, Depends(get_settings)]
IdempotencyKey = Annotated[UUID, Header(alias="Idempotency-Key")]


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.get("", response_model=Page[ProposalView])
def list_proposals(
    db: Database,
    principal: Reader,
    response: Response,
    finding_id: UUID | None = None,
    account_id: Annotated[str | None, Query(pattern=r"^[0-9]{12}$")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ProposalView]:
    _private(response)
    return RemediationService(db).list_proposals(
        principal,
        finding_id=finding_id,
        account_id=account_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{proposal_id}", response_model=ProposalView)
def get_proposal(
    proposal_id: UUID, db: Database, principal: Reader, response: Response
) -> ProposalView:
    _private(response)
    return RemediationService(db).get_proposal(proposal_id, principal)


@router.post("", response_model=ProposalView, status_code=201)
def propose(
    request: ProposalRequest,
    db: Database,
    principal: Proposer,
    key: IdempotencyKey,
    response: Response,
) -> ProposalView:
    _private(response)
    result = RemediationService(db).propose(request, principal, key)
    if result.replayed:
        response.status_code = 200
    return result.value


@router.post("/{proposal_id}/decisions", response_model=DecisionView, status_code=201)
def decide(
    proposal_id: UUID,
    request: DecisionRequest,
    db: Database,
    principal: Approver,
    key: IdempotencyKey,
    response: Response,
) -> DecisionView:
    _private(response)
    result = RemediationService(db).decide(proposal_id, request, principal, key)
    if result.replayed:
        response.status_code = 200
    return result.value


@router.post("/{proposal_id}/revocations", response_model=DecisionView, status_code=201)
def revoke(
    proposal_id: UUID,
    request: RevocationRequest,
    db: Database,
    principal: Approver,
    key: IdempotencyKey,
    response: Response,
) -> DecisionView:
    _private(response)
    result = RemediationService(db).revoke(proposal_id, request, principal, key)
    if result.replayed:
        response.status_code = 200
    return result.value


@router.post("/{proposal_id}/executions", response_model=ExecutionView, status_code=202)
def request_execution(
    proposal_id: UUID,
    request: ExecutionRequest,
    db: Database,
    principal: Executor,
    key: IdempotencyKey,
    settings: AdmissionSettings,
    response: Response,
) -> ExecutionView:
    _private(response)
    result = RemediationExecutionService(db, scope=settings.remediation_admission).admit(
        proposal_id,
        request,
        principal,
        key,
    )
    if result.replayed:
        response.status_code = 200
    return result.value
