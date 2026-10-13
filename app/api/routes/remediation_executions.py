"""Bearer READ projections of execution admission/history, not AWS effects."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database.session import get_db
from app.remediation.execution_contracts import ExecutionView
from app.remediation.verification_contracts import VerificationRequest, VerificationView
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, require_capability
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_verification_service import RemediationVerificationService

router = APIRouter(prefix="/remediation-executions", tags=["remediation-executions"])
Database = Annotated[Session, Depends(get_db)]
Reader = Annotated[Principal, Depends(require_capability(Capability.READ))]
Executor = Annotated[Principal, Depends(require_capability(Capability.EXECUTE))]
IdempotencyKey = Annotated[UUID, Header(alias="Idempotency-Key")]
VerificationSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/{execution_id}/verifications", response_model=VerificationView, status_code=202)
def request_verification(
    execution_id: UUID,
    body: VerificationRequest,
    principal: Executor,
    db: Database,
    key: IdempotencyKey,
    settings: VerificationSettings,
    request: Request,
    response: Response,
) -> VerificationView:
    response.headers["Cache-Control"] = "no-store"
    result = RemediationVerificationService(
        db, scope=settings.remediation_verification
    ).request_verification(
        execution_id,
        body,
        principal,
        key,
        getattr(request.app.state, "scan_executor", None),
    )
    if result.replayed:
        response.status_code = 200
    return result.value


@router.get("", response_model=Page[ExecutionView])
def list_executions(
    db: Database,
    principal: Reader,
    response: Response,
    proposal_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ExecutionView]:
    response.headers["Cache-Control"] = "no-store"
    return RemediationExecutionService(db).list_executions(
        principal,
        proposal_id=proposal_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{execution_id}", response_model=ExecutionView)
def get_execution(
    execution_id: UUID,
    db: Database,
    principal: Reader,
    response: Response,
) -> ExecutionView:
    response.headers["Cache-Control"] = "no-store"
    return RemediationExecutionService(db).get_execution(execution_id, principal)
