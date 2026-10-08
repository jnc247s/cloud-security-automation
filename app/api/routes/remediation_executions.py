"""Bearer READ projections of execution admission/history, not AWS effects."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.remediation.execution_contracts import ExecutionView
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, require_capability
from app.services.remediation_execution_service import RemediationExecutionService

router = APIRouter(prefix="/remediation-executions", tags=["remediation-executions"])
Database = Annotated[Session, Depends(get_db)]
Reader = Annotated[Principal, Depends(require_capability(Capability.READ))]


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
