"""Generic bearer verification READ API. No worker or write identity is exposed."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.remediation.verification_contracts import VerificationView
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, require_capability
from app.services.remediation_verification_service import RemediationVerificationService

router = APIRouter(prefix="/remediation-verifications", tags=["remediation-verifications"])
Database = Annotated[Session, Depends(get_db)]
Reader = Annotated[Principal, Depends(require_capability(Capability.READ))]


@router.get("", response_model=Page[VerificationView])
def list_verifications(
    db: Database,
    principal: Reader,
    response: Response,
    execution_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[VerificationView]:
    response.headers["Cache-Control"] = "no-store"
    return RemediationVerificationService(db).list_verifications(
        principal,
        execution_id=execution_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{verification_id}", response_model=VerificationView)
def get_verification(
    verification_id: UUID, db: Database, principal: Reader, response: Response
) -> VerificationView:
    response.headers["Cache-Control"] = "no-store"
    return RemediationVerificationService(db).get_verification(verification_id, principal)
