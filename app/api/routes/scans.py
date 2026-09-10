"""Authorized REST boundary for asynchronous security scans."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.scan import ScanCreateRequest, ScanDetail, ScanListResponse
from app.security.authentication import Principal
from app.security.authorization import Capability, require_capability
from app.services.scan_executor import ScanExecutor
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])
SessionDependency = Annotated[Session, Depends(get_db)]
ReadPrincipal = Annotated[Principal, Depends(require_capability(Capability.READ))]
ExecutePrincipal = Annotated[Principal, Depends(require_capability(Capability.EXECUTE))]


def get_scan_executor(request: Request) -> ScanExecutor:
    """Return the explicitly lifespan-managed executor for this application."""

    executor = getattr(request.app.state, "scan_executor", None)
    if executor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "scan_executor_unavailable",
                "message": "The scan executor is not available.",
            },
        )
    return executor


ExecutorDependency = Annotated[ScanExecutor, Depends(get_scan_executor)]


@router.post(
    "",
    response_model=ScanDetail,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        status.HTTP_409_CONFLICT: {"description": "Assessment profile version conflict"},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Executor unavailable"},
    },
)
def create_scan(
    body: ScanCreateRequest,
    principal: ExecutePrincipal,
    db: SessionDependency,
    executor: ExecutorDependency,
) -> ScanDetail:
    """Persist a scan identity and enqueue its work without waiting for AWS."""

    return ScanService(db).start_scan(body, executor, actor_id=principal.subject)


@router.get("", response_model=ScanListResponse)
def list_scans(
    db: SessionDependency,
    _principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanListResponse:
    """List scan lifecycle records newest-first."""

    return ScanService(db).list_scans(limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: UUID, db: SessionDependency, _principal: ReadPrincipal) -> ScanDetail:
    """Return one scan's declared scope, verified identity, and result provenance."""

    return ScanService(db).get_scan(scan_id)
