"""Health and readiness endpoints."""

from fastapi import APIRouter, Response, status
from sqlalchemy.exc import SQLAlchemyError

from app.database.session import check_database_connection
from app.schemas.health import HealthResponse, ReadinessChecks, ReadinessResponse

SERVICE_NAME = "cloud-security-control-plane"

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Report process health without depending on external services."""

    return HealthResponse(status="healthy", service=SERVICE_NAME)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
def readiness(response: Response) -> ReadinessResponse:
    """Report whether the application can reach its required database."""

    try:
        check_database_connection()
    except SQLAlchemyError:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(
            status="not_ready",
            service=SERVICE_NAME,
            checks=ReadinessChecks(database="unavailable"),
        )

    return ReadinessResponse(
        status="ready",
        service=SERVICE_NAME,
        checks=ReadinessChecks(database="ready"),
    )
