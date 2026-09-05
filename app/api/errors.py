"""Translate service-boundary errors into stable HTTP responses."""

from fastapi import Request, status
from fastapi.responses import JSONResponse

from app.services.errors import EntityNotFoundError
from app.services.scan_service import ScanSubmissionError


async def entity_not_found_handler(
    _request: Request,
    error: EntityNotFoundError,
) -> JSONResponse:
    """Return a non-sensitive, machine-readable response for a missing entity."""

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "detail": {
                "code": "entity_not_found",
                "message": str(error),
                "entity": error.entity,
                "identifier": error.identifier,
            }
        },
    )


async def scan_submission_error_handler(
    _request: Request,
    error: ScanSubmissionError,
) -> JSONResponse:
    """Expose the durable scan ID after a bounded executor rejects submission."""

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": {
                "code": "scan_submission_failed",
                "message": "The scan was recorded but could not be submitted.",
                "scan_id": str(error.scan_id),
            }
        },
    )
