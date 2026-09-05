"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.errors import entity_not_found_handler, scan_submission_error_handler
from app.api.router import api_router
from app.config import get_settings
from app.logging.config import configure_logging
from app.services.errors import EntityNotFoundError
from app.services.scan_executor import InProcessScanExecutor, ScanExecutor
from app.services.scan_service import ScanSubmissionError

LOGGER = logging.getLogger(__name__)
ExecutorFactory = Callable[[], ScanExecutor]


def create_app(
    *,
    executor_factory: ExecutorFactory = InProcessScanExecutor,
    resume_pending_scans: bool = False,
) -> FastAPI:
    """Create and configure the FastAPI application."""

    settings = get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        executor = executor_factory()
        application.state.scan_executor = executor
        try:
            if resume_pending_scans:
                resumed = executor.resume_pending()
                if resumed:
                    LOGGER.info("Resubmitted %d pending scans.", resumed)
            yield
        finally:
            executor.shutdown(wait=True)

    application = FastAPI(
        title="Cloud Security Control Plane",
        description="Foundation for a production-style AWS security control plane.",
        version=__version__,
        lifespan=lifespan,
    )
    application.add_exception_handler(EntityNotFoundError, entity_not_found_handler)
    application.add_exception_handler(ScanSubmissionError, scan_submission_error_handler)
    application.include_router(api_router)
    return application


app = create_app(resume_pending_scans=True)
