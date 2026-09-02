"""FastAPI application entry point."""

from fastapi import FastAPI

from app import __version__
from app.api.router import api_router
from app.config import get_settings
from app.logging.config import configure_logging


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    settings = get_settings()
    configure_logging(settings.log_level)

    application = FastAPI(
        title="Cloud Security Control Plane",
        description="Foundation for a production-style AWS security control plane.",
        version=__version__,
    )
    application.include_router(api_router)
    return application


app = create_app()
