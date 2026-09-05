"""Top-level API router configuration."""

from fastapi import APIRouter

from app.api.routes.assessments import router as assessments_router
from app.api.routes.controls import router as controls_router
from app.api.routes.exceptions import router as exceptions_router
from app.api.routes.findings import router as findings_router
from app.api.routes.frameworks import router as frameworks_router
from app.api.routes.health import router as health_router
from app.api.routes.resources import router as resources_router
from app.api.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(health_router)

v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(assessments_router)
v1_router.include_router(controls_router)
v1_router.include_router(exceptions_router)
v1_router.include_router(findings_router)
v1_router.include_router(frameworks_router)
v1_router.include_router(resources_router)
v1_router.include_router(scans_router)
api_router.include_router(v1_router)
