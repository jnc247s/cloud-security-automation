"""Response schemas for system health endpoints."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Liveness response."""

    status: Literal["healthy"]
    service: str


class ReadinessChecks(BaseModel):
    """External dependency readiness states."""

    database: Literal["ready", "unavailable"]


class ReadinessResponse(BaseModel):
    """Application readiness response."""

    status: Literal["ready", "not_ready"]
    service: str
    checks: ReadinessChecks
