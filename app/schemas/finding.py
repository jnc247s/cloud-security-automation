"""Validated, non-persistent security finding candidates."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.resource import ResourceScope


class Severity(StrEnum):
    """Supported security finding severities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ControlCategory(StrEnum):
    """High-level security control domains."""

    NETWORK = "network"
    STORAGE = "storage"
    IDENTITY = "identity"
    LOGGING = "logging"


class FindingCandidate(BaseModel):
    """Deterministic rule output awaiting reconciliation for the current scan."""

    model_config = ConfigDict(frozen=True)

    control_id: str = Field(pattern=r"^[A-Z0-9]+-\d{3}$")
    title: str = Field(min_length=1)
    category: ControlCategory
    severity: Severity

    account_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    aws_resource_id: str = Field(min_length=1)
    arn: str | None = None
    name: str | None = None
    scope: ResourceScope
    region: str | None = None

    evidence: dict[str, Any] = Field(default_factory=dict)
    impact: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_scope_and_region(self) -> "FindingCandidate":
        """Keep finding targets consistent with normalized resource identity."""

        if self.scope is ResourceScope.REGIONAL and not self.region:
            raise ValueError("regional finding targets require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global finding targets must not define a region")
        return self

    @property
    def identity(self) -> tuple[str, str, str, str, str, str, str]:
        """Return the stable key used for ordering and future deduplication."""

        return (
            self.control_id,
            self.account_id,
            self.service,
            self.resource_type,
            self.scope.value,
            self.region or "global",
            self.aws_resource_id,
        )
