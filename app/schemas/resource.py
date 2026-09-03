"""Normalized in-memory AWS resource contracts."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ResourceScope(StrEnum):
    """Whether a resource belongs to a region or has account-global scope."""

    GLOBAL = "global"
    REGIONAL = "regional"


class NormalizedResource(BaseModel):
    """Collector output that is independent of boto3 and future persistence models."""

    model_config = ConfigDict(frozen=True)

    account_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    aws_resource_id: str = Field(min_length=1)
    arn: str | None = None
    name: str | None = None
    scope: ResourceScope
    region: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    raw_configuration: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scope_and_region(self) -> "NormalizedResource":
        """Require regional resources to have a region and global resources not to."""

        if self.scope is ResourceScope.REGIONAL and not self.region:
            raise ValueError("regional resources require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global resources must not define a region")
        return self

    @property
    def identity(self) -> tuple[str, str, str, str, str, str]:
        """Return the stable composite identity used for deterministic ordering."""

        return (
            self.account_id,
            self.service,
            self.resource_type,
            self.scope.value,
            self.region or "global",
            self.aws_resource_id,
        )
