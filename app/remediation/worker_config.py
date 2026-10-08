"""Worker-only operator settings. Never load .env or scanner/application settings."""

from pydantic import ConfigDict, Field, StrictBool, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.remediation.contracts import Contract
from app.remediation.execution_contracts import REGION_PATTERN
from app.remediation.worker_contracts import ROLE_ARN_PATTERN


class WorkerScope(Contract):
    """Closed single-account/Region/role scope, independent of admission and scanning."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    enabled: StrictBool = False
    account_id: str | None = Field(default=None, pattern=r"^[0-9]{12}$")
    region: str | None = Field(default=None, max_length=64, pattern=REGION_PATTERN)
    role_arn: str | None = Field(default=None, max_length=2048, pattern=ROLE_ARN_PATTERN)

    @model_validator(mode="after")
    def explicit_matching_scope(self):
        if self.enabled and any(v is None for v in (self.account_id, self.region, self.role_arn)):
            raise ValueError("enabled worker requires explicit account, Region and expected role")
        if self.role_arn is not None:
            parts = self.role_arn.split(":")
            partition, role_account = parts[1], parts[4]
            if self.account_id is not None and role_account != self.account_id:
                raise ValueError("worker role must belong to the configured account")
            if self.region is not None:
                expected = (
                    "aws-cn"
                    if self.region.startswith("cn-")
                    else "aws-us-gov"
                    if self.region.startswith("us-gov-")
                    else "aws"
                )
                if partition != expected:
                    raise ValueError("worker role and Region must use the same AWS partition")
        return self


class WorkerSettings(BaseSettings):
    """Environment-only independent process configuration; credentials are never settings."""

    model_config = SettingsConfigDict(
        env_prefix="REMEDIATION_WORKER_",
        env_file=None,
        extra="forbid",
        hide_input_in_errors=True,
    )
    enabled: bool = False
    account_id: str | None = Field(default=None, pattern=r"^[0-9]{12}$")
    region: str | None = Field(default=None, max_length=64, pattern=REGION_PATTERN)
    role_arn: str | None = Field(default=None, max_length=2048, pattern=ROLE_ARN_PATTERN)
    database_url: str | None = Field(default=None, min_length=1, repr=False)

    @property
    def scope(self) -> WorkerScope:
        return WorkerScope(
            enabled=self.enabled,
            account_id=self.account_id,
            region=self.region,
            role_arn=self.role_arn,
        )

    @model_validator(mode="after")
    def validate_enabled_worker(self):
        _ = self.scope
        if self.enabled and self.database_url is None:
            raise ValueError("enabled worker requires its own database URL")
        return self
