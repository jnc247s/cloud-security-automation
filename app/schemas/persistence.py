"""Validated inputs for recording exact scan coverage."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.inventory import CollectionStatus, CollectorOutcome


class ScanScopeManifestInput(BaseModel):
    """The exact intended and successful scope claimed by one scan."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    aws_account_id: str = Field(min_length=1)
    requested_regions: tuple[str, ...] = Field(min_length=1)
    successful_regions: tuple[str, ...]
    requested_services: tuple[str, ...] = Field(min_length=1)
    requested_collectors: tuple[str, ...] = Field(min_length=1)
    collector_outcomes: tuple[CollectorOutcome, ...] = Field(min_length=1)
    resource_types: tuple[str, ...] = Field(min_length=1)
    enabled_controls: tuple[str, ...] = Field(min_length=1)
    assessment_profile_id: str = Field(min_length=1)
    assessment_profile_version: str = Field(min_length=1)
    assessment_profile_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    control_catalog_id: str = Field(min_length=1)
    control_catalog_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_exact_scope(self) -> Self:
        """Reject ambiguous or internally inconsistent coverage claims."""

        tuple_fields = (
            self.requested_regions,
            self.successful_regions,
            self.requested_services,
            self.requested_collectors,
            self.resource_types,
            self.enabled_controls,
        )
        if any(len(values) != len(set(values)) for values in tuple_fields):
            raise ValueError("scan scope entries must be unique")
        if any(not value for values in tuple_fields for value in values):
            raise ValueError("scan scope entries must not be blank")
        if not set(self.successful_regions).issubset(self.requested_regions):
            raise ValueError("successful regions must be part of the requested scope")

        outcome_names = tuple(outcome.collector_name for outcome in self.collector_outcomes)
        if len(outcome_names) != len(set(outcome_names)):
            raise ValueError("collector outcomes must be unique")
        if set(outcome_names) != set(self.requested_collectors):
            raise ValueError("every requested collector requires exactly one outcome")
        return self

    @property
    def is_complete(self) -> bool:
        """Return whether every requested region and collector succeeded."""

        return bool(
            set(self.successful_regions) == set(self.requested_regions)
            and all(
                outcome.status is CollectionStatus.SUCCEEDED for outcome in self.collector_outcomes
            )
        )

    @property
    def successful_collectors(self) -> tuple[str, ...]:
        """Return collectors that proved complete coverage."""

        return tuple(
            sorted(
                outcome.collector_name
                for outcome in self.collector_outcomes
                if outcome.status is CollectionStatus.SUCCEEDED
            )
        )

    def collector_outcome_document(self) -> dict[str, str]:
        """Return a canonical JSON-ready mapping of collector outcomes."""

        return {
            outcome.collector_name: outcome.status.value
            for outcome in sorted(
                self.collector_outcomes,
                key=lambda item: item.collector_name,
            )
        }
