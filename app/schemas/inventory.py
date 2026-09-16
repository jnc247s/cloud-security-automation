"""In-memory AWS inventory snapshot contract."""

from datetime import datetime
from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from app.assessment.evidence_graph import EvidenceGraph, validate_graph_resources
from app.schemas.resource import NormalizedResource


class CollectionStatus(StrEnum):
    """Completeness state for one requested inventory collector."""

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class CollectorOutcome(BaseModel):
    """Sanitized collection coverage used to prevent unsupported clean results."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    collector_name: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    status: CollectionStatus


class InventorySnapshot(BaseModel):
    """In-memory resource observations bound to one preallocated scan identity."""

    model_config = ConfigDict(frozen=True)

    scan_id: UUID
    account_id: str = Field(min_length=1)
    requested_region: str = Field(min_length=1)
    collected_at: datetime
    collector_outcomes: tuple[CollectorOutcome, ...]
    resources: tuple[NormalizedResource, ...]
    evidence_graph: EvidenceGraph | None = None

    @model_serializer(mode="wrap")
    def serialize_snapshot(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        """Keep graphless Sprint 0--4 serialization byte-shape compatible."""

        document = handler(self)
        if self.evidence_graph is None:
            document.pop("evidence_graph", None)
        return document

    @field_validator("collected_at")
    @classmethod
    def require_aware_collection_time(cls, value: datetime) -> datetime:
        """Require unambiguous evidence timestamps."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("snapshot collected_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def require_unique_collector_outcomes(self) -> Self:
        """Reject ambiguous coverage and bind an optional graph to this snapshot."""

        names = tuple(outcome.collector_name for outcome in self.collector_outcomes)
        if len(names) != len(set(names)):
            raise ValueError("collector outcomes must be unique")
        if self.evidence_graph is not None:
            if self.evidence_graph.scan_id != self.scan_id:
                raise ValueError("evidence graph must identify the inventory snapshot scan")
            if self.evidence_graph.collection_account_id != self.account_id:
                raise ValueError("evidence graph must identify the inventory collection account")
            if self.evidence_graph.collected_at != self.collected_at:
                raise ValueError("evidence graph must use the inventory collection time")
            validate_graph_resources(
                graph=self.evidence_graph,
                resources=self.resources,
                requested_region=self.requested_region,
            )
        return self

    @property
    def resource_count(self) -> int:
        """Return the number of resources in the snapshot."""

        return len(self.resources)

    def collection_status(self, collector_name: str) -> CollectionStatus | None:
        """Return one collector's explicit status, or None when it was not requested."""

        for outcome in self.collector_outcomes:
            if outcome.collector_name == collector_name:
                return outcome.status
        return None

    def collector_succeeded(self, collector_name: str) -> bool:
        """Return true only when the requested collector completed successfully."""

        return self.collection_status(collector_name) is CollectionStatus.SUCCEEDED
