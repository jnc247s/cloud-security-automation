"""In-memory AWS inventory snapshot contract."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.resource import NormalizedResource


class InventorySnapshot(BaseModel):
    """Resources collected during one non-persistent inventory run."""

    model_config = ConfigDict(frozen=True)

    account_id: str = Field(min_length=1)
    requested_region: str = Field(min_length=1)
    collected_at: datetime
    resources: tuple[NormalizedResource, ...]

    @property
    def resource_count(self) -> int:
        """Return the number of resources in the snapshot."""

        return len(self.resources)
