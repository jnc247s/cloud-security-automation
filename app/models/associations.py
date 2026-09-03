"""Association tables shared by persistence models."""

from sqlalchemy import Column, ForeignKey, Index, Integer, Table

from app.database.base import Base

scan_resources = Table(
    "scan_resources",
    Base.metadata,
    Column("scan_id", Integer, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "resource_id",
        Integer,
        ForeignKey("resources.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index("ix_scan_resources_resource_id", "resource_id"),
)
