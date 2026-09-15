"""Canonical persistence entities registered with the shared SQLAlchemy metadata."""

from app.models.assessment import ControlAssessment, EvidenceArtifact
from app.models.audit import AuditEvent
from app.models.control import (
    Control,
    ControlCatalog,
    ControlFrameworkMapping,
    ControlVersion,
    Framework,
    FrameworkReference,
)
from app.models.evidence_graph import (
    ResourceRelationshipObservation,
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
)
from app.models.exception import FindingException
from app.models.finding import Finding, FindingOccurrence
from app.models.profile import PersistedAssessmentProfile
from app.models.resource import Resource, ResourceSnapshot
from app.models.scan import Scan, ScanScopeManifest

__all__ = [
    "AuditEvent",
    "Control",
    "ControlAssessment",
    "ControlCatalog",
    "ControlFrameworkMapping",
    "ControlVersion",
    "EvidenceArtifact",
    "Finding",
    "FindingException",
    "FindingOccurrence",
    "Framework",
    "FrameworkReference",
    "PersistedAssessmentProfile",
    "Resource",
    "ResourceRelationshipObservation",
    "ResourceSnapshot",
    "Scan",
    "ScanScopeManifest",
    "ScanSourceContract",
    "SourceEvidenceArtifact",
    "SourceEvidenceOutcome",
]
