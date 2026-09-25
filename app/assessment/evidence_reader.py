"""Pure source-bound assessment proofs; never calls AWS or evaluates security policy."""

from __future__ import annotations

from collections import defaultdict

from app.assessment.evidence_graph import (
    index_source_outcomes_by_provenance,
    source_provenance_key,
)
from app.assessment.execution import ExecutionContract, RequiredSource
from app.assessment.identities import resource_snapshot_id
from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceSourceState,
    ResourceEvidenceSubject,
)
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope


class IncompleteAssessmentEvidence(ValueError):
    """A declared source/relationship cannot support a decisive assessment."""


class AssessmentEvidenceReader:
    """Revalidate once, then use operation-local indexes for exact graph lookups."""

    def __init__(self, snapshot: InventorySnapshot) -> None:
        self.snapshot = InventorySnapshot.model_validate_json(snapshot.model_dump_json())
        self.graph = self.snapshot.evidence_graph
        self._sources = defaultdict(list)
        self._edges = defaultdict(list)
        self._outcomes = {}
        self._artifacts = {}
        self._provenance = {}
        if self.graph is not None:
            self._outcomes = {o.source_outcome_id: o for o in self.graph.source_outcomes}
            self._artifacts = {a.evidence_reference: a for a in self.graph.artifacts}
            self._provenance = index_source_outcomes_by_provenance(self.graph.source_outcomes)
            for source in self.graph.source_contracts:
                self._sources[(source.collector, source.evidence_kind, source.source_api)].append(
                    source
                )
            for edge in self.graph.relationships:
                self._edges[(edge.source.resource_snapshot_id, edge.relationship_type)].append(edge)

    def _subject_matches(
        self, subject, required: RequiredSource, target: NormalizedResource
    ) -> bool:
        if required.subject == "target" and target.resource_type != "aws_account":
            return getattr(subject, "resource_snapshot_id", None) == self._target_id(target)
        if not isinstance(subject, AccountEvidenceSubject):
            return False
        scope = (
            target.scope
            if required.subject == "target"
            else (
                ResourceScope.GLOBAL
                if required.subject == "global_account"
                else ResourceScope.REGIONAL
            )
        )
        return (
            subject.aws_account_id == self.snapshot.account_id
            and subject.scope is scope
            and subject.region
            == (self.snapshot.requested_region if scope is ResourceScope.REGIONAL else None)
        )

    def _target_id(self, target: NormalizedResource):
        return resource_snapshot_id(
            scan_id=self.snapshot.scan_id,
            account_id=target.account_id,
            service=target.service,
            resource_type=target.resource_type,
            aws_resource_id=target.aws_resource_id,
            scope=target.scope,
            region=target.region,
        )

    def _citation(self, outcome, *, fields=("complete",), allow_absence=False):
        artifact = self._artifacts[outcome.evidence_reference]
        states = {EvidenceSourceState.PRESENT}
        if allow_absence:
            states.add(EvidenceSourceState.EXPECTED_ABSENCE)
        payload = artifact.normalized_payload
        if (
            outcome.state not in states
            or any(payload.get(field) is not True for field in fields)
            or ("admission_complete" in payload and payload["admission_complete"] is not True)
            or payload.get("discarded_item_count", 0) != 0
        ):
            raise IncompleteAssessmentEvidence("required assessment evidence is incomplete")
        return {
            "source_outcome_id": str(outcome.source_outcome_id),
            "artifact_id": str(artifact.artifact_id),
            "evidence_sha256": artifact.evidence_sha256,
        }

    def proof(self, contract: ExecutionContract, target: NormalizedResource) -> dict:
        """Resolve every mandatory source and edge, binding the proof to immutable IDs/digests."""
        if self.graph is None:
            raise IncompleteAssessmentEvidence(
                "a source-aware assessment requires an evidence graph"
            )
        citations = {}
        # Empty resource populations use only their mandatory account coverage sources.
        empty_fallback = (
            contract.target_kind == "resources" and target.resource_type == "aws_account"
        )
        for required in contract.required_sources:
            if empty_fallback and required.subject == "target":
                continue
            matches = [
                source
                for source in self._sources.get(
                    (required.collector, required.evidence_kind, required.source_api), ()
                )
                if source.contract_version == required.contract_version
                and self._subject_matches(source.subject, required, target)
            ]
            if len(matches) != 1:
                raise IncompleteAssessmentEvidence(
                    "required source declaration is absent or ambiguous"
                )
            if required.completion == "admitted_resource_v1" and not (
                matches[0].identity_authoritative
                and isinstance(matches[0].subject, ResourceEvidenceSubject)
            ):
                raise IncompleteAssessmentEvidence(
                    "resource evidence requires authoritative admission"
                )
            outcome = self._outcomes[matches[0].source_outcome_id]
            citations[str(outcome.source_outcome_id)] = self._citation(
                outcome,
                fields=required.completeness_fields,
                allow_absence=required.expected_absence_is_complete,
            )
        edge_ids = []
        for kind in () if empty_fallback else contract.required_relationships:
            edges = self._edges.get((self._target_id(target), kind), ())
            if not edges or any(not edge.is_resolved for edge in edges):
                raise IncompleteAssessmentEvidence("required relationship is absent or unresolved")
            for edge in edges:
                outcomes = self._provenance[source_provenance_key(edge.provenance)]
                if len(outcomes) != 1:
                    raise IncompleteAssessmentEvidence("relationship provenance is ambiguous")
                outcome = outcomes[0]
                # An edge is valid only when its exact source was also required and proved.
                if str(outcome.source_outcome_id) not in citations:
                    raise IncompleteAssessmentEvidence(
                        "relationship source is not a proved required source"
                    )
                edge_ids.append(str(edge.observation_id))
        return {
            "schema_version": "1.0.0",
            "scan_id": str(self.snapshot.scan_id),
            "sources": [citations[key] for key in sorted(citations)],
            "relationship_observation_ids": sorted(edge_ids),
        }

    def validate_candidate(
        self, contract: ExecutionContract, candidate: AssessmentCandidate
    ) -> None:
        """Persistence and engine share the same exact-reference validation, not a second rule."""
        target = NormalizedResource(
            account_id=candidate.account_id,
            service=candidate.service,
            resource_type=candidate.resource_type,
            aws_resource_id=candidate.aws_resource_id,
            scope=candidate.scope,
            region=candidate.region,
        )
        try:
            expected = self.proof(contract, target)
        except IncompleteAssessmentEvidence:
            if (
                candidate.result is not AssessmentResult.INSUFFICIENT_EVIDENCE
                or candidate.evidence_artifacts
            ):
                raise ValueError(
                    "incomplete required sources require an insufficient assessment"
                ) from None
            return
        if (
            candidate.result is not AssessmentResult.INSUFFICIENT_EVIDENCE
            and not candidate.evidence_artifacts
        ):
            raise ValueError("source-aware assessment requires structured source proof")
        for artifact in candidate.evidence_artifacts:
            if artifact.payload.get("source_proof") != expected:
                raise ValueError("assessment source proof differs from retained evidence")
