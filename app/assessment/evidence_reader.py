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
        self.resources = {self._target_id(r): r for r in self.snapshot.resources}
        self._iam_policy_coverage = None
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
        if contract.schema_version == "1.4.0":
            from app.assessment.flow_log_evidence import flow_log_proof

            return flow_log_proof(self, target)
        if contract.schema_version == "1.3.0":
            from app.assessment.security_group_evidence import security_group_proof

            return security_group_proof(self, target)
        if contract.schema_version == "1.1.0":
            from app.assessment.iam_key_evidence import iam_key_proof

            return iam_key_proof(self, contract, target)
        if contract.schema_version == "1.2.0":
            from app.assessment.iam_policy_evidence import iam_policy_proof

            return iam_policy_proof(self, target)
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

    def resolve_source(self, required: RequiredSource, target: NormalizedResource):
        """Resolve a single complete source for bounded joined evidence consumers."""
        matches = [
            source
            for source in self._sources.get(
                (required.collector, required.evidence_kind, required.source_api), ()
            )
            if source.contract_version == required.contract_version
            and self._subject_matches(source.subject, required, target)
        ]
        if len(matches) != 1:
            raise IncompleteAssessmentEvidence("required source is absent or ambiguous")
        source = matches[0]
        if required.completion == "admitted_resource_v1" and not source.identity_authoritative:
            raise IncompleteAssessmentEvidence("required resource admission is unavailable")
        outcome = self._outcomes[source.source_outcome_id]
        citation = self._citation(
            outcome,
            fields=required.completeness_fields,
            allow_absence=required.expected_absence_is_complete,
        )
        return outcome, self._artifacts[outcome.evidence_reference].normalized_payload, citation

    def source_payloads(self, proof: dict, evidence_kind: str) -> tuple[dict, ...]:
        """Read only artifacts cited by a proof already produced by this reader."""
        selected = {item["source_outcome_id"] for item in proof["sources"]}
        return tuple(
            self._artifacts[outcome.evidence_reference].normalized_payload
            for outcome in self._outcomes.values()
            if str(outcome.source_outcome_id) in selected and outcome.evidence_kind == evidence_kind
        )

    def validate_candidate(
        self, contract: ExecutionContract, candidate: AssessmentCandidate, *, profile=None
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
            network_expected = None
            if contract.schema_version == "1.4.0":
                from app.rules.flow_logs import flow_log_result

                if candidate.control_id != "NET-006" or profile is None:
                    raise ValueError("Flow Log validation requires its exact control and profile")
                network_expected = flow_log_result(expected["vpc_flow_logs"], profile)
            if contract.schema_version == "1.3.0":
                from app.assessment.security_group_evidence import NETWORK_CONTROL_IDS
                from app.rules.security_groups import network_result

                if candidate.control_id not in NETWORK_CONTROL_IDS or profile is None:
                    raise ValueError("network validation requires its exact control and profile")
                network_expected = network_result(
                    candidate.control_id, expected["security_group"], profile
                )
            ec2_facts_value = None
            if candidate.control_id in {"EC2-001", "EC2-002", "EC2-003", "EC2-004"}:
                from app.assessment.ec2_evidence import ec2_facts

                ec2_facts_value = ec2_facts(self, contract, target, candidate.control_id)
        except IncompleteAssessmentEvidence:
            if (
                candidate.result is not AssessmentResult.INSUFFICIENT_EVIDENCE
                or candidate.evidence_artifacts
            ):
                raise ValueError(
                    "incomplete required sources require an insufficient assessment"
                ) from None
            return
        if network_expected is not None and candidate.result is not network_expected:
            raise ValueError(
                "network result or applicability differs from retained evidence/policy"
            )
        if (
            candidate.result in {AssessmentResult.PASS, AssessmentResult.FAIL}
            and not candidate.evidence_artifacts
        ):
            raise ValueError("source-aware assessment requires structured source proof")
        if (
            contract.schema_version == "1.2.0"
            and candidate.result is AssessmentResult.NOT_APPLICABLE
            and expected["iam_policy_document"] is not None
        ):
            raise ValueError("in-scope policy documents cannot be not applicable")
        if candidate.result is AssessmentResult.NOT_APPLICABLE and (
            candidate.control_id in {"IAM-005", "IAM-006"}
            or contract.schema_version == "1.1.0"
            and expected["iam_active_keys"]
        ):
            raise ValueError("observed IAM credentials or root controls cannot be not applicable")
        for artifact in candidate.evidence_artifacts:
            if (
                network_expected is not None
                and artifact.payload.get("evaluation_version") != "1.0.0"
            ):
                raise ValueError("network evaluation version differs from contract")
            if artifact.payload.get("source_proof") != expected:
                raise ValueError("assessment source proof differs from retained evidence")
            if ec2_facts_value is not None:
                from app.assessment.ec2_evidence import canonical

                if any(
                    canonical(artifact.payload.get(k)) != canonical(v)
                    for k, v in ec2_facts_value.items()
                ):
                    raise ValueError("EC2 decision facts differ from retained evidence")
                if artifact.payload.get("evaluation_version") != "1.0.0":
                    raise ValueError("EC2 evaluation version differs from contract")
        if ec2_facts_value is not None:
            from app.assessment.ec2_evidence import ec2_not_applicable

            na = ec2_not_applicable(ec2_facts_value)
            if (candidate.result is AssessmentResult.NOT_APPLICABLE) != na:
                raise ValueError("EC2 applicability differs from retained evidence")
