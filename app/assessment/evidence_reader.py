"""Pure source-bound assessment proofs; never calls AWS or evaluates security policy."""

from __future__ import annotations

from collections import defaultdict
from types import MappingProxyType

from app.assessment.evidence_graph import (
    index_source_outcomes_by_provenance,
    source_provenance_key,
)
from app.assessment.execution import ExecutionContract, RequiredSource
from app.assessment.identities import resource_snapshot_id
from app.assessment.models import AssessmentCandidate, AssessmentResult, _freeze_json
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
        self._composition_inventory_digest = None
        self._governance_resource_families = None
        self._governance_population_cache = {}
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

    def composition_inventory_sha256(self):
        """Seal this reader's private validated JSON before binding composition once.

        Legacy readers remain unchanged. The graph is already deeply immutable; only
        resource JSON needs sealing. Caller-owned resources are never modified, and
        a different reader must independently validate and bind its own snapshot.
        """
        if self._composition_inventory_digest is None:
            from app.assessment.identities import inventory_sha256

            for resource in self.snapshot.resources:
                for field in ("tags", "configuration", "raw_configuration"):
                    object.__setattr__(resource, field, _freeze_json(getattr(resource, field)))
            self._composition_inventory_digest = inventory_sha256(self.snapshot)
        return self._composition_inventory_digest

    def governance_resource_families(self):
        """Index and seal only this operation's private validated resource observations.

        Population proofs can then be reused without rescanning caller-owned inventory
        or allowing nested JSON mutation to change cached admission facts. Historical
        readers are unaffected unless the new governance proof is requested.
        """
        if self._governance_resource_families is None:
            families = defaultdict(list)
            for resource in self.snapshot.resources:
                for field in ("tags", "configuration", "raw_configuration"):
                    object.__setattr__(resource, field, _freeze_json(getattr(resource, field)))
                families[(resource.service, resource.resource_type)].append(resource)
            self._governance_resource_families = MappingProxyType(
                {key: tuple(resources) for key, resources in families.items()}
            )
        return self._governance_resource_families

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

    def proof(
        self, contract: ExecutionContract, target: NormalizedResource, *, context=None, profile=None
    ) -> dict:
        """Resolve every mandatory source and edge, binding the proof to immutable IDs/digests."""
        if contract.schema_version == "1.10.0":
            from app.assessment.governance_evidence import governance_proof

            return governance_proof(self, contract, target, profile=profile)
        if self.graph is None:
            raise IncompleteAssessmentEvidence(
                "a source-aware assessment requires an evidence graph"
            )
        if contract.schema_version == "1.9.0":
            from app.assessment.cloudtrail_destination_evidence import destination_proof

            return destination_proof(self, contract, target, context=context, profile=profile)
        if contract.schema_version == "1.8.0":
            from app.assessment.cloudtrail_evidence import cloudtrail_proof

            return cloudtrail_proof(self, contract, target)
        if contract.schema_version == "1.7.0":
            from app.assessment.s3_sensitive_kms_evidence import sensitive_kms_proof

            return sensitive_kms_proof(self, contract, target)
        if contract.schema_version == "1.6.0":
            from app.assessment.s3_exposure_evidence import exposure_proof

            return exposure_proof(self, contract, target)
        if contract.schema_version == "1.5.0":
            from app.assessment.s3_configuration_evidence import s3_configuration_proof

            return s3_configuration_proof(self, contract, target)
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
        self,
        contract: ExecutionContract,
        candidate: AssessmentCandidate,
        *,
        profile=None,
        context=None,
        exact_proof=False,
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
            expected = self.proof(contract, target, context=context, profile=profile)
            network_expected = None
            s3_expected = None
            cloudtrail_expected = None
            governance_expected = None
            if contract.schema_version == "1.10.0":
                from app.assessment.governance_evidence import governance_result

                if candidate.control_id != "GOV-001" or profile is None:
                    raise ValueError("governance validation requires its exact control/profile")
                governance_expected = governance_result(expected, profile)
            if contract.schema_version == "1.9.0":
                from app.assessment.cloudtrail_destination_evidence import destination_result

                if candidate.control_id != "LOG-004":
                    raise ValueError("destination control differs from execution contract")
                cloudtrail_expected = destination_result(expected)
            if contract.schema_version == "1.8.0":
                from app.rules.cloudtrail import cloudtrail_result

                control_id = {
                    "cloudtrail_management_coverage_v1": "LOG-002",
                    "cloudtrail_integrity_v1": "LOG-003",
                }[contract.validation_strategy]
                if candidate.control_id != control_id:
                    raise ValueError("CloudTrail control differs from its execution contract")
                cloudtrail_expected = cloudtrail_result(control_id, expected)
            if contract.schema_version == "1.7.0":
                from app.rules.s3_sensitive_kms import sensitive_kms_result

                if candidate.control_id != "S3-004" or profile is None:
                    raise ValueError("sensitive KMS validation requires its exact control/profile")
                s3_expected = sensitive_kms_result(expected, profile)
            if contract.schema_version == "1.6.0":
                from app.rules.s3_exposure import exposure_result

                if candidate.control_id != "S3-002" or profile is None:
                    raise ValueError("exposure validation requires its exact control and profile")
                s3_expected = exposure_result(expected, profile)
            if contract.schema_version == "1.5.0":
                from app.rules.s3_configuration import s3_configuration_result

                control = {"s3_bpa_v1": "S3-001", "s3_transport_v1": "S3-003"}[
                    contract.validation_strategy
                ]
                if candidate.control_id != control:
                    raise ValueError("S3 control differs from its execution contract")
                s3_expected = s3_configuration_result(control, expected["s3_configuration"])
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
        if governance_expected is not None:
            if candidate.result is not governance_expected:
                raise ValueError("governance result differs from retained evidence/policy")
            if (
                candidate.result
                in {AssessmentResult.NOT_APPLICABLE, AssessmentResult.INSUFFICIENT_EVIDENCE}
                and candidate.evidence_artifacts
            ):
                raise ValueError("nondecisive governance results cannot carry decisive evidence")
        if cloudtrail_expected is not None:
            if candidate.result is not cloudtrail_expected:
                raise ValueError("CloudTrail result differs from retained source evidence")
            if (
                candidate.result
                in {
                    AssessmentResult.NOT_APPLICABLE,
                    AssessmentResult.INSUFFICIENT_EVIDENCE,
                }
                and candidate.evidence_artifacts
            ):
                raise ValueError("nondecisive CloudTrail results must not carry decisive evidence")
        if s3_expected is not None:
            if candidate.result is not s3_expected:
                raise ValueError("S3 result differs from retained source evidence")
            if (
                candidate.result
                in {AssessmentResult.NOT_APPLICABLE, AssessmentResult.INSUFFICIENT_EVIDENCE}
                and candidate.evidence_artifacts
            ):
                raise ValueError("nondecisive S3 results must not carry decisive evidence")
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
                governance_expected is not None
                and artifact.payload.get("evaluation_version") != "1.0.0"
            ):
                raise ValueError("governance evaluation version differs from contract")
            if (
                cloudtrail_expected is not None
                and artifact.payload.get("evaluation_version") != "1.0.0"
            ):
                raise ValueError("CloudTrail evaluation version differs from contract")
            if (network_expected is not None or s3_expected is not None) and artifact.payload.get(
                "evaluation_version"
            ) != "1.0.0":
                raise ValueError("network evaluation version differs from contract")
            proof = artifact.payload.get("source_proof")
            if contract.schema_version in {"1.8.0", "1.9.0", "1.10.0"} or exact_proof:
                from app.assessment.cloudtrail_evidence import exact_json_equal

                proof_matches = exact_json_equal(proof, expected)
            else:
                proof_matches = proof == expected
            if not proof_matches:
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
