"""Deterministic orchestration for registered security controls."""

from app.assessment.controls import build_default_control_catalog
from app.assessment.identities import assessment_scan_id, inventory_sha256, resource_snapshot_id
from app.assessment.models import AssessmentCandidate
from app.assessment.profiles import AssessmentProfile
from app.assessment.provenance import control_catalog_sha256
from app.rules.registry import RuleRegistry
from app.schemas.finding import FindingCandidate
from app.schemas.inventory import InventorySnapshot


class RuleContractError(RuntimeError):
    """Raised when a rule returns output that violates the engine contract."""


class RuleEngine:
    """Evaluate a normalized inventory without AWS, persistence, or side effects."""

    def __init__(self, registry: RuleRegistry) -> None:
        self.registry = registry

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        """Evaluate all rules and return validated findings in stable order."""

        findings: list[FindingCandidate] = []
        seen_identities: set[tuple[str, str, str, str, str, str, str]] = set()

        for rule in self.registry.rules:
            for candidate in rule.evaluate(snapshot):
                if not isinstance(candidate, FindingCandidate):
                    raise RuleContractError(f"{rule.control_id} returned a non-finding candidate")
                if candidate.control_id != rule.control_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned candidate for {candidate.control_id}"
                    )
                if candidate.account_id != snapshot.account_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned candidate for a different AWS account"
                    )
                if candidate.identity in seen_identities:
                    raise RuleContractError(
                        f"{rule.control_id} returned duplicate candidate identity for "
                        f"{candidate.aws_resource_id}"
                    )

                seen_identities.add(candidate.identity)
                findings.append(candidate)

        findings.sort(key=lambda finding: finding.identity)
        return tuple(findings)

    def assess(
        self,
        snapshot: InventorySnapshot,
        profile: AssessmentProfile,
    ) -> tuple[AssessmentCandidate, ...]:
        """Evaluate enabled rules using the canonical four-state assessment contract."""

        registered_ids = {rule.control_id for rule in self.registry.rules}
        unknown_control_ids = set(profile.enabled_controls) - registered_ids
        if unknown_control_ids:
            unknown = ", ".join(sorted(unknown_control_ids))
            raise RuleContractError(f"assessment profile enables unregistered controls: {unknown}")

        assessments: list[AssessmentCandidate] = []
        seen_identities: set[tuple[str, str, str, str, str, str, str]] = set()
        expected_scan_id = assessment_scan_id(snapshot)
        expected_inventory_sha256 = inventory_sha256(snapshot)
        catalog = build_default_control_catalog()
        expected_catalog_sha256 = control_catalog_sha256(catalog)
        if set(profile.enabled_controls) - {control.control_id for control in catalog.controls}:
            raise RuleContractError(
                "enabled controls require a versioned technical catalog contract"
            )

        for rule in self.registry.rules:
            if rule.control_id not in profile.enabled_controls:
                continue

            rule_assessments = rule.assess(snapshot, profile)
            if not rule_assessments:
                raise RuleContractError(
                    f"{rule.control_id} returned no assessment; PASS and NOT_APPLICABLE "
                    "must be explicit"
                )

            for candidate in rule_assessments:
                if not isinstance(candidate, AssessmentCandidate):
                    raise RuleContractError(
                        f"{rule.control_id} returned a non-assessment candidate"
                    )
                if candidate.control_id != rule.control_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for {candidate.control_id}"
                    )
                if candidate.account_id != snapshot.account_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for a different AWS account"
                    )
                if candidate.scan_id != expected_scan_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for a different inventory snapshot"
                    )
                if candidate.inventory_sha256 not in (None, expected_inventory_sha256):
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for different inventory facts"
                    )
                if candidate.control_catalog_sha256 not in (None, expected_catalog_sha256):
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for a different control catalog"
                    )
                expected_resource_snapshot_id = resource_snapshot_id(
                    scan_id=expected_scan_id,
                    account_id=candidate.account_id,
                    service=candidate.service,
                    resource_type=candidate.resource_type,
                    scope=candidate.scope,
                    region=candidate.region,
                    aws_resource_id=candidate.aws_resource_id,
                )
                if candidate.resource_snapshot_id != expected_resource_snapshot_id:
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for a different resource snapshot"
                    )
                if (
                    candidate.profile_id != profile.profile_id
                    or candidate.profile_version != profile.version
                    or candidate.profile_checksum != profile.calculate_content_checksum()
                ):
                    raise RuleContractError(
                        f"{rule.control_id} returned assessment for a different profile version"
                    )
                if candidate.identity in seen_identities:
                    raise RuleContractError(
                        f"{rule.control_id} returned duplicate assessment identity for "
                        f"{candidate.aws_resource_id}"
                    )

                seen_identities.add(candidate.identity)
                assessments.append(
                    candidate.model_copy(
                        update={
                            "inventory_sha256": expected_inventory_sha256,
                            "control_catalog_sha256": expected_catalog_sha256,
                        }
                    )
                )

        assessments.sort(key=lambda assessment: assessment.identity)
        return tuple(assessments)
