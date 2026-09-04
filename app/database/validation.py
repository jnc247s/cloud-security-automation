"""Pure validation of scan coverage and the expected control-target matrix."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from app.assessment.controls import ControlCatalog
from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.schemas.inventory import InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.resource import ResourceScope

# The current catalog does not yet declare collector ownership. Keep the known
# collector contracts explicit: an unrelated outage cannot excuse missing targets.
_RESOURCE_COLLECTIONS = {
    "security_group": ("ec2", "security_groups"),
    "iam_user": ("iam", "iam_users"),
    "s3_bucket": ("s3", "s3_buckets"),
}
_ACCOUNT_SERVICES = {"LOG-001": "cloudtrail"}
_COLLECTOR_GAP = re.compile(r"collector_outcomes\.([a-z][a-z0-9_]*)\.SUCCEEDED")
_SCOPE_SETS = (
    "requested_regions",
    "successful_regions",
    "requested_services",
    "requested_collectors",
    "resource_types",
    "enabled_controls",
)


def canonical_scope_document(scope: ScanScopeManifestInput) -> dict[str, Any]:
    """Return the full scope document with order-independent coverage collections."""

    validated = ScanScopeManifestInput.model_validate(scope.model_dump(mode="python"))
    document = validated.model_dump(mode="json")
    for field in _SCOPE_SETS:
        document[field] = sorted(document[field])
    document["collector_outcomes"] = sorted(
        document["collector_outcomes"], key=lambda item: item["collector_name"]
    )
    return document


def validate_expected_assessments(
    snapshot: InventorySnapshot,
    scope: ScanScopeManifestInput,
    catalog: ControlCatalog,
    assessments: Sequence[AssessmentCandidate],
) -> None:
    """Reject omitted targets and scope claims unsupported by this invocation.

    One InventorySnapshot represents one regional invocation. Account-wide
    collectors may observe resources elsewhere, but those observations do not
    prove that another regional invocation completed.

    Every matching resource needs an explicit result, except that one account
    insufficient-evidence result may represent a genuinely unavailable collector.
    Unknown resource contracts support exact target matrices, but cannot use that
    exception until their collector ownership is defined.
    """

    validated_scope = ScanScopeManifestInput.model_validate(scope.model_dump(mode="python"))
    if validated_scope.requested_regions != (snapshot.requested_region,):
        raise ValueError("requested regions must contain exactly the inventory invocation region")
    if validated_scope.aws_account_id != snapshot.account_id:
        raise ValueError("scope account does not match the inventory account")
    if validated_scope.collector_outcome_document() != {
        outcome.collector_name: outcome.status.value for outcome in snapshot.collector_outcomes
    }:
        raise ValueError("scope collector outcomes do not match the inventory")

    enabled = set(validated_scope.enabled_controls)
    grouped: dict[str, list[AssessmentCandidate]] = {control_id: [] for control_id in enabled}
    for candidate in assessments:
        if candidate.control_id not in grouped:
            raise ValueError(f"assessment uses a disabled control: {candidate.control_id}")
        grouped[candidate.control_id].append(candidate)

    for control_id in sorted(enabled):
        try:
            contract = catalog.get(control_id).technical
        except KeyError as error:
            raise ValueError(f"enabled control is absent from the catalog: {control_id}") from error
        candidates = grouped[control_id]
        if not candidates:
            raise ValueError(f"{control_id} requires an explicit assessment")

        if contract.resource_type == "aws_account":
            if len(candidates) != 1 or not _is_account_target(candidates[0], snapshot):
                raise ValueError(f"{control_id} requires exactly one account assessment")
            expected_service = _ACCOUNT_SERVICES.get(control_id)
            if expected_service is not None and candidates[0].service != expected_service:
                raise ValueError(f"{control_id} account assessment has the wrong service")
            continue

        collection = _RESOURCE_COLLECTIONS.get(contract.resource_type)
        resources = tuple(
            resource
            for resource in snapshot.resources
            if resource.resource_type == contract.resource_type
            and (collection is None or resource.service == collection[0])
        )
        account_candidates = [item for item in candidates if _is_account_target(item, snapshot)]
        if account_candidates:
            if len(candidates) != 1:
                raise ValueError(f"{control_id} account fallback cannot accompany resource results")
            candidate = account_candidates[0]
            if collection is not None and candidate.service != collection[0]:
                raise ValueError(f"{control_id} account fallback has the wrong service")
            if candidate.result is AssessmentResult.INSUFFICIENT_EVIDENCE:
                _validate_collection_gap(candidate, snapshot, collection)
                continue
            if candidate.result is AssessmentResult.NOT_APPLICABLE and not resources:
                if collection is not None and not snapshot.collector_succeeded(collection[1]):
                    raise ValueError(f"{control_id} cannot claim no targets without collection")
                continue
            raise ValueError(
                f"{control_id} requires explicit resource assessments; "
                "account fallback must describe unavailable collection or no applicable targets"
            )

        if not resources:
            raise ValueError(
                f"{control_id} with no targets requires one account N/A or insufficient"
            )
        expected = {resource.identity for resource in resources}
        actual = [candidate.identity[1:] for candidate in candidates]
        if len(expected) != len(resources):
            raise ValueError(f"{control_id} inventory contains duplicate target identities")
        if len(actual) != len(set(actual)):
            raise ValueError(f"{control_id} contains duplicate resource assessments")
        if set(actual) != expected:
            missing = len(expected - set(actual))
            unexpected = len(set(actual) - expected)
            raise ValueError(
                f"{control_id} assessment target matrix differs from inventory: "
                f"{missing} missing, {unexpected} unexpected"
            )


def _is_account_target(candidate: AssessmentCandidate, snapshot: InventorySnapshot) -> bool:
    return bool(
        candidate.resource_type == "aws_account"
        and candidate.account_id == snapshot.account_id
        and candidate.aws_resource_id == snapshot.account_id
        and candidate.scope is ResourceScope.GLOBAL
        and candidate.region is None
    )


def _validate_collection_gap(
    candidate: AssessmentCandidate,
    snapshot: InventorySnapshot,
    collection: tuple[str, str] | None,
) -> None:
    if collection is None:
        raise ValueError(f"{candidate.control_id} has no declared collector for account fallback")
    missing_collectors = {
        match.group(1)
        for path in candidate.missing_evidence
        if (match := _COLLECTOR_GAP.fullmatch(path)) is not None
    }
    if collection[1] not in missing_collectors:
        raise ValueError(
            f"{candidate.control_id} account fallback must name its missing collector "
            f"{collection[1]}"
        )
    if any(snapshot.collector_succeeded(collector) for collector in missing_collectors):
        raise ValueError(f"{candidate.control_id} account fallback names a successful collector")
