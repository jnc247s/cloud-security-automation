"""Sprint 5C IAM account-level evidence collection.

The collector is deliberately fact-only. It validates the two account-summary indicators needed
by later controls and records their provenance without creating an account resource or evaluating
security posture.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceError,
    CollectorResult,
    ResourceCollector,
    build_source_observation,
    collection_status_for,
    require_integer,
    require_mapping,
    require_member,
    source_failure,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_COLLECTOR_VERSION = "1.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_OPERATION_NAME = "get_account_summary"
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)


class IAMAccountEvidenceCollector(ResourceCollector):
    """Collect the global IAM account-summary facts required by IAM-005 and IAM-006."""

    collector_name = "iam_account_evidence"
    produces_evidence_graph = True

    def collect(self) -> list[NormalizedResource]:
        """Preserve the direct collector API while collecting account-only evidence."""

        context = CollectionContext(
            scan_id=uuid4(),
            collection_account_id=self.client_provider.account_id,
            region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
        )
        self.collect_with_context(context)
        return []

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Collect one global IAM account-summary observation."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")

        client = self.client_provider.client("iam")
        account_access_keys_present: bool | None = None
        account_mfa_enabled: bool | None = None
        error: BaseException | None = None

        try:
            response = require_mapping(
                client.get_account_summary(),
                operation_name=_OPERATION_NAME,
                fact_path="response",
            )
            summary = require_mapping(
                require_member(
                    response,
                    "SummaryMap",
                    operation_name=_OPERATION_NAME,
                    fact_path="SummaryMap",
                ),
                operation_name=_OPERATION_NAME,
                fact_path="SummaryMap",
            )
            access_key_flag = _require_presence_flag(summary, "AccountAccessKeysPresent")
            mfa_flag = _require_presence_flag(summary, "AccountMFAEnabled")
            account_access_keys_present = bool(access_key_flag)
            account_mfa_enabled = bool(mfa_flag)
        except _EXPECTED_FAILURES as caught:
            error = caught

        state, failure_category = _state_for(error)
        observation = build_source_observation(
            context=context,
            contract_key="iam.account-summary",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=AccountEvidenceSubject(
                aws_account_id=context.collection_account_id,
                scope=ResourceScope.GLOBAL,
            ),
            evidence_kind="iam.account-summary",
            collector="iam.account-summary",
            collector_version=_COLLECTOR_VERSION,
            source_api="iam:GetAccountSummary",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference="normalized://aws/iam/account-summary",
            evidence_schema="iam.account-summary",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "account_access_keys_present": account_access_keys_present,
                "account_mfa_enabled": account_mfa_enabled,
                "complete": error is None,
                "failure_category": (
                    failure_category.value if failure_category is not None else None
                ),
            },
            state=state,
            failure_category=failure_category,
        )
        outcomes = (observation.outcome,)
        return CollectorResult(
            status=collection_status_for(outcomes),
            source_contracts=(observation.contract,),
            artifacts=(observation.artifact,),
            source_outcomes=outcomes,
        )


def _require_presence_flag(summary: dict[str, Any], name: str) -> int:
    value = require_integer(
        require_member(
            summary,
            name,
            operation_name=_OPERATION_NAME,
            fact_path=f"SummaryMap.{name}",
        ),
        operation_name=_OPERATION_NAME,
        fact_path=f"SummaryMap.{name}",
    )
    if value not in {0, 1}:
        raise CollectorEvidenceError(_OPERATION_NAME, f"SummaryMap.{name}")
    return value


def _state_for(
    error: BaseException | None,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if error is None:
        return EvidenceSourceState.PRESENT, None
    return source_failure(error)
