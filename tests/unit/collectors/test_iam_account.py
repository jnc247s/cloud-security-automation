"""Unit coverage for Sprint 5C IAM account-summary evidence collection."""

from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.assessment.evidence_graph import EvidenceCardinality, ResourceOwnerMode
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.collectors.base import CollectionContext
from app.collectors.iam_account import IAMAccountEvidenceCollector
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import ResourceScope
from tests.fakes import FakeAWSClient, FakeClientProvider, client_error

ACCOUNT_ID = "123456789012"
REGION = "us-gov-west-1"
SCAN_ID = UUID("f248c33e-b555-4dbb-ac47-0e8e14c51468")
COLLECTED_AT = datetime(2026, 9, 16, 16, 30, tzinfo=UTC)


def _context(*, account_id: str = ACCOUNT_ID, region: str = REGION) -> CollectionContext:
    return CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=account_id,
        region=region,
        collected_at=COLLECTED_AT,
    )


def _collector(response: object) -> tuple[IAMAccountEvidenceCollector, FakeAWSClient]:
    client = FakeAWSClient(responses={"get_account_summary": [response]})
    provider = FakeClientProvider(
        {("iam", REGION): client},
        region_name=REGION,
        account_id=ACCOUNT_ID,
        partition="aws-us-gov",
    )
    return IAMAccountEvidenceCollector(provider), client


def _result(response: object):
    collector, _ = _collector(response)
    return collector.collect_with_context(_context())


def test_collects_strict_global_account_summary_evidence() -> None:
    collector, client = _collector(
        {
            "SummaryMap": {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
                "Users": 3,
            }
        }
    )

    result = collector.collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert result.resources == ()
    assert result.relationships == ()
    assert len(result.source_contracts) == len(result.artifacts) == len(result.source_outcomes) == 1

    contract = result.source_contracts[0]
    artifact = result.artifacts[0]
    outcome = result.source_outcomes[0]
    assert contract.contract_key == "iam.account-summary"
    assert contract.contract_version == "1.0.0"
    assert contract.phase is EvidenceCollectionPhase.DISCOVERY
    assert contract.subject == AccountEvidenceSubject(
        aws_account_id=ACCOUNT_ID,
        scope=ResourceScope.GLOBAL,
    )
    assert contract.cardinality is EvidenceCardinality.SINGLE
    assert contract.owner_mode is ResourceOwnerMode.COLLECTION_ACCOUNT
    assert contract.identity_authoritative is False
    assert contract.matches_outcome(outcome)
    assert outcome.evidence_kind == "iam.account-summary"
    assert outcome.collector == "iam.account-summary"
    assert outcome.collector_version == "1.0.0"
    assert outcome.source_api == "iam:GetAccountSummary"
    assert outcome.state is EvidenceSourceState.PRESENT
    assert outcome.failure_category is None
    assert outcome.collected_at == COLLECTED_AT
    assert outcome.evidence_reference == "normalized://aws/iam/account-summary"
    assert outcome.evidence_sha256 == artifact.evidence_sha256
    assert artifact.evidence_schema == "iam.account-summary"
    assert artifact.evidence_schema_version == "1.0.0"
    assert artifact.normalized_payload == {
        "account_id": ACCOUNT_ID,
        "account_access_keys_present": False,
        "account_mfa_enabled": True,
        "complete": True,
        "failure_category": None,
    }
    assert client.calls[0].operation_name == "get_account_summary"
    assert client.calls[0].parameters == {}


@pytest.mark.parametrize("field", ["AccountAccessKeysPresent", "AccountMFAEnabled"])
@pytest.mark.parametrize("value", [True, False, -1, 2, 1.0, "1", None])
def test_presence_flags_reject_non_integer_or_non_binary_values(field: str, value: object) -> None:
    summary: dict[str, object] = {
        "AccountAccessKeysPresent": 0,
        "AccountMFAEnabled": 1,
    }
    summary[field] = value

    result = _result({"SummaryMap": summary})

    assert result.status is CollectionStatus.PARTIAL
    outcome = result.source_outcomes[0]
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert result.artifacts[0].normalized_payload == {
        "account_id": ACCOUNT_ID,
        "account_access_keys_present": None,
        "account_mfa_enabled": None,
        "complete": False,
        "failure_category": "MALFORMED_RESPONSE",
    }


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"SummaryMap": None},
        {"SummaryMap": []},
        {"SummaryMap": {"AccountMFAEnabled": 1}},
        {"SummaryMap": {"AccountAccessKeysPresent": 0}},
    ],
)
def test_malformed_response_fails_closed_without_retaining_raw_values(response: object) -> None:
    result = _result(response)

    assert result.status is CollectionStatus.PARTIAL
    assert result.source_outcomes[0].state is EvidenceSourceState.MALFORMED
    assert result.source_outcomes[0].failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    serialized = "".join(
        item.model_dump_json()
        for item in (*result.source_contracts, *result.artifacts, *result.source_outcomes)
    )
    assert "SummaryMap" not in serialized
    assert "AccountAccessKeysPresent" not in serialized
    assert "AccountMFAEnabled" not in serialized


def test_access_denial_is_sanitized_and_marks_the_only_source_failed() -> None:
    denied = client_error("AccessDenied", "GetAccountSummary", status_code=403)
    result = _result(denied)

    assert result.status is CollectionStatus.FAILED
    outcome = result.source_outcomes[0]
    assert outcome.state is EvidenceSourceState.UNAVAILABLE
    assert outcome.failure_category is EvidenceFailureCategory.ACCESS_DENIED
    serialized = "".join(
        item.model_dump_json()
        for item in (*result.source_contracts, *result.artifacts, *result.source_outcomes)
    )
    assert "simulated" not in serialized
    assert "AccessDenied" not in serialized


def test_programming_defects_are_not_reclassified_as_evidence_failures() -> None:
    result_error = RuntimeError("programming defect")
    collector, _ = _collector(result_error)

    with pytest.raises(RuntimeError, match="programming defect"):
        collector.collect_with_context(_context())


def test_collection_context_account_must_match_provider_before_aws_call() -> None:
    collector, client = _collector(
        {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}}
    )

    with pytest.raises(ValueError, match="context account"):
        collector.collect_with_context(_context(account_id="999999999999"))

    assert client.calls == []


def test_global_observation_does_not_inherit_execution_region() -> None:
    collector, _ = _collector(
        {"SummaryMap": {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 0}}
    )

    result = collector.collect_with_context(_context(region="us-east-1"))

    subject = result.source_outcomes[0].subject
    assert isinstance(subject, AccountEvidenceSubject)
    assert subject.scope is ResourceScope.GLOBAL
    assert subject.region is None
    assert "/us-east-1/" not in result.source_outcomes[0].evidence_reference


def test_direct_collect_invokes_aws_but_returns_no_synthetic_resource() -> None:
    collector, client = _collector(
        {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}}
    )

    assert collector.collect() == []
    assert [call.operation_name for call in client.calls] == ["get_account_summary"]
