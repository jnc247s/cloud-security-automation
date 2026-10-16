"""Signed browser coordination and immutable request history on disposable PostgreSQL."""

import pytest

from tests.api import test_dashboard_operations as checks
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("logout", [False, True])
def test_held_committed_response_and_logout(postgres_engine, monkeypatch, tmp_path, logout):
    checks.test_held_committed_response_never_duplicates_or_restores_a_logged_out_session(
        postgres_engine, monkeypatch, tmp_path, logout
    )


def test_real_timeout_after_committed_response(postgres_engine, monkeypatch, tmp_path):
    checks.test_real_timeout_after_commit_requires_explicit_identical_retry(
        postgres_engine, monkeypatch, tmp_path
    )


def test_uncertain_retry_requires_current_capability(postgres_engine, monkeypatch, tmp_path):
    checks.test_fresh_capability_loss_denies_uncertain_retry_without_erasing_history(
        postgres_engine, monkeypatch, tmp_path
    )


def test_capacity_never_evicts_prior_preparations(postgres_engine, monkeypatch, tmp_path):
    checks.test_api_capacity_refuses_new_preparation_without_eviction_or_dispatch(
        postgres_engine, monkeypatch, tmp_path
    )


@pytest.mark.parametrize("decision", ["APPROVE", "REJECT"])
def test_signed_proposal_decision_admission_and_revocation(
    postgres_engine, monkeypatch, tmp_path, decision
):
    checks.test_signed_three_human_decision_admission_and_revocation_preserve_distinct_authority(
        postgres_engine, monkeypatch, tmp_path, decision
    )


def test_no_self_approval_or_admin_bypass(postgres_engine, monkeypatch, tmp_path):
    checks.test_self_approval_is_denied_by_real_service_without_admin_bypass(
        postgres_engine, monkeypatch, tmp_path
    )


def test_committed_response_loss_and_same_key_recovery(postgres_engine, monkeypatch, tmp_path):
    checks.test_lost_committed_response_is_unconfirmed_then_explicit_same_key_retry_confirms(
        postgres_engine, monkeypatch, tmp_path
    )


@pytest.mark.parametrize("submission_fails", [False, True])
def test_linked_request_and_durable_submission_failure(
    postgres_engine, monkeypatch, tmp_path, submission_fails
):
    checks.test_verification_accepted_request_and_durable_submission_failure_are_not_verdicts(
        postgres_engine, monkeypatch, tmp_path, submission_fails
    )


@pytest.mark.parametrize(
    "fault",
    [
        "response-id",
        "response-actor",
        "response-digest",
        "response-invalid",
        "history-actor",
        "history-digest",
        "history-unauthorized",
    ],
)
def test_untrusted_reference_remains_unconfirmed(postgres_engine, monkeypatch, tmp_path, fault):
    checks.test_malformed_or_cross_bound_response_never_confirms_an_untrusted_reference(
        postgres_engine, monkeypatch, tmp_path, fault
    )
