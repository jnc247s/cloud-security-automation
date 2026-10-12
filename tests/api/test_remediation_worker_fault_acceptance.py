"""Signed authority, real migrated SQLite and real SDK fault/recovery acceptance."""

import pytest

from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.worker_fault_http import (
    GUARD_CASES,
    PREINTENT_CASES,
    RECOVERY_CASES,
    UNCERTAIN_CASES,
    exercise_after_intent_revoke,
    exercise_capacity,
    exercise_guard_rejection,
    exercise_preintent,
    exercise_readback,
    exercise_reclaim,
    exercise_recovery,
    exercise_uncertain,
)


@pytest.mark.parametrize("case", PREINTENT_CASES)
def test_signed_preintent_no_write(migrated_engine, monkeypatch, tmp_path, case):
    exercise_preintent(migrated_engine, monkeypatch, tmp_path, case)


@pytest.mark.parametrize("case", UNCERTAIN_CASES)
def test_signed_one_attempt_uncertainty(migrated_engine, monkeypatch, tmp_path, case):
    exercise_uncertain(migrated_engine, monkeypatch, tmp_path, case)


@pytest.mark.parametrize("case", RECOVERY_CASES)
def test_signed_read_only_recovery(migrated_engine, monkeypatch, tmp_path, case):
    exercise_recovery(migrated_engine, monkeypatch, tmp_path, case)


def test_signed_reclaim_fences_owner_and_retains_budget(migrated_engine, monkeypatch, tmp_path):
    exercise_reclaim(migrated_engine, monkeypatch, tmp_path)


@pytest.mark.parametrize("late", [False, True])
def test_signed_global_readback_limits(migrated_engine, monkeypatch, tmp_path, late):
    exercise_readback(migrated_engine, monkeypatch, tmp_path, late=late)


def test_signed_post_intent_revocation_is_not_cancellation(migrated_engine, monkeypatch, tmp_path):
    exercise_after_intent_revoke(migrated_engine, monkeypatch, tmp_path)


def test_signed_quarantine_retains_target_and_actual_capacity(
    migrated_engine, monkeypatch, tmp_path
):
    exercise_capacity(migrated_engine, monkeypatch, tmp_path)


@pytest.mark.parametrize("case", GUARD_CASES)
def test_signed_fault_helper_rejects_injected_guard_failures(
    migrated_engine, monkeypatch, tmp_path, case
):
    exercise_guard_rejection(migrated_engine, monkeypatch, tmp_path, case)
