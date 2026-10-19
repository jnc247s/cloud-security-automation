"""Revocation cutoffs are closed parent facts, never a cancellation or renewed grant."""

from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(
    "name,phase,before",
    [
        ("revoked-before-intent", "NO_WRITE", True),
        ("revoked-after-ack", "ACKNOWLEDGED", False),
    ],
)
def test_revocation_case_keeps_preintent_prevention_separate_from_retained_ack(name, phase, before):
    from tests.dashboard_integrated_revocation import revocation_case

    value = revocation_case(name)
    assert value.phase == phase and value.before_intent is before
    with pytest.raises(FrozenInstanceError):
        value.phase = "CANCELED"


@pytest.mark.parametrize(
    "name", [None, True, 1, {}, [], "", "revoked", "revoked-after-ack ", "verified"]
)
def test_untrusted_revocation_case_cannot_select_authority_or_provider_work(name):
    from tests.dashboard_integrated_revocation import revocation_case

    with pytest.raises(ValueError, match="Invalid integrated revocation case"):
        revocation_case(name)


@pytest.mark.parametrize("name", ["revoked-before-intent", "revoked-after-ack"])
@pytest.mark.parametrize("fault", [None, "environment", "scenario", "required"])
def test_revocation_read_requires_owning_test_parent_before_sql(monkeypatch, name, fault):
    from tests.dashboard_integrated_revocation import read_revocation

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    touched = []

    def owned():
        touched.append("owned")
        raise RuntimeError("owned boundary")

    parent = SimpleNamespace(scenario=SimpleNamespace(name=name), _owned=owned)
    if fault == "environment":
        monkeypatch.delenv("DASHBOARD_BROWSER_TEST")
    elif fault == "scenario":
        parent.scenario = SimpleNamespace(name="verified")
    if fault:
        with pytest.raises(ValueError):
            read_revocation(parent, None, required=1 if fault == "required" else True)
        assert touched == []
    else:
        with pytest.raises(RuntimeError, match="owned boundary"):
            read_revocation(parent, None, required=True)
        assert touched == ["owned"]


@pytest.mark.parametrize("extra", [False, True])
def test_proven_append_preserves_database_order_without_hashing_sensitive_rows(extra):
    from tests.dashboard_integrated_revocation import _append_proven_rows

    before = ({"id": 2, "actor": ["original"]},)
    addition = {"id": 1, "actor": ["revoker"]}
    after = (addition, *before) + (({"id": 3},) if extra else ())
    actual = _append_proven_rows(before, after, lambda row: row["id"] == 1, exact=not extra)
    assert actual == (addition, *before)
    assert before == ({"id": 2, "actor": ["original"]},)


@pytest.mark.parametrize(
    "after",
    [
        ({"id": 2},),
        ({"id": 1},),
        ({"id": 1}, {"id": 2}, {"id": 3}),
        ({"id": 1}, {"id": 1}, {"id": 2}),
    ],
)
def test_proven_append_rejects_missing_duplicate_or_unexpected_authority_rows(after):
    from tests.dashboard_integrated_revocation import _append_proven_rows

    with pytest.raises(ValueError, match="Invalid append-only signed revocation delta"):
        _append_proven_rows(({"id": 2},), after, lambda row: row["id"] == 1, exact=True)
