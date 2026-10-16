"""Fixture target/ownership guards fail before touching an operator namespace."""

from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.schema import CreateSchema, DropSchema

from tests import dashboard_operation_runtime as runtime

URL = "postgresql+psycopg://cloudsec:synthetic-only@127.0.0.1:5432/cloudsec_test"


@pytest.mark.parametrize(
    "raw",
    [
        "sqlite://",
        "postgresql://127.0.0.1/cloudsec_test",
        "postgresql+psycopg://remote.example.test/cloudsec_test",
        "postgresql+psycopg://localhost/cloudsec_test",
        "postgresql+psycopg://127.0.0.1/production",
        URL + "?options=-csearch_path=public",
        URL + "?host=remote.example.test",
        "postgresql+psycopg://127.0.0.1:0/cloudsec_test",
        "not-a-database",
    ],
)
def test_refuses_nonexplicit_remote_production_or_query_overridden_database(raw):
    with pytest.raises(ValueError) as caught:
        runtime.fixture_database(raw)
    assert "synthetic-only" not in str(caught.value)


@pytest.mark.parametrize(
    "instance",
    [
        "",
        "public",
        "../schema",
        "x'; DROP SCHEMA public",
        None,
        "11111111-1111-1111-1111-111111111111",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
    ],
)
def test_schema_name_has_only_a_canonical_v4_ownership_id(instance):
    with pytest.raises(ValueError):
        runtime.fixture_schema(instance)


class Engine:
    def __init__(
        self, instance, *, owner_matches=True, create_fails=False, database="cloudsec_test"
    ):
        self.instance, self.owner_matches = instance, owner_matches
        self.create_fails, self.database = create_fails, database
        self.statements, self.open_transactions, self.disposed = [], 0, False

    @contextmanager
    def begin(self):
        self.open_transactions += 1
        try:
            yield self
        finally:
            self.open_transactions -= 1

    def execute(self, statement, params=None):
        self.statements.append(statement)
        if isinstance(statement, CreateSchema) and self.create_fails:
            raise RuntimeError("Controlled schema collision")
        value = (
            self.database
            if str(statement) == "SELECT current_database()"
            else (
                "cloudsec.dashboard.ops:" + self.instance if self.owner_matches else "another-owner"
            )
        )
        return SimpleNamespace(scalar_one=lambda: value, scalar_one_or_none=lambda: value)

    def exec_driver_sql(self, statement):
        self.statements.append(statement)

    def dispose(self):
        self.disposed = True


def test_only_its_created_labeled_schema_is_cleaned_without_a_long_transaction(monkeypatch):
    instance = str(uuid4())
    engine = Engine(instance)
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    monkeypatch.setattr(runtime, "create_engine", lambda *args, **kwargs: engine)
    with runtime.owned_schema(URL, instance) as url:
        assert engine.open_transactions == 0
        assert url.query == {"options": "-csearch_path=" + runtime.fixture_schema(instance)}
        assert not any(isinstance(s, DropSchema) for s in engine.statements)
    dropped = [s for s in engine.statements if isinstance(s, DropSchema)]
    assert len(dropped) == 1 and dropped[0].element == runtime.fixture_schema(instance)
    assert dropped[0].cascade and engine.disposed and engine.open_transactions == 0


@pytest.mark.parametrize("fault", ["wrong-owner", "collision", "wrong-database", "missing-guard"])
def test_failed_or_unowned_setup_never_cleans_another_namespace(monkeypatch, fault):
    instance = str(uuid4())
    engine = Engine(
        instance,
        owner_matches=fault != "wrong-owner",
        create_fails=fault == "collision",
        database="not-test" if fault == "wrong-database" else "cloudsec_test",
    )
    calls = []
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "0" if fault == "missing-guard" else "1")
    monkeypatch.setattr(
        runtime, "create_engine", lambda *args, **kwargs: calls.append(True) or engine
    )
    with pytest.raises(RuntimeError):
        with runtime.owned_schema(URL, instance):
            pass
    assert not any(isinstance(s, DropSchema) for s in engine.statements)
    if fault == "missing-guard":
        assert calls == []
    else:
        assert engine.disposed
