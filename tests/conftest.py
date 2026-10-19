"""Shared pytest fixtures."""

import sys
from collections.abc import Generator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@contextmanager
def preserved_import_path() -> Generator[None, None, None]:
    """Keep real migration imports in scope, then restore the caller's exact path."""

    original = sys.path.copy()
    try:
        yield
    finally:
        sys.path[:] = original


@pytest.fixture(autouse=True)
def restore_import_path_after_test() -> Generator[None, None, None]:
    """Do not leak Alembic's repeated path prepends into subsequent test requests."""

    with preserved_import_path():
        yield


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Provide a FastAPI test client with application lifespan handling."""

    with TestClient(create_app()) as test_client:
        yield test_client
