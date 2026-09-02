"""Shared pytest fixtures."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Provide a FastAPI test client with application lifespan handling."""

    with TestClient(app) as test_client:
        yield test_client
