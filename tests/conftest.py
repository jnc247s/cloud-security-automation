"""Shared pytest fixtures."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Provide a FastAPI test client with application lifespan handling."""

    with TestClient(create_app()) as test_client:
        yield test_client
