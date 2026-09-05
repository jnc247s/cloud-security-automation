"""Application startup smoke test."""

from uuid import UUID

from fastapi.testclient import TestClient

from app.main import create_app


class _RecordingExecutor:
    def __init__(self) -> None:
        self.resume_calls = 0
        self.shutdown_calls: list[bool] = []

    def submit(self, _scan_id: UUID) -> None:
        pass

    def resume_pending(self) -> int:
        self.resume_calls += 1
        return 0

    def shutdown(self, *, wait: bool = True) -> None:
        self.shutdown_calls.append(wait)


def test_application_starts_and_exposes_openapi() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Cloud Security Control Plane"
    assert "/api/v1/scans" in response.json()["paths"]
    assert "/api/v1/assessments/{assessment_id}" in response.json()["paths"]


def test_application_lifespan_recovers_and_closes_executor() -> None:
    executor = _RecordingExecutor()
    application = create_app(
        executor_factory=lambda: executor,
        resume_pending_scans=True,
    )

    with TestClient(application) as client:
        assert client.app.state.scan_executor is executor

    assert executor.resume_calls == 1
    assert executor.shutdown_calls == [True]


def test_every_versioned_operation_declares_bearer_authentication() -> None:
    application = create_app()
    document = application.openapi()

    for path, operations in document["paths"].items():
        if not path.startswith("/api/v1"):
            continue
        for operation in operations.values():
            assert {"HTTPBearer": []} in operation["security"], path
