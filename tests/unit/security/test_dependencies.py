"""Tests for the reusable FastAPI authentication and authorization dependencies."""

from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.security.authentication import DEVELOPMENT_BEARER_MARKER, Principal
from app.security.authorization import Capability, require_capability


def _protected_app() -> FastAPI:
    application = FastAPI()
    application.dependency_overrides[get_settings] = lambda: Settings(
        auth_mode="development",
        dev_identity_subject="test-developer",
        dev_identity_roles="VIEWER",
    )

    @application.get("/read")
    def read_route(
        principal: Annotated[
            Principal,
            Depends(require_capability(Capability.READ)),
        ],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    @application.post("/execute")
    def execute_route(
        principal: Annotated[
            Principal,
            Depends(require_capability(Capability.EXECUTE)),
        ],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    return application


def test_protected_route_requires_bearer_authentication() -> None:
    with TestClient(_protected_app()) as client:
        response = client.get("/read")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["detail"]["code"] == "authentication_required"


def test_protected_route_accepts_configured_development_identity() -> None:
    with TestClient(_protected_app()) as client:
        response = client.get(
            "/read",
            headers={"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"},
        )

    assert response.status_code == 200
    assert response.json() == {"subject": "test-developer"}


def test_protected_route_enforces_required_capability() -> None:
    with TestClient(_protected_app()) as client:
        response = client.post(
            "/execute",
            headers={"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "insufficient_capability"


def test_bearer_scheme_is_present_in_openapi_contract() -> None:
    schema = _protected_app().openapi()

    assert schema["components"]["securitySchemes"]["HTTPBearer"] == {
        "scheme": "bearer",
        "type": "http",
    }
    assert schema["paths"]["/read"]["get"]["security"] == [{"HTTPBearer": []}]
