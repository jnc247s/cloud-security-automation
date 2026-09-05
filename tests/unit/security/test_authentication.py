"""Tests for development and OIDC/JWT authentication backends."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.security.authentication import (
    DEVELOPMENT_BEARER_MARKER,
    AuthenticationError,
    DevelopmentAuthenticationBackend,
    OIDCJWTAuthenticationBackend,
    get_current_principal,
)


class _StaticJWKClient:
    def __init__(self, public_key: object) -> None:
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        del token
        return SimpleNamespace(key=self.public_key)


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _token(
    private_key: rsa.RSAPrivateKey,
    *,
    issuer: str = "https://identity.example.test",
    audience: str = "cloud-security-control-plane",
    expires_at: datetime | None = None,
    roles: object = None,
) -> str:
    claims = {
        "aud": audience,
        "exp": expires_at or datetime.now(UTC) + timedelta(minutes=5),
        "iss": issuer,
        "roles": ["ANALYST"] if roles is None else roles,
        "sub": "caller-123",
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def _oidc_backend(private_key: rsa.RSAPrivateKey) -> OIDCJWTAuthenticationBackend:
    return OIDCJWTAuthenticationBackend(
        issuer="https://identity.example.test",
        audience="cloud-security-control-plane",
        jwks_url="https://identity.example.test/.well-known/jwks.json",
        algorithms=("RS256",),
        roles_claim="roles",
        jwks_client=_StaticJWKClient(private_key.public_key()),  # type: ignore[arg-type]
    )


def test_development_backend_requires_explicit_marker() -> None:
    backend = DevelopmentAuthenticationBackend(
        subject="local-developer",
        role_names=("ADMIN",),
    )

    principal = backend.authenticate(DEVELOPMENT_BEARER_MARKER)

    assert principal.subject == "local-developer"
    assert principal.role_names == frozenset({"ADMIN"})
    assert principal.issuer == "development"
    with pytest.raises(AuthenticationError):
        backend.authenticate("wrong-marker")


def test_oidc_backend_verifies_token_and_maps_roles() -> None:
    private_key = _rsa_key()

    principal = _oidc_backend(private_key).authenticate(
        _token(private_key, roles=["viewer", "ANALYST"])
    )

    assert principal.subject == "caller-123"
    assert principal.role_names == frozenset({"VIEWER", "ANALYST"})
    assert principal.issuer == "https://identity.example.test"


@pytest.mark.parametrize(
    ("token_arguments", "signing_key_factory"),
    [
        ({"issuer": "https://wrong-issuer.example.test"}, lambda key: key),
        ({"audience": "wrong-audience"}, lambda key: key),
        (
            {"expires_at": datetime.now(UTC) - timedelta(minutes=1)},
            lambda key: key,
        ),
        ({}, lambda key: _rsa_key()),
    ],
)
def test_oidc_backend_rejects_untrusted_or_expired_tokens(
    token_arguments: dict[str, object],
    signing_key_factory: object,
) -> None:
    trusted_key = _rsa_key()
    signing_key = signing_key_factory(trusted_key)  # type: ignore[operator]

    with pytest.raises(AuthenticationError):
        _oidc_backend(trusted_key).authenticate(_token(signing_key, **token_arguments))  # type: ignore[arg-type]


def test_oidc_backend_rejects_unknown_roles() -> None:
    private_key = _rsa_key()

    with pytest.raises(AuthenticationError):
        _oidc_backend(private_key).authenticate(_token(private_key, roles=["SUPERUSER"]))


def test_current_principal_returns_safe_401_for_invalid_credentials() -> None:
    backend = DevelopmentAuthenticationBackend(
        subject="local-developer",
        role_names=("ADMIN",),
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong")

    with pytest.raises(HTTPException) as error:
        get_current_principal(credentials=credentials, backend=backend)

    assert error.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert error.value.headers == {"WWW-Authenticate": "Bearer"}
    assert error.value.detail["code"] == "authentication_required"
