"""Authentication backends and reusable FastAPI identity dependency."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any, Protocol

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError, PyJWKClient, PyJWKClientError

from app.config import Settings, get_settings

DEVELOPMENT_BEARER_MARKER = "local-development"
_bearer_scheme = HTTPBearer(auto_error=False)


class AuthenticationError(Exception):
    """Represent an authentication failure without leaking verification details."""


@dataclass(frozen=True, slots=True)
class Principal:
    """Verified caller identity used by authorization policy."""

    subject: str
    role_names: frozenset[str]
    issuer: str


class AuthenticationBackend(Protocol):
    """Authenticate one bearer token and return a verified principal."""

    def authenticate(self, token: str) -> Principal:
        """Validate a bearer token and return its principal."""


class DevelopmentAuthenticationBackend:
    """Fixed local identity backend that is never valid in production."""

    def __init__(self, *, subject: str, role_names: tuple[str, ...]) -> None:
        self._subject = subject
        self._role_names = frozenset(role_names)

    def authenticate(self, token: str) -> Principal:
        """Accept only the documented, non-secret local development marker."""

        if not hmac.compare_digest(token, DEVELOPMENT_BEARER_MARKER):
            raise AuthenticationError("invalid development bearer marker")
        return Principal(
            subject=self._subject,
            role_names=self._role_names,
            issuer="development",
        )


class OIDCJWTAuthenticationBackend:
    """Validate signed OIDC JWTs against the configured provider JWKS."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        algorithms: tuple[str, ...],
        roles_claim: str,
        jwks_client: PyJWKClient | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms
        self._roles_claim = roles_claim
        # Cache the JWKS document briefly, but resolve keys by ``kid`` each time so
        # provider rotations that reuse an identifier are not cached indefinitely.
        self._jwks_client = jwks_client or PyJWKClient(
            jwks_url,
            cache_jwk_set=True,
            cache_keys=False,
            lifespan=300,
            timeout=5,
        )

    def authenticate(self, token: str) -> Principal:
        """Verify signature and mandatory OIDC claims, including token expiry."""

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "require": ["exp", "sub"],
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
            return self._principal_from_claims(claims)
        except (InvalidTokenError, PyJWKClientError, TypeError, ValueError) as error:
            raise AuthenticationError("bearer token validation failed") from error

    def _principal_from_claims(self, claims: Mapping[str, Any]) -> Principal:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("bearer token subject is missing")

        raw_roles = claims.get(self._roles_claim)
        if isinstance(raw_roles, str):
            roles = (raw_roles,)
        elif isinstance(raw_roles, list) and all(isinstance(role, str) for role in raw_roles):
            roles = tuple(raw_roles)
        else:
            raise AuthenticationError("bearer token roles are missing")

        role_names = frozenset(role.strip().upper() for role in roles if role.strip())
        allowed_roles = {"ADMIN", "ANALYST", "APPROVER", "VIEWER"}
        if not role_names or not role_names.issubset(allowed_roles):
            raise AuthenticationError("bearer token contains invalid roles")
        return Principal(subject=subject.strip(), role_names=role_names, issuer=self._issuer)


@lru_cache
def _oidc_backend(
    issuer: str,
    audience: str,
    jwks_url: str,
    algorithms: tuple[str, ...],
    roles_claim: str,
) -> OIDCJWTAuthenticationBackend:
    """Reuse the JWKS client and its key cache across requests."""

    return OIDCJWTAuthenticationBackend(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        algorithms=algorithms,
        roles_claim=roles_claim,
    )


def get_authentication_backend(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthenticationBackend:
    """Build the backend selected by validated application configuration."""

    if settings.auth_mode == "development":
        return DevelopmentAuthenticationBackend(
            subject=settings.dev_identity_subject,
            role_names=settings.dev_identity_role_names,
        )

    # Settings validation guarantees these values exist in OIDC mode.
    assert settings.oidc_issuer is not None
    assert settings.oidc_audience is not None
    assert settings.oidc_jwks_url is not None
    return _oidc_backend(
        settings.oidc_issuer,
        settings.oidc_audience,
        settings.oidc_jwks_url,
        settings.oidc_algorithm_names,
        settings.oidc_roles_claim,
    )


def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    backend: Annotated[AuthenticationBackend, Depends(get_authentication_backend)],
) -> Principal:
    """Authenticate the current bearer token or return a safe HTTP 401 response."""

    if credentials is None:
        raise _authentication_http_error()
    try:
        return backend.authenticate(credentials.credentials)
    except AuthenticationError as error:
        raise _authentication_http_error() from error


def _authentication_http_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "authentication_required",
            "message": "A valid bearer token is required.",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )
