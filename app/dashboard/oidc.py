"""Reviewed OAuth/OIDC clients; all endpoints derive from trusted operator configuration."""

import json
import math
from dataclasses import dataclass, field

import httpx2 as httpx
import jwt as pyjwt
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oidc.core import CodeIDToken
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.dashboard.store import Login
from app.security.authentication import Principal, get_authentication_backend


@dataclass(frozen=True)
class VerifiedLogin:
    access_token: str = field(repr=False)
    principal: Principal
    expires: float


class OIDCClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.transport = None

    def _client(self) -> AsyncOAuth2Client:
        settings = self.settings
        assert settings.dashboard_client_secret is not None
        return AsyncOAuth2Client(
            settings.dashboard_client_id,
            settings.dashboard_client_secret.get_secret_value(),
            scope=settings.dashboard_scopes,
            redirect_uri=f"{settings.dashboard_origin}/dashboard/auth/callback",
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_basic",
            timeout=5,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        )

    async def _json(self, url: str) -> dict:
        async with (
            httpx.AsyncClient(
                timeout=5, follow_redirects=False, trust_env=False, transport=self.transport
            ) as client,
            client.stream("GET", url) as response,
        ):
            response.raise_for_status()
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > 65536:
                    raise ValueError("oversized identity-provider response")
            value = json.loads(chunks)
            if not isinstance(value, dict):
                raise ValueError("invalid identity-provider document")
            return value

    async def metadata(self) -> dict:
        settings = self.settings
        metadata = await self._json(f"{settings.oidc_issuer}/.well-known/openid-configuration")
        if metadata.get("issuer") != settings.oidc_issuer:
            raise ValueError("discovery issuer mismatch")
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = metadata.get(name)
            if not isinstance(value, str):
                raise ValueError("incomplete discovery")
            settings._validate_oidc_url(name, value)
            from urllib.parse import urlparse

            parsed = urlparse(value)
            if parsed.username or parsed.password or parsed.fragment or parsed.query:
                raise ValueError("invalid provider endpoint")
        if metadata["jwks_uri"] != settings.oidc_jwks_url:
            raise ValueError("discovery JWKS mismatch")
        return metadata

    async def authorize(self, pending: Login) -> str:
        metadata = await self.metadata()
        async with self._client() as client:
            url, _ = client.create_authorization_url(
                metadata["authorization_endpoint"],
                state=pending.state,
                code_verifier=pending.verifier,
                nonce=pending.nonce,
                resource=self.settings.oidc_audience,
            )
            return url

    async def exchange(self, pending: Login, code: str) -> VerifiedLogin:
        metadata = await self.metadata()
        async with self._client() as client:
            token = await client.fetch_token(
                metadata["token_endpoint"],
                code=code,
                code_verifier=pending.verifier,
                grant_type="authorization_code",
            )
        access = token.get("access_token")
        identity = token.get("id_token")
        if (
            not isinstance(access, str)
            or len(access) > 16384
            or not isinstance(identity, str)
            or len(identity) > 16384
            or str(token.get("token_type", "")).lower() != "bearer"
        ):
            raise ValueError("invalid token response")
        keys = KeySet.import_key_set(await self._json(metadata["jwks_uri"]))
        decoded = jwt.decode(
            identity,
            keys,
            registry=JWSRegistry(algorithms=list(self.settings.oidc_algorithm_names)),
        )
        claims = CodeIDToken(
            decoded.claims,
            decoded.header,
            {
                "iss": {"essential": True, "value": self.settings.oidc_issuer},
                "aud": {"essential": True, "value": self.settings.dashboard_client_id},
            },
            {
                "nonce": pending.nonce,
                "client_id": self.settings.dashboard_client_id,
                "access_token": access,
            },
        )
        claims.validate(leeway=0)
        principal = await run_in_threadpool(
            get_authentication_backend(self.settings).authenticate, access
        )
        if claims["sub"] != principal.subject:
            raise ValueError("identity/access-token subject mismatch")
        # The API already verified this token. Only extract its verified expiry for the store.
        expiry = pyjwt.decode(access, options={"verify_signature": False}).get("exp")
        if type(expiry) not in (int, float) or not math.isfinite(expiry):
            raise ValueError("invalid token lifetime")
        return VerifiedLogin(access, principal, float(expiry))
