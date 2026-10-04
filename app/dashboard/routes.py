"""Cookies stop here. A narrow READ adapter still crosses the real bearer API boundary."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID

import httpx2 as httpx
from authlib.integrations.base_client.errors import OAuthError
from fastapi import APIRouter, HTTPException, Query, Request, Response
from joserfc.errors import JoseError
from starlette.concurrency import run_in_threadpool
from starlette.responses import FileResponse, RedirectResponse
from starlette.staticfiles import StaticFiles

from app.config import Settings
from app.dashboard.investigation_routes import install_investigation
from app.dashboard.oidc import OIDCClient
from app.dashboard.store import BrowserSession, CapacityError, SessionStore, matches_opaque
from app.security.authentication import AuthenticationError, get_authentication_backend

SESSION_COOKIE = "cloudsec_session"
LOGIN_COOKIE = "cloudsec_login"
COOKIE_PATH = "/dashboard"


class Dashboard:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = SessionStore()
        self.oidc = OIDCClient(settings)

    def origin(self, request: Request, *, mutation: bool = False) -> None:
        trusted = self.settings.dashboard_origin
        if str(request.base_url).rstrip("/") != trusted:
            raise HTTPException(403, "Dashboard origin rejected")
        origin = request.headers.get("origin")
        if (
            (mutation and origin != trusted)
            or (origin is not None and origin != trusted)
            or request.headers.get("sec-fetch-site") not in (None, "same-origin", "none")
        ):
            raise HTTPException(403, "Dashboard origin rejected")

    def cookie(self, response: Response, name: str, value: str, *, age: int = 300) -> None:
        response.set_cookie(
            name,
            value,
            max_age=age,
            httponly=True,
            secure=self.settings.dashboard_origin.startswith("https://"),
            samesite="strict" if name == SESSION_COOKIE else "lax",
            path=COOKIE_PATH,
        )

    def clear_cookie(self, response: Response, name: str) -> None:
        response.delete_cookie(
            name,
            path=COOKIE_PATH,
            httponly=True,
            secure=self.settings.dashboard_origin.startswith("https://"),
            samesite="strict" if name == SESSION_COOKIE else "lax",
        )

    async def session(self, request: Request) -> tuple[str, BrowserSession]:
        identifier = request.cookies.get(SESSION_COOKIE, "")
        session = self.store.get(identifier, touch=False)
        if session:
            try:
                await run_in_threadpool(
                    get_authentication_backend(self.settings).authenticate, session.access_token
                )
            except AuthenticationError:
                self.store.revoke(identifier)
                session = None
        if not session:
            raise HTTPException(401, "Dashboard sign-in required")
        return identifier, session

    async def read(
        self, request: Request, path: str, params: dict | None = None, *, operational: bool = False
    ) -> Response:
        self.origin(request)
        identifier, session = await self.session(request)
        # The shared cookie may have changed in another tab since this shell bootstrapped.
        # This public correlation value confers no authority without the cookie/bearer/READ.
        if not matches_opaque(session.context, request.headers.get("x-dashboard-context", "")):
            raise HTTPException(401, "Dashboard session changed")
        if not self.store.get(identifier):
            raise HTTPException(401, "Dashboard sign-in required")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=request.app),
            base_url="http://internal.invalid",
            follow_redirects=False,
            trust_env=False,
        ) as client:
            upstream = await client.get(
                path, params=params, headers={"Authorization": f"Bearer {session.access_token}"}
            )
        if upstream.status_code == 401:
            self.store.revoke(identifier)
        # Logout/expiry during an in-flight read must never return the old identity's data.
        if not self.store.get(identifier, touch=False):
            raise HTTPException(401, "Dashboard sign-in required")
        return Response(
            upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
            headers={"X-Dashboard-Read-At": datetime.now(UTC).isoformat()}
            if operational and upstream.is_success
            else None,
        )


def install_dashboard(application, settings: Settings) -> None:
    boundary = Dashboard(settings)
    application.state.dashboard = boundary
    router = APIRouter(prefix="/dashboard", include_in_schema=False)

    @router.get("/session")
    async def session_status(request: Request, response: Response):
        boundary.origin(request)
        try:
            _, session = await boundary.session(request)
        except HTTPException as error:
            if error.status_code != 401:
                raise
            try:
                browser, login = boundary.store.login(request.cookies.get(LOGIN_COOKIE))
            except CapacityError as error:
                raise HTTPException(503, "Dashboard login capacity reached") from error
            boundary.clear_cookie(response, SESSION_COOKIE)
            boundary.cookie(response, LOGIN_COOKIE, browser)
            return {"authenticated": False, "csrf_token": login.csrf}
        return {
            "authenticated": True,
            "subject": session.principal.subject,
            "roles": sorted(session.principal.role_names),
            "csrf_token": session.csrf,
            "session_context": session.context,
            "expires_at": session.expires,
            "idle_expires_at": session.idle_expires,
        }

    @router.post("/auth/login")
    async def login(request: Request):
        boundary.origin(request, mutation=True)
        # Fixed form field avoids body parsing, arbitrary redirects and reflected provider data.
        csrf = request.headers.get("x-csrf-token", "")
        browser = request.cookies.get(LOGIN_COOKIE, "")
        pending = boundary.store.begin(browser, csrf)
        if not pending:
            raise HTTPException(403, "Dashboard login rejected")
        try:
            url = await boundary.oidc.authorize(pending)
        except (httpx.HTTPError, ValueError, OAuthError) as error:
            boundary.store.discard_login(browser)
            raise HTTPException(503, "Dashboard sign-in unavailable") from error
        # A JSON navigation target contains state/challenge, never a token or verifier.
        return {"authorization_url": url}

    @router.get("/auth/callback")
    async def callback(request: Request):
        if str(request.base_url).rstrip("/") != settings.dashboard_origin:
            raise HTTPException(403, "Dashboard origin rejected")
        params = request.query_params
        allowed = {"code", "state", "error", "error_description", "iss"}
        browser = request.cookies.get(LOGIN_COOKIE, "")
        pending = boundary.store.consume(browser, params.get("state", ""))
        response = RedirectResponse("/dashboard/?login=failed", status_code=303)
        boundary.clear_cookie(response, LOGIN_COOKIE)
        boundary.store.revoke(request.cookies.get(SESSION_COOKIE, ""))
        boundary.clear_cookie(response, SESSION_COOKIE)
        if (
            not pending
            or set(params) - allowed
            or any(len(params.getlist(k)) != 1 for k in params)
            or "error" in params
            or not 0 < len(params.get("code", "")) <= 2048
            or ("iss" in params and params["iss"] != settings.oidc_issuer)
        ):
            return response
        try:
            verified = await boundary.oidc.exchange(pending, params["code"])
            identifier = boundary.store.create(
                verified.access_token, verified.principal, verified.expires
            )
        except (
            httpx.HTTPError,
            ValueError,
            TypeError,
            KeyError,
            OAuthError,
            JoseError,
            AuthenticationError,
            CapacityError,
        ):
            return response
        # Replace, rather than reuse, any existing authenticated session ID.
        boundary.store.revoke(request.cookies.get(SESSION_COOKIE, ""))
        response = RedirectResponse("/dashboard/", status_code=303)
        boundary.clear_cookie(response, LOGIN_COOKIE)
        boundary.cookie(response, SESSION_COOKIE, identifier, age=3600)
        return response

    @router.post("/auth/logout")
    async def logout(request: Request):
        boundary.origin(request, mutation=True)
        identifier, session = await boundary.session(request)
        if not matches_opaque(session.csrf, request.headers.get("x-csrf-token", "")):
            raise HTTPException(403, "Dashboard logout rejected")
        boundary.store.revoke(identifier)
        boundary.store.discard_login(request.cookies.get(LOGIN_COOKIE, ""))
        response = Response(status_code=204)
        boundary.clear_cookie(response, SESSION_COOKIE)
        boundary.clear_cookie(response, LOGIN_COOKIE)
        return response

    @router.get("/api/scans")
    async def scans(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        if set(request.query_params) - {"limit", "offset"}:
            raise HTTPException(422, "Unsupported dashboard parameter")
        if any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
            raise HTTPException(422, "Duplicate dashboard parameter")
        return await boundary.read(request, "/api/v1/scans", {"limit": limit, "offset": offset})

    @router.get("/api/scans/{scan_id}")
    async def scan(request: Request, scan_id: UUID):
        if request.query_params:
            raise HTTPException(422, "Unsupported dashboard parameter")
        return await boundary.read(request, f"/api/v1/scans/{scan_id}")

    @router.get("/api/scans/{scan_id}/technical-posture")
    async def posture(request: Request, scan_id: UUID):
        if request.query_params:
            raise HTTPException(422, "Unsupported dashboard parameter")
        return await boundary.read(request, f"/api/v1/scans/{scan_id}/technical-posture")

    install_investigation(router, boundary)

    static = Path(settings.dashboard_static_dir).resolve()
    if not (static / "index.html").is_file() or not (static / "assets").is_dir():
        raise ValueError("Build the dashboard assets before enabling it")

    @router.get("/")
    async def shell():
        return FileResponse(static / "index.html")

    application.include_router(router)
    application.mount("/dashboard/assets", StaticFiles(directory=static / "assets"))
