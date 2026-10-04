"""Dashboard-only headers and callback access-log sanitization; API defaults stay unchanged."""

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
    "object-src 'none'"
)


class DashboardSecurityMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not (
            scope["path"] == "/dashboard" or scope["path"].startswith("/dashboard/")
        ):
            await self.app(scope, receive, send)
            return

        response_started = False

        async def secured_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                # Uvicorn logs the shared scope at response start: never log callback codes.
                scope["query_string"] = b""
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in {b"cache-control", b"content-security-policy"}
                ]
                headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"content-security-policy", CSP.encode()),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"cross-origin-opener-policy", b"same-origin"),
                        (b"cross-origin-resource-policy", b"same-origin"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, secured_send)
        except Exception:
            # Starlette's outer ServerErrorMiddleware is outside user middleware. Send
            # its same fixed 500 through our boundary first, then re-raise so defects
            # remain observable. Never send a second response after streaming started.
            scope["query_string"] = b""
            if not response_started:
                await PlainTextResponse("Internal Server Error", status_code=500)(
                    scope, receive, secured_send
                )
            raise
        finally:
            scope["query_string"] = b""
