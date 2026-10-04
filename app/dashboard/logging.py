"""Do not let HTTP-client debug logging disclose token-exchange headers or bodies."""

import logging


class IdentityHTTPFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name.startswith(("httpx2", "httpcore2", "authlib")):
            record.msg = "Identity-provider/internal HTTP exchange (details omitted)"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


def protect_identity_logs() -> None:
    redactor = IdentityHTTPFilter()
    loggers = [
        logging.getLogger(),
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
    ]
    for logger in loggers:
        for handler in logger.handlers:
            if not any(isinstance(f, IdentityHTTPFilter) for f in handler.filters):
                handler.addFilter(redactor)
