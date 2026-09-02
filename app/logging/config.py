"""Minimal logging setup for the application foundation."""

import logging


def configure_logging(log_level: str) -> None:
    """Configure the root logger without replacing server-managed handlers."""

    numeric_level = logging.getLevelNamesMapping()[log_level]
    root_logger = logging.getLogger()

    if not root_logger.handlers:
        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

    root_logger.setLevel(numeric_level)
