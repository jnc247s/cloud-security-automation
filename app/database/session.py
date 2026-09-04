"""SQLAlchemy engine and session lifecycle configuration."""

from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def create_database_engine(database_url: str, **overrides: Any) -> Engine:
    """Create an engine with connection options appropriate to its SQL dialect."""

    url = make_url(database_url)
    options: dict[str, Any] = {"pool_pre_ping": True}
    if url.get_backend_name() == "postgresql":
        options["connect_args"] = {"connect_timeout": 5}
    options.update(overrides)
    return create_engine(url, **options)


settings = get_settings()
engine = create_database_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and ensure it is closed after use."""

    with SessionLocal() as session:
        yield session


def check_database_connection() -> None:
    """Raise a SQLAlchemy error when the configured database is unavailable."""

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
