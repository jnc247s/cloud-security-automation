"""SQLAlchemy engine and session lifecycle configuration."""

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    connect_args={"connect_timeout": 5},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and ensure it is closed after use."""

    with SessionLocal() as session:
        yield session


def check_database_connection() -> None:
    """Raise a SQLAlchemy error when the configured database is unavailable."""

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
