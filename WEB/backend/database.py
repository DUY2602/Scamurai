"""Database connection helpers for Railway databases."""

from __future__ import annotations

import os
from collections.abc import Generator
from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


BACKEND_DIR = Path(__file__).resolve().parent
ENV_PATH = BACKEND_DIR / ".env"


def _load_local_env() -> None:
    """Load key/value pairs from backend/.env into process environment."""
    if not ENV_PATH.exists():
        return

    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#") or "=" not in cleaned:
            continue

        key, value = cleaned.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


def _normalize_database_url(raw_url: str) -> str:
    """Convert Railway URLs into SQLAlchemy-compatible driver URLs."""
    database_url = raw_url.strip()
    if not database_url:
        raise RuntimeError(
            "Missing database URL. Set DATABASE_URL or DATABASE_PUBLIC_URL from your Railway service."
        )

    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    elif database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif database_url.startswith("mysql://"):
        database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)

    if database_url.startswith(("postgresql+psycopg://", "postgres://")) and "sslmode=" not in database_url:
        separator = "&" if "?" in database_url else "?"
        database_url = f"{database_url}{separator}sslmode=require"

    if database_url.startswith("mysql+pymysql://") and "ssl_ca=" not in database_url and "ssl_disabled=" not in database_url:
        separator = "&" if "?" in database_url else "?"
        database_url = f"{database_url}{separator}ssl_disabled=false"

    return database_url


def get_database_url() -> str:
    """Read the Railway database URL from environment variables or backend/.env."""
    _load_local_env()
    raw_url = os.getenv("DATABASE_URL") or os.getenv("DATABASE_PUBLIC_URL") or ""
    return _normalize_database_url(raw_url)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Create and cache the SQLAlchemy engine only when it is first needed."""
    return create_engine(
        get_database_url(),
        pool_pre_ping=True,
        pool_recycle=300,
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    """Create and cache the session factory for the active engine."""
    return sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=get_engine(),
    )


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a database session."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def check_database_connection() -> bool:
    """Return True when the Railway database is reachable."""
    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
    return True
