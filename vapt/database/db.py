"""SQLite database initialization."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Default database location — everything lives under ~/.vapt/
DB_DIR = Path.home() / ".vapt"
DB_PATH = DB_DIR / "vapt.db"


class Base(DeclarativeBase):
    """Shared declarative base that all ORM models inherit from."""
    pass


def _set_pragmas(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
    """Enable WAL mode and foreign keys on every new SQLite connection.

    WAL (Write-Ahead Logging) lets readers and writers work at the same time,
    which matters when the monitor is polling in the background.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(db_path: str | Path | None = None):
    """Return a SQLAlchemy engine, creating the DB directory & file if needed."""
    path = Path(db_path) if db_path else DB_PATH
    # Make sure the parent directory exists with restricted permissions
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    url = f"sqlite:///{path}"
    # check_same_thread=False is safe here because SQLAlchemy handles
    # connection pooling and WAL mode prevents write conflicts.
    engine = create_engine(url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_pragmas)
    return engine


def get_session(db_path: str | Path | None = None) -> Session:
    """Spin up a fresh SQLAlchemy session — caller is responsible for closing it."""
    engine = get_engine(db_path)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


def init_db(db_path: str | Path | None = None) -> None:
    """Create all tables if they don't already exist.  Safe to call repeatedly."""
    from vapt.database import models  # noqa: F401

    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
