
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DB_DIR = Path.home() / ".vapt"
DB_PATH = DB_DIR / "vapt.db"


class Base(DeclarativeBase):
    pass


def _set_pragmas(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(db_path: str | Path | None = None):
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    url = f"sqlite:///{path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_pragmas)
    return engine


def get_session(db_path: str | Path | None = None) -> Session:
    engine = get_engine(db_path)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


def init_db(db_path: str | Path | None = None) -> None:
    from vapt.database import models

    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
