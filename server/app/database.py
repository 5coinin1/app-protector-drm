"""Khởi tạo SQLAlchemy engine / session / Base."""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

# check_same_thread=False cần cho SQLite khi dùng với nhiều request.
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: mở session cho mỗi request rồi đóng lại."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Tạo bảng nếu chưa có. Import models để chúng được đăng ký với Base."""
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
