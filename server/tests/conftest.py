"""Fixtures pytest: dùng SQLite in-memory riêng cho test, override get_db."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app, seed_admin
from app.config import settings


@pytest.fixture()
def client():
    # In-memory DB chung cho toàn bộ kết nối trong 1 test (StaticPool).
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Seed admin vào DB test (lifespan không chạy với TestClient theo cách này nên seed thủ công).
    import app.database as database_module

    original_sessionlocal = database_module.SessionLocal
    database_module.SessionLocal = TestingSession
    # main.seed_admin dùng SessionLocal import trực tiếp -> vá ở cả main.
    import app.main as main_module
    main_module.SessionLocal = TestingSession
    seed_admin()

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    database_module.SessionLocal = original_sessionlocal


@pytest.fixture()
def admin_token(client):
    r = client.post("/auth/login", json={"email": settings.admin_email, "password": settings.admin_password})
    assert r.status_code == 200, r.text
    return r.json()["tokens"]["access_token"]


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
