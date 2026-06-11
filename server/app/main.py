"""Điểm khởi động FastAPI: tạo bảng, seed admin, gắn router.

Chạy: uvicorn app.main:app --reload   (trong thư mục server/)
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from .config import settings
from .database import SessionLocal, init_db
from .models import User
from .routes import admin, auth, dashboard, library, packages, runtime
from .security import hash_password


def seed_admin() -> None:
    """Tạo admin mặc định nếu DB chưa có user nào (tiện cho lần chạy đầu)."""
    with SessionLocal() as db:
        has_user = db.scalar(select(User).limit(1))
        if has_user is None:
            db.add(
                User(
                    email=settings.admin_email,
                    password_hash=hash_password(settings.admin_password),
                    role="admin",
                )
            )
            db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_admin()
    yield


app = FastAPI(title="License / Entitlement Server", version="0.1.0", lifespan=lifespan)

app.include_router(auth.router)
app.include_router(library.router)
app.include_router(packages.router)
app.include_router(runtime.router)
app.include_router(admin.router)
app.include_router(dashboard.router)


@app.get("/", include_in_schema=False)
def root():
    # Trang gốc -> Admin Dashboard (UI). API docs ở /docs.
    return RedirectResponse(url="/dashboard")


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}
