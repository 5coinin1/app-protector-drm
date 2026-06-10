"""Cấu hình ứng dụng. Đọc từ biến môi trường / file .env (xem .env.example)."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Thư mục server/ (cha của app/)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = f"sqlite:///{(DATA_DIR / 'app.db').as_posix()}"

    # JWT cho session token người dùng (HS256 — chỉ server tự verify).
    # Token entitlement cho launcher dùng Ed25519, xử lý riêng ở giai đoạn 5.
    jwt_secret: str = "dev-secret-CHANGE-ME-in-production"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_days: int = 14

    # Admin khởi tạo lần đầu (seed nếu chưa có user nào)
    admin_email: str = "admin@example.com"
    admin_password: str = "admin12345"

    # Runtime / DRM (GĐ5)
    device_limit: int = 3          # số thiết bị active tối đa mỗi user
    offline_grace_days: int = 7    # thời hạn chạy offline của entitlement token


@lru_cache
def get_settings() -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return Settings()


settings = get_settings()
