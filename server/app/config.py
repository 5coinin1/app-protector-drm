"""Cấu hình ứng dụng. Đọc từ biến môi trường / file .env (xem .env.example)."""
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Thư mục server/ (cha của app/)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# Giá trị placeholder: nếu jwt_secret còn để như vầy nghĩa là CHƯA đặt secret thật.
_DEFAULT_JWT_SECRET = "dev-secret-CHANGE-ME-in-production"
_JWT_SECRET_FILE = DATA_DIR / "jwt_secret.key"


def _resolve_jwt_secret(value: str) -> str:
    """Không hardcode secret: ưu tiên giá trị đặt qua .env/biến môi trường; nếu chưa đặt thì
    sinh secret ngẫu nhiên bền (lưu data/jwt_secret.key, gitignore) — ổn định qua các lần khởi động."""
    if value and value != _DEFAULT_JWT_SECRET:
        return value
    if _JWT_SECRET_FILE.exists():
        return _JWT_SECRET_FILE.read_text(encoding="utf-8").strip()
    generated = secrets.token_urlsafe(48)
    _JWT_SECRET_FILE.write_text(generated, encoding="utf-8")
    return generated


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = f"sqlite:///{(DATA_DIR / 'app.db').as_posix()}"

    # JWT cho session token người dùng (HS256 — chỉ server tự verify).
    # Token entitlement cho launcher dùng Ed25519, xử lý riêng ở giai đoạn 5.
    jwt_secret: str = _DEFAULT_JWT_SECRET   # được thay bằng secret thật trong get_settings()
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_days: int = 14

    # Rate-limit đăng nhập (chống brute-force): tối đa N lần fail / cửa sổ thời gian / mỗi IP.
    login_max_attempts: int = 5
    login_window_seconds: int = 300

    # Admin khởi tạo lần đầu (seed nếu chưa có user nào)
    admin_email: str = "admin@example.com"
    admin_password: str = "admin12345"

    # Runtime / DRM (GĐ5)
    device_limit: int = 3          # số thiết bị active tối đa mỗi user
    offline_grace_days: int = 7    # thời hạn chạy offline của entitlement token

    # Đóng gói trên Dashboard (gọi Protector CLI ngay từ web).
    # protector.exe nằm ở <repo>/protector/build/protector.exe theo mặc định.
    protector_exe: str = str(BASE_DIR.parent / "protector" / "build" / "protector.exe")
    # protector.exe link tới DLL của MSYS2; cần thư mục này trong PATH khi chạy.
    mingw_bin: str = r"C:\msys64\mingw64\bin"
    # Thư mục giữ keypair ký manifest (protector tự sinh nếu chưa có) — dùng chung mọi product.
    protector_keys_dir: str = str(DATA_DIR / "protector_keys")
    # Công cụ giải nén ngoài cho .rar/.7z khi đóng gói trên Dashboard (Python chỉ đọc .zip sẵn).
    unrar_exe: str = r"C:\Program Files\WinRAR\UnRAR.exe"
    sevenzip_exe: str = r"C:\Program Files\7-Zip\7z.exe"


@lru_cache
def get_settings() -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    s = Settings()
    s.jwt_secret = _resolve_jwt_secret(s.jwt_secret)  # không để secret mặc định đi vào thực tế
    return s


settings = get_settings()
