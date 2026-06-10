"""Cấu hình client."""
import os

# URL server license (đổi nếu chạy nơi khác)
SERVER_URL = os.environ.get("DRM_SERVER", "http://127.0.0.1:8000")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Thư mục chứa các protected package đã "cài": apps/<product_id>/{launcher.exe, payload.enc, ...}
APPS_DIR = os.path.join(BASE_DIR, "apps")

# File lưu session (token + cache library). Gitignore. GĐ7 sẽ nâng cấp DPAPI.
SESSION_FILE = os.path.join(BASE_DIR, ".session.json")

# Timeout HTTP (giây)
HTTP_TIMEOUT = 8
