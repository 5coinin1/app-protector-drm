"""Cấu hình client."""
import os

# URL server license (đổi nếu chạy nơi khác). Mặc định HTTPS (xem server/run.py + tools/gen_cert.py).
SERVER_URL = os.environ.get("DRM_SERVER", "https://127.0.0.1:8000")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)

# Cert pinning: chỉ TIN đúng cert tự ký của server (certs/server.crt) → chống MITM/giả server.
# requests dùng file này làm CA bundle: cert nào khác sẽ bị từ chối bắt tay TLS.
# Nếu không tìm thấy file (vd. server thật có cert do CA cấp) -> dùng CA hệ thống (True).
SERVER_CERT = os.environ.get("DRM_SERVER_CERT", os.path.join(REPO_ROOT, "certs", "server.crt"))
SERVER_VERIFY = SERVER_CERT if os.path.isfile(SERVER_CERT) else True

# Thư mục chứa các protected package đã "cài": apps/<product_id>/{launcher.exe, payload.enc, ...}
APPS_DIR = os.path.join(BASE_DIR, "apps")

# File lưu session (token + cache library). Gitignore. GĐ7 sẽ nâng cấp DPAPI.
SESSION_FILE = os.path.join(BASE_DIR, ".session.json")

# Timeout HTTP (giây)
HTTP_TIMEOUT = 8
