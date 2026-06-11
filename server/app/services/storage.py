"""Lưu trữ protected package trên server (cho luồng publish/install tự động).

Mỗi product có thư mục riêng: server/data/packages/<product_id>/ chứa các file
*được phép phát hành* cho client tải về. KHÔNG chứa payload key (key cấp riêng lúc Play).
"""
import re

from ..config import DATA_DIR

PACKAGES_DIR = DATA_DIR / "packages"

# Chỉ những file này được upload/tải. Cố ý KHÔNG có SECRET_payload_key.b64.
ALLOWED_FILES = ("payload.enc", "manifest.signed.json", "public_key.pem")

_PID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def is_valid_product_id(product_id: str) -> bool:
    """Chặn path traversal: product_id chỉ gồm chữ/số/_/- (khớp ProductIn pattern)."""
    return bool(product_id) and bool(_PID_RE.match(product_id))


def package_storage_dir(product_id: str):
    return PACKAGES_DIR / product_id
