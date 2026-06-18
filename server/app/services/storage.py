"""Lưu trữ protected package trên server (cho luồng publish/install tự động).

Mỗi product có thư mục riêng: server/data/packages/<product_id>/ chứa các file
*được phép phát hành* cho client tải về. KHÔNG chứa payload key (key cấp riêng lúc Play).
"""
import base64
import re

from ..config import DATA_DIR

# Payload key = AES-256 -> 32 byte. Base64 của 32 byte luôn dài 44 ký tự (kết thúc '=').
PAYLOAD_KEY_BYTES = 32

PACKAGES_DIR = DATA_DIR / "packages"

# Chỉ những file này được upload/tải. Cố ý KHÔNG có SECRET_payload_key.b64.
ALLOWED_FILES = ("payload.enc", "manifest.signed.json", "public_key.pem")

_PID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def is_valid_product_id(product_id: str) -> bool:
    """Chặn path traversal: product_id chỉ gồm chữ/số/_/- (khớp ProductIn pattern)."""
    return bool(product_id) and bool(_PID_RE.match(product_id))


def is_valid_payload_key_b64(value: str) -> bool:
    """Payload key hợp lệ = base64 hợp lệ giải ra ĐÚNG 32 byte (khóa AES-256).

    Loại bỏ key rác/sai định dạng trước khi lưu — tránh đè nhầm key đúng (vd của bản auto-pack)
    bằng chuỗi vô nghĩa, dẫn tới giải mã thất bại lúc Play mà không rõ lý do.
    """
    if not value:
        return False
    try:
        return len(base64.b64decode(value.strip(), validate=True)) == PAYLOAD_KEY_BYTES
    except Exception:
        return False


def package_storage_dir(product_id: str):
    return PACKAGES_DIR / product_id
